use std::{net::IpAddr, path::Path, sync::Arc};

use anyhow::{Context, Result, ensure};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path as RoutePath, Query, Request, State},
    http::{HeaderValue, StatusCode, header, uri::Authority},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use openssl::{rand::rand_bytes, sha::sha256};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tokio::sync::Semaphore;
use url::{Host, Url};
use zeroize::Zeroizing;

use crate::{
    Conversation, FILE_LIMIT, MAX_ATTACHMENTS, Message, SendText, SetTapback, Status, Tapback,
    engine::Engine, storage,
};

#[derive(Clone)]
pub struct AccessPolicy(Option<Arc<Credentials>>);

#[derive(Deserialize, Serialize)]
struct Account {
    username: String,
    password_hash: String,
}

struct Credentials {
    account: Account,
    slots: Arc<Semaphore>,
}

impl AccessPolicy {
    pub fn loopback() -> Self {
        Self(None)
    }

    pub fn from_file(path: &Path) -> Result<Self> {
        let account: Account = serde_json::from_slice(&storage::read_private(path)?)?;
        validate_username(&account.username)?;
        let hash = PasswordHash::new(&account.password_hash)
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        ensure!(
            hash.algorithm.as_str() == "argon2id",
            "Expected an Argon2id password hash"
        );
        Ok(Self(Some(Arc::new(Credentials {
            account,
            slots: Arc::new(Semaphore::new(2)),
        }))))
    }

    pub fn requires_login(&self) -> bool {
        self.0.is_some()
    }
}

pub fn save_account(path: &Path, username: &str, password: &str) -> Result<()> {
    validate_username(username)?;
    ensure!(
        (12..=512).contains(&password.len()),
        "Use a password between 12 and 512 bytes"
    );
    let mut seed = Zeroizing::new([0; 16]);
    rand_bytes(seed.as_mut())?;
    let salt = SaltString::encode_b64(seed.as_ref()).map_err(|error| anyhow::anyhow!("{error}"))?;
    let password_hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|error| anyhow::anyhow!("{error}"))?
        .to_string();
    storage::write_private(
        path,
        &serde_json::to_vec(&Account {
            username: username.into(),
            password_hash,
        })?,
    )
}

pub fn validate_username(username: &str) -> Result<()> {
    ensure!(
        (1..=64).contains(&username.len())
            && username
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric()
                    || matches!(byte, b'.' | b'-' | b'_' | b'@')),
        "Use 1–64 letters, numbers, or . - _ @ in the server username"
    );
    Ok(())
}

pub fn server_url(input: &str) -> Result<Url> {
    let url = Url::parse(input.trim()).context("Enter the server URL with http:// or https://")?;
    let local = match url.host() {
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        Some(Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
        None => false,
    };
    ensure!(
        (url.scheme() == "https" && url.host().is_some()) || (url.scheme() == "http" && local),
        "Use HTTPS for a network server. HTTP is available on loopback"
    );
    ensure!(
        url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && url.path() == "/",
        "Enter the server origin. Put the username and password in their own fields"
    );
    Ok(url)
}

#[derive(Deserialize)]
struct MessageQuery {
    address: String,
    #[serde(default)]
    offset: u32,
}

#[derive(Deserialize)]
struct ConversationQuery {
    address: String,
}

#[derive(Serialize, Deserialize)]
pub struct ApiError {
    pub error: String,
}

pub fn router(engine: Engine, access: AccessPolicy) -> Router {
    Router::new()
        .route("/v1/status", get(status))
        .route(
            "/v1/conversations",
            get(conversations).delete(delete_conversation),
        )
        .route("/v1/messages", get(messages).post(send))
        .route("/v1/messages/{id}/tapback", put(set_tapback))
        .route("/v1/calls/{id}/decline", post(decline_call))
        .route("/v1/attachments/{id}/{index}", get(attachment))
        .layer(DefaultBodyLimit::max(
            FILE_LIMIT.div_ceil(3) * 4 + 48 * 1024,
        ))
        .layer(middleware::from_fn_with_state(access, authorize))
        .layer(middleware::from_fn(no_store))
        .with_state(engine)
}

async fn status(State(engine): State<Engine>) -> Json<Status> {
    Json(engine.status())
}

async fn conversations(State(engine): State<Engine>) -> Result<Json<Vec<Conversation>>, Failure> {
    Ok(Json(engine.chats()?))
}

async fn delete_conversation(
    State(engine): State<Engine>,
    Query(query): Query<ConversationQuery>,
) -> Result<StatusCode, Failure> {
    engine.delete_conversation(&query.address)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn messages(
    State(engine): State<Engine>,
    Query(query): Query<MessageQuery>,
) -> Result<Json<Vec<Message>>, Failure> {
    Ok(Json(engine.messages(&query.address, query.offset)?))
}

async fn send(
    State(engine): State<Engine>,
    Json(request): Json<SendText>,
) -> Result<Json<Message>, Failure> {
    Ok(Json(engine.send(request).await?))
}

async fn set_tapback(
    State(engine): State<Engine>,
    RoutePath(id): RoutePath<uuid::Uuid>,
    Json(request): Json<SetTapback>,
) -> Result<Json<Vec<Tapback>>, Failure> {
    Ok(Json(engine.set_message_tapback(id, request).await?))
}

async fn decline_call(
    State(engine): State<Engine>,
    RoutePath(id): RoutePath<uuid::Uuid>,
) -> Result<StatusCode, Failure> {
    engine.decline_call(id).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn attachment(
    State(engine): State<Engine>,
    RoutePath((id, index)): RoutePath<(uuid::Uuid, usize)>,
) -> Result<impl IntoResponse, Failure> {
    if index >= MAX_ATTACHMENTS {
        return Err(anyhow::anyhow!("Invalid attachment index").into());
    }
    let bytes = engine.attachment(id, index).await?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        bytes,
    ))
}

struct Failure(anyhow::Error);

impl From<anyhow::Error> for Failure {
    fn from(error: anyhow::Error) -> Self {
        Self(error)
    }
}

impl IntoResponse for Failure {
    fn into_response(self) -> Response {
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(ApiError {
                error: self.0.to_string(),
            }),
        )
            .into_response()
    }
}

async fn no_store(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn authorize(State(access): State<AccessPolicy>, request: Request, next: Next) -> Response {
    if request
        .headers()
        .get("x-messages-api")
        .and_then(|value| value.to_str().ok())
        != Some("1")
        || request.headers().contains_key(header::ORIGIN)
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Some(credentials) = access.0 else {
        if !local_authority(&request) {
            return StatusCode::FORBIDDEN.into_response();
        }
        return next.run(request).await;
    };
    let Some(secret) = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(decode_basic)
    else {
        return unauthenticated();
    };
    let Ok(slot) = credentials.slots.clone().try_acquire_owned() else {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    };
    let valid = tokio::task::spawn_blocking(move || {
        let _slot = slot;
        let (username, password) = secret
            .split_once(':')
            .expect("Basic credentials have a delimiter");
        let username_matches =
            sha256(username.as_bytes()).ct_eq(&sha256(credentials.account.username.as_bytes()));
        let password_matches =
            PasswordHash::new(&credentials.account.password_hash).is_ok_and(|hash| {
                Argon2::default()
                    .verify_password(password.as_bytes(), &hash)
                    .is_ok()
            });
        bool::from(username_matches) && password_matches
    })
    .await
    .unwrap_or(false);
    if valid {
        next.run(request).await
    } else {
        unauthenticated()
    }
}

fn decode_basic(header: &str) -> Option<Zeroizing<String>> {
    let (scheme, encoded) = header.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") || encoded.len() > 800 {
        return None;
    }
    let decoded = Zeroizing::new(STANDARD.decode(encoded).ok()?);
    let text = std::str::from_utf8(&decoded).ok()?;
    let (username, password) = text.split_once(':')?;
    if username.len() > 64 || password.len() > 512 {
        return None;
    }
    Some(Zeroizing::new(text.into()))
}

fn local_authority(request: &Request) -> bool {
    let host = request.uri().authority().cloned().or_else(|| {
        request
            .headers()
            .get(header::HOST)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<Authority>().ok())
    });
    host.is_some_and(|authority| {
        let name = authority.host();
        name.eq_ignore_ascii_case("localhost")
            || name
                .trim_start_matches('[')
                .trim_end_matches(']')
                .parse::<IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    })
}

fn unauthenticated() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(
            header::WWW_AUTHENTICATE,
            "Basic realm=\"Linux Messages\", charset=\"UTF-8\"",
        )],
        Json(ApiError {
            error: "The server requires a valid username and password".into(),
        }),
    )
        .into_response()
}
