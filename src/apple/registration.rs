use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use openssl::{
    ec::{EcGroup, EcKey},
    nid::Nid,
    pkey::{PKey, Private},
    rsa::Rsa,
};
use plist::{Data, Dictionary, Value};
use reqwest::{
    Client,
    header::{HeaderMap, HeaderName, HeaderValue},
};
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::address;

use super::{
    Identity, Session,
    aps::TOPIC,
    certified_rsa,
    crypto::KeyPair,
    http::{apple_client, plist_xml_gzip, read_response},
    nonce, rsa_signature,
};

const REGISTER_URL: &str =
    "https://identity.ess.apple.com/WebObjects/TDIdentityService.woa/wa/register";

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
struct Registration {
    #[serde(flatten)]
    device: DeviceRegistration,
    user_id: String,
    auth_certificate: Data,
    auth_private_key: Data,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) struct DeviceRegistration {
    pub(super) version: u32,
    pub(super) handle: String,
    pub(super) push_token: Data,
    pub(super) push_certificate: Data,
    pub(super) push_private_key: Data,
    pub(super) protocol_version: u32,
    pub(super) user_agent: String,
    pub(super) device_name: String,
    pub(super) hardware_version: String,
    pub(super) os_version: String,
    pub(super) software_version: String,
    pub(super) private_device_data: Dictionary,
    pub(super) validation_data: Data,
}

pub(super) struct AccountAuth {
    pub user_id: String,
    pub certificate: Data,
    pub key: PKey<Private>,
}

impl Drop for Registration {
    fn drop(&mut self) {
        clear_data(&mut self.auth_private_key);
    }
}

impl Drop for DeviceRegistration {
    fn drop(&mut self) {
        for field in [
            &mut self.push_token,
            &mut self.push_private_key,
            &mut self.validation_data,
        ] {
            clear_data(field);
        }
    }
}

fn clear_data(data: &mut Data) {
    use zeroize::Zeroize;
    let mut bytes: Vec<u8> = std::mem::replace(data, Data::new(Vec::new())).into();
    bytes.zeroize();
}

impl DeviceRegistration {
    pub(super) fn token(&self) -> Result<[u8; 32]> {
        self.push_token
            .as_ref()
            .try_into()
            .context("Expected a 32-byte APNs device token")
    }

    pub(super) fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1 && self.protocol_version > 0,
            "Invalid registration version"
        );
        ensure!(
            !self.validation_data.as_ref().is_empty(),
            "Apple device validation data is required"
        );
        ensure!(
            !self.user_agent.is_empty()
                && self.user_agent.len() <= 256
                && self
                    .user_agent
                    .bytes()
                    .all(|byte| byte == b' ' || byte.is_ascii_graphic()),
            "Invalid Apple device user agent"
        );
        address(&self.handle)?;
        self.token()?;
        certified_rsa(&self.push_certificate, &self.push_private_key)?;
        Ok(())
    }
}

pub async fn register_device(input: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let registration: Registration =
        plist::from_bytes(input).context("Could not decode registration plist")?;
    registration.device.validate()?;
    let auth = AccountAuth {
        user_id: registration.user_id.clone(),
        certificate: registration.auth_certificate.clone(),
        key: certified_rsa(
            &registration.auth_certificate,
            &registration.auth_private_key,
        )?,
    };
    register(&apple_client()?, &registration.device, auth).await
}

pub(super) async fn register(
    client: &Client,
    registration: &DeviceRegistration,
    auth: AccountAuth,
) -> Result<Zeroizing<Vec<u8>>> {
    let handle = address(&registration.handle)?;
    let token = registration.token()?;
    let push = certified_rsa(
        &registration.push_certificate,
        &registration.push_private_key,
    )?;
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let signing = PKey::from_ec_key(
        EcKey::generate(&group).context("Could not generate a P-256 message key")?,
    )?;
    let encryption = PKey::from_rsa(Rsa::generate(1280)?)?;
    let signing_bytes = Zeroizing::new(signing.private_key_to_der()?);
    let encryption_bytes = Zeroizing::new(encryption.private_key_to_der()?);
    let pair = KeyPair::private(&signing_bytes, &encryption_bytes)?;

    let document = registration_document(registration, &auth.user_id, &handle, pair.public_der()?);
    let body = plist_xml_gzip(&document)?;
    let mut headers = HeaderMap::new();
    for (key, value) in [
        ("x-push-token", STANDARD.encode(token)),
        (
            "x-protocol-version",
            registration.protocol_version.to_string(),
        ),
        (
            "user-agent",
            format!(
                "com.apple.invitation-registration {}",
                registration.user_agent
            ),
        ),
        ("x-auth-user-id-0", auth.user_id.clone()),
        ("content-type", "application/x-apple-plist".into()),
        ("content-encoding", "gzip".into()),
        ("accept-encoding", "gzip".into()),
    ] {
        headers.insert(HeaderName::from_static(key), HeaderValue::from_str(&value)?);
    }
    for (name, suffix, cert, key) in [
        ("push", "", &registration.push_certificate, &push),
        ("auth", "-0", &auth.certificate, &auth.key),
    ] {
        let nonce = nonce(1)?;
        let mut signed = nonce.to_vec();
        for field in [
            b"id-register".as_slice(),
            b"",
            body.as_slice(),
            token.as_slice(),
        ] {
            signed.extend_from_slice(&u32::try_from(field.len())?.to_be_bytes());
            signed.extend_from_slice(field);
        }
        for (kind, value) in [
            ("nonce", STANDARD.encode(nonce)),
            ("sig", STANDARD.encode(rsa_signature(key, &signed)?)),
            ("cert", STANDARD.encode(cert.as_ref())),
        ] {
            headers.insert(
                HeaderName::from_bytes(format!("x-{name}-{kind}{suffix}").as_bytes())?,
                HeaderValue::from_str(&value)?,
            );
        }
    }
    let response = client
        .post(REGISTER_URL)
        .headers(headers)
        .body(body)
        .send()
        .await
        .context("Could not reach Apple's registration endpoint")?
        .error_for_status()?;
    let bytes = read_response(response).await?;
    let response: RegisterReply =
        plist::from_bytes(&bytes).context("Could not decode Apple's registration response")?;
    let cert = registered_certificate(response, &auth.user_id, &handle)?;
    let session = Session {
        version: 1,
        handle,
        push_token: Data::new(token.to_vec()),
        push_certificate: registration.push_certificate.clone(),
        push_private_key: registration.push_private_key.clone(),
        ids_certificate: cert,
        ids_private_key: Data::new(auth.key.private_key_to_der()?),
        signing_private_key: Data::new(signing_bytes.to_vec()),
        encryption_private_key: Data::new(encryption_bytes.to_vec()),
        protocol_version: registration.protocol_version,
        user_agent: registration.user_agent.clone(),
    };
    let mut serialized = Zeroizing::new(Vec::new());
    plist::to_writer_binary(&mut *serialized, &session)?;
    Identity::parse(&serialized)
        .context("Apple returned a certificate incompatible with the session")?;
    Ok(serialized)
}

fn registration_document(
    input: &DeviceRegistration,
    user_id: &str,
    handle: &str,
    public_identity: Vec<u8>,
) -> Value {
    let map = |fields: &[(&str, Value)]| {
        Value::Dictionary(
            fields
                .iter()
                .map(|(key, item)| (key.to_string(), item.clone()))
                .collect(),
        )
    };
    let client_data = map(&[
        ("public-message-identity-key", Value::Data(public_identity)),
        ("public-message-identity-version", 2.into()),
        ("ec-version", 1.into()),
        ("supports-emoji-tapbacks", Value::Boolean(true)),
    ]);
    let account = map(&[
        ("user-id", user_id.into()),
        ("uris", Value::Array(vec![map(&[("uri", handle.into())])])),
        ("client-data", client_data),
    ]);
    let capabilities = map(&[
        ("flags", 17.into()),
        ("name", "Messenger".into()),
        ("version", 1.into()),
    ]);
    let service = map(&[
        ("service", TOPIC.into()),
        ("sub-services", Value::Array(Vec::new())),
        ("capabilities", Value::Array(vec![capabilities])),
        ("users", Value::Array(vec![account])),
    ]);
    map(&[
        ("device-name", input.device_name.as_str().into()),
        ("hardware-version", input.hardware_version.as_str().into()),
        ("os-version", input.os_version.as_str().into()),
        ("software-version", input.software_version.as_str().into()),
        ("language", "en-US".into()),
        (
            "private-device-data",
            Value::Dictionary(input.private_device_data.clone()),
        ),
        ("services", Value::Array(vec![service])),
        (
            "validation-data",
            Value::Data(input.validation_data.as_ref().to_vec()),
        ),
    ])
}

#[derive(Deserialize)]
struct RegisterReply {
    status: u64,
    #[serde(default)]
    services: Vec<RegistrationService>,
}

#[derive(Deserialize)]
struct RegistrationService {
    service: String,
    #[serde(default)]
    users: Vec<RegisteredUser>,
}

#[derive(Deserialize)]
struct RegisteredUser {
    #[serde(rename = "user-id")]
    user_id: String,
    status: u64,
    cert: Option<Data>,
    #[serde(default)]
    uris: Vec<RegisteredUri>,
}

#[derive(Deserialize)]
struct RegisteredUri {
    uri: String,
    status: u64,
}

fn registered_certificate(response: RegisterReply, user_id: &str, handle: &str) -> Result<Data> {
    ensure!(
        response.status == 0,
        "Apple rejected registration (status {})",
        response.status
    );
    let account = response
        .services
        .into_iter()
        .find(|entry| entry.service == TOPIC)
        .context("Apple did not return an iMessage registration")?
        .users
        .into_iter()
        .find(|entry| entry.user_id == user_id)
        .context("Apple did not return the requested account")?;
    ensure!(
        account.status == 0,
        "Apple rejected the iMessage account (status {})",
        account.status
    );
    let registered = account
        .uris
        .iter()
        .find(|entry| address(&entry.uri).is_ok_and(|uri| uri == handle))
        .context("Apple did not register the requested iMessage address")?;
    ensure!(
        registered.status == 0,
        "Apple rejected the iMessage address (status {})",
        registered.status
    );
    account
        .cert
        .context("Apple did not return an IDS certificate")
}
