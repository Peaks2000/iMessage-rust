use std::{
    io::{Read, Write},
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use flate2::{Compression, read::GzDecoder, write::GzEncoder};
use openssl::{
    ec::{EcGroup, EcKey},
    nid::Nid,
    pkey::PKey,
    rsa::Rsa,
};
use plist::{Data, Dictionary, Value};
use reqwest::{
    Certificate, Client,
    header::{HeaderMap, HeaderName, HeaderValue},
};
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::address;

use super::{
    Identity, Session,
    aps::{CERTIFICATES, TOPIC},
    certified_rsa,
    crypto::KeyPair,
    nonce, rsa_signature,
};

const REGISTER_URL: &str =
    "https://identity.ess.apple.com/WebObjects/TDIdentityService.woa/wa/register";
const MAX_RESPONSE: usize = 256 * 1024;

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct Registration {
    version: u32,
    user_id: String,
    handle: String,
    push_token: Data,
    push_certificate: Data,
    push_private_key: Data,
    auth_certificate: Data,
    auth_private_key: Data,
    protocol_version: u32,
    user_agent: String,
    device_name: String,
    hardware_version: String,
    os_version: String,
    software_version: String,
    private_device_data: Dictionary,
    validation_data: Data,
}

impl Drop for Registration {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        for field in [
            &mut self.push_token,
            &mut self.push_private_key,
            &mut self.auth_private_key,
            &mut self.validation_data,
        ] {
            let mut bytes: Vec<u8> = std::mem::replace(field, Data::new(Vec::new())).into();
            bytes.zeroize();
        }
    }
}

pub async fn register_device(input: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let registration: Registration =
        plist::from_bytes(input).context("Could not decode registration plist")?;
    ensure!(
        registration.version == 1 && registration.protocol_version > 0,
        "Invalid registration version"
    );
    ensure!(
        !registration.validation_data.as_ref().is_empty(),
        "Apple device validation data is required"
    );
    let handle = address(&registration.handle)?;
    let token: [u8; 32] = registration
        .push_token
        .as_ref()
        .try_into()
        .context("Expected a 32-byte APNs device token")?;
    let push = certified_rsa(
        &registration.push_certificate,
        &registration.push_private_key,
    )?;
    let auth = certified_rsa(
        &registration.auth_certificate,
        &registration.auth_private_key,
    )?;
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let signing = PKey::from_ec_key(
        EcKey::generate(&group).context("Could not generate a P-256 message key")?,
    )?;
    let encryption = PKey::from_rsa(Rsa::generate(1280)?)?;
    let signing_bytes = Zeroizing::new(signing.private_key_to_der()?);
    let encryption_bytes = Zeroizing::new(encryption.private_key_to_der()?);
    let pair = KeyPair::private(&signing_bytes, &encryption_bytes)?;

    let document = registration_document(&registration, &handle, pair.public_der()?);
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    plist::to_writer_xml(&mut encoder, &document)?;
    encoder.flush()?;
    let body = encoder.finish()?;
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
        ("x-auth-user-id-0", registration.user_id.clone()),
        ("content-type", "application/x-apple-plist".into()),
        ("content-encoding", "gzip".into()),
        ("accept-encoding", "gzip".into()),
    ] {
        headers.insert(HeaderName::from_static(key), HeaderValue::from_str(&value)?);
    }
    for (name, suffix, cert, key) in [
        ("push", "", &registration.push_certificate, &push),
        ("auth", "-0", &registration.auth_certificate, &auth),
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
    let client = apple_client()?;
    let mut response = client
        .post(REGISTER_URL)
        .headers(headers)
        .body(body)
        .send()
        .await
        .context("Could not reach Apple's registration endpoint")?
        .error_for_status()?;
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            bytes.len() + chunk.len() <= MAX_RESPONSE,
            "Apple registration response exceeds size limit"
        );
        bytes.extend_from_slice(&chunk);
    }
    if bytes.starts_with(&[0x1f, 0x8b]) {
        let mut decoded = Vec::new();
        GzDecoder::new(bytes.as_slice())
            .take(MAX_RESPONSE as u64 + 1)
            .read_to_end(&mut decoded)?;
        ensure!(
            decoded.len() <= MAX_RESPONSE,
            "Apple registration response exceeds size limit"
        );
        bytes = decoded;
    }
    let response: RegisterReply =
        plist::from_bytes(&bytes).context("Could not decode Apple's registration response")?;
    let cert = registered_certificate(response, &registration.user_id, &handle)?;
    let session = Session {
        version: 1,
        handle,
        push_token: Data::new(token.to_vec()),
        push_certificate: registration.push_certificate.clone(),
        push_private_key: registration.push_private_key.clone(),
        ids_certificate: cert,
        ids_private_key: registration.auth_private_key.clone(),
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

fn apple_client() -> Result<Client> {
    let mut client = Client::builder()
        .tls_built_in_root_certs(false)
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(20));
    for certificate in CERTIFICATES {
        client = client.add_root_certificate(Certificate::from_der(certificate)?);
    }
    Ok(client.build()?)
}

fn registration_document(input: &Registration, handle: &str, public_identity: Vec<u8>) -> Value {
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
    ]);
    let account = map(&[
        ("user-id", input.user_id.as_str().into()),
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
