use std::collections::BTreeMap;

use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use openssl::{
    ec::{EcGroup, EcKey},
    nid::Nid,
    pkey::{PKey, Private},
    rsa::Rsa,
    x509::X509,
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
    facetime,
    http::{apple_client, plist_xml_gzip, read_response},
    nonce,
    provisioning::DeviceProvider,
    rsa_signature,
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
    #[serde(default)]
    pub(super) include_facetime: bool,
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
    let mut registration: Registration =
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
    register(&apple_client()?, &mut registration.device, auth, None, None).await
}

pub(super) async fn register(
    client: &Client,
    registration: &mut DeviceRegistration,
    auth: AccountAuth,
    fresh_proof_provider: Option<&DeviceProvider>,
    existing: Option<&Identity>,
) -> Result<Zeroizing<Vec<u8>>> {
    register_at(
        client,
        REGISTER_URL,
        registration,
        auth,
        fresh_proof_provider,
        existing,
    )
    .await
}

async fn register_at(
    client: &Client,
    endpoint: &str,
    registration: &mut DeviceRegistration,
    auth: AccountAuth,
    fresh_proof_provider: Option<&DeviceProvider>,
    existing: Option<&Identity>,
) -> Result<Zeroizing<Vec<u8>>> {
    let handle = address(&registration.handle)?;
    let token = registration.token()?;
    let push = certified_rsa(
        &registration.push_certificate,
        &registration.push_private_key,
    )?;
    let (signing_bytes, encryption_bytes) = if let Some(identity) = existing {
        ensure!(
            identity.handle == handle
                && identity.token == token
                && identity.push_cert == registration.push_certificate.as_ref()
                && identity.push_key.public_eq(&push)
                && identity.ids_key.public_eq(&auth.key),
            "The FaceTime registration does not match the saved iMessage identity"
        );
        identity.message_keys.registration_keys()?
    } else {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let signing = PKey::from_ec_key(
            EcKey::generate(&group).context("Could not generate a P-256 message key")?,
        )?;
        let encryption = PKey::from_rsa(Rsa::generate(1280)?)?;
        (
            Zeroizing::new(signing.private_key_to_der()?),
            Zeroizing::new(encryption.private_key_to_der()?),
        )
    };
    let pair = KeyPair::private(&signing_bytes, &encryption_bytes)?;
    let public_identity = pair.public_der()?;
    let relay_signing = if existing.is_some() || registration.include_facetime {
        Some(
            match existing.and_then(|identity| identity.facetime_relay_signing.clone()) {
                Some(signing) => signing,
                None => facetime::RelaySigningKey::generate()?,
            },
        )
    } else {
        None
    };
    let relay_directory = relay_signing
        .as_ref()
        .map(facetime::RelaySigningKey::directory_data)
        .transpose()?;

    let submit = async |registration: &DeviceRegistration, services| {
        let document = registration_document(
            registration,
            &auth.user_id,
            &handle,
            &public_identity,
            relay_directory.as_deref(),
            services,
        );
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
            .post(endpoint)
            .headers(headers)
            .body(body)
            .send()
            .await
            .context("Could not reach Apple's registration endpoint")?
            .error_for_status()?;
        let bytes = read_response(response).await?;
        plist::from_bytes::<RegisterReply>(&bytes)
            .context("Could not decode Apple's registration response")
    };
    let (cert, facetime_certificates) = if let Some(identity) = existing {
        let response = submit(registration, Services::FaceTime).await?;
        let calls = required_facetime_certificates(&response, &auth, &handle)?;
        (Data::new(identity.ids_cert.clone()), calls)
    } else {
        let register_new = async |registration: &DeviceRegistration, include_facetime| {
            let services = if include_facetime {
                Services::Both
            } else {
                Services::Messages
            };
            let response = submit(registration, services).await?;
            select_certificates(&response, &auth, &handle, include_facetime)
        };
        match register_new(registration, registration.include_facetime).await {
            Err(error) if registration.include_facetime && error.is::<RegistrationRejected>() => {
                let Some(provider) = fresh_proof_provider else {
                    return Err(error);
                };
                // Retry an explicit rejection using the same keys and a new validation proof.
                let proof = provider.validation().await.with_context(|| {
                format!(
                    "{error}. Could not refresh device validation to retry iMessage registration"
                )
            })?;
                clear_data(&mut registration.validation_data);
                registration.validation_data = proof;
                register_new(registration, false)
                    .await
                    .with_context(|| format!("{error}. The iMessage registration retry failed"))?
            }
            result => result?,
        }
    };
    let facetime_relay_signing_private_key =
        if facetime_certificates.contains_key(facetime::SIGNALING) {
            relay_signing
                .as_ref()
                .map(facetime::RelaySigningKey::private_der)
                .transpose()?
                .map(|bytes| Data::new(bytes.to_vec()))
        } else {
            None
        };
    let session = Session {
        version: 1,
        handle,
        push_token: Data::new(token.to_vec()),
        push_certificate: registration.push_certificate.clone(),
        push_private_key: registration.push_private_key.clone(),
        ids_certificate: cert,
        ids_private_key: Data::new(auth.key.private_key_to_der()?),
        facetime_certificates,
        facetime_relay_signing_private_key,
        signing_private_key: Data::new(signing_bytes.to_vec()),
        encryption_private_key: Data::new(encryption_bytes.to_vec()),
        protocol_version: existing.map_or(registration.protocol_version, |identity| {
            identity.protocol_version
        }),
        user_agent: existing
            .map_or(&registration.user_agent, |identity| &identity.user_agent)
            .clone(),
    };
    let mut serialized = Zeroizing::new(Vec::new());
    plist::to_writer_binary(&mut *serialized, &session)?;
    Identity::parse(&serialized)
        .context("Apple returned a certificate incompatible with the session")?;
    Ok(serialized)
}

#[derive(Clone, Copy)]
enum Services {
    Both,
    Messages,
    FaceTime,
}

fn registration_document(
    input: &DeviceRegistration,
    user_id: &str,
    handle: &str,
    public_identity: &[u8],
    relay_directory: Option<&[u8]>,
    services: Services,
) -> Value {
    let map = |fields: &[(&str, Value)]| {
        Value::Dictionary(
            fields
                .iter()
                .map(|(key, item)| (key.to_string(), item.clone()))
                .collect(),
        )
    };
    let client_data = Dictionary::from_iter([
        (
            "public-message-identity-key",
            Value::Data(public_identity.to_vec()),
        ),
        ("public-message-identity-version", 2.into()),
        ("ec-version", 1.into()),
    ]);
    let account = |client_data| {
        Dictionary::from_iter([
            ("user-id", user_id.into()),
            ("uris", Value::Array(vec![map(&[("uri", handle.into())])])),
            ("client-data", Value::Dictionary(client_data)),
        ])
    };
    let service = |name: &str, subservices: &[&str], capability: &str, flags: i32, user: Value| {
        let capabilities = map(&[
            ("flags", flags.into()),
            ("name", capability.into()),
            ("version", 1.into()),
        ]);
        map(&[
            ("service", name.into()),
            (
                "sub-services",
                Value::Array(subservices.iter().map(|name| (*name).into()).collect()),
            ),
            ("capabilities", Value::Array(vec![capabilities])),
            ("users", Value::Array(vec![user])),
        ])
    };
    let mut requested = Vec::new();
    if !matches!(services, Services::FaceTime) {
        let mut messaging_data = client_data.clone();
        messaging_data.insert("supports-emoji-tapbacks".into(), Value::Boolean(true));
        requested.push(service(
            TOPIC,
            &[],
            "Messenger",
            17,
            Value::Dictionary(account(messaging_data)),
        ));
    }
    if !matches!(services, Services::Messages) {
        let mut account = account(client_data);
        if let Some(directory) = relay_directory {
            // Advertise only the device identity used for relay signatures. IDS signaling
            // continues to use the legacy encryption identity above.
            account.insert("kt-loggable-data".into(), Value::Data(directory.to_vec()));
        }
        let account = Value::Dictionary(account);
        requested.extend([
            service(facetime::SIGNALING, &[], "Invitation", 1, account.clone()),
            service(
                facetime::VIDEO_SERVICE,
                &[facetime::VIDEO],
                "Invitation",
                1,
                account,
            ),
        ]);
    }
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
        ("services", Value::Array(requested)),
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
    services: Vec<Value>,
}

#[derive(Debug)]
struct RegistrationRejected {
    scope: String,
    status: u64,
}

impl std::fmt::Display for RegistrationRejected {
    fn fmt(&self, format: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            format,
            "Apple rejected {} (status {})",
            self.scope, self.status
        )
    }
}

impl std::error::Error for RegistrationRejected {}

fn check_status(status: u64, scope: &str) -> Result<()> {
    if status != 0 {
        return Err(RegistrationRejected {
            scope: scope.to_owned(),
            status,
        }
        .into());
    }
    Ok(())
}

#[derive(Deserialize)]
struct RegistrationService {
    status: Option<u64>,
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

fn select_certificates(
    reply: &RegisterReply,
    auth: &AccountAuth,
    handle: &str,
    include_facetime: bool,
) -> Result<(Data, BTreeMap<String, Data>)> {
    check_status(reply.status, "registration")?;
    let messages = registered_certificate(reply, TOPIC, &auth.user_id, handle)?;
    let mut calls = BTreeMap::new();
    if include_facetime {
        for service in [facetime::SIGNALING, facetime::VIDEO_SERVICE] {
            if let Ok(certificate) = checked_facetime_certificate(reply, auth, handle, service) {
                calls.insert(service.to_owned(), certificate);
            }
        }
    }
    Ok((messages, calls))
}

fn required_facetime_certificates(
    reply: &RegisterReply,
    auth: &AccountAuth,
    handle: &str,
) -> Result<BTreeMap<String, Data>> {
    check_status(reply.status, "FaceTime registration")?;
    let signal = checked_facetime_certificate(reply, auth, handle, facetime::SIGNALING)
        .context("Apple did not grant FaceTime to this iMessage address")?;
    let mut calls = BTreeMap::from([(facetime::SIGNALING.to_owned(), signal)]);
    if let Ok(video) = checked_facetime_certificate(reply, auth, handle, facetime::VIDEO_SERVICE) {
        calls.insert(facetime::VIDEO_SERVICE.to_owned(), video);
    }
    Ok(calls)
}

fn checked_facetime_certificate(
    reply: &RegisterReply,
    auth: &AccountAuth,
    handle: &str,
    service: &str,
) -> Result<Data> {
    let certificate = registered_certificate(reply, service, &auth.user_id, handle)?;
    let public = X509::from_der(certificate.as_ref())?.public_key()?;
    ensure!(
        auth.key.public_eq(&public),
        "Apple returned a FaceTime certificate for a different key"
    );
    Ok(certificate)
}

fn registered_certificate(
    response: &RegisterReply,
    service: &str,
    user_id: &str,
    handle: &str,
) -> Result<Data> {
    let entry = response
        .services
        .iter()
        .find(|entry| {
            entry
                .as_dictionary()
                .and_then(|fields| fields.get("service"))
                .and_then(Value::as_string)
                == Some(service)
        })
        .with_context(|| format!("Apple did not return a registration for {service}"))?;
    let service_reply: RegistrationService = plist::from_value(entry)
        .with_context(|| format!("Apple returned an invalid registration for {service}"))?;
    let scope = if service == TOPIC {
        "iMessage"
    } else {
        "FaceTime"
    };
    if let Some(status) = service_reply.status {
        check_status(status, scope)?;
    }
    let account = service_reply
        .users
        .iter()
        .find(|entry| entry.user_id == user_id)
        .context("Apple did not return the requested account")?;
    check_status(account.status, &format!("the {scope} account"))?;
    let registered = account
        .uris
        .iter()
        .find(|entry| address(&entry.uri).is_ok_and(|uri| uri == handle))
        .with_context(|| format!("Apple did not register the requested {scope} address"))?;
    check_status(registered.status, &format!("the {scope} address"))?;
    account
        .cert
        .clone()
        .context("Apple did not return an IDS certificate")
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        io::Read,
        os::unix::fs::PermissionsExt,
        sync::{Arc, Mutex},
    };

    use axum::{Router, body::Bytes, routing::post};
    use flate2::read::GzDecoder;
    use openssl::{asn1::Asn1Time, hash::MessageDigest, sign::Verifier, x509::X509NameBuilder};

    use super::*;

    const ACCOUNT: &str = "D:fixture";
    const HANDLE: &str = "mailto:person@example.org";
    const TOKEN: [u8; 32] = [0x4c; 32];

    fn identity_certificate() -> Result<(PKey<Private>, Data)> {
        let rsa = PKey::from_rsa(Rsa::generate(2048)?)?;
        let cert = certificate_for(&rsa, "Registration fixture")?;
        Ok((rsa, cert))
    }

    fn certificate_for(rsa: &PKey<Private>, common_name: &str) -> Result<Data> {
        let mut name = X509NameBuilder::new()?;
        name.append_entry_by_text("CN", common_name)?;
        let name = name.build();
        let mut builder = X509::builder()?;
        builder.set_subject_name(&name)?;
        builder.set_issuer_name(&name)?;
        builder.set_pubkey(rsa)?;
        builder.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
        builder.set_not_after(Asn1Time::days_from_now(1)?.as_ref())?;
        builder.sign(rsa, MessageDigest::sha256())?;
        Ok(Data::new(builder.build().to_der()?))
    }

    fn device(key: &PKey<Private>, cert: &Data) -> Result<DeviceRegistration> {
        Ok(DeviceRegistration {
            version: 1,
            handle: HANDLE.into(),
            push_token: Data::new(TOKEN.to_vec()),
            push_certificate: cert.clone(),
            push_private_key: Data::new(key.private_key_to_der()?),
            protocol_version: 1660,
            user_agent: "[macOS,15.7.5,24G624,Mac14,2]".into(),
            device_name: "Registration fixture".into(),
            hardware_version: "Mac14,2".into(),
            os_version: "macOS,15.7.5,24G624".into(),
            software_version: "24G624".into(),
            private_device_data: Dictionary::new(),
            validation_data: Data::new(b"initial-proof".to_vec()),
            include_facetime: true,
        })
    }

    fn accepted(service: &str, certificate: &Data) -> Value {
        let uri = Value::Dictionary(Dictionary::from_iter([
            ("uri", Value::from(HANDLE)),
            ("status", 0.into()),
        ]));
        let user = Value::Dictionary(Dictionary::from_iter([
            ("user-id", ACCOUNT.into()),
            ("status", 0.into()),
            ("cert", Value::Data(certificate.as_ref().to_vec())),
            ("uris", Value::Array(vec![uri])),
        ]));
        Value::Dictionary(Dictionary::from_iter([
            ("service", service.into()),
            ("users", Value::Array(vec![user])),
        ]))
    }

    fn reply(status: u64, services: Vec<Value>) -> Result<Vec<u8>> {
        let value = Dictionary::from_iter([
            ("status", status.into()),
            ("services", Value::Array(services)),
        ]);
        let mut bytes = Vec::new();
        plist::to_writer_binary(&mut bytes, &value)?;
        Ok(bytes)
    }

    fn request_identity(
        headers: &HeaderMap,
        compressed: &[u8],
        push_key: &PKey<Private>,
        auth_key: &PKey<Private>,
    ) -> Result<(Dictionary, Vec<u8>)> {
        assert_eq!(headers["content-encoding"], "gzip");
        assert_eq!(headers["x-auth-user-id-0"], ACCOUNT);
        assert_eq!(STANDARD.decode(headers["x-push-token"].as_bytes())?, TOKEN);
        for (role, suffix, key) in [("push", "", push_key), ("auth", "-0", auth_key)] {
            let header = |kind| {
                headers
                    .get(format!("x-{role}-{kind}{suffix}"))
                    .unwrap()
                    .as_bytes()
            };
            let nonce = STANDARD.decode(header("nonce"))?;
            assert_eq!(nonce.len(), 17);
            let signature = STANDARD.decode(header("sig"))?;
            assert_eq!(signature[..2], [1, 1]);
            let mut verifier = Verifier::new(MessageDigest::sha1(), key)?;
            verifier.update(&nonce)?;
            for field in [b"id-register".as_slice(), b"", compressed, TOKEN.as_slice()] {
                verifier.update(&(field.len() as u32).to_be_bytes())?;
                verifier.update(field)?;
            }
            assert!(verifier.verify(&signature[2..])?);
        }
        let mut plist = Vec::new();
        GzDecoder::new(compressed).read_to_end(&mut plist)?;
        let document: Dictionary = plist::from_bytes(&plist)?;
        let key = document["services"].as_array().unwrap()[0]
            .as_dictionary()
            .unwrap()["users"]
            .as_array()
            .unwrap()[0]
            .as_dictionary()
            .unwrap()["client-data"]
            .as_dictionary()
            .unwrap()["public-message-identity-key"]
            .as_data()
            .unwrap()
            .to_vec();
        Ok((document, key))
    }

    fn service_names(document: &Dictionary) -> Vec<&str> {
        document["services"]
            .as_array()
            .unwrap()
            .iter()
            .map(|service| {
                service.as_dictionary().unwrap()["service"]
                    .as_string()
                    .unwrap()
            })
            .collect()
    }

    fn advertised_relay_key(document: &Dictionary, service: usize) -> Option<&[u8]> {
        let service = document["services"].as_array()?[service].as_dictionary()?;
        let user = service["users"].as_array()?.first()?.as_dictionary()?;
        user.get("kt-loggable-data")?.as_data()
    }

    fn advertised_emoji_tapbacks(document: &Dictionary, service: usize) -> Option<bool> {
        let service = document["services"].as_array()?[service].as_dictionary()?;
        let user = service["users"].as_array()?.first()?.as_dictionary()?;
        user["client-data"]
            .as_dictionary()?
            .get("supports-emoji-tapbacks")?
            .as_boolean()
    }

    #[tokio::test]
    async fn enabling_face_time_reuses_the_original_keys_and_never_reregisters_messages()
    -> Result<()> {
        let (push_key, push_cert) = identity_certificate()?;
        let (ids_key, messages_cert) = identity_certificate()?;
        let authorization = certificate_for(&ids_key, "Fresh account authorization")?;
        let face_time = certificate_for(&ids_key, "FaceTime registration")?;
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let signing = PKey::from_ec_key(EcKey::generate(&group)?)?;
        let encryption = PKey::from_rsa(Rsa::generate(1280)?)?;
        let old = Session {
            version: 1,
            handle: HANDLE.to_owned(),
            push_token: Data::new(TOKEN.to_vec()),
            push_certificate: push_cert.clone(),
            push_private_key: Data::new(push_key.private_key_to_der()?),
            ids_certificate: messages_cert.clone(),
            ids_private_key: Data::new(ids_key.private_key_to_der()?),
            facetime_certificates: BTreeMap::new(),
            facetime_relay_signing_private_key: None,
            signing_private_key: Data::new(signing.private_key_to_der()?),
            encryption_private_key: Data::new(encryption.private_key_to_der()?),
            protocol_version: 1650,
            user_agent: "[Mac OS X,10.11.6,15G31,MacBookPro11,3]".to_owned(),
        };
        let mut encoded = Zeroizing::new(Vec::new());
        plist::to_writer_binary(&mut *encoded, &old)?;
        let previous = Identity::parse(&encoded)?;

        let responses = [
            reply(
                0,
                vec![
                    accepted(facetime::SIGNALING, &face_time),
                    accepted(facetime::VIDEO_SERVICE, &face_time),
                ],
            )?,
            reply(71, Vec::new())?,
            reply(0, vec![accepted(facetime::SIGNALING, &push_cert)])?,
        ];
        for (index, response) in responses.into_iter().enumerate() {
            let (requests, mut captured) = tokio::sync::mpsc::unbounded_channel();
            let router = Router::new().route(
                "/register",
                post(move |headers: HeaderMap, body: Bytes| {
                    requests.send((headers, body)).unwrap();
                    let response = response.clone();
                    async move { response }
                }),
            );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let url = format!("http://{}/register", listener.local_addr()?);
            let server = tokio::spawn(async move { axum::serve(listener, router).await });
            let auth = AccountAuth {
                user_id: ACCOUNT.into(),
                certificate: authorization.clone(),
                key: ids_key.clone(),
            };
            let result = register_at(
                &Client::builder().no_proxy().build()?,
                &url,
                &mut device(&push_key, &push_cert)?,
                auth,
                None,
                Some(&previous),
            )
            .await;
            let (headers, payload) = captured.try_recv()?;
            let (document, advertised_key) =
                request_identity(&headers, &payload, &push_key, &ids_key)?;
            let advertised_relay_key =
                advertised_relay_key(&document, 0).context("Missing FaceTime device key")?;
            facetime::PeerDeviceKey::from_directory(advertised_relay_key)?;
            if index == 0 {
                let upgraded = Identity::parse(&result?)?;
                assert!(upgraded.same_messaging_registration(&previous)?);
                assert_eq!(upgraded.profile_id(), previous.profile_id());
                assert_eq!(
                    upgraded.ids_certificate(TOPIC),
                    Some(messages_cert.as_ref())
                );
                assert_eq!(
                    upgraded.ids_certificate(facetime::SIGNALING),
                    Some(face_time.as_ref())
                );
                assert_eq!(
                    upgraded.ids_certificate(facetime::VIDEO),
                    Some(face_time.as_ref())
                );
                let signer = upgraded
                    .facetime_relay_signing
                    .context("Missing persisted FaceTime relay key")?;
                assert_eq!(signer.directory_data()?.as_slice(), advertised_relay_key);
            } else {
                assert!(result.is_err());
            }
            assert_eq!(
                service_names(&document),
                [facetime::SIGNALING, facetime::VIDEO_SERVICE]
            );
            assert_eq!(advertised_key, previous.message_keys.public_der()?);
            assert_eq!(
                STANDARD.decode(headers["x-auth-cert-0"].as_bytes())?,
                authorization.as_ref()
            );
            assert!(captured.try_recv().is_err());
            server.abort();
        }
        assert!(!previous.facetime_registered());
        Ok(())
    }

    #[test]
    fn optional_face_time_certificates_must_match_the_requested_account_key() -> Result<()> {
        let (key, cert) = identity_certificate()?;
        let (_, other_cert) = identity_certificate()?;
        let auth = AccountAuth {
            user_id: ACCOUNT.into(),
            certificate: cert.clone(),
            key,
        };
        let reply: RegisterReply = plist::from_bytes(&reply(
            0,
            vec![
                accepted(TOPIC, &cert),
                accepted(facetime::SIGNALING, &cert),
                accepted(facetime::VIDEO_SERVICE, &other_cert),
            ],
        )?)?;
        let (messages, calls) = select_certificates(&reply, &auth, HANDLE, true)?;
        assert_eq!(messages, cert);
        assert_eq!(
            calls,
            BTreeMap::from([(facetime::SIGNALING.to_owned(), cert.clone())])
        );
        let (_, excluded) = select_certificates(&reply, &auth, HANDLE, false)?;
        assert!(excluded.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn face_time_registration_uses_a_single_signed_request_or_retries_messages_with_fresh_validation()
    -> Result<()> {
        let root = tempfile::tempdir()?;
        let helper = root.path().join("validation-helper");
        std::fs::write(
            &helper,
            "#!/bin/sh\ntest \"$1\" = validation || exit 1\nprintf %s ZnJlc2gtcHJvb2Y=\n",
        )?;
        std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o700))?;
        let provider = DeviceProvider::LocalHelper(helper);
        let (push_key, push_cert) = identity_certificate()?;
        let (auth_key, auth_cert) = identity_certificate()?;
        let client = Client::builder().no_proxy().build()?;
        for (rejected, face_time_granted) in [(false, true), (false, false), (true, false)] {
            let mut services = vec![accepted(TOPIC, &auth_cert)];
            if face_time_granted {
                services.extend([
                    accepted(facetime::SIGNALING, &auth_cert),
                    accepted(facetime::VIDEO_SERVICE, &auth_cert),
                ]);
            } else if !rejected {
                services.extend([
                    Value::Dictionary(Dictionary::from_iter([
                        ("service", Value::from(facetime::SIGNALING)),
                        ("status", 71.into()),
                    ])),
                    Value::Dictionary(Dictionary::from_iter([
                        ("service", Value::from(facetime::VIDEO_SERVICE)),
                        ("users", Value::from("unavailable")),
                    ])),
                ]);
            }
            let mut replies = VecDeque::from([reply(0, services)?]);
            if rejected {
                replies.push_front(reply(71, Vec::new())?);
            }
            let replies = Arc::new(Mutex::new(replies));
            let (requests, mut captured) = tokio::sync::mpsc::unbounded_channel();
            let handler = move |headers: HeaderMap, body: Bytes| {
                let next = replies
                    .lock()
                    .unwrap()
                    .pop_front()
                    .expect("Unexpected extra registration attempt");
                requests.send((headers, body)).unwrap();
                async move { next }
            };
            let router = Router::new().route("/register", post(handler));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let url = format!("http://{}/register", listener.local_addr()?);
            let server = tokio::spawn(async move { axum::serve(listener, router).await });
            let auth = AccountAuth {
                user_id: ACCOUNT.into(),
                certificate: auth_cert.clone(),
                key: auth_key.clone(),
            };
            let saved = register_at(
                &client,
                &url,
                &mut device(&push_key, &push_cert)?,
                auth,
                Some(&provider),
                None,
            )
            .await?;
            let identity = Identity::parse(&saved)?;
            assert_eq!(identity.facetime_registered(), face_time_granted);
            assert_eq!(
                identity.ids_certificate(facetime::VIDEO).is_some(),
                face_time_granted
            );
            let (headers, body) = captured.try_recv()?;
            let (initial, initial_key) = request_identity(&headers, &body, &push_key, &auth_key)?;
            assert_eq!(identity.can_sign_relay_prekey(), face_time_granted);
            assert!(advertised_relay_key(&initial, 0).is_none());
            assert!(advertised_relay_key(&initial, 1).is_some());
            assert_eq!(advertised_emoji_tapbacks(&initial, 0), Some(true));
            assert_eq!(advertised_emoji_tapbacks(&initial, 1), None);
            assert_eq!(advertised_emoji_tapbacks(&initial, 2), None);
            assert_eq!(
                service_names(&initial),
                [TOPIC, facetime::SIGNALING, facetime::VIDEO_SERVICE]
            );
            assert_eq!(
                initial["validation-data"].as_data(),
                Some(b"initial-proof".as_slice())
            );
            if rejected {
                let (retry_headers, body) = captured.try_recv()?;
                let (retry, retry_key) =
                    request_identity(&retry_headers, &body, &push_key, &auth_key)?;
                assert_eq!(service_names(&retry), [TOPIC]);
                assert!(advertised_relay_key(&retry, 0).is_none());
                assert_eq!(advertised_emoji_tapbacks(&retry, 0), Some(true));
                assert_eq!(retry_key, initial_key);
                assert_eq!(
                    retry["validation-data"].as_data(),
                    Some(b"fresh-proof".as_slice())
                );
                assert_ne!(headers["x-auth-nonce-0"], retry_headers["x-auth-nonce-0"]);
            }
            assert!(captured.try_recv().is_err());
            server.abort();
        }
        Ok(())
    }
}
