use std::{
    fs::OpenOptions,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::Rsa,
    sha::sha256,
    x509::{X509, X509NameBuilder, X509ReqBuilder},
};
use plist::{Data, Dictionary, Value};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use super::{
    aps::enroll_push_token,
    certified_rsa,
    gsa::{Anisette, SmsPrompts, login, validate_login},
    http::{client_builder, plist_xml, read_response},
    provider_command,
    registration::DeviceRegistration,
};
use crate::{address, now_ms, storage};

const ACTIVATE: &str = "https://albert.apple.com/deviceservices/deviceActivation?device=MacOS";
const MAX_HELPER_OUTPUT: u64 = 96 * 1024;
const MAC_IDS_PROTOCOL: u32 = 1660;

pub struct AutomaticSetup {
    pub connection: DeviceConnection,
    pub opencore_config: Option<PathBuf>,
    pub address: String,
}

#[derive(Clone)]
pub enum DeviceConnection {
    MacOverSsh(String),
    LocalHelper(PathBuf),
}

impl AutomaticSetup {
    pub async fn sign_in(
        self,
        root: &Path,
        account: &str,
        password: Zeroizing<String>,
        prompts: &mut impl SmsPrompts,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let handle = address(if self.address.trim().is_empty() {
            account
        } else {
            &self.address
        })
        .context("Enter a registered iMessage email address or international phone number")?;
        validate_login(account, &password)?;
        let provider = DeviceProvider::new(self.connection)?;
        let computer = provider.describe().await?;
        if let Some(path) = &self.opencore_config {
            let file =
                std::fs::File::open(path).context("Could not open the OpenCore config.plist")?;
            ensure!(
                file.metadata()?.is_file() && file.metadata()?.len() <= 2 * 1024 * 1024,
                "Select a valid OpenCore config.plist file"
            );
            let config: OpenCoreConfig = plist::from_reader(file)
                .context("Could not read PlatformInfo → Generic from the OpenCore config")?;
            config.platform_info.generic.check(&computer)?;
        }
        let profile = computer.profile();
        let _activation_lock = lock_profile(root, &profile)?;
        let (push, token) = provision_push(root, &profile, &computer, &provider).await?;
        let mut device = computer.registration(handle, token, &push);
        let mut anisette = Anisette::from_provider(provider.clone());
        login(
            &mut device,
            &mut anisette,
            Some(&provider),
            account,
            password,
            prompts,
        )
        .await
    }
}

pub fn default_device_helper(root: &Path) -> Option<PathBuf> {
    let configured = std::env::var_os("IMESSAGE_DEVICE_HELPER")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("device-helper"));
    if configured.is_file() {
        Some(configured)
    } else {
        None
    }
}

#[derive(Clone)]
pub(super) struct DeviceProvider {
    connection: DeviceConnection,
}

impl DeviceProvider {
    fn new(connection: DeviceConnection) -> Result<Self> {
        let connection = match connection {
            DeviceConnection::LocalHelper(path) => {
                DeviceConnection::LocalHelper(provider_command::executable(&path)?)
            }
            DeviceConnection::MacOverSsh(host) => {
                let host = host.trim();
                ensure!(
                    (1..=320).contains(&host.len())
                        && !host.starts_with('-')
                        && host
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || b"._@:-[]".contains(&byte)),
                    "Enter an SSH host or alias such as user@mac.local"
                );
                DeviceConnection::MacOverSsh(host.to_owned())
            }
        };
        Ok(Self { connection })
    }

    pub(in crate::apple) async fn call(
        &self,
        operation: &str,
        input: &[u8],
        maximum: u64,
    ) -> Result<Zeroizing<Vec<u8>>> {
        match &self.connection {
            DeviceConnection::LocalHelper(path) => {
                provider_command::run(path, &[operation], operation, input, maximum).await
            }
            DeviceConnection::MacOverSsh(host) => {
                let remote = format!("~/.local/bin/imessage-mac-device {operation}");
                provider_command::run(Path::new("/usr/bin/ssh"), &[
                    "-T", "-oBatchMode=yes", "-oStrictHostKeyChecking=yes", "-oConnectTimeout=8",
                    "--", host, &remote,
                ], operation, input, maximum).await.with_context(|| format!(
                    "The Mac helper could not complete {operation}. Check SSH access and the Mac helper installation"
                ))
            }
        }
    }

    async fn describe(&self) -> Result<Computer> {
        let metadata = self.call("describe", &[], MAX_HELPER_OUTPUT).await?;
        let computer: Computer = serde_json::from_slice(&metadata)
            .context("The device helper returned invalid hardware information")?;
        computer.validate()?;
        Ok(computer)
    }

    pub(super) async fn validation(&self) -> Result<Data> {
        let bytes = self.call("validation", &[], MAX_HELPER_OUTPUT).await?;
        let proof = Zeroizing::new(
            STANDARD
                .decode(std::str::from_utf8(&bytes)?.trim())
                .context("The device helper returned invalid Apple validation data")?,
        );
        ensure!(
            !proof.is_empty(),
            "The device helper returned empty Apple validation data"
        );
        Ok(Data::new(proof.to_vec()))
    }

    async fn activation_signature(&self, payload: &[u8]) -> Result<ActivationSignature> {
        let bytes = self
            .call("activation-sign", payload, MAX_HELPER_OUTPUT)
            .await?;
        let signed: ActivationSignature = serde_json::from_slice(&bytes)
            .context("The device helper returned an invalid activation signature")?;
        Ok(signed)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct Computer {
    model: String,
    serial: String,
    uuid: Uuid,
    os_version: String,
    build_version: String,
    device_name: String,
}

impl Computer {
    fn validate(&self) -> Result<()> {
        let sample = |value: &str, max, extra: &[u8]| {
            (1..=max).contains(&value.len())
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || extra.contains(&byte))
        };
        ensure!(
            sample(&self.model, 40, b",")
                && sample(&self.serial, 32, b"")
                && !self.uuid.is_nil()
                && sample(&self.os_version, 30, b".")
                && sample(&self.build_version, 30, b"")
                && (1..=100).contains(&self.device_name.len())
                && !self.device_name.chars().any(char::is_control),
            "The device helper returned invalid Mac hardware or OS information"
        );
        Ok(())
    }

    fn profile(&self) -> String {
        let pinned = format!(
            "{}\n{}\n{}",
            self.uuid,
            self.model,
            self.serial.to_ascii_uppercase()
        );
        sha256(pinned.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn registration(
        &self,
        handle: String,
        token: [u8; 32],
        push: &PushActivation,
    ) -> DeviceRegistration {
        let uuid = self.uuid.to_string().to_uppercase();
        let time = (now_ms() as f64 / 1000.) - 978_307_200.;
        let metadata = Dictionary::from_iter([
            ("ap", "0".into()),
            ("d", format!("{time:.6}").into()),
            ("dt", Value::Integer(1.into())),
            ("gt", "0".into()),
            ("h", "1".into()),
            ("m", "0".into()),
            ("p", "0".into()),
            ("pb", self.build_version.as_str().into()),
            ("pn", "macOS".into()),
            ("pv", self.os_version.as_str().into()),
            ("s", "0".into()),
            ("t", "0".into()),
            ("u", uuid.into()),
            ("v", "1".into()),
        ]);
        DeviceRegistration {
            version: 1,
            handle,
            push_token: Data::new(token.to_vec()),
            push_certificate: push.certificate.clone(),
            push_private_key: push.key.clone(),
            protocol_version: MAC_IDS_PROTOCOL,
            user_agent: format!(
                "[macOS,{},{},{}]",
                self.os_version, self.build_version, self.model
            ),
            device_name: self.device_name.clone(),
            hardware_version: self.model.clone(),
            os_version: format!("macOS,{},{}", self.os_version, self.build_version),
            software_version: self.build_version.clone(),
            private_device_data: metadata,
            validation_data: Data::new(Vec::new()),
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct OpenCoreConfig {
    platform_info: PlatformInfo,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct PlatformInfo {
    generic: GenericIdentity,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GenericIdentity {
    system_product_name: String,
    system_serial_number: String,
    #[serde(rename = "SystemUUID")]
    system_uuid: Uuid,
}

impl GenericIdentity {
    fn check(&self, computer: &Computer) -> Result<()> {
        ensure!(
            self.system_product_name == computer.model
                && self
                    .system_serial_number
                    .eq_ignore_ascii_case(&computer.serial)
                && self.system_uuid == computer.uuid,
            "The OpenCore model, serial, or UUID does not match the Mac that supplied validation"
        );
        Ok(())
    }
}

#[derive(Deserialize, Serialize)]
struct PushActivation {
    certificate: Data,
    key: Data,
    token: Option<Data>,
}

impl Drop for PushActivation {
    fn drop(&mut self) {
        let mut key: Vec<u8> = std::mem::replace(&mut self.key, Data::new(Vec::new())).into();
        key.zeroize();
    }
}

fn lock_profile(root: &Path, profile: &str) -> Result<std::fs::File> {
    let lock = OpenOptions::new()
        .mode(0o600)
        .create(true)
        .truncate(false)
        .write(true)
        .open(root.join(format!("activation-{profile}.lock")))?;
    fs2::FileExt::try_lock_exclusive(&lock)
        .context("Device setup is already running for this Mac")?;
    Ok(lock)
}

async fn provision_push(
    root: &Path,
    profile: &str,
    computer: &Computer,
    provider: &DeviceProvider,
) -> Result<(PushActivation, [u8; 32])> {
    let keyring_id = format!("activation:{}:{profile}", root.display());
    let mut push = match storage::read_activation(&keyring_id)? {
        Some(bytes) => plist::from_bytes::<PushActivation>(&bytes)
            .context("Could not read the saved Apple push identity")?,
        None => {
            let push =
                request_push_activation(computer, provider, &client_builder().build()?, ACTIVATE)
                    .await?;
            save_activation(&keyring_id, &push)?;
            push
        }
    };
    let key = certified_rsa(&push.certificate, &push.key)?;
    let cached = push
        .token
        .as_ref()
        .map(|data| <[u8; 32]>::try_from(data.as_ref()).context("Invalid saved Apple push token"))
        .transpose()?;
    let token = match cached {
        Some(token) => token,
        None => {
            let token = enroll_push_token(push.certificate.as_ref(), &key, None).await?;
            push.token = Some(Data::new(token.to_vec()));
            save_activation(&keyring_id, &push)?;
            token
        }
    };
    Ok((push, token))
}

fn save_activation(keyring_id: &str, push: &PushActivation) -> Result<()> {
    let mut bytes = Zeroizing::new(Vec::new());
    plist::to_writer_binary(&mut *bytes, push)?;
    storage::save_activation(keyring_id, &bytes)
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
struct ActivationSignature {
    certificate_chain: String,
    signature: String,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct ActivationInfo<'a> {
    activation_randomness: String,
    activation_state: &'static str,
    build_version: &'a str,
    device_cert_request: Data,
    device_class: &'static str,
    product_type: &'a str,
    product_version: &'a str,
    serial_number: &'a str,
    #[serde(rename = "UniqueDeviceID")]
    unique_device_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct SignedActivation {
    activation_info_complete: bool,
    #[serde(rename = "ActivationInfoXML")]
    activation_info_xml: Data,
    fair_play_cert_chain: Data,
    fair_play_signature: Data,
}

async fn request_push_activation(
    computer: &Computer,
    provider: &DeviceProvider,
    client: &reqwest::Client,
    endpoint: &str,
) -> Result<PushActivation> {
    let key = PKey::from_rsa(Rsa::generate(1024)?)?;
    let info = plist_xml(&ActivationInfo {
        activation_randomness: Uuid::new_v4().to_string().to_uppercase(),
        activation_state: "Unactivated",
        build_version: &computer.build_version,
        device_cert_request: Data::new(push_request(&key)?),
        device_class: "MacOS",
        product_type: &computer.model,
        product_version: &computer.os_version,
        serial_number: &computer.serial,
        unique_device_id: computer.uuid.to_string().to_uppercase(),
    })?;
    let signed = provider.activation_signature(&info).await?;
    let chain = STANDARD
        .decode(signed.certificate_chain)
        .context("The device helper returned an invalid activation certificate chain")?;
    let signature = STANDARD
        .decode(signed.signature)
        .context("The device helper returned an invalid activation signature")?;
    ensure!(
        !chain.is_empty() && !signature.is_empty(),
        "The device helper omitted the activation chain or signature"
    );
    let body = plist_xml(&SignedActivation {
        activation_info_complete: true,
        activation_info_xml: Data::new(info.to_vec()),
        fair_play_cert_chain: Data::new(chain),
        fair_play_signature: Data::new(signature),
    })?;
    let plist = std::str::from_utf8(&body)?;
    let result = client
        .post(endpoint)
        .header(
            "user-agent",
            format!(
                "ApplePushService/4.0 {}/{}",
                computer.model, computer.build_version
            ),
        )
        .form(&[("activation-info", plist)])
        .send()
        .await
        .context("Could not reach Apple's push activation endpoint")?
        .error_for_status()?;
    let payload = read_response(result).await?;
    let cert = activation_certificate(&payload)?;
    let public_key = cert.public_key()?;
    ensure!(
        key.public_eq(&public_key),
        "Apple's push certificate did not match the generated key"
    );
    Ok(PushActivation {
        certificate: Data::new(cert.to_der()?),
        key: Data::new(key.private_key_to_der()?),
        token: None,
    })
}

fn push_request(key: &PKey<Private>) -> Result<Vec<u8>> {
    let mut subject = X509NameBuilder::new()?;
    subject.append_entry_by_text("CN", "Client Push Certificate")?;
    let subject = subject.build();
    let mut request = X509ReqBuilder::new()?;
    request.set_subject_name(&subject)?;
    request.set_pubkey(key)?;
    request.sign(key, MessageDigest::sha1())?;
    Ok(request.build().to_pem()?)
}

fn activation_certificate(body: &[u8]) -> Result<X509> {
    let plist = if let Ok(text) = std::str::from_utf8(body)
        && let Some((_, payload)) = text.split_once("<Protocol>")
    {
        payload
            .split_once("</Protocol>")
            .context("Invalid Apple push activation response")?
            .0
            .trim()
            .as_bytes()
    } else {
        body
    };
    let value: Value =
        plist::from_bytes(plist).context("Could not decode Apple's push activation response")?;
    let record = value
        .as_dictionary()
        .and_then(|value| value.get("device-activation"))
        .and_then(Value::as_dictionary)
        .and_then(|value| value.get("activation-record"))
        .and_then(Value::as_dictionary)
        .and_then(|value| value.get("DeviceCertificate"))
        .and_then(Value::as_data)
        .context("Apple did not issue a push certificate")?;
    X509::from_pem(record)
        .or_else(|_| X509::from_der(record))
        .context("Apple returned an invalid push certificate")
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, os::unix::fs::PermissionsExt};

    use super::*;
    use axum::{Form, Router, extract::Query, routing::post};
    use openssl::{
        asn1::Asn1Time,
        x509::{X509, X509Req},
    };

    const DEVICE: &str = r#"{"model":"Macmini8,1","serial":"OFFLINE1234","uuid":"103445AB-396B-45E0-9455-9AEDD15D1869","os-version":"15.7","build-version":"24G123","device-name":"Test Mac"}"#;

    #[test]
    fn opencore_identity_must_match_the_provider() -> Result<()> {
        let computer: Computer = serde_json::from_str(DEVICE)?;
        let generic = Dictionary::from_iter([
            ("SystemProductName", computer.model.as_str()),
            ("SystemSerialNumber", computer.serial.as_str()),
            ("SystemUUID", "103445AB-396B-45E0-9455-9AEDD15D1869"),
        ]);
        let input = Dictionary::from_iter([(
            "PlatformInfo",
            Value::Dictionary(Dictionary::from_iter([(
                "Generic",
                Value::Dictionary(generic),
            )])),
        )]);
        let config: OpenCoreConfig = plist::from_bytes(&plist_xml(&input)?)?;
        config.platform_info.generic.check(&computer)?;
        let mut another = computer;
        another.uuid = Uuid::new_v4();
        assert!(config.platform_info.generic.check(&another).is_err());
        Ok(())
    }

    #[tokio::test]
    async fn activation_generates_the_csr_and_accepts_only_matching_apple_certificate() -> Result<()>
    {
        let temp = tempfile::tempdir()?;
        let helper = temp.path().join("device-helper");
        std::fs::write(
            &helper,
            format!(
                r#"#!/bin/sh
case "$1" in
 describe) printf '%s' '{DEVICE}' ;;
 activation-sign)
     input=$(cat)
     case "$input" in *Client*|*DeviceCertRequest*) ;; *) exit 3 ;; esac
     printf '%s' '{{"certificate-chain":"Y2hhaW4=","signature":"c2lnbmF0dXJl"}}' ;;
 *) exit 5 ;;
esac
"#
            ),
        )?;
        std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o700))?;
        let provider = DeviceProvider::new(DeviceConnection::LocalHelper(helper))?;
        let computer = provider.describe().await?;
        let app = Router::new().route(
            "/activation",
            post(
                |Query(options): Query<HashMap<String, String>>,
                 Form(parameters): Form<HashMap<String, String>>| async move {
                    let signed: Dictionary =
                        plist::from_bytes(parameters["activation-info"].as_bytes()).unwrap();
                    assert_eq!(
                        signed["FairPlayCertChain"].as_data(),
                        Some(b"chain".as_slice())
                    );
                    assert_eq!(
                        signed["FairPlaySignature"].as_data(),
                        Some(b"signature".as_slice())
                    );
                    let info: Dictionary =
                        plist::from_bytes(signed["ActivationInfoXML"].as_data().unwrap()).unwrap();
                    assert_eq!(info["DeviceClass"].as_string(), Some("MacOS"));
                    assert_eq!(info["SerialNumber"].as_string(), Some("OFFLINE1234"));
                    let requested =
                        X509Req::from_pem(info["DeviceCertRequest"].as_data().unwrap()).unwrap();
                    let requested_key = requested.public_key().unwrap();
                    assert!(requested.verify(&requested_key).unwrap());
                    let issuer = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
                    let mut certificate = X509::builder().unwrap();
                    certificate.set_version(2).unwrap();
                    certificate
                        .set_subject_name(requested.subject_name())
                        .unwrap();
                    certificate
                        .set_issuer_name(requested.subject_name())
                        .unwrap();
                    certificate
                        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
                        .unwrap();
                    certificate
                        .set_not_after(&Asn1Time::days_from_now(1).unwrap())
                        .unwrap();
                    let public_key = if options.contains_key("wrong") {
                        issuer
                            .public_key_to_pem()
                            .and_then(|pem| PKey::public_key_from_pem(&pem))
                            .unwrap()
                    } else {
                        requested_key
                    };
                    certificate.set_pubkey(&public_key).unwrap();
                    certificate.sign(&issuer, MessageDigest::sha256()).unwrap();
                    let document = Dictionary::from_iter([(
                        "device-activation",
                        Value::Dictionary(Dictionary::from_iter([(
                            "activation-record",
                            Value::Dictionary(Dictionary::from_iter([(
                                "DeviceCertificate",
                                Value::Data(certificate.build().to_pem().unwrap()),
                            )])),
                        )])),
                    )]);
                    format!(
                        "<Protocol>{}</Protocol>",
                        String::from_utf8(plist_xml(&document).unwrap().to_vec()).unwrap()
                    )
                },
            ),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let endpoint = format!("http://{}/activation", listener.local_addr()?);
        let mock = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = reqwest::Client::builder().no_proxy().build()?;
        let mut activation =
            request_push_activation(&computer, &provider, &client, &endpoint).await?;
        let mut saved = Zeroizing::new(Vec::new());
        plist::to_writer_binary(&mut *saved, &activation)?;
        let saved_before_token: PushActivation = plist::from_bytes(&saved)?;
        assert!(saved_before_token.token.is_none());
        certified_rsa(&saved_before_token.certificate, &saved_before_token.key)?;
        activation.token = Some(Data::new(vec![7; 32]));
        saved.zeroize();
        plist::to_writer_binary(&mut *saved, &activation)?;
        let saved_with_token: PushActivation = plist::from_bytes(&saved)?;
        assert_eq!(
            saved_with_token.token.as_ref().map(Data::as_ref),
            Some([7; 32].as_slice())
        );
        let result = request_push_activation(
            &computer,
            &provider,
            &client,
            &format!("{endpoint}?wrong=1"),
        )
        .await;
        assert!(
            result
                .err()
                .context("Expected certificate mismatch")?
                .to_string()
                .contains("did not match the generated key")
        );
        mock.abort();
        Ok(())
    }
}
