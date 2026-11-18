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
    rsa::{Padding, Rsa},
    sha::sha256,
    sign::Signer,
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
    http::{apple_client, client_builder, plist_xml, read_response},
    local_adi::LocalAdi,
    provider_command,
    registration::DeviceRegistration,
    ssh_setup::MacConnection,
};
use crate::{address, now_ms, storage};

const ACTIVATE: &str = "https://albert.apple.com/deviceservices/deviceActivation?device=MacOS";
const VALIDATION_CERTIFICATE: &str =
    "https://static.ess.apple.com/identity/validation/cert-1.0.plist";
const VALIDATION_SESSION: &str =
    "https://identity.ess.apple.com/WebObjects/TDIdentityService.woa/wa/initializeValidation";
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
    OnDevice(PathBuf),
    OnDeviceHelper(PathBuf),
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
        let use_local_adi = matches!(
            self.connection,
            DeviceConnection::MacOverSsh(_) | DeviceConnection::OnDeviceHelper(_)
        );
        let provider = match self.connection {
            DeviceConnection::MacOverSsh(host) => {
                let mac = MacConnection::open(root, &host, prompts).await?;
                mac.install_helper().await?;
                DeviceProvider::MacOverSsh(std::sync::Arc::new(mac))
            }
            connection => DeviceProvider::new(connection)?,
        };
        if let DeviceProvider::OnDevice(local) = &provider {
            return local
                .sign_in(root, handle, account, password, prompts)
                .await;
        }
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
        if let DeviceProvider::MacOverSsh(connection) = &provider {
            let status = connection.run("validation-status", &[], 128).await?;
            match status.as_slice() {
                b"ready" => (),
                b"unsupported-el-capitan" => anyhow::bail!(
                    "This El Capitan build uses a different validation binary from the supported OS X 10.11.6 Combo Update"
                ),
                b"no-native-validation" => anyhow::bail!(
                    "macOS {} did not provide the native iMessage validation interface",
                    computer.os_version
                ),
                _ => anyhow::bail!("The Mac returned an unknown device validation status"),
            }
        }
        let profile = computer.profile();
        let _activation_lock = lock_profile(root, &profile)?;
        let mut anisette = if use_local_adi {
            Anisette::from_local(LocalAdi::new(
                format!("adi:{}:{profile}", root.display()),
                &computer,
            )?)
        } else {
            Anisette::from_provider(provider.clone())
        };
        let (push, token) = provision_push(root, &profile, &computer, &provider, None).await?;
        let mut device = computer.registration(handle, token, &push);
        login(
            &mut device,
            &mut anisette,
            Some(Proofs::Provider(&provider)),
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
pub(super) enum DeviceProvider {
    LocalHelper(PathBuf),
    MacOverSsh(std::sync::Arc<MacConnection>),
    OnDevice(std::sync::Arc<LocalDevice>),
}

pub(super) enum Proofs<'a> {
    Provider(&'a DeviceProvider),
    Local {
        qualification: Data,
        registration: Data,
    },
}

impl Proofs<'_> {
    pub(super) async fn qualification(&self) -> Result<Data> {
        match self {
            Self::Provider(source) => source.validation().await,
            Self::Local { qualification, .. } => Ok(qualification.clone()),
        }
    }

    pub(super) async fn registration(self) -> Result<Data> {
        match self {
            Self::Provider(source) => source.validation().await,
            Self::Local { registration, .. } => Ok(registration),
        }
    }
}

impl DeviceProvider {
    fn new(connection: DeviceConnection) -> Result<Self> {
        Ok(match connection {
            DeviceConnection::LocalHelper(path) | DeviceConnection::OnDeviceHelper(path) => {
                Self::LocalHelper(provider_command::executable(&path)?)
            }
            DeviceConnection::MacOverSsh(_) => {
                anyhow::bail!("Mac setup needs an open SSH connection")
            }
            DeviceConnection::OnDevice(path) => {
                Self::OnDevice(std::sync::Arc::new(LocalDevice::load(&path)?))
            }
        })
    }

    pub(in crate::apple) async fn call(
        &self,
        operation: &str,
        input: &[u8],
        maximum: u64,
    ) -> Result<Zeroizing<Vec<u8>>> {
        match self {
            Self::LocalHelper(path) => {
                provider_command::run(path, &[operation], operation, input, maximum).await
            }
            Self::MacOverSsh(connection) => connection.run(operation, input, maximum).await,
            Self::OnDevice(_) => anyhow::bail!("This operation needs an external device helper"),
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
        if let Self::MacOverSsh(connection) = self {
            let client = apple_client()?;
            let reply = validation_reply(client.get(VALIDATION_CERTIFICATE)).await?;
            let certificate = validation_field(&reply, "cert")?;
            let proof = connection
                .validation_exchange(certificate, async |challenge| {
                    let request = plist_xml(&Dictionary::from_iter([(
                        "session-info-request",
                        Value::Data(challenge.to_vec()),
                    )]))?;
                    let reply = validation_reply(
                        client
                            .post(VALIDATION_SESSION)
                            .header("content-type", "application/x-apple-plist")
                            .body(request.to_vec()),
                    )
                    .await?;
                    ensure!(
                        reply.get("status").is_none_or(|status| {
                            status.as_signed_integer() == Some(0) || status.as_string() == Some("0")
                        }),
                        "Apple rejected the Mac validation challenge"
                    );
                    Ok(Zeroizing::new(
                        validation_field(&reply, "session-info")?.to_vec(),
                    ))
                })
                .await?;
            return Ok(Data::new(proof.to_vec()));
        }
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
        if let Self::OnDevice(device) = self {
            let signing = device
                .activation
                .as_ref()
                .context("The device file has no activation credential")?;
            let key = PKey::private_key_from_der(signing.key.as_ref())
                .context("Invalid local activation signing key")?;
            let mut signer = Signer::new(MessageDigest::sha1(), &key)?;
            signer.set_rsa_padding(Padding::PKCS1)?;
            return Ok(ActivationSignature {
                certificate_chain: STANDARD.encode(&signing.chain),
                signature: STANDARD.encode(signer.sign_oneshot_to_vec(payload)?),
            });
        }
        if let Self::MacOverSsh(connection) = self {
            let status = connection.run("activation-status", &[], 128).await?;
            match status.as_slice() {
                b"ready" => (),
                b"unknown-system-signer" => anyhow::bail!(
                    "This El Capitan build uses an Apple push signer that iMessage does not recognize"
                ),
                b"unavailable-system-signer" => {
                    anyhow::bail!("El Capitan could not load its Apple push signer")
                }
                b"missing-signing-key" => anyhow::bail!(
                    "The Mac needs an Apple-issued activation signing key in ~/Library/Application Support/LinuxMessages/activation-key.pem, readable only by your Mac user"
                ),
                b"missing-certificate-chain" => anyhow::bail!(
                    "The Mac needs the matching Apple activation certificate chain in ~/Library/Application Support/LinuxMessages/activation-chain.pem"
                ),
                _ => anyhow::bail!("The Mac returned an unknown activation status"),
            }
        }
        let bytes = self
            .call("activation-sign", payload, MAX_HELPER_OUTPUT)
            .await?;
        let signed: ActivationSignature = serde_json::from_slice(&bytes)
            .context("The device helper returned an invalid activation signature")?;
        Ok(signed)
    }
}

async fn validation_reply(request: reqwest::RequestBuilder) -> Result<Dictionary> {
    let response = request
        .send()
        .await
        .context("Could not reach Apple's device validation service from Linux")?;
    ensure!(
        response.status().is_success(),
        "Apple's device validation service returned HTTP {}",
        response.status().as_u16()
    );
    let reply = read_response(response).await?;
    plist::from_bytes(&reply).context("Apple returned an invalid device validation response")
}

fn validation_field<'a>(reply: &'a Dictionary, field: &str) -> Result<&'a [u8]> {
    reply
        .get(field)
        .and_then(Value::as_data)
        .filter(|bytes| !bytes.is_empty())
        .with_context(|| format!("Apple omitted {field} from its device validation response"))
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(super) struct LocalDevice {
    version: u32,
    computer: Computer,
    qualification_data: Data,
    registration_data: Data,
    push: Option<PushActivation>,
    activation: Option<LocalActivation>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct LocalActivation {
    key: Data,
    chain: Data,
}

impl Drop for LocalActivation {
    fn drop(&mut self) {
        let mut key = Vec::<u8>::from(std::mem::replace(&mut self.key, Data::new(Vec::new())));
        key.zeroize();
    }
}

impl LocalDevice {
    fn load(path: &Path) -> Result<Self> {
        let bytes =
            storage::read_private(path).context("Could not open the private Apple device file")?;
        let device: Self =
            plist::from_bytes(&bytes).context("Could not read the on-device Apple profile")?;
        ensure!(
            device.version == 1,
            "Unsupported on-device Apple profile version"
        );
        device.computer.validate()?;
        let valid = |proof: &Data| (1..=MAX_HELPER_OUTPUT as usize).contains(&proof.as_ref().len());
        ensure!(
            valid(&device.qualification_data)
                && valid(&device.registration_data)
                && device.qualification_data != device.registration_data,
            "The device file needs two separate, fresh Apple validation proofs"
        );
        ensure!(
            device.push.is_some() != device.activation.is_some(),
            "The device file needs one set of Apple push or activation credentials"
        );
        if let Some(push) = &device.push {
            certified_rsa(&push.certificate, &push.key)?;
            ensure!(
                push.token
                    .as_ref()
                    .is_none_or(|token| token.as_ref().len() == 32),
                "Invalid Apple push token"
            );
        }
        if let Some(activation) = &device.activation {
            let chain = X509::stack_from_pem(activation.chain.as_ref())
                .context("Invalid local activation certificate chain")?;
            let leaf = chain
                .first()
                .context("Missing local activation certificate")?;
            let key = certified_rsa(&Data::new(leaf.to_der()?), &activation.key)?;
            drop(key);
        }
        Ok(device)
    }

    async fn sign_in(
        self: &std::sync::Arc<Self>,
        root: &Path,
        handle: String,
        account: &str,
        password: Zeroizing<String>,
        prompts: &mut impl SmsPrompts,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let profile = self.computer.profile();
        let _activation_lock = lock_profile(root, &profile)?;
        let mut adi = LocalAdi::new(format!("adi:{}:{profile}", root.display()), &self.computer)?;
        // Check account-independent provisioning before making an Apple activation request.
        let _ = adi.headers().await?;
        let provider = DeviceProvider::OnDevice(self.clone());
        let (push, token) =
            provision_push(root, &profile, &self.computer, &provider, self.push.clone()).await?;
        let mut device = self.computer.registration(handle, token, &push);
        let mut anisette = Anisette::from_local(adi);
        login(
            &mut device,
            &mut anisette,
            Some(Proofs::Local {
                qualification: self.qualification_data.clone(),
                registration: self.registration_data.clone(),
            }),
            account,
            password,
            prompts,
        )
        .await
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub(super) struct Computer {
    pub(super) model: String,
    pub(super) serial: String,
    pub(super) uuid: Uuid,
    pub(super) os_version: String,
    pub(super) build_version: String,
    device_name: String,
}

impl Computer {
    pub(super) fn for_contacts(identity: &super::Identity) -> Self {
        let parts: Vec<_> = identity
            .user_agent
            .trim_matches(['[', ']'])
            .splitn(4, ',')
            .collect();
        let (os, build, model) = match parts.as_slice() {
            ["macOS", os, build, model] => (*os, *build, *model),
            _ => ("15.7.5", "24G624", "Mac14,2"),
        };
        let seed = sha256(format!("icloud-contacts/{}", identity.profile_id()).as_bytes());
        let uuid =
            uuid::Builder::from_random_bytes(seed[..16].try_into().expect("Fixed UUID size"))
                .into_uuid();
        Self {
            model: model.into(),
            serial: String::new(),
            uuid,
            os_version: os.into(),
            build_version: build.into(),
            device_name: "iMessage for Linux".into(),
        }
    }

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
            include_facetime: true,
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

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
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

pub(super) fn lock_profile(root: &Path, profile: &str) -> Result<std::fs::File> {
    let lock = OpenOptions::new()
        .mode(0o600)
        .create(true)
        .truncate(false)
        .write(true)
        .open(root.join(format!("activation-{profile}.lock")))?;
    fs2::FileExt::try_lock_exclusive(&lock)
        .context("Device setup is already running for this Apple identity")?;
    Ok(lock)
}

async fn provision_push(
    root: &Path,
    profile: &str,
    computer: &Computer,
    provider: &DeviceProvider,
    imported: Option<PushActivation>,
) -> Result<(PushActivation, [u8; 32])> {
    let keyring_id = format!("activation:{}:{profile}", root.display());
    let saved = storage::read_activation(&keyring_id)?
        .map(|bytes| {
            plist::from_bytes::<PushActivation>(&bytes)
                .context("Could not read the saved Apple push identity")
        })
        .transpose()?;
    let import = imported.is_some();
    let mut push = match (imported, saved) {
        (Some(mut push), saved) => {
            if push.token.is_none()
                && let Some(saved) = saved
                && push.certificate == saved.certificate
                && push.key == saved.key
            {
                push.token = saved.token.clone();
            }
            push
        }
        (None, Some(saved)) => saved,
        (None, None) => {
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
            token
        }
    };
    if import || cached.is_none() {
        save_activation(&keyring_id, &push)?;
    }
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
    async fn private_local_profile_supplies_two_proofs_and_signs_on_linux() -> Result<()> {
        use openssl::sign::Verifier;

        let temp = tempfile::tempdir()?;
        let path = temp.path().join("local-device.plist");
        let computer: Dictionary = serde_json::from_str(DEVICE)?;
        let key = PKey::from_rsa(Rsa::generate(2048)?)?;
        let mut name = X509NameBuilder::new()?;
        name.append_entry_by_text("CN", "Test activation")?;
        let name = name.build();
        let mut cert = X509::builder()?;
        cert.set_version(2)?;
        cert.set_subject_name(&name)?;
        cert.set_issuer_name(&name)?;
        cert.set_pubkey(&key)?;
        cert.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
        cert.set_not_after(Asn1Time::days_from_now(1)?.as_ref())?;
        cert.sign(&key, MessageDigest::sha256())?;
        let cert = cert.build();
        let mut profile = Dictionary::from_iter([
            ("version", 1.into()),
            ("computer", Value::Dictionary(computer)),
            (
                "qualification-data",
                Value::Data(b"fixture qualification".to_vec()),
            ),
            (
                "registration-data",
                Value::Data(b"fixture registration".to_vec()),
            ),
            (
                "activation",
                Value::Dictionary(Dictionary::from_iter([
                    ("key", Value::Data(key.private_key_to_der()?)),
                    ("chain", Value::Data(cert.to_pem()?)),
                ])),
            ),
        ]);
        storage::write_private(&path, &plist_xml(&profile)?)?;
        let provider = DeviceProvider::new(DeviceConnection::OnDevice(path.clone()))?;
        let signed = provider.activation_signature(b"test push request").await?;
        let mut verifier = Verifier::new(MessageDigest::sha1(), &key)?;
        assert!(
            verifier.verify_oneshot(&STANDARD.decode(signed.signature)?, b"test push request")?
        );
        assert_eq!(STANDARD.decode(signed.certificate_chain)?, cert.to_pem()?);
        let DeviceProvider::OnDevice(local) = provider else {
            unreachable!()
        };
        assert_ne!(local.qualification_data, local.registration_data);
        profile.insert(
            "registration-data".into(),
            profile["qualification-data"].clone(),
        );
        storage::write_private(&path, &plist_xml(&profile)?)?;
        assert!(LocalDevice::load(&path).is_err());
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
