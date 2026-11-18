mod anisette;
mod srp;

use std::{fmt, path::Path, time::Duration};

use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use openssl::sha::sha256;
use plist::{Dictionary, Value};
use reqwest::{
    Client, Method, RequestBuilder, Response, StatusCode,
    header::{HeaderMap, HeaderValue},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{
    http::{apple_client, plist_xml, read_response},
    provisioning::Proofs,
    registration::{DeviceRegistration, register},
};
pub(super) use anisette::Anisette;
pub(super) use anisette::DeviceHeaders;
use srp::Exchange;

const GSA: &str = "https://gsa.apple.com";
const PET_SERVICE: &str = "com.apple.gs.idms.pet";
const DEFAULT_SIGN_IN_RETRY: Duration = Duration::from_secs(2);
const MAX_SIGN_IN_RETRY: Duration = Duration::from_secs(10);

pub struct TrustedPhone {
    id: u32,
    pub last_two_digits: String,
}

pub enum TrustedDeviceResponse {
    Code(Zeroizing<String>),
    UseSms,
}

pub enum AppleSetupStage {
    ValidateDevice,
    SignIn,
    AuthorizeDevice,
    RegisterDevice,
}

pub trait SmsPrompts {
    /// Return the zero-based index of the trusted phone to use.
    fn choose_phone(&mut self, phones: &[TrustedPhone]) -> impl Future<Output = Result<usize>>;
    fn read_code(&mut self) -> impl Future<Output = Result<Zeroizing<String>>>;

    fn read_trusted_device_code(&mut self) -> impl Future<Output = Result<TrustedDeviceResponse>> {
        async { self.read_code().await.map(TrustedDeviceResponse::Code) }
    }

    fn request_icloud_contacts(&self) -> bool {
        false
    }

    fn received_icloud_contacts(&mut self, _grant: Result<super::IcloudContactsGrant>) {}

    fn setup_stage(&mut self, _stage: AppleSetupStage) {}

    fn prefers_ssh_password(&self) -> bool {
        false
    }

    fn ssh_prompt(
        &mut self,
        _prompt: super::SshPrompt,
    ) -> impl Future<Output = Result<Zeroizing<String>>> {
        async { anyhow::bail!("Mac sign-in needs an interactive SSH prompt") }
    }
}

pub async fn login_device_sms(
    device_plist: &[u8],
    anisette_helper: &Path,
    account: &str,
    password: Zeroizing<String>,
    prompts: &mut impl SmsPrompts,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut device: DeviceRegistration =
        plist::from_bytes(device_plist).context("Could not decode Apple device plist")?;
    device.validate()?;
    let mut anisette = Anisette::new(anisette_helper)?;
    login(
        &mut device,
        &mut anisette,
        None,
        account,
        password,
        prompts,
        None,
    )
    .await
}

pub(super) fn validate_login(account: &str, password: &str) -> Result<()> {
    let account = account.trim();
    ensure!(
        !account.is_empty()
            && account.len() <= 254
            && !account.contains([':', '\r', '\n'])
            && !password.is_empty(),
        "Enter your Apple Account email or phone and password"
    );
    Ok(())
}

pub(super) async fn login(
    device: &mut DeviceRegistration,
    anisette: &mut Anisette,
    proofs: Option<Proofs<'_>>,
    account: &str,
    password: Zeroizing<String>,
    prompts: &mut impl SmsPrompts,
    existing: Option<&super::Identity>,
) -> Result<Zeroizing<Vec<u8>>> {
    let account = account.trim();
    validate_login(account, &password)?;
    if let Some(proofs) = &proofs {
        prompts.setup_stage(AppleSetupStage::ValidateDevice);
        qualify_device(device, proofs).await?;
    }
    let client = apple_client()?;
    let gsa = GrandSlam {
        client: &client,
        origin: GSA,
        push_token: device.token()?,
        mac_provisioned: proofs.is_some(),
    };
    let password_hash = Zeroizing::new(sha256(password.as_bytes()));
    drop(password);
    prompts.setup_stage(AppleSetupStage::SignIn);
    let session = gsa
        .sign_in(anisette, account, &password_hash, prompts)
        .await?;
    // The account can pause for a trusted-device or SMS code. A connected provider can
    // issue a fresh qualification proof when Apple Account verification has finished.
    if session.verified_with_code
        && let Some(proofs @ Proofs::Provider(_)) = &proofs
    {
        prompts.setup_stage(AppleSetupStage::ValidateDevice);
        qualify_device(device, proofs).await?;
    }
    prompts.setup_stage(AppleSetupStage::AuthorizeDevice);
    let headers = anisette.headers().await?;
    let auth = super::ids_auth::authenticate(
        &client,
        device,
        account,
        &session,
        headers,
        existing.map(|identity| &identity.ids_key),
    )
    .await?;
    let fresh_proof_provider = match &proofs {
        Some(Proofs::Provider(provider)) => Some(*provider),
        _ => None,
    };
    if let Some(proofs) = proofs {
        prompts.setup_stage(AppleSetupStage::ValidateDevice);
        device.validation_data = proofs
            .registration()
            .await
            .context("Could not validate the device for registration")?;
    }
    prompts.setup_stage(AppleSetupStage::RegisterDevice);
    let registration = register(&client, device, auth, fresh_proof_provider, existing).await?;
    if existing.is_none() && prompts.request_icloud_contacts() {
        let grant = super::icloud_contacts::authorize(account, &session, anisette).await;
        prompts.received_icloud_contacts(grant);
    }
    Ok(registration)
}

async fn qualify_device(device: &mut DeviceRegistration, proofs: &Proofs<'_>) -> Result<()> {
    device.validation_data = proofs
        .qualification()
        .await
        .context("Could not validate the Apple device")?;
    device.validate()
}

pub async fn authorize_icloud_contacts(
    root: &Path,
    identity: &super::Identity,
    account: &str,
    password: Zeroizing<String>,
    prompts: &mut impl SmsPrompts,
) -> Result<super::IcloudContactsGrant> {
    let account = account.trim();
    validate_login(account, &password)?;
    let profile = identity.profile_id();
    let _lock = super::provisioning::lock_profile(root, &profile)?;
    let computer = super::provisioning::Computer::for_contacts(identity);
    let mut anisette = Anisette::from_local(super::local_adi::LocalAdi::new(
        format!("icloud-adi:{}:{profile}", root.display()),
        &computer,
    )?);
    let client = apple_client()?;
    let gsa = GrandSlam {
        client: &client,
        origin: GSA,
        push_token: identity.token,
        mac_provisioned: true,
    };
    let password_hash = Zeroizing::new(sha256(password.as_bytes()));
    drop(password);
    let session = gsa
        .sign_in(&mut anisette, account, &password_hash, prompts)
        .await?;
    super::icloud_contacts::authorize(account, &session, &mut anisette).await
}

struct GrandSlam<'a> {
    client: &'a Client,
    origin: &'a str,
    push_token: [u8; 32],
    mac_provisioned: bool,
}

pub(super) struct LoginSession {
    pub adsid: String,
    pub pet: Zeroizing<String>,
    verified_with_code: bool,
}

enum PasswordStep {
    Challenge(Challenge),
    Verified(LoginSession),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ChallengeKind {
    Sms,
    TrustedDevice { code_already_sent: bool },
}

impl ChallengeKind {
    fn from_status(status: &Dictionary) -> Result<Option<Self>> {
        match status
            .get("au")
            .and_then(Value::as_string)
            .filter(|value| !value.is_empty())
        {
            Some("secondaryAuth") => Ok(Some(Self::Sms)),
            Some("trustedDeviceSecondaryAuth") => Ok(Some(Self::TrustedDevice {
                code_already_sent: false,
            })),
            Some(_) => anyhow::bail!("Apple requires an unsupported account verification method"),
            None if status.get("hsc").and_then(Value::as_signed_integer) == Some(409) => {
                // Apple can deliver a trusted-device code during SRP completion.
                Ok(Some(Self::TrustedDevice {
                    code_already_sent: true,
                }))
            }
            None => Ok(None),
        }
    }
}

struct Challenge {
    kind: ChallengeKind,
    adsid: String,
    identity_token: Zeroizing<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PhoneResponse {
    #[serde(default)]
    trusted_phone_numbers: Vec<ApplePhone>,
    trusted_phone_number: Option<ApplePhone>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApplePhone {
    id: u32,
    #[serde(default)]
    last_two_digits: String,
    #[serde(default)]
    number_with_dial_code: String,
}

impl ApplePhone {
    fn masked(self) -> TrustedPhone {
        let mut reversed = self
            .last_two_digits
            .bytes()
            .filter(u8::is_ascii_digit)
            .rev()
            .take(2)
            .collect::<Vec<_>>();
        if reversed.len() != 2 {
            reversed = self
                .number_with_dial_code
                .bytes()
                .filter(u8::is_ascii_digit)
                .rev()
                .take(2)
                .collect();
        }
        let last_two_digits = reversed.into_iter().rev().map(char::from).collect();
        TrustedPhone {
            id: self.id,
            last_two_digits,
        }
    }
}

#[derive(Debug)]
struct SignInUnavailable {
    retry_after: Option<Duration>,
}

impl SignInUnavailable {
    fn new(response: &Response) -> Self {
        let retry_after = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| {
                if let Ok(seconds) = value.parse::<u64>() {
                    Some(Duration::from_secs(seconds))
                } else {
                    let date = DateTime::parse_from_rfc2822(value).ok()?;
                    let delay = date.signed_duration_since(Utc::now());
                    Some(delay.to_std().unwrap_or_default())
                }
            });
        Self { retry_after }
    }

    fn retry_delay(&self) -> Option<Duration> {
        let delay = self.retry_after.unwrap_or(DEFAULT_SIGN_IN_RETRY);
        (delay <= MAX_SIGN_IN_RETRY).then_some(delay)
    }
}

impl fmt::Display for SignInUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Apple Account sign-in is temporarily unavailable (HTTP 503)."
        )?;
        if let Some(delay) = self.retry_after.filter(|delay| !delay.is_zero()) {
            let seconds = delay.as_secs() + u64::from(delay.subsec_nanos() != 0);
            write!(formatter, " Apple requested a wait of {seconds} seconds.")?;
        }
        Ok(())
    }
}

impl std::error::Error for SignInUnavailable {}

struct PhoneOptions {
    phones: Vec<TrustedPhone>,
    sent_to: Option<u32>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VerifyRequest<'a> {
    phone_number: PhoneId,
    mode: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    security_code: Option<SecurityCode<'a>>,
}

#[derive(Serialize)]
struct PhoneId {
    id: u32,
}

#[derive(Serialize)]
struct SecurityCode<'a> {
    code: &'a str,
}

impl GrandSlam<'_> {
    async fn sign_in(
        &self,
        anisette: &mut Anisette,
        account: &str,
        password: &[u8; 32],
        prompts: &mut impl SmsPrompts,
    ) -> Result<LoginSession> {
        let challenge = match self.password_step(anisette, account, password).await? {
            PasswordStep::Verified(session) => return Ok(session),
            PasswordStep::Challenge(challenge) => challenge,
        };
        if let Some(session) = self
            .complete_challenge(anisette, &challenge, prompts)
            .await?
        {
            return Ok(session);
        }
        match self.password_step(anisette, account, password).await? {
            PasswordStep::Verified(mut session) => {
                ensure!(
                    session.adsid == challenge.adsid,
                    "Apple changed the account after verification"
                );
                session.verified_with_code = true;
                Ok(session)
            }
            PasswordStep::Challenge(_) => {
                anyhow::bail!("Apple still requires verification after accepting the code")
            }
        }
    }

    async fn complete_challenge(
        &self,
        anisette: &mut Anisette,
        challenge: &Challenge,
        prompts: &mut impl SmsPrompts,
    ) -> Result<Option<LoginSession>> {
        if let ChallengeKind::TrustedDevice { code_already_sent } = challenge.kind {
            if !code_already_sent {
                let response = self
                    .verification_request(
                        anisette.headers().await?.gsa_headers(),
                        challenge,
                        Method::GET,
                        "/auth/verify/trusteddevice",
                    )?
                    .header("accept", "text/x-xml-plist")
                    .header("content-type", "text/x-xml-plist")
                    .send()
                    .await
                    .context("Could not reach Apple's trusted-device verification service")?;
                ensure!(
                    response.status().is_success(),
                    "Apple declined to send a trusted-device code (HTTP {})",
                    response.status().as_u16()
                );
            }
            if let TrustedDeviceResponse::Code(code) = prompts.read_trusted_device_code().await? {
                return self
                    .verify_trusted_device(&anisette.headers().await?, challenge, code.trim())
                    .await;
            }
        }
        self.complete_sms(anisette, challenge, prompts).await
    }

    async fn verify_trusted_device(
        &self,
        device: &DeviceHeaders,
        challenge: &Challenge,
        code: &str,
    ) -> Result<Option<LoginSession>> {
        validate_code(code)?;
        let mut code = HeaderValue::from_str(code)?;
        code.set_sensitive(true);
        let response = self
            .verification_request(
                device.gsa_headers(),
                challenge,
                Method::GET,
                "/grandslam/GsService2/validate",
            )?
            .header("accept", "text/x-xml-plist")
            .header("content-type", "text/x-xml-plist")
            .header("security-code", code)
            .send()
            .await
            .context("Could not reach Apple's trusted-device verification service")?;
        finish_verification(response, challenge, "trusted-device").await
    }

    async fn complete_sms(
        &self,
        anisette: &mut Anisette,
        challenge: &Challenge,
        prompts: &mut impl SmsPrompts,
    ) -> Result<Option<LoginSession>> {
        let options = self
            .phone_options(&anisette.headers().await?, challenge)
            .await?;
        let id = if let Some(id) = options.sent_to {
            id
        } else {
            let index = if options.phones.len() == 1 {
                0
            } else {
                prompts.choose_phone(&options.phones).await?
            };
            let phone = options
                .phones
                .get(index)
                .context("Select one of the trusted phone numbers Apple returned")?;
            self.send_code(&anisette.headers().await?, challenge, phone.id)
                .await?;
            phone.id
        };
        let code = prompts.read_code().await?;
        self.verify_code(&anisette.headers().await?, challenge, id, code.trim())
            .await
    }

    async fn password_step(
        &self,
        anisette: &mut Anisette,
        account: &str,
        password: &[u8; 32],
    ) -> Result<PasswordStep> {
        let token = if self.mac_provisioned {
            self.push_token
                .iter()
                .map(|byte| format!("{byte:02X}"))
                .collect::<String>()
        } else {
            STANDARD.encode(self.push_token)
        };
        let mut retried = false;
        let (device, srp, cpd, init) = loop {
            let device = anisette.headers().await?;
            let srp = Exchange::start()?;
            let request_id = Uuid::new_v4().to_string().to_uppercase();
            let cpd = device.client_data(&request_id, &token);
            let result = self
                .srp_request(
                    &device,
                    Dictionary::from_iter([
                        ("o", "init".into()),
                        ("u", account.into()),
                        ("A2k", Value::Data(srp.public().to_vec())),
                        ("ps", Value::Array(vec!["s2k".into(), "s2k_fo".into()])),
                        ("cpd", Value::Dictionary(cpd.clone())),
                    ]),
                )
                .await;
            match result {
                Ok(init) => break (device, srp, cpd, init),
                Err(error) => {
                    let delay = error
                        .downcast_ref::<SignInUnavailable>()
                        .and_then(SignInUnavailable::retry_delay);
                    let Some(delay) = delay.filter(|_| !retried) else {
                        return Err(error);
                    };
                    // Each attempt opens a fresh SRP exchange before submitting a password proof.
                    retried = true;
                    tokio::time::sleep(delay).await;
                }
            }
        };
        let salt = required_bytes(&init, "s")?;
        let server = required_bytes(&init, "B")?;
        let iterations = init
            .get("i")
            .and_then(Value::as_unsigned_integer)
            .and_then(|count| usize::try_from(count).ok())
            .context("Apple omitted the SRP iteration count")?;
        let protocol = init.get("sp").and_then(Value::as_string).unwrap_or("s2k");
        let proof = srp.answer(account, password, salt, iterations, protocol, server)?;
        let complete = self
            .srp_request(
                &device,
                Dictionary::from_iter([
                    ("o", "complete".into()),
                    ("u", account.into()),
                    ("c", required_text(&init, "c")?.into()),
                    ("M1", Value::Data(proof.client.to_vec())),
                    ("cpd", Value::Dictionary(cpd)),
                ]),
            )
            .await?;
        let payload = proof.open(
            required_bytes(&complete, "M2")?,
            required_bytes(&complete, "spd")?,
        )?;
        let session: Dictionary =
            plist::from_bytes(&payload).context("Could not decode Apple's SRP session")?;
        let adsid = session
            .get("adsid")
            .or_else(|| session.get("DsPrsId"))
            .and_then(|value| {
                value
                    .as_string()
                    .map(str::to_owned)
                    .or_else(|| value.as_unsigned_integer().map(|number| number.to_string()))
            })
            .filter(|value| !value.is_empty())
            .context("Apple omitted the account identifier")?;
        let status = complete
            .get("Status")
            .and_then(Value::as_dictionary)
            .context("Apple omitted the sign-in status")?;
        match ChallengeKind::from_status(status)? {
            Some(kind) => {
                let token = required_text(&session, "GsIdmsToken")
                    .or_else(|_| required_text(&session, "GsIdMS"))?;
                let raw = Zeroizing::new(format!("{adsid}:{token}"));
                Ok(PasswordStep::Challenge(Challenge {
                    kind,
                    adsid,
                    identity_token: Zeroizing::new(STANDARD.encode(raw.as_bytes())),
                }))
            }
            None => {
                let pet = session
                    .get("t")
                    .and_then(Value::as_dictionary)
                    .and_then(|tokens| tokens.get(PET_SERVICE))
                    .and_then(Value::as_dictionary)
                    .and_then(|token| token.get("token"))
                    .and_then(Value::as_string)
                    .filter(|value| !value.is_empty())
                    .context("Apple omitted the account authorization token")?;
                Ok(PasswordStep::Verified(LoginSession {
                    adsid,
                    pet: Zeroizing::new(pet.into()),
                    verified_with_code: false,
                }))
            }
        }
    }

    async fn srp_request(&self, device: &DeviceHeaders, packet: Dictionary) -> Result<Dictionary> {
        let body = plist_xml(&Dictionary::from_iter([
            (
                "Header",
                Value::Dictionary(Dictionary::from_iter([("Version", "1.0.1")])),
            ),
            ("Request", Value::Dictionary(packet)),
        ]))?;
        let response = self
            .client
            .post(format!("{}/grandslam/GsService2", self.origin))
            .headers(device.gsa_headers())
            .header("connection", "close")
            .header("accept", "*/*")
            .header("content-type", "text/x-xml-plist")
            .body(body.to_vec())
            .send()
            .await
            .context("Could not reach Apple Account sign-in")?;
        let status = response.status();
        if status == StatusCode::SERVICE_UNAVAILABLE {
            return Err(SignInUnavailable::new(&response).into());
        }
        let body = read_response(response).await?;
        let decoded: GsaReply = match plist::from_bytes(&body) {
            Ok(decoded) => decoded,
            Err(_) if !status.is_success() => {
                anyhow::bail!("Apple Account sign-in failed (HTTP {})", status.as_u16())
            }
            Err(_) => anyhow::bail!("Apple returned an unreadable sign-in response"),
        };
        let returned = decoded
            .response
            .get("Status")
            .and_then(Value::as_dictionary)
            .and_then(|value| value.get("ec"))
            .and_then(Value::as_signed_integer)
            .context("Apple omitted the sign-in status")?;
        ensure!(
            returned == 0 && status.is_success(),
            "Apple rejected sign-in (Apple status {returned}, HTTP {})",
            status.as_u16()
        );
        Ok(decoded.response)
    }

    async fn phone_options(
        &self,
        device: &DeviceHeaders,
        challenge: &Challenge,
    ) -> Result<PhoneOptions> {
        let response = self
            .auth_request(device, challenge, Method::GET, "/auth", None)
            .await?;
        let status = response.status();
        ensure!(
            matches!(status, StatusCode::OK | StatusCode::CREATED),
            "Apple could not list the account's trusted phone numbers (HTTP {})",
            status.as_u16()
        );
        let devices: PhoneResponse = serde_json::from_slice(&read_response(response).await?)
            .context("Could not read the account's trusted phone numbers from Apple")?;
        let preferred = devices.trusted_phone_number.as_ref().map(|phone| phone.id);
        let mut phones = devices
            .trusted_phone_numbers
            .into_iter()
            .map(ApplePhone::masked)
            .collect::<Vec<_>>();
        if let Some(phone) = devices.trusted_phone_number
            && !phones.iter().any(|candidate| candidate.id == phone.id)
        {
            phones.push(phone.masked());
        }
        ensure!(
            !phones.is_empty(),
            "Apple returned no trusted phone numbers for SMS"
        );
        let sent_to = (status == StatusCode::CREATED).then(|| preferred.unwrap_or(phones[0].id));
        Ok(PhoneOptions { phones, sent_to })
    }

    async fn send_code(
        &self,
        device: &DeviceHeaders,
        challenge: &Challenge,
        number_id: u32,
    ) -> Result<()> {
        let request = VerifyRequest {
            phone_number: PhoneId { id: number_id },
            mode: "sms",
            security_code: None,
        };
        let response = self
            .auth_request(
                device,
                challenge,
                Method::PUT,
                "/auth/verify/phone",
                Some(&request),
            )
            .await?;
        ensure!(
            response.status().is_success(),
            "Apple declined to send an SMS code (HTTP {})",
            response.status().as_u16()
        );
        Ok(())
    }

    async fn verify_code(
        &self,
        device: &DeviceHeaders,
        challenge: &Challenge,
        number_id: u32,
        code: &str,
    ) -> Result<Option<LoginSession>> {
        validate_code(code)?;
        let request = VerifyRequest {
            phone_number: PhoneId { id: number_id },
            mode: "sms",
            security_code: Some(SecurityCode { code }),
        };
        let response = self
            .auth_request(
                device,
                challenge,
                Method::POST,
                "/auth/verify/phone/securitycode",
                Some(&request),
            )
            .await?;
        finish_verification(response, challenge, "SMS").await
    }

    async fn auth_request(
        &self,
        device: &DeviceHeaders,
        challenge: &Challenge,
        method: Method,
        path: &str,
        body: Option<&VerifyRequest<'_>>,
    ) -> Result<Response> {
        let mut request = self
            .verification_request(device.sms_headers(), challenge, method, path)?
            .header("accept", "application/json");
        if let Some(body) = body {
            request = request.json(body);
        }
        request
            .send()
            .await
            .context("Could not reach Apple's SMS verification service")
    }

    fn verification_request(
        &self,
        headers: HeaderMap,
        challenge: &Challenge,
        method: Method,
        path: &str,
    ) -> Result<RequestBuilder> {
        let mut identity = HeaderValue::from_str(&challenge.identity_token)?;
        identity.set_sensitive(true);
        Ok(self
            .client
            .request(method, format!("{}{path}", self.origin))
            .headers(headers)
            .header("connection", "close")
            .header("x-apple-identity-token", identity))
    }
}

fn validate_code(code: &str) -> Result<()> {
    ensure!(
        code.len() == 6 && code.bytes().all(|byte| byte.is_ascii_digit()),
        "Enter the six-digit Apple verification code"
    );
    Ok(())
}

async fn finish_verification(
    response: Response,
    challenge: &Challenge,
    method: &str,
) -> Result<Option<LoginSession>> {
    ensure!(
        response.status().is_success(),
        "Apple declined {method} verification (HTTP {})",
        response.status().as_u16()
    );
    let encoded = response
        .headers()
        .get("x-apple-pe-token")
        .map(|header| STANDARD.decode(header.as_bytes()).map(Zeroizing::new))
        .transpose()
        .context("Apple returned an invalid authorization token")?;
    let bytes = read_response(response).await?;
    check_verification_body(&bytes, method)?;
    let Some(decoded) = encoded else {
        return Ok(None);
    };
    let token = std::str::from_utf8(&decoded)?
        .split(':')
        .nth(1)
        .filter(|token| !token.is_empty())
        .context("Apple returned an empty authorization token")?;
    Ok(Some(LoginSession {
        adsid: challenge.adsid.clone(),
        pet: Zeroizing::new(token.to_owned()),
        verified_with_code: true,
    }))
}

fn check_verification_body(bytes: &[u8], method: &str) -> Result<()> {
    if let Ok(plist) = plist::from_bytes::<Dictionary>(bytes) {
        let status = plist
            .get("Status")
            .and_then(Value::as_dictionary)
            .unwrap_or(&plist);
        let code = status
            .get("ec")
            .and_then(Value::as_signed_integer)
            .unwrap_or(0);
        ensure!(
            code == 0,
            "Apple declined the {method} code (Apple status {code})"
        );
    } else if let Ok(json) = serde_json::from_slice::<serde_json::Value>(bytes) {
        ensure!(
            !json
                .get("serviceErrors")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|errors| !errors.is_empty()),
            "Apple declined the {method} code"
        );
    } else {
        ensure!(
            bytes.iter().all(u8::is_ascii_whitespace),
            "Apple returned an unreadable {method} verification response"
        );
    }
    Ok(())
}

#[derive(Deserialize)]
struct GsaReply {
    #[serde(rename = "Response")]
    response: Dictionary,
}

fn required_text<'a>(dict: &'a Dictionary, name: &str) -> Result<&'a str> {
    dict.get(name)
        .and_then(Value::as_string)
        .filter(|value| !value.is_empty())
        .with_context(|| format!("Apple omitted the {name} field"))
}

fn required_bytes<'a>(dict: &'a Dictionary, name: &str) -> Result<&'a [u8]> {
    dict.get(name)
        .and_then(Value::as_data)
        .filter(|value| !value.is_empty())
        .with_context(|| format!("Apple omitted the {name} field"))
}

#[cfg(test)]
mod tests {
    use std::{
        os::unix::fs::PermissionsExt,
        sync::{Arc, Mutex},
    };

    use axum::{
        Json, Router,
        body::Bytes,
        extract::State,
        http::HeaderMap,
        response::IntoResponse,
        routing::{get, post, put},
    };
    use plist::Data;
    use serde_json::json;

    use super::*;

    struct Prompts {
        choices: usize,
        code: &'static str,
    }

    #[tokio::test]
    async fn validates_the_device_before_starting_apple_account_sign_in() -> Result<()> {
        struct SetupProgress(Vec<AppleSetupStage>);

        impl SmsPrompts for SetupProgress {
            async fn choose_phone(&mut self, _: &[TrustedPhone]) -> Result<usize> {
                anyhow::bail!("Device validation should fail before choosing a phone")
            }

            async fn read_code(&mut self) -> Result<Zeroizing<String>> {
                anyhow::bail!("Device validation should fail before requesting a code")
            }

            fn setup_stage(&mut self, stage: AppleSetupStage) {
                self.0.push(stage);
            }
        }

        let folder = tempfile::tempdir()?;
        let helper = folder.path().join("device-helper");
        std::fs::write(
            &helper,
            "#!/bin/sh\n[ \"$1\" = validation ] || exit 1\nprintf '%s' 'invalid!'\n",
        )?;
        std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o700))?;
        let provider = crate::apple::provisioning::DeviceProvider::LocalHelper(helper);
        let mut anisette = Anisette::from_provider(provider.clone());
        let mut device = DeviceRegistration {
            version: 1,
            handle: "mailto:fixture@example.org".into(),
            // An invalid push token ensures this fixture cannot reach Apple's account endpoints.
            push_token: Data::new(Vec::new()),
            push_certificate: Data::new(Vec::new()),
            push_private_key: Data::new(Vec::new()),
            protocol_version: 1660,
            user_agent: "[macOS,11.7.10,20G1427,MacBookPro11,3]".into(),
            device_name: "Fixture".into(),
            hardware_version: "MacBookPro11,3".into(),
            os_version: "macOS,11.7.10,20G1427".into(),
            software_version: "20G1427".into(),
            private_device_data: Dictionary::new(),
            validation_data: Data::new(Vec::new()),
            include_facetime: true,
        };
        let mut prompts = SetupProgress(Vec::new());
        let result = login(
            &mut device,
            &mut anisette,
            Some(Proofs::Provider(&provider)),
            "fixture@example.org",
            Zeroizing::new("fixture-password".to_owned()),
            &mut prompts,
            None,
        )
        .await;
        let error = result.err().context("Invalid device proof was accepted")?;
        assert!(format!("{error:#}").contains("invalid Apple validation data"));
        assert!(matches!(
            prompts.0.as_slice(),
            [AppleSetupStage::ValidateDevice]
        ));
        Ok(())
    }

    impl SmsPrompts for Prompts {
        async fn choose_phone(&mut self, phones: &[TrustedPhone]) -> Result<usize> {
            self.choices += 1;
            assert_eq!(phones[0].last_two_digits, "47");
            assert_eq!(phones[1].last_two_digits, "21");
            Ok(1)
        }

        async fn read_code(&mut self) -> Result<Zeroizing<String>> {
            Ok(Zeroizing::new(self.code.to_owned()))
        }
    }

    #[derive(Clone)]
    struct Fixture {
        auto_sent: bool,
        requests: Arc<Mutex<Vec<&'static str>>>,
    }

    #[tokio::test]
    async fn sms_challenge_uses_apple_phone_id_and_preserves_leading_zeroes() -> Result<()> {
        for auto_sent in [false, true] {
            let fixture = Fixture {
                auto_sent,
                requests: Arc::new(Mutex::new(Vec::new())),
            };
            let app = Router::new()
                .route("/auth", get(|State(fixture): State<Fixture>, headers: HeaderMap| async move {
                    assert_headers(&headers);
                    fixture.requests.lock().unwrap().push("list");
                    let mut phones = json!({"trustedPhoneNumbers":[
                        {"id": 9, "numberWithDialCode": "+44••••47"},
                        {"id": 72, "lastTwoDigits": "21"},
                    ]});
                    let code = if fixture.auto_sent {
                        phones["trustedPhoneNumber"] = json!({"id": 72});
                        StatusCode::CREATED
                    } else {
                        StatusCode::OK
                    };
                    (code, Json(phones))
                }))
                .route("/auth/verify/phone", put(|State(fixture): State<Fixture>, headers: HeaderMap, Json(body): Json<serde_json::Value>| async move {
                    assert_headers(&headers);
                    assert!(!fixture.auto_sent);
                    assert_eq!(body, json!({"phoneNumber":{"id":72},"mode":"sms"}));
                    fixture.requests.lock().unwrap().push("send");
                    StatusCode::OK
                }))
                .route("/auth/verify/phone/securitycode", post(|State(fixture): State<Fixture>, headers: HeaderMap, Json(body): Json<serde_json::Value>| async move {
                    assert_headers(&headers);
                    assert_eq!(body["phoneNumber"]["id"], 72);
                    assert_eq!(body["mode"], "sms");
                    fixture.requests.lock().unwrap().push("verify");
                    match body["securityCode"]["code"].as_str() {
                        Some("000123") if fixture.auto_sent => (StatusCode::OK, "").into_response(),
                        Some("000123") => (StatusCode::OK, [("x-apple-pe-token", STANDARD.encode("com.apple.gs.idms.pet:fixture-pet:300"))], "").into_response(),
                        _ => (StatusCode::OK, "<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>ec</key><integer>-21669</integer></dict></plist>").into_response(),
                    }
                }))
                .with_state(fixture.clone());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let origin = format!("http://{}", listener.local_addr()?);
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            let client = Client::builder().no_proxy().build()?;
            let service = GrandSlam {
                client: &client,
                origin: &origin,
                push_token: [0; 32],
                mac_provisioned: false,
            };
            let challenge = Challenge {
                kind: ChallengeKind::Sms,
                adsid: "123".into(),
                identity_token: Zeroizing::new("fixture-identity".into()),
            };
            let temp = tempfile::tempdir()?;
            let mut anisette = fixture_anisette(temp.path())?;
            let mut prompts = Prompts {
                choices: 0,
                code: "000123",
            };
            let result = service
                .complete_sms(&mut anisette, &challenge, &mut prompts)
                .await?;
            if auto_sent {
                assert!(result.is_none());
                assert_eq!(prompts.choices, 0);
                assert_eq!(*fixture.requests.lock().unwrap(), ["list", "verify"]);
            } else {
                let result = result.context("The fixture supplies a PET")?;
                assert_eq!(result.adsid, "123");
                assert_eq!(result.pet.as_str(), "fixture-pet");
                assert!(result.verified_with_code);
                assert_eq!(prompts.choices, 1);
                assert_eq!(
                    *fixture.requests.lock().unwrap(),
                    ["list", "send", "verify"]
                );
            }
            let error = service
                .verify_code(&anisette.headers().await?, &challenge, 72, "987654")
                .await
                .err()
                .context("The fixture rejects invalid SMS codes")?;
            assert!(error.to_string().contains("-21669"));
            server.abort();
        }
        Ok(())
    }

    #[tokio::test]
    async fn trusted_device_challenges_use_the_device_route_with_an_explicit_sms_fallback()
    -> Result<()> {
        struct DevicePrompts(bool);
        impl SmsPrompts for DevicePrompts {
            async fn choose_phone(&mut self, _: &[TrustedPhone]) -> Result<usize> {
                panic!("The fixture has a single phone")
            }

            async fn read_code(&mut self) -> Result<Zeroizing<String>> {
                assert!(self.0, "An SMS prompt requires the user's choice");
                Ok(Zeroizing::new("000234".to_owned()))
            }

            async fn read_trusted_device_code(&mut self) -> Result<TrustedDeviceResponse> {
                if self.0 {
                    Ok(TrustedDeviceResponse::UseSms)
                } else {
                    Ok(TrustedDeviceResponse::Code(Zeroizing::new(
                        "000123".to_owned(),
                    )))
                }
            }
        }

        for (status, use_sms, expected) in [
            (
                Dictionary::from_iter([("au", Value::String("trustedDeviceSecondaryAuth".into()))]),
                false,
                vec!["push", "validate"],
            ),
            (
                Dictionary::from_iter([("hsc", Value::Integer(409.into()))]),
                false,
                vec!["validate"],
            ),
            (
                Dictionary::from_iter([("hsc", Value::Integer(409.into()))]),
                true,
                vec!["phones", "send-sms", "verify-sms"],
            ),
        ] {
            let requests = Arc::new(Mutex::new(Vec::new()));
            let app = Router::new().fallback(
                |State(requests): State<Arc<Mutex<Vec<&'static str>>>>, method: Method, uri: axum::http::Uri, headers: HeaderMap, body: Bytes| async move {
                    assert_headers(&headers);
                    let mut requests = requests.lock().unwrap();
                    match (method.as_str(), uri.path()) {
                        ("GET", "/auth/verify/trusteddevice") => {
                            assert_eq!(headers["accept"], "text/x-xml-plist");
                            assert!(!headers.contains_key("security-code"));
                            requests.push("push");
                            StatusCode::OK.into_response()
                        }
                        ("GET", "/grandslam/GsService2/validate") => {
                            assert_eq!(headers["accept"], "text/x-xml-plist");
                            assert_eq!(headers["security-code"], "000123");
                            requests.push("validate");
                            (StatusCode::OK, [("x-apple-pe-token", STANDARD.encode("com.apple.gs.idms.pet:trusted-pet"))], "<plist version=\"1.0\"><dict><key>ec</key><integer>0</integer></dict></plist>").into_response()
                        }
                        ("GET", "/auth") => {
                            requests.push("phones");
                            Json(json!({"trustedPhoneNumbers": [{"id": 72, "lastTwoDigits": "21"}]})).into_response()
                        }
                        ("PUT", "/auth/verify/phone") => {
                            assert_eq!(serde_json::from_slice::<serde_json::Value>(&body).unwrap(), json!({"phoneNumber":{"id":72},"mode":"sms"}));
                            requests.push("send-sms");
                            StatusCode::OK.into_response()
                        }
                        ("POST", "/auth/verify/phone/securitycode") => {
                            assert_eq!(serde_json::from_slice::<serde_json::Value>(&body).unwrap()["securityCode"]["code"], "000234");
                            requests.push("verify-sms");
                            StatusCode::OK.into_response()
                        }
                        _ => panic!("Unexpected verification request"),
                    }
                }
            ).with_state(requests.clone());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let origin = format!("http://{}", listener.local_addr()?);
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            let client = Client::builder().no_proxy().build()?;
            let gsa = GrandSlam {
                client: &client,
                origin: &origin,
                push_token: [0; 32],
                mac_provisioned: true,
            };
            let challenge = Challenge {
                kind: ChallengeKind::from_status(&status)?
                    .context("Expected a verification challenge")?,
                adsid: "123".into(),
                identity_token: Zeroizing::new("fixture-identity".into()),
            };
            let folder = tempfile::tempdir()?;
            let mut anisette = fixture_anisette(folder.path())?;
            let session = gsa
                .complete_challenge(&mut anisette, &challenge, &mut DevicePrompts(use_sms))
                .await?;
            assert_eq!(
                session.as_ref().map(|session| session.pet.as_str()),
                (!use_sms).then_some("trusted-pet")
            );
            assert_eq!(*requests.lock().unwrap(), expected);
            server.abort();
        }
        Ok(())
    }

    #[derive(Clone)]
    struct SignInFixture {
        retry_after: &'static str,
        requests: Arc<Mutex<Vec<Dictionary>>>,
    }

    #[tokio::test]
    async fn unavailable_sign_in_retries_only_a_fresh_challenge() -> Result<()> {
        for retry_after in ["0", "120"] {
            let fixture = SignInFixture {
                retry_after,
                requests: Arc::new(Mutex::new(Vec::new())),
            };
            let app = Router::new()
                .route(
                    "/grandslam/GsService2",
                    post(
                        |State(fixture): State<SignInFixture>, body: Bytes| async move {
                            let document: Dictionary = plist::from_bytes(&body).unwrap();
                            let request = document["Request"].as_dictionary().unwrap().clone();
                            let is_init = request["o"].as_string() == Some("init");
                            let mut requests = fixture.requests.lock().unwrap();
                            requests.push(request);
                            if requests.len() == 1 || !is_init {
                                return (
                                    StatusCode::SERVICE_UNAVAILABLE,
                                    [
                                        ("retry-after", fixture.retry_after),
                                        ("content-type", "text/html"),
                                    ],
                                    "<html>Service Unavailable</html>",
                                )
                                    .into_response();
                            }
                            let reply = Dictionary::from_iter([(
                                "Response",
                                Value::Dictionary(Dictionary::from_iter([
                                    (
                                        "Status",
                                        Value::Dictionary(Dictionary::from_iter([("ec", 0_i64)])),
                                    ),
                                    ("s", Value::Data(vec![1; 16])),
                                    ("B", Value::Data(vec![3])),
                                    ("i", 1.into()),
                                    ("c", "fixture challenge".into()),
                                ])),
                            )]);
                            (StatusCode::OK, plist_xml(&reply).unwrap().to_vec()).into_response()
                        },
                    ),
                )
                .with_state(fixture.clone());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let origin = format!("http://{}", listener.local_addr()?);
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            let client = Client::builder().no_proxy().build()?;
            let service = GrandSlam {
                client: &client,
                origin: &origin,
                push_token: [0; 32],
                mac_provisioned: true,
            };
            let temp = tempfile::tempdir()?;
            let mut anisette = fixture_anisette(temp.path())?;
            let error = service
                .password_step(&mut anisette, "fixture@example.com", &[1; 32])
                .await
                .err()
                .context("The fixture returns an unavailable response")?;
            assert!(error.is::<SignInUnavailable>());
            let message = error.to_string();
            assert!(
                message.contains("Apple Account sign-in is temporarily unavailable (HTTP 503)")
            );
            let requests = fixture.requests.lock().unwrap();
            if retry_after == "0" {
                let operations: Vec<_> = requests
                    .iter()
                    .map(|request| request["o"].as_string().unwrap())
                    .collect();
                assert_eq!(operations, ["init", "init", "complete"]);
                assert_ne!(requests[0]["A2k"], requests[1]["A2k"]);
                assert_ne!(requests[0]["cpd"], requests[1]["cpd"]);
                assert_eq!(requests[1]["cpd"], requests[2]["cpd"]);
            } else {
                assert_eq!(requests.len(), 1);
                assert!(message.contains("120 seconds"));
            }
            server.abort();
        }
        Ok(())
    }

    fn fixture_anisette(root: &Path) -> Result<Anisette> {
        let helper = root.join("headers");
        std::fs::write(
            &helper,
            r#"#!/bin/sh
cat <<'JSON'
{"X-Apple-I-MD":"otp","X-Apple-I-MD-M":"machine","X-Apple-I-MD-RINFO":"1","X-Apple-I-MD-LU":"local","X-Mme-Device-Id":"device","X-Apple-I-Client-Time":"2026-11-15T12:01:00Z","X-Mme-Client-Info":"fixture client","User-Agent":"fixture agent","Authorization":"must not be forwarded"}
JSON
"#,
        )?;
        std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o700))?;
        Anisette::new(&helper)
    }

    fn assert_headers(headers: &HeaderMap) {
        assert_eq!(headers["x-apple-identity-token"], "fixture-identity");
        assert_eq!(headers["x-apple-i-md"], "otp");
        assert_eq!(headers["x-mme-client-info"], "fixture client");
        assert!(!headers.contains_key("authorization"));
    }
}
