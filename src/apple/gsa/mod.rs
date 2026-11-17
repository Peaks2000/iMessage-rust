mod anisette;
mod srp;

use std::path::Path;

use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use openssl::sha::sha256;
use plist::{Dictionary, Value};
use reqwest::{Client, Method, Response, StatusCode, header::HeaderValue};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{
    http::{apple_client, plist_xml, read_response},
    registration::{DeviceRegistration, register},
};
pub(super) use anisette::Anisette;
pub(super) use anisette::DeviceHeaders;
use srp::Exchange;

const GSA: &str = "https://gsa.apple.com";
const PET_SERVICE: &str = "com.apple.gs.idms.pet";

pub struct TrustedPhone {
    id: u32,
    pub last_two_digits: String,
}

pub trait SmsPrompts {
    /// Return the zero-based index of the trusted phone to use.
    fn choose_phone(&mut self, phones: &[TrustedPhone]) -> impl Future<Output = Result<usize>>;
    fn read_code(&mut self) -> impl Future<Output = Result<Zeroizing<String>>>;
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
    login(&mut device, &mut anisette, None, account, password, prompts).await
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
    proofs: Option<super::provisioning::Proofs<'_>>,
    account: &str,
    password: Zeroizing<String>,
    prompts: &mut impl SmsPrompts,
) -> Result<Zeroizing<Vec<u8>>> {
    let account = account.trim();
    validate_login(account, &password)?;
    let client = apple_client()?;
    let gsa = GrandSlam {
        client: &client,
        origin: GSA,
        push_token: device.token()?,
        mac_provisioned: proofs.is_some(),
    };
    let password_hash = Zeroizing::new(sha256(password.as_bytes()));
    drop(password);
    let session = gsa
        .sign_in(anisette, account, &password_hash, prompts)
        .await?;
    let headers = anisette.headers().await?;
    if let Some(proofs) = &proofs {
        device.validation_data = proofs.qualification().await?;
        device.validate()?;
    }
    let auth = super::ids_auth::authenticate(&client, device, account, session, headers).await?;
    if let Some(proofs) = proofs {
        device.validation_data = proofs.registration().await?;
    }
    register(&client, device, auth).await
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
}

enum PasswordStep {
    Sms(Challenge),
    Verified(LoginSession),
}

struct Challenge {
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
        let challenge = match self
            .password_step(&anisette.headers().await?, account, password)
            .await?
        {
            PasswordStep::Verified(session) => return Ok(session),
            PasswordStep::Sms(challenge) => challenge,
        };
        if let Some(session) = self.complete_sms(anisette, &challenge, prompts).await? {
            return Ok(session);
        }
        match self
            .password_step(&anisette.headers().await?, account, password)
            .await?
        {
            PasswordStep::Verified(session) => {
                ensure!(
                    session.adsid == challenge.adsid,
                    "Apple changed the account after SMS verification"
                );
                Ok(session)
            }
            PasswordStep::Sms(_) => {
                anyhow::bail!("Apple still requires verification after accepting the SMS code")
            }
        }
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
        device: &DeviceHeaders,
        account: &str,
        password: &[u8; 32],
    ) -> Result<PasswordStep> {
        let srp = Exchange::start()?;
        let request_id = Uuid::new_v4().to_string().to_uppercase();
        let token = if self.mac_provisioned {
            self.push_token
                .iter()
                .map(|byte| format!("{byte:02X}"))
                .collect::<String>()
        } else {
            STANDARD.encode(self.push_token)
        };
        let cpd = device.client_data(&request_id, &token);
        let init = self
            .srp_request(
                device,
                Dictionary::from_iter([
                    ("o", "init".into()),
                    ("u", account.into()),
                    ("A2k", Value::Data(srp.public().to_vec())),
                    ("ps", Value::Array(vec!["s2k".into(), "s2k_fo".into()])),
                    ("cpd", Value::Dictionary(cpd.clone())),
                ]),
            )
            .await?;
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
                device,
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
        let authentication = status
            .get("au")
            .and_then(Value::as_string)
            .filter(|value| !value.is_empty())
            .or_else(|| {
                (status.get("hsc").and_then(Value::as_signed_integer) == Some(409))
                    .then_some("trustedDeviceSecondaryAuth")
            });
        match authentication {
            Some("secondaryAuth" | "trustedDeviceSecondaryAuth") => {
                let token = required_text(&session, "GsIdmsToken")
                    .or_else(|_| required_text(&session, "GsIdMS"))?;
                let raw = Zeroizing::new(format!("{adsid}:{token}"));
                Ok(PasswordStep::Sms(Challenge {
                    adsid,
                    identity_token: Zeroizing::new(STANDARD.encode(raw.as_bytes())),
                }))
            }
            Some(_) => {
                anyhow::bail!("Apple requires an account verification method other than SMS")
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
        let body = read_response(response).await?;
        let decoded: GsaReply = plist::from_bytes(&body).with_context(|| {
            format!(
                "Apple returned an unreadable sign-in response (HTTP {})",
                status.as_u16()
            )
        })?;
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
        ensure!(
            code.len() == 6 && code.bytes().all(|byte| byte.is_ascii_digit()),
            "Enter the six-digit Apple SMS code"
        );
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
        ensure!(
            response.status() == StatusCode::OK,
            "Apple declined SMS verification (HTTP {})",
            response.status().as_u16()
        );
        let encoded = response
            .headers()
            .get("x-apple-pe-token")
            .map(|header| STANDARD.decode(header.as_bytes()).map(Zeroizing::new))
            .transpose()
            .context("Apple returned an invalid authorization token")?;
        let bytes = read_response(response).await?;
        check_verification_body(&bytes)?;
        let Some(decoded) = encoded else {
            return Ok(None);
        };
        let pieces = std::str::from_utf8(&decoded)?
            .split(':')
            .collect::<Vec<_>>();
        let token = pieces
            .get(1)
            .filter(|token| !token.is_empty())
            .context("Apple returned an empty authorization token")?;
        Ok(Some(LoginSession {
            adsid: challenge.adsid.clone(),
            pet: Zeroizing::new((*token).to_owned()),
        }))
    }

    async fn auth_request(
        &self,
        device: &DeviceHeaders,
        challenge: &Challenge,
        method: Method,
        path: &str,
        body: Option<&VerifyRequest<'_>>,
    ) -> Result<Response> {
        let mut identity = HeaderValue::from_str(&challenge.identity_token)?;
        identity.set_sensitive(true);
        let mut request = self
            .client
            .request(method, format!("{}{path}", self.origin))
            .headers(device.sms_headers())
            .header("connection", "close")
            .header("accept", "application/json")
            .header("x-apple-identity-token", identity);
        if let Some(body) = body {
            request = request.json(body);
        }
        request
            .send()
            .await
            .context("Could not reach Apple's SMS verification service")
    }
}

fn check_verification_body(bytes: &[u8]) -> Result<()> {
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
            "Apple declined the SMS code (Apple status {code})"
        );
    } else if let Ok(json) = serde_json::from_slice::<serde_json::Value>(bytes) {
        ensure!(
            !json
                .get("serviceErrors")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|errors| !errors.is_empty()),
            "Apple declined the SMS code"
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
        extract::State,
        http::HeaderMap,
        response::IntoResponse,
        routing::{get, post, put},
    };
    use serde_json::json;

    use super::*;

    struct Prompts {
        choices: usize,
        code: &'static str,
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
                adsid: "123".into(),
                identity_token: Zeroizing::new("fixture-identity".into()),
            };
            let temp = tempfile::tempdir()?;
            let helper = temp.path().join("headers");
            std::fs::write(
                &helper,
                r#"#!/bin/sh
cat <<'JSON'
{"X-Apple-I-MD":"otp","X-Apple-I-MD-M":"machine","X-Apple-I-MD-RINFO":"1","X-Apple-I-MD-LU":"local","X-Mme-Device-Id":"device","X-Apple-I-Client-Time":"2026-11-15T12:01:00Z","X-Mme-Client-Info":"fixture client","User-Agent":"fixture agent","Authorization":"must not be forwarded"}
JSON
"#,
            )?;
            std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o700))?;
            let mut anisette = Anisette::new(&helper)?;
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

    fn assert_headers(headers: &HeaderMap) {
        assert_eq!(headers["x-apple-identity-token"], "fixture-identity");
        assert_eq!(headers["x-apple-i-md"], "otp");
        assert_eq!(headers["x-mme-client-info"], "fixture client");
        assert!(!headers.contains_key("authorization"));
    }
}
