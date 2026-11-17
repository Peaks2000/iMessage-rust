use std::fmt::Write;

use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use openssl::{
    hash::MessageDigest,
    pkey::PKey,
    rsa::Rsa,
    sha::sha1,
    x509::{X509, X509NameBuilder, X509ReqBuilder},
};
use plist::{Data, Dictionary, Value};
use reqwest::Client;
use serde::Deserialize;
use uuid::Uuid;
use zeroize::Zeroize;

use super::{
    gsa::{DeviceHeaders, LoginSession},
    http::{client_builder, plist_xml, plist_xml_gzip, read_response},
    registration::{AccountAuth, DeviceRegistration},
};

const SETUP: &str = "https://setup.icloud.com/setup/signin/v2/login";
const IDS_DELEGATE: &str = "com.apple.private.ids";
const AUTH_CERT: &str =
    "https://profile.ess.apple.com/WebObjects/VCProfileService.woa/wa/authenticateDS";

pub(super) async fn authenticate(
    apple: &Client,
    device: &DeviceRegistration,
    username: &str,
    session: &LoginSession,
    headers: DeviceHeaders,
) -> Result<AccountAuth> {
    let setup = client_builder().build()?;
    let request = plist_xml(&Dictionary::from_iter([
        (
            "delegates",
            Value::Dictionary(Dictionary::from_iter([(
                IDS_DELEGATE,
                Value::Dictionary(Dictionary::from_iter([("protocol-version", "4")])),
            )])),
        ),
        ("protocolVersion", "1.0".into()),
        (
            "userInfo",
            Value::Dictionary(Dictionary::from_iter([
                ("client-id", Uuid::new_v4().to_string().to_uppercase()),
                ("language", "en-US".to_owned()),
                ("timezone", "UTC".to_owned()),
            ])),
        ),
    ]))?;
    let response = setup
        .post(SETUP)
        .headers(headers.headers())
        .header("content-type", "text/x-xml-plist")
        .header("x-apple-adsid", &session.adsid)
        .header(
            "x-mme-nas-qualify",
            STANDARD.encode(device.validation_data.as_ref()),
        )
        .basic_auth(username, Some(session.pet.as_str()))
        .body(request.to_vec())
        .send()
        .await
        .context("Could not reach Apple's iMessage account authorization")
        .and_then(checked_response)?;
    let reply: SetupReply = plist::from_bytes(&read_response(response).await?)
        .context("Could not read Apple's iMessage account authorization response")?;
    ensure!(
        reply.status == 0,
        "Apple declined iMessage account authorization (Apple status {})",
        reply.status
    );
    let delegate = reply
        .delegates
        .ids
        .context("Apple did not return the iMessage account authorization delegate")?;
    ensure!(
        delegate.status == 0,
        "Apple rejected the iMessage account delegate (Apple status {})",
        delegate.status
    );
    let mut grant = delegate
        .service_data
        .context("Apple omitted the iMessage account grant")?;
    ensure!(
        !grant.profile_id.is_empty() && !grant.auth_token.is_empty(),
        "Apple returned an incomplete iMessage account grant"
    );

    let key = PKey::from_rsa(Rsa::generate(2048)?)?;
    let mut common_name = String::new();
    for byte in sha1(grant.profile_id.as_bytes()) {
        write!(common_name, "{byte:02X}")?;
    }
    let mut subject = X509NameBuilder::new()?;
    subject.append_entry_by_text("CN", &common_name)?;
    let mut csr = X509ReqBuilder::new()?;
    csr.set_subject_name(&subject.build())?;
    csr.set_pubkey(&key)?;
    csr.sign(&key, MessageDigest::sha1())?;
    let request = Dictionary::from_iter([
        ("realm-user-id", grant.profile_id.as_str().into()),
        ("csr", Value::Data(csr.build().to_der()?)),
        (
            "authentication-data",
            Value::Dictionary(Dictionary::from_iter([(
                "auth-token",
                Value::String(std::mem::take(&mut grant.auth_token)),
            )])),
        ),
    ]);
    let response = apple
        .post(AUTH_CERT)
        .header(
            "user-agent",
            format!("com.apple.invitation-registration {}", device.user_agent),
        )
        .header("x-protocol-version", device.protocol_version.to_string())
        .header("content-type", "application/x-apple-plist")
        .header("content-encoding", "gzip")
        .body(plist_xml_gzip(&request)?)
        .send()
        .await
        .context("Could not reach Apple's IDS certificate service")
        .and_then(checked_response)?;
    let mut reply: CertReply = plist::from_bytes(&read_response(response).await?)
        .context("Could not read Apple's IDS certificate response")?;
    ensure!(
        reply.status == 0,
        "Apple declined the IDS certificate request (Apple status {})",
        reply.status
    );
    let certificate = reply
        .cert
        .take()
        .context("Apple omitted the IDS certificate")?;
    let public = X509::from_der(certificate.as_ref())?.public_key()?;
    ensure!(
        key.public_eq(&public),
        "Apple's IDS certificate did not match its requested key"
    );
    Ok(AccountAuth {
        user_id: std::mem::take(&mut grant.profile_id),
        certificate,
        key,
    })
}

fn checked_response(response: reqwest::Response) -> Result<reqwest::Response> {
    ensure!(
        response.status().is_success(),
        "Apple refused the iMessage authorization request (HTTP {})",
        response.status().as_u16()
    );
    Ok(response)
}

#[derive(Deserialize)]
struct SetupReply {
    status: i64,
    #[serde(default)]
    delegates: Delegates,
}

#[derive(Deserialize, Default)]
struct Delegates {
    #[serde(rename = "com.apple.private.ids")]
    ids: Option<Delegate>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
struct Delegate {
    status: i64,
    service_data: Option<Grant>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
struct Grant {
    profile_id: String,
    auth_token: String,
}

impl Drop for Grant {
    fn drop(&mut self) {
        self.auth_token.zeroize();
    }
}

#[derive(Deserialize)]
struct CertReply {
    status: i64,
    cert: Option<Data>,
}
