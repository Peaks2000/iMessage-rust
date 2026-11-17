use anyhow::{Context, Result, ensure};
use plist::{Dictionary, Value};
use reqwest::header::{HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{
    gsa::{Anisette, LoginSession},
    http::{client_builder, plist_xml, read_response},
    local_adi::{LocalAdi, LocalAdiDevice},
};

const LOGIN_DELEGATES: &str = "https://setup.icloud.com/setup/iosbuddy/loginDelegates";
const MOBILEME: &str = "com.apple.mobileme";

#[derive(Deserialize, Serialize)]
pub struct IcloudContactsGrant {
    pub dsid: String,
    pub token: Zeroizing<String>,
    pub url: Option<String>,
    device: Option<LocalAdiDevice>,
}

impl IcloudContactsGrant {
    pub async fn carddav_headers(&self) -> Result<HeaderMap> {
        let Some(device) = &self.device else {
            return Ok(HeaderMap::new());
        };
        let mut anisette = Anisette::from_local(LocalAdi::open(device.clone())?);
        let mut headers = anisette.headers().await?.headers();
        let mut udid = HeaderValue::from_str(&headers["x-mme-device-id"].to_str()?.to_lowercase())?;
        udid.set_sensitive(true);
        headers.insert("x-client-udid", udid);
        headers.insert("x-mme-language", HeaderValue::from_static("en"));
        let profile = headers["x-mme-client-info"].to_str()?;
        headers.insert(
            "x-mme-client-info",
            client_info(
                profile,
                "com.apple.AppleAccount/1.0 (com.apple.Preferences/1112.96)",
            )?,
        );
        Ok(headers)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct DelegateRequest<'a> {
    apple_id: &'a str,
    password: &'a str,
    client_id: String,
    delegates: Dictionary,
}

pub(super) async fn authorize(
    account: &str,
    login: &LoginSession,
    anisette: &mut Anisette,
) -> Result<IcloudContactsGrant> {
    let mut headers = anisette.headers().await?.headers();
    let profile = headers["x-mme-client-info"].to_str()?;
    headers.insert(
        "x-mme-client-info",
        client_info(profile, "com.apple.AOSKit/282 (com.apple.accountsd/113)")?,
    );
    headers.insert(
        "user-agent",
        "com.apple.iCloudHelper/282 CFNetwork/1408.0.4 Darwin/22.5.0".parse()?,
    );
    let request = DelegateRequest {
        apple_id: account,
        password: login.pet.as_str(),
        client_id: headers["x-mme-device-id"].to_str()?.to_owned(),
        delegates: Dictionary::from_iter([(MOBILEME, Dictionary::new())]),
    };
    let payload = plist_xml(&request)?;
    let response = client_builder()
        .build()?
        .post(LOGIN_DELEGATES)
        .headers(headers)
        .header("content-type", "text/x-xml-plist")
        .header("accept", "*/*")
        .header("x-apple-adsid", &login.adsid)
        .basic_auth(account, Some(login.pet.as_str()))
        .body(payload.to_vec())
        .send()
        .await
        .context("Could not reach iCloud account authorization")?;
    ensure!(
        response.status().is_success(),
        "iCloud account authorization returned HTTP {}",
        response.status().as_u16()
    );
    let bytes = read_response(response).await?;
    let reply: Dictionary = plist::from_bytes(&bytes)
        .map_err(|_| anyhow::anyhow!("Could not read the iCloud account authorization reply"))?;
    let mut grant = parse_reply(&reply)?;
    grant.device = anisette.local_device().cloned();
    Ok(grant)
}

fn client_info(profile: &str, app: &str) -> Result<HeaderValue> {
    let platform = profile.split(" <com.apple.").next().unwrap_or(profile);
    Ok(format!("{platform} <{app}>").parse()?)
}

fn parse_reply(reply: &Dictionary) -> Result<IcloudContactsGrant> {
    let delegate = reply
        .get("delegates")
        .and_then(Value::as_dictionary)
        .and_then(|delegates| delegates.get(MOBILEME))
        .and_then(Value::as_dictionary)
        .context("Apple did not return iCloud account authorization")?;
    let status = delegate
        .get("status")
        .or_else(|| reply.get("status"))
        .and_then(Value::as_signed_integer);
    ensure!(
        status == Some(0),
        "Apple declined iCloud account authorization (Apple status {})",
        status.unwrap_or(-1)
    );
    let data = delegate
        .get("service-data")
        .and_then(Value::as_dictionary)
        .context("Apple omitted the iCloud account grant")?;
    let account_info = data.get("appleAccountInfo").and_then(Value::as_dictionary);
    let dsid = reply
        .get("dsid")
        .or_else(|| account_info.and_then(|info| info.get("dsid").or_else(|| info.get("dsPrsID"))))
        .and_then(|value| {
            value
                .as_string()
                .map(str::to_owned)
                .or_else(|| value.as_unsigned_integer().map(|id| id.to_string()))
        })
        .filter(|id| !id.is_empty() && id.len() <= 32 && id.bytes().all(|ch| ch.is_ascii_digit()))
        .context("Apple omitted the iCloud account identifier")?;
    let tokens = data
        .get("tokens")
        .and_then(Value::as_dictionary)
        .context("Apple omitted the iCloud access tokens")?;
    let token = tokens
        .get("mmeAuthToken")
        .and_then(Value::as_string)
        .filter(|token| !token.is_empty() && token.len() <= 16_384)
        .context("Apple omitted the iCloud access token")?;
    let url = data
        .get("config")
        .and_then(Value::as_dictionary)
        .and_then(|config| config.get("com.apple.Dataclass.Contacts"))
        .and_then(Value::as_dictionary)
        .and_then(|contacts| contacts.get("url"))
        .and_then(Value::as_string)
        .map(str::to_owned);
    Ok(IcloudContactsGrant {
        dsid,
        token: Zeroizing::new(token.to_owned()),
        url,
        device: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_contacts_configuration_from_the_mobileme_grant() -> Result<()> {
        let value = serde_json::json!({
            "delegates": {
                "com.apple.mobileme": {
                    "status": 0,
                    "service-data": {
                        "appleAccountInfo": { "dsid": 123456789 },
                        "tokens": { "mmeAuthToken": "test-token" },
                        "config": {
                            "com.apple.Dataclass.Contacts": {
                                "url": "https://p123-contacts.icloud.com"
                            }
                        }
                    }
                }
            }
        });
        let grant = parse_reply(&serde_json::from_value(value)?)?;
        assert_eq!(grant.dsid, "123456789");
        assert_eq!(grant.token.as_str(), "test-token");
        assert_eq!(
            grant.url.as_deref(),
            Some("https://p123-contacts.icloud.com")
        );
        Ok(())
    }
}
