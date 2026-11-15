use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use plist::{Dictionary, Value};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use tokio::{io::AsyncReadExt, process::Command, time::timeout};
use zeroize::Zeroize;

const MAX_HEADERS: u64 = 16 * 1024;
const REQUIRED: &[&str] = &[
    "X-Apple-I-MD",
    "X-Apple-I-MD-M",
    "X-Apple-I-MD-RINFO",
    "X-Apple-I-MD-LU",
    "X-Mme-Device-Id",
    "X-Apple-I-Client-Time",
    "X-Mme-Client-Info",
    "User-Agent",
];
const OPTIONAL: &[&str] = &[
    "X-Apple-I-SRL-NO",
    "X-Apple-I-TimeZone",
    "X-Apple-Locale",
    "X-Apple-I-ROM",
    "X-Apple-I-MLB",
];

pub(super) struct Anisette {
    helper: PathBuf,
    identity: Option<[String; 4]>,
}

pub(in crate::apple) struct DeviceHeaders(HashMap<&'static str, String>);

impl Anisette {
    pub(super) fn new(helper: &Path) -> Result<Self> {
        let helper = helper
            .canonicalize()
            .context("Could not find the Anisette helper")?;
        ensure!(
            helper.is_file(),
            "The Anisette helper must be an executable file"
        );
        Ok(Self {
            helper,
            identity: None,
        })
    }

    pub(super) async fn headers(&mut self) -> Result<DeviceHeaders> {
        let bytes = timeout(Duration::from_secs(20), self.run_helper())
            .await
            .context("The Anisette helper timed out")??;
        let headers = DeviceHeaders::parse(&bytes)?;
        let identity = [
            "X-Apple-I-MD-M",
            "X-Apple-I-MD-LU",
            "X-Mme-Device-Id",
            "X-Mme-Client-Info",
        ]
        .map(|field| headers.0[field].clone());
        if let Some(previous) = &self.identity {
            ensure!(
                previous == &identity,
                "The Anisette helper changed device identity during sign-in"
            );
        } else {
            self.identity = Some(identity);
        }
        Ok(headers)
    }

    async fn run_helper(&self) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        let mut child = Command::new(&self.helper)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .context("Could not run the Anisette helper")?;
        let mut bytes = zeroize::Zeroizing::new(Vec::new());
        child
            .stdout
            .take()
            .context("Anisette helper stdout is unavailable")?
            .take(MAX_HEADERS + 1)
            .read_to_end(&mut bytes)
            .await?;
        ensure!(
            bytes.len() as u64 <= MAX_HEADERS,
            "The Anisette helper response is too large"
        );
        ensure!(
            child.wait().await?.success(),
            "The Anisette helper exited unsuccessfully"
        );
        Ok(bytes)
    }
}

impl DeviceHeaders {
    fn parse(bytes: &[u8]) -> Result<Self> {
        let mut supplied: HashMap<String, String> =
            serde_json::from_slice(bytes).map_err(|_| {
                anyhow::anyhow!("The Anisette helper must emit a JSON object of string headers")
            })?;
        let mut accepted = Self(HashMap::new());
        for (name, mut value) in supplied.drain() {
            if let Some(&canonical) = REQUIRED
                .iter()
                .chain(OPTIONAL)
                .find(|field| field.eq_ignore_ascii_case(&name))
            {
                ensure!(
                    !value.is_empty()
                        && value.len() <= 4096
                        && HeaderValue::from_str(&value).is_ok(),
                    "Invalid {canonical} header from the Anisette helper"
                );
                ensure!(
                    !accepted.0.contains_key(canonical),
                    "Duplicate {canonical} header from the Anisette helper"
                );
                accepted.0.insert(canonical, value);
            } else {
                value.zeroize();
            }
        }
        for field in REQUIRED {
            ensure!(
                accepted.0.contains_key(field),
                "The Anisette helper omitted {field}"
            );
        }
        Ok(accepted)
    }

    pub(in crate::apple) fn headers(&self) -> HeaderMap {
        self.0
            .iter()
            .map(|(key, value)| {
                let mut header =
                    HeaderValue::from_str(value).expect("Anisette headers were validated");
                header.set_sensitive(true);
                (
                    HeaderName::from_bytes(key.as_bytes()).expect("Fixed Anisette header name"),
                    header,
                )
            })
            .collect()
    }

    fn plist_headers(&self) -> Dictionary {
        self.0
            .iter()
            .filter(|(key, _)| !matches!(**key, "User-Agent" | "X-Mme-Client-Info"))
            .map(|(key, value)| (*key, Value::String(value.clone())))
            .collect()
    }

    pub(super) fn gsa_headers(&self) -> HeaderMap {
        let mut headers = self.headers();
        for (key, value) in [
            ("x-apple-ak-context-type", "imessage"),
            ("x-apple-client-app-name", "Messages"),
            ("x-apple-i-client-bundle-id", "com.apple.MobileSMS"),
            ("accept-language", "en-US,en;q=0.9"),
        ] {
            headers.insert(key, HeaderValue::from_static(value));
        }
        headers
    }

    pub(super) fn client_data(&self, request_id: &str, push_token: &[u8; 32]) -> Dictionary {
        let mut data = self.plist_headers();
        data.extend(
            [
                ("X-Apple-I-Device-Configuration-Mode", "0".into()),
                ("X-Apple-I-Request-UUID", request_id.into()),
                ("X-Apple-Requested-Partition", "0".into()),
                (
                    "X-Apple-Security-Upgrade-Context",
                    "com.apple.authkit.generic".into(),
                ),
                ("capp", "Messages".into()),
                ("cbid", "com.apple.MobileSMS".into()),
                ("loc", "en_US".into()),
                ("svct", "imessage".into()),
                ("ptkn", STANDARD.encode(push_token).into()),
                ("X-Apple-Offer-Security-Upgrade", Value::Boolean(true)),
                ("bootstrap", Value::Boolean(true)),
                ("ckgen", Value::Boolean(true)),
                ("fcd", Value::Boolean(true)),
                ("icscrec", Value::Boolean(true)),
                ("prkgen", Value::Boolean(true)),
                ("pbe", Value::Boolean(false)),
                ("at", 0.into()),
            ]
            .into_iter()
            .map(|(key, value)| (key.into(), value)),
        );
        data
    }

    pub(super) fn sms_headers(&self) -> HeaderMap {
        let mut headers = self.gsa_headers();
        for (key, value) in [
            ("x-apple-requested-partition", "0"),
            ("x-apple-i-deviceusermode", "0"),
            ("x-apple-i-cdp-circle-status", "false"),
            (
                "x-apple-security-upgrade-context",
                "com.apple.authkit.generic",
            ),
        ] {
            headers.insert(key, HeaderValue::from_static(value));
        }
        headers
    }
}

impl Drop for DeviceHeaders {
    fn drop(&mut self) {
        for value in self.0.values_mut() {
            value.zeroize();
        }
    }
}
