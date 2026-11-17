use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use anyhow::{Result, ensure};
use plist::{Dictionary, Value};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use zeroize::Zeroize;

use super::super::{
    local_adi::{LocalAdi, LocalAdiDevice},
    provider_command,
    provisioning::DeviceProvider,
};

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

pub(in crate::apple) struct Anisette {
    source: Source,
    identity: Option<[String; 4]>,
}

enum Source {
    Helper(PathBuf),
    Device(DeviceProvider),
    OnDevice(Box<LocalAdi>),
}

pub(in crate::apple) struct DeviceHeaders(HashMap<&'static str, String>);

impl Anisette {
    pub(super) fn new(helper: &Path) -> Result<Self> {
        Ok(Self {
            source: Source::Helper(provider_command::executable(helper)?),
            identity: None,
        })
    }

    pub(in crate::apple) fn from_provider(provider: DeviceProvider) -> Self {
        Self {
            source: Source::Device(provider),
            identity: None,
        }
    }

    pub(in crate::apple) fn from_local(adi: LocalAdi) -> Self {
        Self {
            source: Source::OnDevice(Box::new(adi)),
            identity: None,
        }
    }

    pub(in crate::apple) fn local_device(&self) -> Option<&LocalAdiDevice> {
        match &self.source {
            Source::OnDevice(adi) => Some(adi.device()),
            _ => None,
        }
    }

    pub(in crate::apple) async fn headers(&mut self) -> Result<DeviceHeaders> {
        let bytes = match &mut self.source {
            Source::Helper(helper) => {
                provider_command::run(helper, &[], "Anisette", &[], MAX_HEADERS).await?
            }
            Source::Device(provider) => provider.call("anisette", &[], MAX_HEADERS).await?,
            Source::OnDevice(adi) => adi.headers().await?,
        };
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

    pub(super) fn client_data(&self, request_id: &str, push_token: &str) -> Dictionary {
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
                ("ptkn", push_token.into()),
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
