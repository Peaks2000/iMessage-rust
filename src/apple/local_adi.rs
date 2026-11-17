use std::{
    ffi::c_void,
    path::PathBuf,
    ptr::{self, NonNull},
};

use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{SecondsFormat, Utc};
use libloading::Library;
use openssl::rand::rand_bytes;
use plist::{Data, Dictionary, Value};
use reqwest::{Client, RequestBuilder, Url};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{
    http::{apple_client, plist_xml, read_response},
    provisioning::Computer,
};
use crate::storage;

const LOOKUP: &str = "https://gsa.apple.com/grandslam/GsService2/lookup";
const BUFFER: usize = 4096;
type Begin = unsafe extern "C" fn(
    *const u8,
    usize,
    *const u8,
    u32,
    *mut *mut c_void,
    *mut u8,
    *mut usize,
) -> i32;
type Finish = unsafe extern "C" fn(
    *mut c_void,
    *const u8,
    usize,
    *const u8,
    *const u8,
    *mut u8,
    *mut usize,
) -> i32;
type Free = unsafe extern "C" fn(*mut c_void);
type Generate = unsafe extern "C" fn(*const u8, usize, *const u8, i64, *mut u8, *mut u8) -> i32;

pub(super) struct LocalAdi {
    api: Api,
    client: Client,
    keyring: String,
    client_info: String,
    device_id: String,
    serial: String,
    state: Option<State>,
}

struct Api {
    begin: Begin,
    finish: Finish,
    free: Free,
    generate: Generate,
    _library: Library,
}

struct Provisioning<'a> {
    handle: NonNull<c_void>,
    api: &'a Api,
}

impl Drop for Provisioning<'_> {
    fn drop(&mut self) {
        // The handle came from this library's begin function and is owned by this value.
        unsafe { (self.api.free)(self.handle.as_ptr()) };
    }
}

#[derive(Serialize, Deserialize)]
struct State {
    hardware: [u8; 20],
    profile: Data,
    routing: String,
}

impl Drop for State {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.hardware.zeroize();
        let mut data = Vec::<u8>::from(std::mem::replace(&mut self.profile, Data::new(Vec::new())));
        data.zeroize();
    }
}

impl LocalAdi {
    pub(super) fn new(keyring: String, computer: &Computer) -> Result<Self> {
        let state = storage::read_activation(&keyring)?
            .map(|bytes| {
                plist::from_bytes(&bytes)
                    .context("Could not read the saved local Apple device identity")
            })
            .transpose()?;
        Ok(Self {
            api: Api::load()?,
            client: apple_client()?,
            keyring,
            client_info: format!(
                "<{}> <macOS;{};{}> <com.apple.AuthKit/1 (com.apple.akd/1.0)>",
                computer.model, computer.os_version, computer.build_version
            ),
            device_id: computer.uuid.to_string().to_uppercase(),
            serial: computer.serial.clone(),
            state,
        })
    }

    pub(in crate::apple) async fn headers(&mut self) -> Result<Zeroizing<Vec<u8>>> {
        if self.state.is_none() {
            let state = self.provision().await?;
            let mut encoded = Zeroizing::new(Vec::new());
            plist::to_writer_binary(&mut *encoded, &state)?;
            storage::save_activation(&self.keyring, &encoded)?;
            self.state = Some(state);
        }
        let state = self
            .state
            .as_ref()
            .context("Could not load the local device identity")?;
        let mut machine = Zeroizing::new([0; 60]);
        let mut otp = Zeroizing::new([0; 28]);
        otp[..8].copy_from_slice(&[0, 0, 0, 5, 0, 0, 0, 16]);
        otp[27] = 1;
        // The build script fixes the ABI. The state and all output buffers stay live through the call.
        let status = unsafe {
            (self.api.generate)(
                state.profile.as_ref().as_ptr(),
                state.profile.as_ref().len(),
                state.hardware.as_ptr(),
                Utc::now().timestamp(),
                machine.as_mut_ptr(),
                otp[8..24].as_mut_ptr(),
            )
        };
        ensure!(
            status == 0,
            "Could not generate local Apple device authentication headers"
        );
        let document = [
            ("X-Apple-I-MD", STANDARD.encode(&otp[..])),
            ("X-Apple-I-MD-M", STANDARD.encode(&machine[..])),
            ("X-Apple-I-MD-RINFO", state.routing.clone()),
            (
                "X-Apple-I-MD-LU",
                STANDARD.encode(self.device_id.as_bytes()),
            ),
            ("X-Mme-Device-Id", self.device_id.clone()),
            ("X-Apple-I-Client-Time", client_time()),
            ("X-Mme-Client-Info", self.client_info.clone()),
            ("X-Apple-I-SRL-NO", self.serial.clone()),
            ("X-Apple-I-TimeZone", "UTC".to_owned()),
            ("X-Apple-Locale", "en_US".to_owned()),
            ("User-Agent", "akd/1.0".to_owned()),
        ];
        let mut bytes = Zeroizing::new(Vec::new());
        serde_json::to_writer(
            &mut *bytes,
            &document
                .into_iter()
                .collect::<std::collections::BTreeMap<_, _>>(),
        )?;
        Ok(bytes)
    }

    async fn provision(&self) -> Result<State> {
        let urls = self
            .request(self.client.get(LOOKUP))
            .await
            .context("Could not look up Apple's Anisette provisioning endpoints")?;
        let urls = urls
            .get("urls")
            .and_then(Value::as_dictionary)
            .context("Apple omitted the device provisioning endpoints")?;
        let start = endpoint(urls, "midStartProvisioning")?;
        let end = endpoint(urls, "midFinishProvisioning")?;
        let started = self
            .request(self.client.post(start).body(body(Dictionary::new())?))
            .await
            .context("Could not start local Anisette provisioning")?;
        let challenge = binary(
            response(&started).context("Could not start local Anisette provisioning")?,
            "spim",
        )?;
        let mut hardware = Zeroizing::new([0; 20]);
        rand_bytes(hardware.as_mut())?;
        let mut handle = ptr::null_mut();
        let mut request = Zeroizing::new([0; BUFFER]);
        let mut written = 0;
        // All pointers borrow validated slices or fixed-size storage for this synchronous call.
        let result = unsafe {
            (self.api.begin)(
                challenge.as_ptr(),
                challenge.len(),
                hardware.as_ptr(),
                Utc::now().timestamp().try_into()?,
                &mut handle,
                request.as_mut_ptr(),
                &mut written,
            )
        };
        let session = NonNull::new(handle).map(|handle| Provisioning {
            handle,
            api: &self.api,
        });
        ensure!(
            result == 0 && (1..=BUFFER).contains(&written),
            "Could not prepare the local device provisioning request"
        );
        let session =
            session.context("The local Anisette library returned no provisioning session")?;
        let request = body(Dictionary::from_iter([(
            "cpim",
            STANDARD.encode(&request[..written]),
        )]))?;
        let finished = self
            .request(self.client.post(end).body(request))
            .await
            .context("Could not finish local Anisette provisioning")?;
        let finished =
            response(&finished).context("Could not finish local Anisette provisioning")?;
        let ptm = binary(finished, "ptm")?;
        let trust = binary(finished, "tk")?;
        let routing = string(finished, "X-Apple-I-MD-RINFO")?;
        ensure!(
            trust.len() == 16 && routing.parse::<u64>().is_ok(),
            "Apple returned invalid device provisioning parameters"
        );
        let mut output = Zeroizing::new([0; BUFFER]);
        // The provisioning session is live and the preceding checks guarantee the trust key size.
        let result = unsafe {
            (self.api.finish)(
                session.handle.as_ptr(),
                ptm.as_ptr(),
                ptm.len(),
                trust.as_ptr(),
                hardware.as_ptr(),
                output.as_mut_ptr(),
                &mut written,
            )
        };
        ensure!(
            result == 0 && (1..=BUFFER).contains(&written),
            "Could not finish local device provisioning"
        );
        Ok(State {
            hardware: *hardware,
            profile: Data::new(output[..written].to_vec()),
            routing: routing.to_owned(),
        })
    }

    async fn request(&self, request: RequestBuilder) -> Result<Dictionary> {
        let mut request = request
            .header("Accept", "*/*")
            .header("Accept-Language", "en-US,en;q=0.9")
            .header("Accept-Encoding", "gzip")
            .header("User-Agent", "akd/1.0")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("X-Mme-Device-Id", &self.device_id)
            .header(
                "X-Apple-I-MD-LU",
                STANDARD.encode(self.device_id.as_bytes()),
            )
            .header("X-Mme-Client-Info", &self.client_info)
            .header("X-Apple-Client-App-Name", "akd")
            .header("X-Apple-I-Client-Time", client_time())
            .header("X-Apple-I-TimeZone", "UTC")
            .header("X-Apple-Locale", "en_US");
        if !self.serial.is_empty() {
            request = request.header("X-Apple-I-SRL-NO", &self.serial);
        }
        let reply = request
            .send()
            .await
            .context("Could not reach Apple's Anisette service")?;
        let status = reply.status();
        let payload = read_response(reply).await?;
        if !status.is_success() {
            if let Ok(reply) = plist::from_bytes::<Dictionary>(&payload) {
                let _ = response(&reply)
                    .with_context(|| format!("Apple returned HTTP {}", status.as_u16()))?;
            }
            anyhow::bail!(
                "Apple rejected local Anisette provisioning (HTTP {})",
                status.as_u16()
            );
        }
        Ok(plist::from_bytes(&payload)?)
    }
}

impl Api {
    fn load() -> Result<Self> {
        let path = if let Some(path) = std::env::var_os("IMESSAGE_ANISETTE_LIBRARY") {
            PathBuf::from(path)
        } else {
            directories::BaseDirs::new()
                .context("Could not find the install directory")?
                .home_dir()
                .join(".local/lib/linux-imessage/libimessage-adi.so")
        };
        let path = path
            .canonicalize()
            .context("The local Anisette library is missing. See docs/apple-session.md")?;
        let metadata = path.metadata()?;
        use std::os::unix::fs::PermissionsExt as _;
        ensure!(
            metadata.is_file() && metadata.permissions().mode() & 0o022 == 0,
            "The local Anisette library must be a regular file writable only by its owner"
        );
        // Only the installed library or an explicitly configured path is accepted. No library search
        // or device package content participates in this decision.
        unsafe {
            let library = Library::new(path)?;
            Ok(Self {
                begin: *library.get(b"imessage_adi_begin\0")?,
                finish: *library.get(b"imessage_adi_finish\0")?,
                free: *library.get(b"imessage_adi_free\0")?,
                generate: *library.get(b"imessage_adi_headers\0")?,
                _library: library,
            })
        }
    }
}

fn client_time() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn string<'a>(dict: &'a Dictionary, key: &str) -> Result<&'a str> {
    dict.get(key)
        .and_then(Value::as_string)
        .context("Missing Apple device provisioning field")
}

fn binary(dict: &Dictionary, key: &str) -> Result<Zeroizing<Vec<u8>>> {
    let value = dict
        .get(key)
        .context("Missing Apple device provisioning data")?;
    let data = if let Some(data) = value.as_data() {
        data.to_vec()
    } else {
        STANDARD.decode(
            value
                .as_string()
                .context("Invalid Apple device provisioning data")?,
        )?
    };
    ensure!(
        (1..=BUFFER).contains(&data.len()),
        "Invalid Apple device provisioning size"
    );
    Ok(Zeroizing::new(data))
}

fn endpoint(urls: &Dictionary, key: &str) -> Result<Url> {
    let url = Url::parse(string(urls, key)?)?;
    ensure!(
        url.scheme() == "https"
            && url.port_or_known_default() == Some(443)
            && url.username().is_empty()
            && url.password().is_none()
            && url.domain() == Some("gsa.apple.com"),
        "Invalid Apple device provisioning endpoint"
    );
    Ok(url)
}

fn body(request: Dictionary) -> Result<Vec<u8>> {
    let document = Dictionary::from_iter([("Header", Dictionary::new()), ("Request", request)]);
    Ok(plist_xml(&document)?.to_vec())
}

fn response(document: &Dictionary) -> Result<&Dictionary> {
    let reply = document
        .get("Response")
        .and_then(Value::as_dictionary)
        .context("Invalid Apple device provisioning response")?;
    let code = reply
        .get("Status")
        .and_then(Value::as_dictionary)
        .and_then(|status| status.get("ec"))
        .and_then(Value::as_signed_integer)
        .context("Apple did not return a device provisioning status")?;
    ensure!(
        code == 0,
        "Apple declined local device provisioning (Apple status {code})"
    );
    Ok(reply)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "This test provisions an anonymous ADI identity with Apple over HTTPS"]
    async fn provision_without_account_or_helper() -> Result<()> {
        crate::install_tls_provider();
        let mut adi = LocalAdi {
            api: Api::load()?,
            client: apple_client()?,
            keyring: String::new(),
            client_info:
                "<MacBookPro11,1> <macOS;10.11.6;15G22010> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
                    .into(),
            device_id: uuid::Uuid::new_v4().to_string().to_uppercase(),
            serial: String::new(),
            state: None,
        };
        adi.state = Some(adi.provision().await?);
        let headers = adi.headers().await?;
        let document: serde_json::Value = serde_json::from_slice(&headers)?;
        assert_eq!(binary_length(&document, "X-Apple-I-MD")?, 28);
        assert_eq!(binary_length(&document, "X-Apple-I-MD-M")?, 60);
        Ok(())
    }

    fn binary_length(document: &serde_json::Value, key: &str) -> Result<usize> {
        Ok(STANDARD
            .decode(document[key].as_str().context("Missing header")?)?
            .len())
    }
}
