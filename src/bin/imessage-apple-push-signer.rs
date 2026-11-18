// SPDX-License-Identifier: LGPL-2.1-or-later

use std::io::{self, Read};

use anyhow::{Context, Result, ensure};
use aps::ActivationSigner;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Serialize;
use zeroize::Zeroizing;

const MAX_REQUEST: u64 = 64 * 1024;

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct Reply {
    certificate_chain: String,
    signature: String,
}

fn main() -> Result<()> {
    let mut xml = Zeroizing::new(Vec::new());
    io::stdin()
        .lock()
        .take(MAX_REQUEST + 1)
        .read_to_end(&mut xml)?;
    ensure!(
        (1..=MAX_REQUEST).contains(&(xml.len() as u64)),
        "Invalid push activation request size"
    );
    let request: plist::Dictionary =
        plist::from_bytes(&xml).context("Invalid push activation request")?;
    ensure!(
        request.get("DeviceClass").and_then(plist::Value::as_string) == Some("MacOS")
            && request
                .get("ActivationState")
                .and_then(plist::Value::as_string)
                == Some("Unactivated")
            && request
                .get("DeviceCertRequest")
                .and_then(plist::Value::as_data)
                .is_some(),
        "Expected a macOS push activation request"
    );

    let signed = aps::MacOsActivationSigner::new()
        .sign(&xml)
        .context("Could not sign macOS push activation")?;
    serde_json::to_writer(
        io::stdout().lock(),
        &Reply {
            certificate_chain: STANDARD.encode(signed.certificate_chain),
            signature: STANDARD.encode(signed.signature),
        },
    )?;
    Ok(())
}
