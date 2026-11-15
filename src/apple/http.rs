use std::{io::Read, time::Duration};

use anyhow::{Result, ensure};
use flate2::{Compression, read::GzDecoder, write::GzEncoder};
use reqwest::{Certificate, Client, ClientBuilder, Response};
use serde::Serialize;
use zeroize::Zeroizing;

use super::aps::CERTIFICATES;

const MAX_RESPONSE: usize = 256 * 1024;

pub(super) fn client_builder() -> ClientBuilder {
    Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .timeout(Duration::from_secs(20))
}

pub(super) fn apple_client() -> Result<Client> {
    let mut client = client_builder()
        .tls_built_in_root_certs(false)
        .cookie_store(true);
    for certificate in CERTIFICATES {
        client = client.add_root_certificate(Certificate::from_der(certificate)?);
    }
    Ok(client.build()?)
}

pub(super) fn plist_xml(value: &impl Serialize) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    plist::to_writer_xml(&mut *bytes, value)?;
    Ok(bytes)
}

pub(super) fn plist_xml_gzip(value: &impl Serialize) -> Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    plist::to_writer_xml(&mut encoder, value)?;
    Ok(encoder.finish()?)
}

pub(super) async fn read_response(mut response: Response) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            bytes.len() + chunk.len() <= MAX_RESPONSE,
            "Apple response exceeds size limit"
        );
        bytes.extend_from_slice(&chunk);
    }
    if bytes.starts_with(&[0x1f, 0x8b]) {
        let mut decoded = Zeroizing::new(Vec::new());
        GzDecoder::new(bytes.as_slice())
            .take(MAX_RESPONSE as u64 + 1)
            .read_to_end(&mut decoded)?;
        ensure!(
            decoded.len() <= MAX_RESPONSE,
            "Apple response exceeds size limit"
        );
        return Ok(decoded);
    }
    Ok(bytes)
}
