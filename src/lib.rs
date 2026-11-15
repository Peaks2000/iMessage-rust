pub mod api;
pub mod apple;
pub mod engine;
mod history;
pub mod storage;

use serde::{Deserialize, Serialize};

pub const TEXT_LIMIT: usize = 4096;
pub const PAGE_SIZE: u32 = 75;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Conversation {
    pub address: String,
    pub preview: String,
    pub updated_ms: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Message {
    pub id: String,
    pub address: String,
    pub body: String,
    pub outgoing: bool,
    pub timestamp_ms: i64,
    pub status: Delivery,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Delivery {
    Received,
    Pending,
    Accepted,
    Failed,
    Unknown,
    Demo,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Status {
    pub demo: bool,
    pub connected: bool,
    pub detail: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SendText {
    pub id: uuid::Uuid,
    pub address: String,
    pub body: String,
}

pub fn address(input: &str) -> anyhow::Result<String> {
    let input = input.trim();
    let raw = input
        .strip_prefix("tel:")
        .or_else(|| input.strip_prefix("mailto:"))
        .unwrap_or(input);
    if let Some(number) = raw.strip_prefix('+') {
        let digits = number
            .chars()
            .filter(|c| !matches!(c, ' ' | '-' | '(' | ')'))
            .collect::<String>();
        anyhow::ensure!(
            (7..=15).contains(&digits.len())
                && digits.as_bytes()[0] != b'0'
                && digits.bytes().all(|c| c.is_ascii_digit()),
            "Enter an international phone number"
        );
        return Ok(format!("tel:+{digits}"));
    }
    let (local, host) = raw.split_once('@').ok_or_else(|| {
        anyhow::anyhow!("Enter an email address or an international phone number")
    })?;
    anyhow::ensure!(
        !local.is_empty()
            && !host.is_empty()
            && host.contains('.')
            && !host.contains('@')
            && raw.len() <= 254
            && raw.bytes().all(|c| c.is_ascii_graphic()),
        "Enter a valid email address"
    );
    Ok(format!("mailto:{}", raw.to_ascii_lowercase()))
}

pub fn display_address(address: &str) -> &str {
    address.split_once(':').map_or(address, |(_, name)| name)
}

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

pub fn install_tls_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
