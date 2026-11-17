mod aps;
mod crypto;
mod gsa;
mod http;
mod ids_auth;
mod madrid;
mod provider_command;
mod provisioning;
mod registration;
pub use gsa::{SmsPrompts, TrustedPhone, login_device_sms};
pub use provisioning::{AutomaticSetup, DeviceConnection, default_device_helper};
pub use registration::register_device;

use anyhow::{Context, Result, ensure};
pub(crate) use madrid::Madrid;
use openssl::{
    hash::MessageDigest,
    pkey::{Id, PKey, PKeyRef, Private},
    rand::rand_bytes,
    rsa::Padding,
    sha::sha256,
    sign::Signer,
    x509::X509,
};
use plist::Data;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{address, now_ms};

pub struct Identity {
    handle: String,
    token: [u8; 32],
    push_cert: Vec<u8>,
    push_key: PKey<Private>,
    ids_cert: Vec<u8>,
    ids_key: PKey<Private>,
    message_keys: crypto::KeyPair<Private>,
    protocol_version: u32,
    user_agent: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct Session {
    version: u32,
    handle: String,
    push_token: Data,
    push_certificate: Data,
    push_private_key: Data,
    ids_certificate: Data,
    ids_private_key: Data,
    signing_private_key: Data,
    encryption_private_key: Data,
    protocol_version: u32,
    user_agent: String,
}

impl Drop for Session {
    fn drop(&mut self) {
        // plist::Data has no mutable accessor, so take ownership before clearing the bytes.
        use zeroize::Zeroize;
        for field in [
            &mut self.push_token,
            &mut self.push_private_key,
            &mut self.ids_private_key,
            &mut self.signing_private_key,
            &mut self.encryption_private_key,
        ] {
            let mut bytes: Vec<u8> = std::mem::replace(field, Data::new(Vec::new())).into();
            bytes.zeroize();
        }
    }
}

impl Identity {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let session: Session =
            plist::from_bytes(bytes).context("Could not decode version 1 Apple session plist")?;
        ensure!(session.version == 1, "Unsupported Apple session version");
        ensure!(
            session.protocol_version > 0
                && session.user_agent.len() <= 256
                && !session.user_agent.is_empty()
                && session
                    .user_agent
                    .bytes()
                    .all(|byte| byte == b' ' || byte.is_ascii_graphic()),
            "Invalid Apple device protocol version or user agent"
        );
        let token = session
            .push_token
            .as_ref()
            .try_into()
            .context("Expected a 32-byte APNs device token")?;
        let message_keys = crypto::KeyPair::private(
            session.signing_private_key.as_ref(),
            session.encryption_private_key.as_ref(),
        )
        .context("Invalid legacy iMessage encryption or signing private key")?;
        Ok(Self {
            handle: address(&session.handle)?,
            token,
            push_cert: session.push_certificate.as_ref().to_vec(),
            push_key: certified_rsa(&session.push_certificate, &session.push_private_key)
                .context("Invalid APNs certificate or private key")?,
            ids_cert: session.ids_certificate.as_ref().to_vec(),
            ids_key: certified_rsa(&session.ids_certificate, &session.ids_private_key)
                .context("Invalid IDS certificate or private key")?,
            message_keys,
            protocol_version: session.protocol_version,
            user_agent: session.user_agent.clone(),
        })
    }

    pub(crate) fn profile_id(&self) -> String {
        let mut identity = Zeroizing::new(self.token.to_vec());
        identity.extend_from_slice(self.handle.as_bytes());
        format!(
            "apple-{}",
            sha256(&identity)[..16]
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        )
    }
}

fn certified_rsa(certificate: &Data, key: &Data) -> Result<PKey<Private>> {
    let key = PKey::private_key_from_der(key.as_ref())?;
    ensure!(
        key.id() == Id::RSA,
        "Expected an RSA certificate private key"
    );
    let public = X509::from_der(certificate.as_ref())?.public_key()?;
    ensure!(
        key.public_eq(&public),
        "Certificate does not match its private key"
    );
    Ok(key)
}

fn nonce(kind: u8) -> Result<[u8; 17]> {
    let mut nonce = [0; 17];
    nonce[0] = kind;
    nonce[1..9].copy_from_slice(&((now_ms() as u64 / 1000) * 1000).to_be_bytes());
    rand_bytes(&mut nonce[9..])?;
    Ok(nonce)
}

fn rsa_signature(key: &PKeyRef<Private>, data: &[u8]) -> Result<Vec<u8>> {
    let mut signer = Signer::new(MessageDigest::sha1(), key)?;
    signer.set_rsa_padding(Padding::PKCS1)?;
    let mut signature = vec![1, 1];
    signature.extend(signer.sign_oneshot_to_vec(data)?);
    Ok(signature)
}
