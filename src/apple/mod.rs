mod aps;
mod crypto;
mod facetime;
mod gsa;
mod http;
mod icloud_contacts;
mod ids_auth;
mod local_adi;
mod madrid;
mod message_content;
mod mmcs;
mod mmcs_wire;
mod provider_command;
mod provisioning;
mod registration;
mod ssh_setup;
mod tapback;
pub use gsa::{
    AppleSetupStage, SmsPrompts, TrustedDeviceResponse, TrustedPhone, authorize_icloud_contacts,
    login_device_sms,
};
pub use icloud_contacts::IcloudContactsGrant;
pub use madrid::IdsRegistrationNeedsRenewal;
pub use provisioning::{AutomaticSetup, DeviceConnection, default_device_helper};
pub use registration::register_device;
pub use ssh_setup::{SshPrompt, run_ssh_askpass};

use anyhow::{Context, Result, ensure};
#[cfg(feature = "desktop")]
pub(crate) use facetime::RtpHeader as CallRtpHeader;
#[cfg(test)]
pub(crate) use facetime::decode as decode_call_fixture;
#[cfg(test)]
pub(crate) use facetime::relay::tests::parsed_allocation as call_relay_fixture;
#[cfg(test)]
pub(crate) use facetime::signed_avc_fixture;
#[cfg(feature = "desktop")]
pub(crate) use facetime::{
    AAC_ELD_PT, AAC_ELD_SAMPLE_RATE, AUDIO_RED_PT, CAMERA_HEIGHT, CAMERA_WIDTH, CallDevice,
    HEVC_FEATURE_BITS, HEVC_PT,
};
pub use facetime::{
    CallAvcMaterial, CallKey, CallKeyOffer, CallMediaDescription, CallMediaHandshake, CallMediaKey,
    CallPeerKeys, CallRelayAllocation, CallRelayBinding, CallRelayConnection, CallRelayKeys,
    CallRelayProfile, CallRelayStream, CallRtpDescription, RelayChannel, RelayDatagramChannel,
    RelayStreamDirection,
};
pub(crate) use facetime::{
    CallEndpoint, CallMediaExchange, CallRtpProtection, CallSignal, LocalCallPrekey, OutgoingRelay,
    PeerKeyOffer, PeerMediaOffer, PeerPrekey, RING_TIMEOUT_MS, RelayMediaEvent, RelayPeerUpdate,
    RingingRelay, SignedRelayKeys, SignedRelayPrekey,
};
pub(crate) use madrid::{Incoming, Madrid, MessageDestinations, Notification, OutgoingCallTargets};
pub(crate) use mmcs::{AuthorizedDownload, AuthorizedUpload};
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
    facetime_certificates: std::collections::BTreeMap<String, Vec<u8>>,
    facetime_relay_signing: Option<facetime::RelaySigningKey>,
    facetime_device: Option<IdsDevice>,
    message_keys: crypto::KeyPair<Private>,
    protocol_version: u32,
    user_agent: String,
}

#[derive(Deserialize, Serialize, PartialEq, Eq, Clone)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct IdsDevice {
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
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    facetime_certificates: std::collections::BTreeMap<String, Data>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    facetime_relay_signing_private_key: Option<Data>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    facetime_device: Option<IdsDevice>,
    signing_private_key: Data,
    encryption_private_key: Data,
    protocol_version: u32,
    user_agent: String,
}

impl Drop for Session {
    fn drop(&mut self) {
        // plist::Data has no mutable accessor, so take ownership before clearing the bytes.
        use zeroize::Zeroize;
        if let Some(secret) = self.facetime_relay_signing_private_key.take() {
            Vec::from(secret).zeroize();
        }
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
    pub fn facetime_registered(&self) -> bool {
        self.ids_certificate(facetime::SIGNALING).is_some()
    }

    pub fn facetime_video_registered(&self) -> bool {
        self.facetime_registered() && self.ids_certificate(facetime::VIDEO).is_some()
    }

    pub(crate) fn can_sign_relay_prekey(&self) -> bool {
        self.facetime_relay_signing.is_some()
    }

    pub(crate) fn sign_relay_prekey(
        &self,
        call: uuid::Uuid,
        prekey: &[u8; 65],
    ) -> Result<Option<SignedRelayPrekey>> {
        self.facetime_relay_signing
            .as_ref()
            .map(|key| key.sign_prekey(call, prekey))
            .transpose()
    }

    pub(crate) fn sign_relay_keys(
        &self,
        offer: &CallKeyOffer,
        endpoint: CallEndpoint,
    ) -> Result<Option<SignedRelayKeys>> {
        self.facetime_relay_signing
            .as_ref()
            .map(|key| {
                let receiver = endpoint
                    .participant()
                    .context("Missing FaceTime receiving participant")?;
                key.sign_keys(offer, receiver)
            })
            .transpose()
    }

    #[cfg(feature = "desktop")]
    pub(crate) fn call_device(&self) -> Option<CallDevice> {
        self.facetime_registered()
            .then(|| CallDevice::from_ids_user_agent(self.ids_device(facetime::SIGNALING).1))
            .flatten()
    }

    pub fn handle(&self) -> &str {
        &self.handle
    }

    pub(crate) fn same_messaging_identity(&self, other: &Self) -> Result<bool> {
        Ok(self.handle == other.handle
            && self.token == other.token
            && self.push_cert == other.push_cert
            && self.ids_key.public_eq(&other.ids_key)
            && self.message_keys.public_der()? == other.message_keys.public_der()?)
    }

    pub(crate) fn same_messaging_registration(&self, other: &Self) -> Result<bool> {
        Ok(self.same_messaging_identity(other)?
            && self.ids_cert == other.ids_cert
            && self.user_agent == other.user_agent
            && self.protocol_version == other.protocol_version)
    }

    pub(crate) fn same_facetime_registration(&self, other: &Self) -> bool {
        self.facetime_certificates == other.facetime_certificates
            && self.facetime_device == other.facetime_device
            && match (&self.facetime_relay_signing, &other.facetime_relay_signing) {
                (Some(first), Some(second)) => first.same_key(second),
                (None, None) => true,
                _ => false,
            }
    }

    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let session: Session =
            plist::from_bytes(bytes).context("Could not decode version 1 Apple session plist")?;
        ensure!(session.version == 1, "Unsupported Apple session version");
        ensure!(
            session.protocol_version > 0 && valid_ids_user_agent(&session.user_agent),
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
        let ids_key = certified_rsa(&session.ids_certificate, &session.ids_private_key)
            .context("Invalid IDS certificate or private key")?;
        let mut facetime_certificates = std::collections::BTreeMap::new();
        for (service, certificate) in &session.facetime_certificates {
            ensure!(
                matches!(
                    service.as_str(),
                    facetime::SIGNALING | facetime::VIDEO_SERVICE
                ),
                "Unknown calling service"
            );
            let public = X509::from_der(certificate.as_ref())?.public_key()?;
            ensure!(
                ids_key.public_eq(&public),
                "The FaceTime certificate does not match the IDS signing key"
            );
            facetime_certificates.insert(service.clone(), certificate.as_ref().to_vec());
        }
        let facetime_relay_signing = session
            .facetime_relay_signing_private_key
            .as_ref()
            .map(|key| facetime::RelaySigningKey::from_der(key.as_ref()))
            .transpose()
            .context("Invalid FaceTime relay device key")?;
        ensure!(
            facetime_relay_signing.is_none()
                || facetime_certificates.contains_key(facetime::SIGNALING),
            "FaceTime relay key requires a calling registration"
        );
        let facetime_device = session.facetime_device.as_ref();
        ensure!(
            facetime_device.is_none_or(|device| {
                facetime_certificates.contains_key(facetime::SIGNALING)
                    && device.protocol_version > 0
                    && valid_ids_user_agent(&device.user_agent)
            }),
            "Invalid FaceTime device metadata"
        );
        Ok(Self {
            handle: address(&session.handle)?,
            token,
            push_cert: session.push_certificate.as_ref().to_vec(),
            push_key: certified_rsa(&session.push_certificate, &session.push_private_key)
                .context("Invalid APNs certificate or private key")?,
            ids_cert: session.ids_certificate.as_ref().to_vec(),
            ids_key,
            facetime_certificates,
            facetime_relay_signing,
            facetime_device: facetime_device.cloned(),
            message_keys,
            protocol_version: session.protocol_version,
            user_agent: session.user_agent.clone(),
        })
    }

    fn ids_device(&self, topic: &str) -> (u32, &str) {
        if matches!(
            topic,
            facetime::SIGNALING | facetime::VIDEO | facetime::relay::RELAY_TOPIC
        ) && let Some(device) = &self.facetime_device
        {
            (device.protocol_version, &device.user_agent)
        } else {
            (self.protocol_version, &self.user_agent)
        }
    }

    fn ids_certificate(&self, topic: &str) -> Option<&[u8]> {
        match topic {
            aps::TOPIC => Some(&self.ids_cert),
            facetime::SIGNALING => self
                .facetime_certificates
                .get(facetime::SIGNALING)
                .map(Vec::as_slice),
            facetime::VIDEO => self
                .facetime_certificates
                .get(facetime::VIDEO_SERVICE)
                .map(Vec::as_slice),
            _ => None,
        }
    }

    pub fn profile_id(&self) -> String {
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

fn valid_ids_user_agent(agent: &str) -> bool {
    (1..=256).contains(&agent.len())
        && agent
            .bytes()
            .all(|byte| byte == b' ' || byte.is_ascii_graphic())
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
