use std::sync::Arc;

use anyhow::{Context, Result, ensure};
use openssl::{
    bn::BigNumContext,
    cipher::Cipher,
    cipher_ctx::{CipherCtx, CipherCtxFlags},
    derive::Deriver,
    ec::{EcGroup, EcKey, EcPoint, PointConversionForm},
    md::Md,
    nid::Nid,
    pkey::{Id, PKey, Private, Public},
    pkey_ctx::PkeyCtx,
    rand::rand_bytes,
};
use plist::{Dictionary, Value};
use tokio::sync::watch;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::IncomingCall;

const POINT_LEN: usize = 65;
const SECRET_LEN: usize = 32;
const WRAPPED_LEN: usize = POINT_LEN + SECRET_LEN + 8;
const WRAP_INFO: &[u8] = b"GFT-MKM-Wrapping";

#[derive(Clone)]
pub(crate) struct PeerPrekey {
    encoded: [u8; POINT_LEN],
    key: PKey<Public>,
}

impl PeerPrekey {
    pub(crate) fn parse(mode: u32, bytes: &[u8]) -> Result<Self> {
        ensure!(mode == 1, "Unsupported FaceTime key wrapping mode");
        let encoded: [u8; POINT_LEN] =
            bytes.try_into().context("Invalid FaceTime prekey length")?;
        ensure!(encoded[0] == 4, "Expected an uncompressed FaceTime prekey");
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let mut context = BigNumContext::new()?;
        let point = EcPoint::from_bytes(&group, &encoded, &mut context)?;
        let key = EcKey::from_public_key(&group, &point)?;
        key.check_key()?;
        Ok(Self {
            encoded,
            key: PKey::from_ec_key(key)?,
        })
    }

    #[cfg(test)]
    pub(crate) fn same_as(&self, other: &Self) -> bool {
        self.encoded == other.encoded
    }
}

pub(crate) struct PeerMediaOffer {
    pub(crate) description: Vec<u8>,
    pub(crate) prekey: Option<PeerPrekey>,
}

struct WrappedCallKey {
    participant: u64,
    generation: u32,
    identifier: [u8; 16],
    short_identifier_len: u8,
    bytes: [u8; WRAPPED_LEN],
    salt: [u8; 16],
}

pub(crate) struct PeerKeyOffer {
    session: Option<WrappedCallKey>,
    media: Option<WrappedCallKey>,
    pub(crate) participant: u64,
}

impl PeerKeyOffer {
    pub(super) fn parse(
        session: Option<&plist::Dictionary>,
        media: Option<&plist::Dictionary>,
    ) -> Option<Self> {
        let session = match session {
            Some(fields) => Some(WrappedCallKey::parse(fields, false)?),
            None => None,
        };
        let media = match media {
            Some(fields) => Some(WrappedCallKey::parse(fields, true)?),
            None => None,
        };
        let participant = session.as_ref().or(media.as_ref())?.participant;
        if media
            .as_ref()
            .is_some_and(|key| key.participant != participant)
        {
            return None;
        }
        Some(Self {
            session,
            media,
            participant,
        })
    }
}

impl WrappedCallKey {
    fn parse(fields: &plist::Dictionary, media: bool) -> Option<Self> {
        let number = |key| fields.get(key)?.as_unsigned_integer();
        let data = |key| fields.get(key)?.as_data();
        let participant = super::participant_id(fields.get("participantID")?)?;
        if number("rtmpwm")? != 1 {
            return None;
        }
        let (generation, identifier, bytes, salt, short_identifier_len) = if media {
            (
                number("mkgc")?,
                data("mki")?,
                data("mkm")?,
                data("mks")?,
                match fields.get("smkil") {
                    Some(value) => value.as_unsigned_integer()?,
                    None => 0,
                },
            )
        } else {
            (number("skgc")?, data("ski")?, data("skm")?, data("sks")?, 0)
        };
        if generation == 0 || short_identifier_len > 16 {
            return None;
        }
        let bytes: [u8; WRAPPED_LEN] = bytes.try_into().ok()?;
        if bytes[0] != 4 {
            return None;
        }
        Some(Self {
            participant,
            generation: generation.try_into().ok()?,
            identifier: identifier.try_into().ok()?,
            short_identifier_len: short_identifier_len.try_into().ok()?,
            bytes,
            salt: salt.try_into().ok()?,
        })
    }
}

#[derive(Clone, Default)]
pub struct CallPeerKeys {
    pub session: Option<Arc<CallKey>>,
    pub media: Option<Arc<CallKey>>,
}

pub struct CallKey {
    pub generation: u32,
    pub identifier: [u8; 16],
    pub short_identifier_len: u8,
    pub key: CallMediaKey,
    pub(super) call_id: Uuid,
    pub(super) participant: u64,
    pub(super) kind: CallKeyKind,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum CallKeyKind {
    LocalSession,
    PeerSession,
    LocalMedia,
    PeerMedia,
}

pub struct CallKeyOffer {
    /// Wrapped material ready to be sent in an authenticated IDS key packet.
    pub payload: Vec<u8>,
    pub session: CallKey,
    pub media: CallKey,
}

pub(crate) struct CallMediaExchange {
    pub(crate) handshake: Arc<CallMediaHandshake>,
    local: PKey<Private>,
    received: watch::Sender<CallPeerKeys>,
}

impl CallMediaExchange {
    pub(crate) fn prepare(
        call: IncomingCall,
        description: &[u8],
        peer: &PeerPrekey,
    ) -> Result<Self> {
        let (local, local_public) = new_key()?;
        let (received, keys) = watch::channel(CallPeerKeys::default());
        let handshake = Arc::new(CallMediaHandshake {
            call,
            description: description.to_vec(),
            peer: peer.clone(),
            local_public,
            peer_keys: keys,
        });
        Ok(Self {
            handshake,
            local,
            received,
        })
    }

    /// Install newer keys only after the engine matches the IDS sender to the call.
    pub(crate) fn receive(&self, offer: PeerKeyOffer) -> Result<()> {
        let current = self.received.borrow().clone();
        let session = self.open_newer(
            offer.session,
            current.session.as_deref(),
            CallKeyKind::PeerSession,
        )?;
        let media = self.open_newer(
            offer.media,
            current.media.as_deref(),
            CallKeyKind::PeerMedia,
        )?;
        if session.is_some() || media.is_some() {
            self.received.send_replace(CallPeerKeys {
                session: session.or(current.session),
                media: media.or(current.media),
            });
        }
        Ok(())
    }

    fn open_newer(
        &self,
        wrapped: Option<WrappedCallKey>,
        current: Option<&CallKey>,
        kind: CallKeyKind,
    ) -> Result<Option<Arc<CallKey>>> {
        let Some(wrapped) = wrapped.filter(|wrapped| {
            current.is_none_or(|current| wrapped.generation > current.generation)
        }) else {
            return Ok(None);
        };
        let key = self.open_inbound_key(&wrapped.bytes, &wrapped.salt)?;
        Ok(Some(Arc::new(CallKey {
            generation: wrapped.generation,
            identifier: wrapped.identifier,
            short_identifier_len: wrapped.short_identifier_len,
            key,
            call_id: self.handshake.call.id,
            participant: wrapped.participant,
            kind,
        })))
    }

    fn open_inbound_key(&self, wrapped: &[u8], salt: &[u8]) -> Result<CallMediaKey> {
        let wrapped: &[u8; WRAPPED_LEN] = wrapped
            .try_into()
            .context("Invalid FaceTime wrapped key length")?;
        let salt = salt
            .try_into()
            .context("Invalid FaceTime media salt length")?;
        let sender = PeerPrekey::parse(1, &wrapped[..POINT_LEN])?;
        let wrapping_key = wrap_key(
            &self.local,
            &sender,
            &self.handshake.local_public,
            &sender.encoded,
        )?;
        let mut output = Zeroizing::new([0; SECRET_LEN + 24]);
        let size = aes_wrap(&wrapping_key, &wrapped[POINT_LEN..], &mut *output, false)
            .context("FaceTime key integrity check failed")?;
        ensure!(size == SECRET_LEN, "Invalid FaceTime unwrapped key length");
        let mut secret = Zeroizing::new([0; SECRET_LEN]);
        secret.copy_from_slice(&output[..size]);
        Ok(CallMediaKey { secret, salt })
    }
}

impl Drop for CallMediaExchange {
    fn drop(&mut self) {
        self.received.send_replace(CallPeerKeys::default());
    }
}

/// Ephemeral key exchange for the signed caller attached to this ringing session.
pub struct CallMediaHandshake {
    call: IncomingCall,
    peer: PeerPrekey,
    description: Vec<u8>,
    local_public: [u8; POINT_LEN],
    peer_keys: watch::Receiver<CallPeerKeys>,
}

impl CallMediaHandshake {
    pub fn call(&self) -> &IncomingCall {
        &self.call
    }

    /// The original participant description from verified IDS signaling.
    pub fn peer_description(&self) -> &[u8] {
        &self.description
    }

    /// Read the caller's media description directly from the authenticated join.
    pub fn decode_peer_description(&self) -> Result<super::CallMediaDescription> {
        super::CallMediaDescription::parse(&self.description, self.call.mode)
    }

    pub fn public_prekey(&self) -> &[u8; POINT_LEN] {
        &self.local_public
    }

    /// Receive the keys recovered from authenticated packets for this call.
    pub fn watch_peer_keys(&self) -> watch::Receiver<CallPeerKeys> {
        self.peer_keys.clone()
    }

    /// Build an initial key offer using the local participant ID assigned by the relay.
    /// Keep the returned offer for retries so the peer can deduplicate its generation.
    pub fn build_key_offer(&self, local_participant: u64) -> Result<CallKeyOffer> {
        ensure!(
            local_participant != 0,
            "Missing local FaceTime participant ID"
        );
        let mut session_id = [0; 16];
        rand_bytes(&mut session_id)?;
        let participant = local_participant.to_be_bytes();
        let mut media_id = [0; 16];
        media_id[1] = 0x10;
        media_id[2..6].copy_from_slice(&participant[..4]);
        media_id[7..11].copy_from_slice(&participant[4..]);
        let (session, wrapped_session) = self.new_outbound_key()?;
        let (media, wrapped_media) = self.new_outbound_key()?;
        let session = CallKey {
            generation: 1,
            identifier: session_id,
            short_identifier_len: 0,
            key: session,
            call_id: self.call.id,
            participant: local_participant,
            kind: CallKeyKind::LocalSession,
        };
        let media = CallKey {
            generation: 1,
            identifier: media_id,
            short_identifier_len: 2,
            key: media,
            call_id: self.call.id,
            participant: local_participant,
            kind: CallKeyKind::LocalMedia,
        };
        let common = || {
            Dictionary::from_iter([
                ("participantID", Value::from(local_participant)),
                ("rtmpwm", Value::from(1)),
            ])
        };
        let mut session_fields = common();
        session_fields.extend(Dictionary::from_iter([
            ("skgc", Value::from(session.generation)),
            ("ski", Value::Data(session.identifier.to_vec())),
            ("skm", Value::Data(wrapped_session.into())),
            ("sks", Value::Data(session.key.salt().to_vec())),
        ]));
        let mut media_fields = common();
        media_fields.extend(Dictionary::from_iter([
            ("mkgc", Value::from(media.generation)),
            ("mki", Value::Data(media.identifier.to_vec())),
            ("mkm", Value::Data(wrapped_media.into())),
            ("mks", Value::Data(media.key.salt().to_vec())),
            ("smkil", Value::from(u32::from(media.short_identifier_len))),
        ]));
        let group = self.call.id.to_string().to_ascii_uppercase();
        let mut payload = Vec::new();
        plist::to_writer_binary(
            &mut payload,
            &Dictionary::from_iter([
                ("s", Value::from(group.as_str())),
                ("fanout-groupID-key", Value::from(group.as_str())),
                ("rtskm", Value::Dictionary(session_fields)),
                ("rtmkm", Value::Dictionary(media_fields)),
            ]),
        )?;
        Ok(CallKeyOffer {
            payload,
            session,
            media,
        })
    }

    fn new_outbound_key(&self) -> Result<(CallMediaKey, [u8; WRAPPED_LEN])> {
        let mut key = CallMediaKey {
            secret: Zeroizing::new([0; SECRET_LEN]),
            salt: [0; 16],
        };
        rand_bytes(key.secret.as_mut())?;
        rand_bytes(&mut key.salt)?;
        let (ephemeral, public) = new_key()?;
        let wrapping_key = wrap_key(&ephemeral, &self.peer, &self.peer.encoded, &public)?;
        let mut wrapped = [0; WRAPPED_LEN];
        wrapped[..POINT_LEN].copy_from_slice(&public);
        let mut output = Zeroizing::new([0; SECRET_LEN + 24]);
        let size = aes_wrap(&wrapping_key, key.secret.as_ref(), &mut *output, true)?;
        ensure!(
            size == WRAPPED_LEN - POINT_LEN,
            "Invalid FaceTime wrapped key length"
        );
        wrapped[POINT_LEN..].copy_from_slice(&output[..size]);
        Ok((key, wrapped))
    }
}

/// Unwrapped key material lives only in memory and clears when dropped.
pub struct CallMediaKey {
    secret: Zeroizing<[u8; SECRET_LEN]>,
    salt: [u8; 16],
}

impl CallMediaKey {
    pub fn salt(&self) -> &[u8; 16] {
        &self.salt
    }

    pub(super) fn derive<const N: usize>(&self, info: &[&[u8]]) -> Result<Zeroizing<[u8; N]>> {
        hkdf(self.secret.as_ref(), &self.salt, info)
    }

    /// Derive the 16-byte SRTP master key and 14-byte master salt for an SSRC.
    pub fn srtp_key(&self, ssrc: u32) -> Result<Zeroizing<[u8; 30]>> {
        self.derive(&[&ssrc.to_le_bytes()])
    }

    #[cfg(test)]
    pub(super) fn fixture(secret: [u8; SECRET_LEN], salt: [u8; 16]) -> Self {
        Self {
            secret: Zeroizing::new(secret),
            salt,
        }
    }
}

fn new_key() -> Result<(PKey<Private>, [u8; POINT_LEN])> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let key = EcKey::generate(&group)?;
    let mut context = BigNumContext::new()?;
    let encoded =
        key.public_key()
            .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut context)?;
    Ok((
        PKey::from_ec_key(key)?,
        encoded
            .try_into()
            .ok()
            .context("Invalid generated FaceTime prekey")?,
    ))
}

fn wrap_key(
    private: &PKey<Private>,
    peer: &PeerPrekey,
    recipient: &[u8; POINT_LEN],
    sender: &[u8; POINT_LEN],
) -> Result<Zeroizing<[u8; SECRET_LEN]>> {
    let mut derive = Deriver::new(private)?;
    derive.set_peer(&peer.key)?;
    let mut shared = Zeroizing::new([0; SECRET_LEN]);
    ensure!(
        derive.derive(shared.as_mut())? == SECRET_LEN,
        "Invalid FaceTime shared key length"
    );
    hkdf(
        shared.as_ref(),
        &[],
        &[WRAP_INFO, &recipient[1..], &sender[1..]],
    )
}

pub(super) fn hkdf<const N: usize>(
    input: &[u8],
    salt: &[u8],
    info: &[&[u8]],
) -> Result<Zeroizing<[u8; N]>> {
    let mut kdf = PkeyCtx::new_id(Id::HKDF)?;
    kdf.derive_init()?;
    kdf.set_hkdf_md(Md::sha256())?;
    kdf.set_hkdf_key(input)?;
    kdf.set_hkdf_salt(salt)?;
    for field in info {
        kdf.add_hkdf_info(field)?;
    }
    let mut output = Zeroizing::new([0; N]);
    ensure!(
        kdf.derive(Some(output.as_mut()))? == N,
        "Invalid FaceTime derived key length"
    );
    Ok(output)
}

fn aes_wrap(
    key: &[u8; SECRET_LEN],
    input: &[u8],
    output: &mut [u8],
    encrypt: bool,
) -> Result<usize> {
    let mut cipher = CipherCtx::new()?;
    cipher.set_flags(CipherCtxFlags::FLAG_WRAP_ALLOW);
    if encrypt {
        cipher.encrypt_init(Some(Cipher::aes_256_wrap()), Some(key), None)?;
    } else {
        cipher.decrypt_init(Some(Cipher::aes_256_wrap()), Some(key), None)?;
    }
    let count = cipher.cipher_update(input, Some(output))?;
    Ok(count + cipher.cipher_final(&mut output[count..])?)
}

#[cfg(test)]
mod tests {
    use openssl::bn::BigNum;

    use super::*;

    fn synthetic_call() -> IncomingCall {
        IncomingCall {
            id: uuid::Uuid::new_v4(),
            caller: "mailto:peer@example.com".into(),
            mode: Some(crate::CallMode::Video),
            received_ms: 0,
            expires_ms: 45_000,
        }
    }

    fn exchange_with_key(
        call: IncomingCall,
        peer: PeerPrekey,
        local: PKey<Private>,
        local_public: [u8; POINT_LEN],
    ) -> CallMediaExchange {
        let (received, peer_keys) = watch::channel(CallPeerKeys::default());
        CallMediaExchange {
            received,
            local,
            handshake: Arc::new(CallMediaHandshake {
                call,
                description: Vec::new(),
                peer,
                local_public,
                peer_keys,
            }),
        }
    }

    #[test]
    fn opens_an_independent_ecdh_and_aes_wrap_vector() -> Result<()> {
        // Synthetic P-256 scalars 11 and 17, generated independently with Python cryptography.
        let receiver = hex::decode(concat!(
            "043ed113b7883b4c590638379db0c21cda16742ed0255048bf433391d374bc21d190",
            "99209accc4c8a224c843afa4f4c68a090d04da5e9889dae2f8eefce82a3740"
        ))?;
        let wrapped = hex::decode(concat!(
            "0447776904c0f1cc3a9c0984b66f75301a5fa68678f0d64af8ba1abce34738a73",
            "eaa005ee6b5b957286231856577648e8381b2804428d5733f32f787ff71f1fcdcd",
            "01b8abae444af640e764cc431d8bdbe2ae675805be7158c216b6b50cc396828481196ab7cdc0d1a"
        ))?;
        let salt: Vec<_> = (240..=255).collect();
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let private = BigNum::from_u32(11)?;
        let mut ctx = BigNumContext::new()?;
        let point = EcPoint::from_bytes(&group, &receiver, &mut ctx)?;
        let key = EcKey::from_private_components(&group, &private, &point)?;
        key.check_key()?;
        let peer = PeerPrekey::parse(1, &wrapped[..POINT_LEN])?;
        let call = exchange_with_key(
            synthetic_call(),
            peer,
            PKey::from_ec_key(key)?,
            receiver.try_into().unwrap(),
        );
        let key = call.open_inbound_key(&wrapped, &salt)?;
        assert_eq!(
            hex::encode(key.srtp_key(0x1234_5678)?.as_ref()),
            "38e8454bd959632d385ae3dcdd600a333c201e13a055540bcfba4ab5d4da"
        );
        assert_eq!(
            hex::encode(key.srtp_key(0x8765_4321)?.as_ref()),
            "816835d973aa41d4505cbb607fdb18372e0d307bc449f1c3f597eda33940"
        );
        assert!(call.open_inbound_key(&wrapped[..64], &salt).is_err());
        assert!(call.open_inbound_key(&wrapped, &salt[..15]).is_err());
        let mut tampered = wrapped;
        tampered[WRAPPED_LEN - 1] ^= 1;
        assert!(call.open_inbound_key(&tampered, &salt).is_err());
        assert!(PeerPrekey::parse(2, call.handshake.public_prekey()).is_err());
        let mut invalid_point = [0; POINT_LEN];
        invalid_point[0] = 4;
        assert!(PeerPrekey::parse(1, &invalid_point).is_err());
        Ok(())
    }

    #[test]
    fn roles_exchange_fresh_keys_and_only_the_intended_recipient_can_open_them() -> Result<()> {
        let (receiver_private, receiver_public) = new_key()?;
        let receiver_prekey = PeerPrekey::parse(1, &receiver_public)?;
        let sender =
            CallMediaExchange::prepare(synthetic_call(), b"signed description", &receiver_prekey)?;
        let receiver = exchange_with_key(
            sender.handshake.call().clone(),
            PeerPrekey::parse(1, sender.handshake.public_prekey())?,
            receiver_private,
            receiver_public,
        );
        let (tx, wrapped) = sender.handshake.new_outbound_key()?;
        let rx = receiver.open_inbound_key(&wrapped, tx.salt())?;
        assert_eq!(sender.handshake.peer_description(), b"signed description");
        assert_eq!(*rx.srtp_key(1)?, *tx.srtp_key(1)?);
        assert_ne!(*rx.srtp_key(1)?, *tx.srtp_key(2)?);
        assert!(sender.open_inbound_key(&wrapped, tx.salt()).is_err());
        assert_ne!(wrapped, sender.handshake.new_outbound_key()?.1);
        Ok(())
    }

    #[test]
    fn key_offers_install_atomically_and_ignore_an_older_generation() -> Result<()> {
        let (private, public) = new_key()?;
        let peer = PeerPrekey::parse(1, &public)?;
        let call = synthetic_call();
        let sender = CallMediaExchange::prepare(call.clone(), b"fixture", &peer)?;
        let receiver = exchange_with_key(
            call,
            PeerPrekey::parse(1, sender.handshake.public_prekey())?,
            private,
            public,
        );
        let key_updates = receiver.handshake.watch_peer_keys();
        let initial = sender.handshake.build_key_offer(7)?;
        let second = sender.handshake.build_key_offer(7)?;
        let parse = |body: &Dictionary| {
            PeerKeyOffer::parse(
                body.get("rtskm").and_then(Value::as_dictionary),
                body.get("rtmkm").and_then(Value::as_dictionary),
            )
            .context("Missing key offer")
        };
        let initial: Dictionary = plist::from_bytes(&initial.payload)?;
        receiver.receive(parse(&initial)?)?;
        let first_media = key_updates.borrow().media.as_ref().unwrap().clone();
        assert_eq!(first_media.generation, 1);
        let mut next: Dictionary = plist::from_bytes(&second.payload)?;
        next.get_mut("rtskm")
            .unwrap()
            .as_dictionary_mut()
            .unwrap()
            .insert("skgc".into(), Value::from(2));
        next.get_mut("rtmkm")
            .unwrap()
            .as_dictionary_mut()
            .unwrap()
            .insert("mkgc".into(), Value::from(2));

        let mut corrupt = next.clone();
        let session = corrupt
            .get_mut("rtskm")
            .unwrap()
            .as_dictionary_mut()
            .unwrap();
        let mut cipher = session["skm"].as_data().unwrap().to_vec();
        cipher[WRAPPED_LEN - 1] ^= 1;
        session.insert("skm".into(), Value::Data(cipher));
        assert!(receiver.receive(parse(&corrupt)?).is_err());
        assert!(Arc::ptr_eq(
            &first_media,
            key_updates.borrow().media.as_ref().unwrap()
        ));

        receiver.receive(parse(&next)?)?;
        receiver.receive(parse(&initial)?)?;
        let latest = key_updates.borrow();
        let media = latest.media.as_ref().unwrap();
        assert_eq!(media.generation, 2);
        assert_eq!(*media.key.srtp_key(28)?, *second.media.key.srtp_key(28)?);
        assert_eq!(latest.session.as_ref().unwrap().generation, 2);
        Ok(())
    }
}
