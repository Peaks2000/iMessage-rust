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

    pub(crate) fn same_as(&self, other: &Self) -> bool {
        self.encoded == other.encoded
    }
}

pub(crate) struct PeerMediaOffer {
    pub(crate) description: Vec<u8>,
    pub(crate) prekey: Option<PeerPrekey>,
}

/// Ephemeral key exchange for the signed caller attached to this ringing session.
pub struct CallMediaHandshake {
    call: IncomingCall,
    peer: PeerPrekey,
    description: Vec<u8>,
    local: PKey<Private>,
    local_public: [u8; POINT_LEN],
}

impl CallMediaHandshake {
    pub(crate) fn prepare(
        call: IncomingCall,
        description: &[u8],
        peer: &PeerPrekey,
    ) -> Result<Self> {
        let (local, local_public) = new_key()?;
        Ok(Self {
            call,
            peer: peer.clone(),
            description: description.to_vec(),
            local,
            local_public,
        })
    }

    pub fn call(&self) -> &IncomingCall {
        &self.call
    }

    /// Signed participant description. The media engine still needs to decode its contents.
    pub fn peer_description(&self) -> &[u8] {
        &self.description
    }

    pub fn public_prekey(&self) -> &[u8; POINT_LEN] {
        &self.local_public
    }

    /// Generate a fresh local session or media master key and wrap it for the caller.
    pub fn new_outbound_key(&self) -> Result<(CallMediaKey, [u8; WRAPPED_LEN])> {
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

    /// The material must already be authenticated as coming from this call's peer by IDS.
    pub fn open_inbound_key(&self, wrapped: &[u8], salt: &[u8]) -> Result<CallMediaKey> {
        let wrapped: &[u8; WRAPPED_LEN] = wrapped
            .try_into()
            .context("Invalid FaceTime wrapped key length")?;
        let salt = salt
            .try_into()
            .context("Invalid FaceTime media salt length")?;
        let sender = PeerPrekey::parse(1, &wrapped[..POINT_LEN])?;
        let wrapping_key = wrap_key(&self.local, &sender, &self.local_public, &sender.encoded)?;
        let mut output = Zeroizing::new([0; SECRET_LEN + 24]);
        let size = aes_wrap(&wrapping_key, &wrapped[POINT_LEN..], &mut *output, false)
            .context("FaceTime key integrity check failed")?;
        ensure!(size == SECRET_LEN, "Invalid FaceTime unwrapped key length");
        let mut secret = Zeroizing::new([0; SECRET_LEN]);
        secret.copy_from_slice(&output[..size]);
        Ok(CallMediaKey { secret, salt })
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

    /// Derive the 16-byte SRTP master key and 14-byte master salt for an SSRC.
    pub fn srtp_key(&self, ssrc: u32) -> Result<Zeroizing<[u8; 30]>> {
        hkdf(self.secret.as_ref(), &self.salt, &[&ssrc.to_le_bytes()])
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

fn hkdf<const N: usize>(input: &[u8], salt: &[u8], info: &[&[u8]]) -> Result<Zeroizing<[u8; N]>> {
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
        let call = CallMediaHandshake {
            call: synthetic_call(),
            description: Vec::new(),
            local_public: receiver.try_into().unwrap(),
            local: PKey::from_ec_key(key)?,
            peer,
        };
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
        assert!(PeerPrekey::parse(2, &call.local_public).is_err());
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
            CallMediaHandshake::prepare(synthetic_call(), b"signed description", &receiver_prekey)?;
        let receiver = CallMediaHandshake {
            call: sender.call().clone(),
            peer: PeerPrekey::parse(1, sender.public_prekey())?,
            description: Vec::new(),
            local: receiver_private,
            local_public: receiver_public,
        };
        let (tx, wrapped) = sender.new_outbound_key()?;
        let rx = receiver.open_inbound_key(&wrapped, tx.salt())?;
        assert_eq!(sender.peer_description(), b"signed description");
        assert_eq!(*rx.srtp_key(1)?, *tx.srtp_key(1)?);
        assert_ne!(*rx.srtp_key(1)?, *tx.srtp_key(2)?);
        assert!(sender.open_inbound_key(&wrapped, tx.salt()).is_err());
        assert_ne!(wrapped, sender.new_outbound_key()?.1);
        Ok(())
    }
}
