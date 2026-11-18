use anyhow::{Context, Result, ensure};
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey, EcPoint},
    ecdsa::EcdsaSig,
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Public},
    sign::Verifier,
};
use plist::Data;
use prost::Message;
use serde::Deserialize;
use uuid::Uuid;
use zeroize::Zeroizing;

const KEYING_CONTEXT: &[u8] = b"com.apple.FaceTime.QRKeying";
const MAX_DIRECTORY_KEY: usize = 1024;
const MAX_KEY_MATERIAL: usize = 4096;

/// The device signing key from an authenticated IDS reply for one exact push token.
#[derive(Clone)]
pub(crate) struct PeerDeviceKey(PKey<Public>);

impl PeerDeviceKey {
    pub(in crate::apple) fn from_directory(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_DIRECTORY_KEY,
            "Invalid IDS device signing identity"
        );
        let key = DirectoryIdentity::decode(bytes)?
            .device
            .context("Missing IDS device signing identity")?
            .x;
        ensure!(key.len() == 32, "Invalid compact IDS device key");
        let mut compressed = [3; 33];
        compressed[1..].copy_from_slice(&key);
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let mut ctx = BigNumContext::new()?;
        let mut point = EcPoint::from_bytes(&group, &compressed, &mut ctx)?;
        let (mut x, mut y, mut prime, mut a, mut b) = (
            BigNum::new()?,
            BigNum::new()?,
            BigNum::new()?,
            BigNum::new()?,
            BigNum::new()?,
        );
        group.components_gfp(&mut prime, &mut a, &mut b, &mut ctx)?;
        point.affine_coordinates_gfp(&group, &mut x, &mut y, &mut ctx)?;
        let mut other_y = BigNum::new()?;
        other_y.checked_sub(&prime, &y)?;
        // The compact key stores only X. Apple chooses the smaller of the two Y coordinates.
        if other_y < y {
            point.set_affine_coordinates_gfp(&group, &x, &other_y, &mut ctx)?;
        }
        let key = EcKey::from_public_key(&group, &point)?;
        key.check_key()?;
        Ok(Self(PKey::from_ec_key(key)?))
    }

    pub(super) fn verify_material(&self, call: Uuid, bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        ensure!(
            bytes.len() <= MAX_KEY_MATERIAL,
            "FaceTime relay key envelope is too large"
        );
        let signed: SignedMaterial = plist::from_bytes(bytes)?;
        ensure!(
            Uuid::parse_str(&signed.session)? == call && signed.signature.as_ref().len() == 64,
            "FaceTime relay key has an invalid session or signature length"
        );
        let signature = signed.signature.as_ref();
        let signature = EcdsaSig::from_private_components(
            BigNum::from_slice(&signature[..32])?,
            BigNum::from_slice(&signature[32..])?,
        )?
        .to_der()?;
        let mut verifier = Verifier::new(MessageDigest::sha256(), &self.0)?;
        verifier.update(KEYING_CONTEXT)?;
        verifier.update(signed.session.as_bytes())?;
        verifier.update(signed.payload.as_ref())?;
        ensure!(
            verifier.verify(&signature)?,
            "FaceTime relay key signature did not match the IDS device"
        );
        Ok(Zeroizing::new(signed.payload.into()))
    }
}

#[derive(Message)]
struct DirectoryIdentity {
    #[prost(message, optional, tag = "1")]
    device: Option<DirectoryDevice>,
}

#[derive(Message)]
struct DirectoryDevice {
    #[prost(bytes = "vec", tag = "1")]
    x: Vec<u8>,
}

#[derive(Deserialize)]
struct SignedMaterial {
    #[serde(rename = "sessionID")]
    session: String,
    payload: Data,
    signature: Data,
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use openssl::{pkey::Private, sign::Signer};
    use plist::{Dictionary, Value};

    pub(crate) fn fixture_signer() -> Result<(PKey<Private>, PeerDeviceKey)> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let mut ctx = BigNumContext::new()?;
        let scalar = BigNum::from_u32(1)?; // The test uses the P-256 generator's canonical Y.
        let mut point = EcPoint::new(&group)?;
        point.mul_generator2(&group, &scalar, &mut ctx)?;
        let private = PKey::from_ec_key(EcKey::from_private_components(&group, &scalar, &point)?)?;
        let data = DirectoryIdentity {
            device: Some(DirectoryDevice {
                x: hex::decode("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")?,
            }),
        };
        Ok((
            private,
            PeerDeviceKey::from_directory(&data.encode_to_vec())?,
        ))
    }

    pub(crate) fn signed_key(key: &PKey<Private>, call: Uuid, payload: &[u8]) -> Result<Vec<u8>> {
        let call = call.to_string().to_ascii_uppercase();
        let mut signer = Signer::new(MessageDigest::sha256(), key)?;
        signer.update(b"com.apple.FaceTime.QRKeying")?;
        signer.update(call.as_bytes())?;
        signer.update(payload)?;
        let der = EcdsaSig::from_der(&signer.sign_to_vec()?)?;
        let mut raw = der.r().to_vec_padded(32)?;
        raw.extend_from_slice(&der.s().to_vec_padded(32)?);
        let fields = Dictionary::from_iter([
            ("sessionID", Value::String(call)),
            ("payload", Value::Data(payload.to_vec())),
            ("signature", Value::Data(raw)),
        ]);
        let mut bytes = Vec::new();
        plist::to_writer_binary(&mut bytes, &fields)?;
        Ok(bytes)
    }

    #[test]
    fn signed_key_material_is_bound_to_one_device_session_and_payload() -> Result<()> {
        let call = Uuid::new_v4();
        let (private, pinned) = fixture_signer()?;
        let raw = signed_key(&private, call, b"original session key")?;
        assert_eq!(
            pinned.verify_material(call, &raw)?.as_slice(),
            b"original session key"
        );
        assert!(pinned.verify_material(Uuid::new_v4(), &raw).is_err());
        let other_group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let forged = PKey::from_ec_key(EcKey::generate(&other_group)?)?;
        let wrong_signer = signed_key(&forged, call, b"original session key")?;
        assert!(pinned.verify_material(call, &wrong_signer).is_err());
        let mut modified: Dictionary = plist::from_bytes(&raw)?;
        modified.insert(
            "payload".to_owned(),
            Value::Data(b"modified session key".to_vec()),
        );
        let mut invalid = Vec::new();
        plist::to_writer_binary(&mut invalid, &modified)?;
        assert!(pinned.verify_material(call, &invalid).is_err());
        Ok(())
    }
}
