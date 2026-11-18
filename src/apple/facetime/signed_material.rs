use anyhow::{Context, Result, ensure};
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey, EcPoint},
    ecdsa::EcdsaSig,
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private, Public},
    rand::rand_bytes,
    sign::{Signer, Verifier},
};
use plist::Data;
use prost::Message;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

const KEYING_CONTEXT: &[u8] = b"com.apple.FaceTime.QRKeying";
const MAX_DIRECTORY_KEY: usize = 1024;
const MAX_KEY_MATERIAL: usize = 4096;
const KT_VERSION: u32 = 5;

#[derive(Clone)]
pub(crate) struct SignedRelayPrekey {
    pub(super) call: Uuid,
    pub(super) material_id: [u8; 20],
    pub(super) contents: Vec<u8>,
}

/// The device signing key registered with IDS for the FaceTime services.
#[derive(Clone)]
pub(in crate::apple) struct RelaySigningKey(PKey<Private>);

impl RelaySigningKey {
    pub(in crate::apple) fn generate() -> Result<Self> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        loop {
            let key = EcKey::generate(&group)?;
            if compact_x(&key)?.is_some() {
                return Ok(Self(PKey::from_ec_key(key)?));
            }
        }
    }

    pub(in crate::apple) fn from_der(der: &[u8]) -> Result<Self> {
        ensure!(
            der.len() <= MAX_DIRECTORY_KEY,
            "Invalid FaceTime device key length"
        );
        let key = PKey::private_key_from_der(der)?;
        let ec = key.ec_key()?;
        ensure!(
            ec.group().curve_name() == Some(Nid::X9_62_PRIME256V1) && compact_x(&ec)?.is_some(),
            "Invalid compact FaceTime signing key"
        );
        ec.check_key()?;
        Ok(Self(key))
    }

    pub(in crate::apple) fn private_der(&self) -> Result<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(self.0.private_key_to_der()?))
    }

    pub(in crate::apple) fn same_key(&self, other: &Self) -> bool {
        self.0.public_eq(&other.0)
    }

    pub(in crate::apple) fn directory_data(&self) -> Result<Vec<u8>> {
        let x = compact_x(&self.0.ec_key()?)?.context("Invalid compact FaceTime signing key")?;
        Ok(DirectoryIdentity {
            device: Some(DirectoryDevice { x }),
            kt_version: Some(KT_VERSION),
        }
        .encode_to_vec())
    }

    pub(in crate::apple) fn sign_prekey(
        &self,
        call: Uuid,
        prekey: &[u8; 65],
    ) -> Result<SignedRelayPrekey> {
        let mut payload = Vec::new();
        plist::to_writer_binary(
            &mut payload,
            &plist::Dictionary::from_iter([
                ("public-prekey", plist::Value::Data(prekey.to_vec())),
                ("wrap-mode", 1.into()),
                ("creation-date", (crate::now_ms() as f64 / 1_000.).into()),
            ]),
        )?;
        let mut material_id = [0; 20];
        rand_bytes(&mut material_id)?;
        Ok(SignedRelayPrekey {
            call,
            material_id,
            contents: sign_material(&self.0, call, payload)?,
        })
    }
}

fn compact_x(key: &EcKey<Private>) -> Result<Option<Vec<u8>>> {
    let mut ctx = BigNumContext::new()?;
    let (mut x, mut y, mut prime, mut a, mut b) = (
        BigNum::new()?,
        BigNum::new()?,
        BigNum::new()?,
        BigNum::new()?,
        BigNum::new()?,
    );
    let group = key.group();
    group.components_gfp(&mut prime, &mut a, &mut b, &mut ctx)?;
    key.public_key()
        .affine_coordinates_gfp(group, &mut x, &mut y, &mut ctx)?;
    y.mul_word(2)?;
    if y > prime {
        return Ok(None);
    }
    Ok(Some(x.to_vec_padded(32)?))
}

fn sign_material(key: &PKey<Private>, call: Uuid, payload: Vec<u8>) -> Result<Vec<u8>> {
    let session = call.to_string().to_ascii_uppercase();
    let mut signer = Signer::new(MessageDigest::sha256(), key)?;
    signer.update(KEYING_CONTEXT)?;
    signer.update(session.as_bytes())?;
    signer.update(&payload)?;
    let signature = EcdsaSig::from_der(&signer.sign_to_vec()?)?;
    let mut raw = signature.r().to_vec_padded(32)?;
    raw.extend_from_slice(&signature.s().to_vec_padded(32)?);
    let mut bytes = Vec::new();
    plist::to_writer_binary(
        &mut bytes,
        &SignedMaterial {
            session,
            payload: Data::new(payload),
            signature: Data::new(raw),
        },
    )?;
    Ok(bytes)
}

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
    #[prost(uint32, optional, tag = "3")]
    kt_version: Option<u32>,
}

#[derive(Message)]
struct DirectoryDevice {
    #[prost(bytes = "vec", tag = "1")]
    x: Vec<u8>,
}

#[derive(Deserialize, Serialize)]
struct SignedMaterial {
    #[serde(rename = "sessionID")]
    session: String,
    payload: Data,
    signature: Data,
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
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
            kt_version: None,
        };
        Ok((
            private,
            PeerDeviceKey::from_directory(&data.encode_to_vec())?,
        ))
    }

    pub(crate) fn signed_key(key: &PKey<Private>, call: Uuid, payload: &[u8]) -> Result<Vec<u8>> {
        sign_material(key, call, payload.to_vec())
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
