use anyhow::{Context, Result, ensure};
use openssl::{
    bn::BigNumContext,
    cipher_ctx::CipherCtx,
    ec::{EcGroup, EcKey, EcPoint, PointConversionForm},
    encrypt::{Decrypter, Encrypter},
    hash::MessageDigest,
    memcmp,
    nid::Nid,
    pkey::{HasPublic, PKey, Private, Public},
    rand::rand_bytes,
    rsa::{Padding, Rsa},
    sha::sha256,
    sign::{Signer, Verifier},
    symm::{Cipher, decrypt, encrypt},
};
use zeroize::Zeroizing;

pub(super) fn aes128_ctr(key: &[u8], counter: &[u8; 16], data: &mut [u8]) -> Result<()> {
    let mut cipher = CipherCtx::new()?;
    cipher.encrypt_init(
        Some(openssl::cipher::Cipher::aes_128_ctr()),
        Some(key),
        Some(counter),
    )?;
    ensure!(
        cipher.cipher_update_inplace(data, data.len())? == data.len(),
        "Unexpected AES-CTR output length"
    );
    Ok(())
}

const CTR_IV: [u8; 16] = 1u128.to_be_bytes();
const RSA_PREFIX: usize = 100;
const LEGACY_VERSION: u8 = 2;

pub(super) struct KeyPair<T> {
    signing: PKey<T>,
    encryption: PKey<T>,
    fingerprint: [u8; 32],
}

impl<T: HasPublic> KeyPair<T> {
    fn new(signing: EcKey<T>, encryption: Rsa<T>) -> Result<Self> {
        ensure!(
            signing.group().curve_name() == Some(Nid::X9_62_PRIME256V1),
            "Expected a P-256 signing key"
        );
        ensure!(
            encryption.size() == 160,
            "Expected a legacy 1280-bit encryption key"
        );
        signing.check_key()?;
        let fields = public_fields(&signing, &encryption)?;
        let mut identity = Vec::new();
        for field in &fields {
            identity.extend_from_slice(&(field.len() as u16).to_be_bytes());
            identity.extend_from_slice(field);
        }
        Ok(Self {
            signing: PKey::from_ec_key(signing)?,
            encryption: PKey::from_rsa(encryption)?,
            fingerprint: sha256(&identity),
        })
    }
}

impl KeyPair<Public> {
    pub(super) fn decode(encoded: &[u8]) -> Result<Self> {
        let mut outer = encoded;
        let mut fields = der_value(&mut outer, 0x30)?;
        ensure!(outer.is_empty(), "Unexpected bytes after public identity");
        let point = identity_field(&mut fields, 1)?;
        let rsa = identity_field(&mut fields, 2)?;
        ensure!(fields.is_empty(), "Unexpected bytes in public identity");
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let mut context = BigNumContext::new()?;
        let point = EcPoint::from_bytes(&group, point, &mut context)?;
        Self::new(
            EcKey::from_public_key(&group, &point)?,
            Rsa::public_key_from_der_pkcs1(rsa)?,
        )
    }
}

impl KeyPair<Private> {
    pub(super) fn public_der(&self) -> Result<Vec<u8>> {
        let fields = public_fields(&self.signing.ec_key()?, &self.encryption.rsa()?)?;
        Ok(encode_identity(fields))
    }

    pub(super) fn private(signing: &[u8], encryption: &[u8]) -> Result<Self> {
        Self::new(
            PKey::private_key_from_der(signing)?.ec_key()?,
            PKey::private_key_from_der(encryption)?.rsa()?,
        )
    }

    pub(super) fn seal(&self, recipient: &KeyPair<Public>, text: &[u8]) -> Result<Vec<u8>> {
        let mut seed = Zeroizing::new([0; 11]);
        rand_bytes(seed.as_mut())?;
        let aes = message_key(&seed, text, &self.fingerprint, &recipient.fingerprint)?;
        let ciphertext = encrypt(Cipher::aes_128_ctr(), aes.as_ref(), Some(&CTR_IV), text)?;
        let split = ciphertext.len().min(RSA_PREFIX);
        let mut rsa_plaintext = Zeroizing::new(aes.to_vec());
        rsa_plaintext.extend_from_slice(&ciphertext[..split]);
        let mut rsa = Encrypter::new(&recipient.encryption)?;
        rsa.set_rsa_padding(Padding::PKCS1_OAEP)?;
        rsa.set_rsa_oaep_md(MessageDigest::sha1())?;
        rsa.set_rsa_mgf1_md(MessageDigest::sha1())?;
        let mut body = vec![0; rsa.encrypt_len(&rsa_plaintext)?];
        let used = rsa.encrypt(&rsa_plaintext, &mut body)?;
        body.truncate(used);
        body.extend_from_slice(&ciphertext[split..]);
        let signature =
            Signer::new(MessageDigest::sha1(), &self.signing)?.sign_oneshot_to_vec(&body)?;
        let mut result = vec![LEGACY_VERSION];
        result.extend_from_slice(&u16::try_from(body.len())?.to_be_bytes());
        result.extend_from_slice(&body);
        result.push(u8::try_from(signature.len())?);
        result.extend_from_slice(&signature);
        Ok(result)
    }

    pub(super) fn open(&self, sender: &KeyPair<Public>, envelope: &[u8]) -> Result<Vec<u8>> {
        ensure!(
            envelope.len() >= 4 && envelope[0] == LEGACY_VERSION,
            "Unknown encrypted payload"
        );
        let length = u16::from_be_bytes([envelope[1], envelope[2]]) as usize;
        let body = envelope
            .get(3..3 + length)
            .context("Truncated ciphertext")?;
        let signature = envelope.get(3 + length..).context("Missing signature")?;
        let (&signature_len, signature) = signature.split_first().context("Missing signature")?;
        ensure!(
            usize::from(signature_len) == signature.len(),
            "Invalid signature length"
        );
        ensure!(
            Verifier::new(MessageDigest::sha1(), &sender.signing)?
                .verify_oneshot(signature, body)?,
            "Sender signature verification failed"
        );

        let rsa_size = self.encryption.size();
        ensure!(body.len() >= rsa_size, "Missing RSA ciphertext");
        let (wrapped, tail) = body.split_at(rsa_size);
        let mut rsa = Decrypter::new(&self.encryption)?;
        rsa.set_rsa_padding(Padding::PKCS1_OAEP)?;
        rsa.set_rsa_oaep_md(MessageDigest::sha1())?;
        rsa.set_rsa_mgf1_md(MessageDigest::sha1())?;
        let mut output = Zeroizing::new(vec![0; rsa.decrypt_len(wrapped)?]);
        let size = rsa.decrypt(wrapped, &mut output)?;
        ensure!(
            (16..=16 + RSA_PREFIX).contains(&size) && (tail.is_empty() || size == 16 + RSA_PREFIX),
            "Invalid wrapped message size"
        );
        let mut ciphertext = output[16..size].to_vec();
        ciphertext.extend_from_slice(tail);
        let text = decrypt(
            Cipher::aes_128_ctr(),
            &output[..16],
            Some(&CTR_IV),
            &ciphertext,
        )?;
        let expected = message_key(
            output[..11].try_into()?,
            &text,
            &sender.fingerprint,
            &self.fingerprint,
        )?;
        ensure!(
            memcmp::eq(expected.as_ref(), &output[..16]),
            "Message key authentication failed"
        );
        Ok(text)
    }
}

fn message_key(
    seed: &[u8; 11],
    plaintext: &[u8],
    sender: &[u8],
    receiver: &[u8],
) -> Result<Zeroizing<[u8; 16]>> {
    let mac_key = PKey::hmac(seed)?;
    let mut mac = Signer::new(MessageDigest::sha256(), &mac_key)?;
    mac.update(plaintext)?;
    mac.update(&[LEGACY_VERSION])?;
    mac.update(sender)?;
    mac.update(receiver)?;
    let tag = Zeroizing::new(mac.sign_to_vec()?);
    let mut key = Zeroizing::new([0; 16]);
    key[..11].copy_from_slice(seed);
    key[11..].copy_from_slice(&tag[..5]);
    Ok(key)
}

fn public_fields<T: HasPublic>(signing: &EcKey<T>, encryption: &Rsa<T>) -> Result<[Vec<u8>; 2]> {
    let mut context = BigNumContext::new()?;
    Ok([
        signing.public_key().to_bytes(
            signing.group(),
            PointConversionForm::UNCOMPRESSED,
            &mut context,
        )?,
        encryption.public_key_to_der_pkcs1()?,
    ])
}

fn encode_identity(fields: [Vec<u8>; 2]) -> Vec<u8> {
    fn der(tag: u8, bytes: &[u8], out: &mut Vec<u8>) {
        out.push(tag);
        // Legacy identities have fixed key sizes. The longest DER field fits in one byte.
        let length = u8::try_from(bytes.len()).expect("Fixed legacy public key encoding size");
        if length >= 128 {
            out.push(0x81);
        }
        out.push(length);
        out.extend_from_slice(bytes);
    }
    let mut tagged = Vec::new();
    for (index, field) in fields.into_iter().enumerate() {
        let length = (field.len() as u16).to_be_bytes();
        der(
            0x81 + index as u8,
            &[length.as_slice(), &field].concat(),
            &mut tagged,
        );
    }
    let mut result = Vec::new();
    der(0x30, &tagged, &mut result);
    result
}

fn der_value<'a>(input: &mut &'a [u8], tag: u8) -> Result<&'a [u8]> {
    ensure!(
        input.len() >= 2 && input[0] == tag,
        "Unexpected public identity field"
    );
    let size = input[1];
    *input = &input[2..];
    let length = if size < 128 {
        size as usize
    } else {
        let count = usize::from(size & 127);
        ensure!(
            (1..=2).contains(&count) && input.len() >= count && input[0] != 0,
            "Invalid DER length"
        );
        let length = input[..count]
            .iter()
            .fold(0usize, |n, byte| (n << 8) | usize::from(*byte));
        ensure!(length >= 128, "Non-canonical DER length");
        *input = &input[count..];
        length
    };
    ensure!(length <= input.len(), "Truncated public identity");
    let (value, rest) = input.split_at(length);
    *input = rest;
    Ok(value)
}

fn identity_field<'a>(input: &mut &'a [u8], field: u8) -> Result<&'a [u8]> {
    let bytes = der_value(input, 0x80 | field)?;
    ensure!(bytes.len() >= 2, "Truncated public key length");
    ensure!(
        u16::from_be_bytes([bytes[0], bytes[1]]) as usize == bytes.len() - 2,
        "Invalid public key length"
    );
    Ok(&bytes[2..])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> Result<(KeyPair<Private>, KeyPair<Public>)> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let ec = EcKey::generate(&group)?;
        let rsa = Rsa::generate(1280)?;
        let private = KeyPair::new(ec, rsa)?;
        let public = KeyPair::decode(&private.public_der()?)?;
        Ok((private, public))
    }

    #[test]
    fn signed_encryption_round_trip_and_tampering() -> Result<()> {
        let (sender, sender_public) = identity()?;
        let (recipient, recipient_public) = identity()?;
        for text in [b"short".as_slice(), &[23; 512]] {
            let mut envelope = sender.seal(&recipient_public, text)?;
            assert_eq!(recipient.open(&sender_public, &envelope)?, text);
            assert!(recipient.open(&recipient_public, &envelope).is_err());
            envelope[14] ^= 1;
            assert!(recipient.open(&sender_public, &envelope).is_err());
            for end in 0..envelope.len() {
                assert!(recipient.open(&sender_public, &envelope[..end]).is_err());
            }
        }
        Ok(())
    }
}
