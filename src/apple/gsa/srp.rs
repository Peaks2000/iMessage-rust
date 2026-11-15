use std::ops::{Deref, DerefMut};

use anyhow::{Context, Result, ensure};
use openssl::{
    bn::{BigNum, BigNumContext, BigNumRef},
    hash::MessageDigest,
    memcmp,
    pkcs5::pbkdf2_hmac,
    pkey::PKey,
    rand::rand_bytes,
    sha::{Sha256, sha256},
    sign::Signer,
    symm::{Cipher, decrypt},
};
use zeroize::Zeroizing;

// The 2048-bit SRP group from RFC 5054, Appendix A.
const MODULUS: &str = concat!(
    "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC319294",
    "3DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310D",
    "CD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FB",
    "D5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF74",
    "7359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A",
    "436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D",
    "5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E73",
    "03CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6",
    "94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F",
    "9E4AFF73",
);

pub(super) struct Exchange {
    private: SecretNumber,
    public: Vec<u8>,
}

pub(super) struct Proof {
    pub client: [u8; 32],
    server: Zeroizing<[u8; 32]>,
    key: Zeroizing<[u8; 32]>,
}

impl Exchange {
    pub(super) fn start() -> Result<Self> {
        let mut random = Zeroizing::new([0; 32]);
        rand_bytes(random.as_mut())?;
        random[0] |= 0x80;
        Self::from_private(random.as_ref())
    }

    fn from_private(private: &[u8]) -> Result<Self> {
        let private = SecretNumber::from_bytes(private)?;
        let generator = BigNum::from_u32(2)?;
        let modulus = BigNum::from_hex_str(MODULUS)?;
        let mut context = BigNumContext::new()?;
        let mut public = BigNum::new()?;
        public.mod_exp(&generator, &private, &modulus, &mut context)?;
        Ok(Self {
            private,
            public: public.to_vec(),
        })
    }

    pub(super) fn public(&self) -> &[u8] {
        &self.public
    }

    pub(super) fn answer(
        &self,
        account: &str,
        password_hash: &[u8; 32],
        salt: &[u8],
        iterations: usize,
        protocol: &str,
        server_public: &[u8],
    ) -> Result<Proof> {
        ensure!(
            (1..=256).contains(&server_public.len()),
            "Invalid Apple SRP public value length"
        );
        ensure!(
            (1..=64).contains(&salt.len()) && (1..=1_000_000).contains(&iterations),
            "Invalid Apple SRP derivation parameters"
        );

        let derived_input = match protocol {
            "s2k" => Zeroizing::new(password_hash.to_vec()),
            "s2k_fo" => {
                let hex = b"0123456789abcdef";
                Zeroizing::new(
                    password_hash
                        .iter()
                        .flat_map(|byte| [hex[usize::from(byte >> 4)], hex[usize::from(byte & 15)]])
                        .collect::<Vec<_>>(),
                )
            }
            _ => anyhow::bail!("Apple selected an unsupported SRP protocol"),
        };
        let modulus = BigNum::from_hex_str(MODULUS)?;
        let server = BigNum::from_slice(server_public)?;
        ensure!(
            server.num_bits() != 0 && server < modulus,
            "Invalid Apple SRP public value"
        );
        let server_bytes = server.to_vec();
        let generator = BigNum::from_u32(2)?;
        let modulus_bytes = modulus.to_vec();
        let padded_generator = generator.to_vec_padded(modulus.num_bytes())?;

        let mut derived = Zeroizing::new([0; 32]);
        pbkdf2_hmac(
            &derived_input,
            salt,
            iterations,
            MessageDigest::sha256(),
            derived.as_mut(),
        )?;
        // GrandSlam omits the account name from x but still binds it into M1.
        let identity_hash = Zeroizing::new(hash(&[b":", derived.as_ref()]));
        let start = identity_hash
            .iter()
            .position(|byte| *byte != 0)
            .unwrap_or(identity_hash.len());
        let x_hash = Zeroizing::new(hash(&[salt, &identity_hash[start..]]));
        let x = SecretNumber::from_bytes(x_hash.as_ref())?;
        let k = BigNum::from_slice(&hash(&[&modulus_bytes, &padded_generator]))?;
        let mut padded_public = [0; 256];
        padded_public[256 - self.public.len()..].copy_from_slice(&self.public);
        let padded_server = server.to_vec_padded(modulus.num_bytes())?;
        let u = BigNum::from_slice(&hash(&[&padded_public, &padded_server]))?;
        ensure!(u.num_bits() != 0, "Invalid Apple SRP scramble");

        let mut context = BigNumContext::new_secure()?;
        let mut verifier = SecretNumber::new()?;
        verifier.mod_exp(&generator, &x, &modulus, &mut context)?;
        let mut weighted_verifier = SecretNumber::new()?;
        weighted_verifier.mod_mul(&k, &verifier, &modulus, &mut context)?;
        let mut base = SecretNumber::new()?;
        base.mod_sub(&server, &weighted_verifier, &modulus, &mut context)?;
        ensure!(base.num_bits() != 0, "Invalid Apple SRP premaster base");
        let mut product = SecretNumber::new()?;
        product.checked_mul(&u, &x, &mut context)?;
        let mut exponent = SecretNumber::new()?;
        exponent.checked_add(&self.private, &product)?;
        let mut premaster = SecretNumber::new()?;
        premaster.mod_exp(&base, &exponent, &modulus, &mut context)?;

        let premaster_bytes = Zeroizing::new(premaster.to_vec());
        let key = Zeroizing::new(sha256(&premaster_bytes));
        let mut group_hash = sha256(&modulus_bytes);
        for (part, other) in group_hash.iter_mut().zip(sha256(&padded_generator)) {
            *part ^= other;
        }
        let client = hash(&[
            &group_hash,
            &sha256(account.as_bytes()),
            salt,
            &self.public,
            &server_bytes,
            key.as_ref(),
        ]);
        let server = Zeroizing::new(hash(&[&self.public, &client, key.as_ref()]));
        Ok(Proof {
            client,
            server,
            key,
        })
    }
}

impl Proof {
    pub(super) fn open(&self, server_proof: &[u8], encrypted: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        ensure!(
            server_proof.len() == self.server.len()
                && memcmp::eq(server_proof, self.server.as_ref()),
            "Apple SRP server proof did not match"
        );
        let mac = PKey::hmac(self.key.as_ref())?;
        let derive = |label| -> Result<Zeroizing<Vec<u8>>> {
            Ok(Zeroizing::new(
                Signer::new(MessageDigest::sha256(), &mac)?.sign_oneshot_to_vec(label)?,
            ))
        };
        let key = derive(b"extra data key:")?;
        let iv = derive(b"extra data iv:")?;
        let bytes = decrypt(Cipher::aes_256_cbc(), &key, Some(&iv[..16]), encrypted)
            .context("Could not decrypt Apple's SRP session data")?;
        Ok(Zeroizing::new(bytes))
    }
}

struct SecretNumber(BigNum);

impl SecretNumber {
    fn new() -> Result<Self> {
        Ok(Self::protect(BigNum::new()?))
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self::protect(BigNum::from_slice(bytes)?))
    }

    fn protect(mut number: BigNum) -> Self {
        number.set_const_time();
        Self(number)
    }
}

impl Deref for SecretNumber {
    type Target = BigNumRef;

    fn deref(&self) -> &BigNumRef {
        &self.0
    }
}

impl DerefMut for SecretNumber {
    fn deref_mut(&mut self) -> &mut BigNumRef {
        &mut self.0
    }
}

impl Drop for SecretNumber {
    fn drop(&mut self) {
        self.0.clear();
    }
}

fn hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    for part in parts {
        hash.update(part);
    }
    hash.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(hex: &str) -> Vec<u8> {
        hex.as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn verifies_independent_s2k_and_s2k_fo_server_vectors() -> Result<()> {
        // These fixtures use a separate Python server-side SRP calculation, with a short
        // public A and a leading zero in the inner password hash to test the wire encodings.
        let exchange = Exchange::from_private(&[1])?;
        assert_eq!(exchange.public(), &[2]);
        let vectors = [
            (
                "s2k",
                "0002f4",
                concat!(
                    "9c03017fbc1725fc8863af8d192548ca4d73b498dbec4698af4108bb1308d8c3d9ded5e386202412640450d0af68888da426deb19ef8f257bf1bb8074d3c69111e7ef100b881f7718b8544f256a11578d4be791b640cfed37af23ab708708de7c51c12ed9431b4d5f0f98f5b14f47fedff9fb1b2e27ad0f09dc207b9cdb96746b262",
                    "399b8430c3c943ca07ec952ac2cf1d71b362849dbaa2402abc371e9611840bcb8fc3971c7a10d981463a18853719651a3f9a3b27aaf335eb8a0c7df6f78a9b2dfa622a34c9a36468549b5a394f0061d0c559972ee2653e7882840aaa946a9085ad4a59c66d93280ff5347aa1c218261c313593115b8082a33f53e95b56d5"
                ),
                "fc95a2aeb48774fd6fc3f39c5ac32f113d95ca51a90ab7be6cf3ca8413008b57",
                "a48d693cf29a8a5fdbbbe83f1db0da04bf2a2fd203a34fa4e84a3851245276b0",
                "34aeda19b7446d3268b3a3b42a93c6edb0e859af4d509cdd0a7e0f701bd038d9",
            ),
            (
                "s2k_fo",
                "00004d",
                concat!(
                    "3c07afa23b518c141033090adeebaaa35df4d4589e1f481aa43e628a4cbbf0b2ebea901a54c5ced4c9e71877d3883552585da8a0857651829e84054ebaa49d2f794bc3290d6ffe7427a18a86f183a87a55f9aea0d02f4c19e20741deb95f76a075435fb5fb29cc56755f30b0da6389afbc4d6c7c8f28fc791a18f944250",
                    "ba84f967daa58e842c8d5a342fe7ae0c8bc97e096958d44df32dbc2bf84c952fff2cd56844811869e3e5c8d2f4ef0a2f25207210cbb78c6f00150f1a1e14de3af9f033a6b06f00d513a15bfd9c5c17a451b7a23a4ab95aceb61a5a94cd25087d3fd56f1f5389925253e1d8eae3fb3239b987ebf395f685531c6c3fb83a722dbd0ee17"
                ),
                "841c9adcd30a0a4fdd14746e7e9cf66e0690cbf8e34684cf63e62eb4b6a2d9d6",
                "d9e084b98500f05aa26a28416dfc29bf42574d14123b2a02d9871e68d4fb66ee",
                "c4501e854d624823c016f23bed29526438e3a02980a53be704c26a3a65d58b05",
            ),
        ];
        for (protocol, salt, public_b, m1, m2, cipher) in vectors {
            let proof = exchange.answer(
                "offline@example.com",
                &sha256(b"fixture password only"),
                &bytes(salt),
                1000,
                protocol,
                &bytes(public_b),
            )?;
            assert_eq!(proof.client.as_slice(), bytes(m1), "{protocol}");
            let mut server_proof = bytes(m2);
            let encrypted = bytes(cipher);
            assert_eq!(
                &*proof.open(&server_proof, &encrypted)?,
                b"authenticated fixture session"
            );
            server_proof[9] ^= 1;
            assert!(proof.open(&server_proof, &encrypted).is_err());
        }
        assert!(
            exchange
                .answer("offline@example.com", &[0; 32], &[1], 1000, "s2k", &[0])
                .is_err()
        );
        Ok(())
    }
}
