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
            public: public.to_vec_padded(modulus.num_bytes())?,
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
        let x_hash = Zeroizing::new(hash(&[salt, identity_hash.as_ref()]));
        let x = SecretNumber::from_bytes(x_hash.as_ref())?;
        let k = BigNum::from_slice(&hash(&[&modulus_bytes, &padded_generator]))?;
        let padded_server = server.to_vec_padded(modulus.num_bytes())?;
        let u = BigNum::from_slice(&hash(&[&self.public, &padded_server]))?;
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

        // GrandSlam uses CoreCrypto's SRP-6a hash variant with fixed-width group elements.
        let premaster_bytes = Zeroizing::new(premaster.to_vec_padded(modulus.num_bytes())?);
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
            &padded_server,
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
        // An independent Python server calculation exercises leading zeros in the group
        // elements and in the inner password hash for both password derivations.
        let exchange = Exchange::from_private(&[1])?;
        let mut public = [0; 256];
        public[255] = 2;
        assert_eq!(exchange.public(), public);
        let vectors = [
            (
                "s2k",
                "0002f4",
                concat!(
                    "1e25cf95163eabdf9e90d0f5758acf2ceb076173b54ff052de9904305e7c73d6b5498ee8498d4ba532b55f5119b8765ea82e758b800ef570b8f61335f562ac0c27d17b08f7963f176b8871b06655bb9b9f4fae66d5852c10aa5bceecf38d4b81091f9d6182688a36ade2c3a4e29b4399f6693018518f102c424993a6fde33110",
                    "1fc9e3ad98ad209d96d4feea0e700a70e4a8119d253d074a480831e4bdccc55034d46aef455817472628eaa660060288a8b475476e149e4c9e5865d72931f04d2a834338b5c90f595dd56243552281f87ac7692ca71607be1e26f65f0aa2d83d795415df47550fbbfa3b368feecafa82351b49e5a11e43a457f1db6784eec20b"
                ),
                "ba710caac30494bed62a43144b699d751d45428c602c821d36499856f6a3f4cd",
                "181e80e42b010a8ff14e0eadba9579aedb8face2482e448cf2aeb13beb36a83e",
                "f0f76d52ffd071a485f6ece3c801cc7f02102c8a4716b7cf734bcc0ecffadda4",
            ),
            (
                "s2k_fo",
                "00004d",
                concat!(
                    "0077218f3271eb3d4e86e0599dd840f021aa6805f9111cc1311c5ac8f7cde04cff363fc6a17afe27b5633b3548c1a89d18bd9d4a4fc01aaffa0ee80b2cc6d90625f71702abcc750bdbf5ed1c87d6605ace55d377ee533c51f2749294edb3593aa8194f8fd6deb4146896624c1675e50e2561c7f94bbb88b5d19ed3baf60c2b40",
                    "35732a24d134ac6442793888ead29f2be287187fbd65b25a3d085255983d01aa41a25c4270aeb26ea3e7b10ce22c1df2363be0db5d55408961eb25e2400857770935ad28648d3cbcc22e4adbd6f3bd964c06ce4f1d51236a42035d756d23c33f35634135bba35145e96bca57194e3cb192fe95655fd3108b8229444ec011ccd1"
                ),
                "b6334f77b3ea29e3cc626c543d12b10c51552157b9fea8d3597305e9a4a88a3f",
                "0e19979fb1f807f7ff7dd07771ab4a70c3ca0e30832041271617eec69d8bf4b5",
                "0c033ddf54e2d98c179989c284985abb66279eb10a4164a40e4d9e5d4c5fa51f",
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
