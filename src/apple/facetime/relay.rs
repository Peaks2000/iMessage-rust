mod binding;
mod http3;
mod quic;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::{Context, Result, ensure};
use openssl::rand::rand_bytes;
use plist::{Dictionary, Value};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::address;

use super::{CallEndpoint, SIGNALING, media::hkdf, participant_id};

pub use binding::{CallRelayBinding, CallRelayProfile, RelayChannel};
pub use quic::{CallRelayConnection, CallRelayStream, RelayStreamDirection};

pub(in crate::apple) const RELAY_TOPIC: &str = "com.apple.private.alloy.quickrelay";

pub(in crate::apple) fn allocation_request(
    request: Uuid,
    session: Uuid,
    push_id: [u8; 4],
    local: &str,
    user_agent: &str,
    (caller, caller_push, caller_session_token): (&str, &[u8; 32], &[u8]),
) -> Dictionary {
    let destination = Dictionary::from_iter([
        ("tP", Value::from(caller)),
        ("t", Value::Data(caller_push.to_vec())),
        ("sT", Value::Data(caller_session_token.to_vec())),
        ("D", Value::Boolean(false)),
    ]);
    Dictionary::from_iter([
        ("c", Value::from(200)),
        ("ua", Value::from(user_agent)),
        ("i", Value::from(i32::from_be_bytes(push_id))),
        ("U", Value::Data(request.as_bytes().to_vec())),
        ("sP", Value::from(local)),
        ("dtl", Value::Array(vec![Value::Dictionary(destination)])),
        ("qr", Value::from(0)),
        ("qids", Value::Data(session.as_bytes().to_vec())),
        (
            "qgid",
            Value::from(session.to_string().to_ascii_uppercase()),
        ),
        ("qgmc", Value::from(2)),
        ("qai", Value::from(SIGNALING)),
        ("qat", Value::from(3)),
        ("qv", Value::from(25)),
    ])
}

/// Apple relay credentials tied to the local device and the verified caller.
pub struct CallRelayAllocation {
    pub call_id: Uuid,
    pub endpoint: SocketAddr,
    pub local_participant: u64,
    pub caller_participant: u64,
    relay_id: Vec<u8>,
    token: Zeroizing<Vec<u8>>,
    shared_key: Zeroizing<Vec<u8>>,
}

/// Fresh authentication and packet keys for one relay connection attempt.
pub struct CallRelayKeys {
    pub identity: Zeroizing<Vec<u8>>,
    pub tls_psk: Zeroizing<[u8; 32]>,
    pub hop_keys: Zeroizing<[u8; 64]>,
    pub session_keys: Zeroizing<[u8; 48]>,
}

impl CallRelayAllocation {
    pub(in crate::apple) fn parse(
        mut reply: Dictionary,
        request: Uuid,
        session: Uuid,
        local: (&str, &[u8; 32]),
        caller: (&str, CallEndpoint),
    ) -> Result<Self> {
        // Own the secret fields before validating anything else, including on failure.
        let shared_key = remove_secret(&mut reply, "qrsk");
        let token = remove_secret(&mut reply, "qrst");
        let shared_key = shared_key.context("Missing FaceTime relay key")?;
        let token = token.context("Missing FaceTime relay token")?;
        let bytes = |name: &str| reply.get(name).and_then(Value::as_data);
        ensure!(
            bytes("U") == Some(request.as_bytes()),
            "Unexpected FaceTime relay request ID"
        );
        ensure!(
            bytes("qids") == Some(session.as_bytes()),
            "Unexpected FaceTime relay call ID"
        );
        ensure!(
            shared_key.len() == 20 && !token.is_empty() && token.len() <= 1024,
            "Invalid FaceTime relay credentials"
        );
        let ip = match bytes("qrip").context("Missing FaceTime relay address")? {
            [a, b, c, d] => IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d)),
            addr if addr.len() == 16 => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(addr)?)),
            _ => anyhow::bail!("Invalid FaceTime relay address"),
        };
        let port = reply
            .get("qrp")
            .and_then(Value::as_unsigned_integer)
            .and_then(|port| u16::try_from(port).ok())
            .filter(|port| *port != 0)
            .context("Invalid FaceTime relay port")?;
        let ip = ip.to_canonical();
        let local_address = match ip {
            IpAddr::V4(addr) => addr.is_private() || addr.is_link_local() || addr.is_broadcast(),
            IpAddr::V6(addr) => addr.is_unique_local() || addr.is_unicast_link_local(),
        };
        ensure!(
            !local_address && !ip.is_unspecified() && !ip.is_multicast() && !ip.is_loopback(),
            "Invalid FaceTime relay destination"
        );
        let relay_id = bytes("qrsi")
            .filter(|key| !key.is_empty() && key.len() <= 64)
            .context("Invalid FaceTime relay identifier")?
            .to_vec();
        let local_participant = reply
            .get("qri")
            .and_then(participant_id)
            .context("Missing local FaceTime relay participant")?;
        let caller_participant = caller
            .1
            .participant()
            .context("Missing authenticated caller participant")?;
        ensure!(
            local_participant != caller_participant,
            "FaceTime relay reused a participant ID"
        );
        let allocations = reply
            .get("qal")
            .and_then(Value::as_array)
            .filter(|entries| entries.len() <= 64)
            .context("Invalid FaceTime relay participants")?;
        let bound = |expected_id, expected_handle: &str, expected_token: &[u8]| {
            let mut matching =
                allocations
                    .iter()
                    .filter_map(Value::as_dictionary)
                    .filter(|entry| {
                        entry.get("qri").and_then(participant_id) == Some(expected_id)
                            || entry.get("t").and_then(Value::as_data) == Some(expected_token)
                    });
            matching.next().is_some_and(|entry| {
                entry.get("qri").and_then(participant_id) == Some(expected_id)
                    && entry.get("t").and_then(Value::as_data) == Some(expected_token)
                    && entry
                        .get("tP")
                        .and_then(Value::as_string)
                        .and_then(|uri| address(uri).ok())
                        .as_deref()
                        == Some(expected_handle)
            }) && matching.next().is_none()
        };
        ensure!(
            bound(local_participant, local.0, local.1)
                && bound(caller_participant, caller.0, caller.1.push_token()),
            "FaceTime relay participants do not match the call"
        );
        Ok(Self {
            call_id: session,
            endpoint: SocketAddr::new(ip, port),
            local_participant,
            caller_participant,
            relay_id,
            token,
            shared_key,
        })
    }

    pub fn derive_keys(&self) -> Result<CallRelayKeys> {
        let mut salt = [0; 12];
        rand_bytes(&mut salt)?;
        self.derive_with_salt(salt)
    }

    fn derive_with_salt(&self, salt: [u8; 12]) -> Result<CallRelayKeys> {
        let mut identity = Zeroizing::new(Vec::with_capacity(1 + salt.len() + self.token.len()));
        identity.push(0);
        identity.extend_from_slice(&salt);
        identity.extend_from_slice(self.token.as_ref());
        let local = self.local_participant.to_be_bytes();
        Ok(CallRelayKeys {
            identity,
            tls_psk: hkdf(self.shared_key.as_ref(), &salt, &[b"QR-QUIC-V0"])?,
            hop_keys: hkdf(
                self.shared_key.as_ref(),
                &salt,
                &[b"QR-HBH-KDF", &self.relay_id, &local],
            )?,
            session_keys: hkdf(
                self.shared_key.as_ref(),
                &salt,
                &[b"QuickRelay KDF", &self.relay_id, &local],
            )?,
        })
    }
}

fn remove_secret(reply: &mut Dictionary, field: &str) -> Option<Zeroizing<Vec<u8>>> {
    match reply.remove(field)? {
        Value::Data(bytes) => Some(Zeroizing::new(bytes)),
        _ => None,
    }
}

#[cfg(test)]
pub(in crate::apple) mod tests {
    use super::*;

    pub(in crate::apple) const LOCAL: &str = "mailto:local@example.org";
    pub(in crate::apple) const CALLER: &str = "mailto:caller@example.org";
    pub(in crate::apple) const LOCAL_ID: u64 = 0x8000_0000_0000_0022;
    pub(in crate::apple) const CALLER_ID: u64 = 77;

    pub(in crate::apple) fn allocation_fixture(request: Uuid, call: Uuid) -> Dictionary {
        let allocation = |id: u64, uri, token| {
            Value::Dictionary(Dictionary::from_iter([
                ("qri", Value::from(id as i64)),
                ("tP", Value::from(uri)),
                ("t", Value::Data(vec![token; 32])),
            ]))
        };
        Dictionary::from_iter([
            ("U", Value::Data(request.as_bytes().to_vec())),
            ("qids", Value::Data(call.as_bytes().to_vec())),
            ("qrip", Value::Data(vec![203, 0, 113, 42])),
            ("qrp", Value::from(443)),
            ("qrsi", Value::Data(b"relay-id".to_vec())),
            ("qrst", Value::Data(b"relay-token".to_vec())),
            ("qrsk", Value::Data((0..20).collect())),
            ("qri", Value::from(LOCAL_ID as i64)),
            (
                "qal",
                Value::Array(vec![
                    allocation(LOCAL_ID, LOCAL, 1),
                    allocation(CALLER_ID, CALLER, 2),
                ]),
            ),
        ])
    }

    #[test]
    fn relay_secrets_match_independently_derived_vectors() -> Result<()> {
        let request = Uuid::new_v4();
        let call = Uuid::new_v4();
        let allocation = CallRelayAllocation::parse(
            allocation_fixture(request, call),
            request,
            call,
            (LOCAL, &[1; 32]),
            (CALLER, CallEndpoint::new([2; 32], Some(CALLER_ID))),
        )?;
        let keys = allocation.derive_with_salt(*b"test-salt-v1")?;
        assert_eq!(allocation.local_participant, LOCAL_ID);
        assert_eq!(allocation.endpoint, "203.0.113.42:443".parse()?);
        assert_eq!(&*keys.identity, b"\0test-salt-v1relay-token");
        assert_eq!(
            hex::encode(keys.tls_psk.as_ref()),
            "2f6882e08160668fe2f2e05800f7e9ad5d59b94e9f6be8ebc82ca07664143da6"
        );
        assert_eq!(
            hex::encode(keys.hop_keys.as_ref()),
            concat!(
                "bb4e9686006bd6216dc292c5173a08f7e99d007c2069c8f0c7ca78e15f0f32992",
                "504cfe7c744cb7ab79cad96e3b8e1993dacd38c263f2c189240ecbb202c5af1"
            )
        );
        assert_eq!(
            hex::encode(keys.session_keys.as_ref()),
            "34fc0bf9b6f491fe9ee9f18be02f15d183b303ee2ab6cb9fc2b747ea235a3e552f108ab82bceda46a598b77b5c6a61ae"
        );
        assert_ne!(*allocation.derive_keys()?.tls_psk, *keys.tls_psk);
        Ok(())
    }

    #[test]
    fn rejects_cross_call_allocations_and_conflicting_device_bindings() {
        let request = Uuid::new_v4();
        let call = Uuid::new_v4();
        let parse = |allocation| {
            CallRelayAllocation::parse(
                allocation,
                request,
                call,
                (LOCAL, &[1; 32]),
                (CALLER, CallEndpoint::new([2; 32], Some(CALLER_ID))),
            )
        };
        assert!(parse(allocation_fixture(request, Uuid::new_v4())).is_err());
        assert!(parse(allocation_fixture(Uuid::new_v4(), call)).is_err());
        let valid = allocation_fixture(request, call);
        let mut invalid = valid.clone();
        invalid.insert("qrsk".into(), Value::Data(vec![0; 19]));
        assert!(parse(invalid).is_err());
        let mut invalid = valid.clone();
        invalid.insert("qrip".into(), Value::Data(vec![127, 0, 0, 1]));
        assert!(parse(invalid).is_err());
        let mut invalid = valid.clone();
        invalid.insert("qri".into(), Value::from(CALLER_ID));
        assert!(parse(invalid).is_err());
        let mut invalid = valid;
        let participants = invalid.get_mut("qal").unwrap().as_array_mut().unwrap();
        participants[1]
            .as_dictionary_mut()
            .unwrap()
            .insert("t".into(), Value::Data(vec![3; 32]));
        assert!(parse(invalid).is_err());
    }
}
