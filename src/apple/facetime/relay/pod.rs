use std::ops::Range;

use anyhow::{Result, ensure};
use openssl::{
    cipher::Cipher,
    cipher_ctx::CipherCtx,
    md::Md,
    memcmp,
    pkey::{Id, PKey, Private},
    pkey_ctx::{HkdfMode, PkeyCtx},
    sign::Signer,
};
use zeroize::Zeroizing;

use super::{CallRelayConnection, RelayChannel, wire::take_varint};
use crate::apple::crypto::aes128_ctr;

const TAG_LEN: usize = 6;
const PN_OFFSET: usize = 5;
const SAMPLE_OFFSET: usize = PN_OFFSET + 4;
const SAMPLE_END: usize = SAMPLE_OFFSET + 16;
const MAX_SEND_PACKET: usize = 1200;
pub(super) const MAX_RECEIVE_PACKET: usize = 2048;
const SEND_HEADER_LEN: usize = PN_OFFSET + 4;
const DATAGRAM: u8 = 0x30;
const MAX_PACKET_NUMBER: u32 = 1 << 30;
// A 48-bit relay tag is separate from end-to-end media authentication. Keep the number
// of failed checks per key bounded to limit the chance of accepting a forged relay packet.
const MAX_BAD_TAGS: u32 = 1 << 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayDatagramChannel {
    Media,
    Signaling,
}

impl RelayDatagramChannel {
    fn exporter_labels(self) -> (&'static str, &'static str) {
        match self {
            Self::Media => ("AVC client", "AVC server"),
            Self::Signaling => ("IDS client", "IDS server"),
        }
    }
}

pub(super) fn destination_id(packet: &[u8]) -> Option<[u8; 4]> {
    if packet.len() < SAMPLE_END || packet.len() > MAX_RECEIVE_PACKET || packet[0] & 0xc0 != 0x40 {
        return None;
    }
    packet[1..PN_OFFSET].try_into().ok()
}

pub(super) struct Pod {
    send_id: [u8; 4],
    receive_id: [u8; 4],
    send_keys: DirectionKeys,
    receive_keys: DirectionKeys,
    next_packet: u32,
    received: ReceiveWindow,
    bad_tags: u32,
}

impl Pod {
    pub(super) fn new(
        transport: &CallRelayConnection,
        channel: RelayChannel,
        kind: RelayDatagramChannel,
    ) -> Result<Self> {
        let (client, server) = kind.exporter_labels();
        let mut local = Zeroizing::new([0; 32]);
        let mut remote = Zeroizing::new([0; 32]);
        transport.export_keying_material(local.as_mut(), client)?;
        transport.export_keying_material(remote.as_mut(), server)?;
        Self::from_keys(
            channel.server_connection_id,
            channel.client_connection_id,
            &local,
            &remote,
        )
    }

    pub(super) fn from_keys(
        send_id: [u8; 4],
        receive_id: [u8; 4],
        local: &[u8; 32],
        remote: &[u8; 32],
    ) -> Result<Self> {
        Ok(Self {
            send_id,
            receive_id,
            send_keys: DirectionKeys::derive(local)?,
            receive_keys: DirectionKeys::derive(remote)?,
            next_packet: 0,
            received: ReceiveWindow::default(),
            bad_tags: 0,
        })
    }

    pub(super) fn seal(&mut self, data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        ensure!(
            data.len() < MAX_SEND_PACKET - SEND_HEADER_LEN - TAG_LEN,
            "FaceTime relay datagram exceeds the available packet size"
        );
        let number = self.next_packet;
        ensure!(
            number < MAX_PACKET_NUMBER,
            "FaceTime relay packet key exhausted"
        );
        // Burn the number even if the send later fails or is canceled.
        self.next_packet += 1;

        let pad = SAMPLE_END.saturating_sub(SEND_HEADER_LEN + 1 + data.len() + TAG_LEN);
        let mut packet = Zeroizing::new(Vec::with_capacity(
            SEND_HEADER_LEN + pad + 1 + data.len() + TAG_LEN,
        ));
        packet.push(0x43); // Fixed bit and a full four-byte packet number.
        packet.extend_from_slice(&self.send_id);
        packet.extend_from_slice(&number.to_be_bytes());
        packet.resize(SEND_HEADER_LEN + pad, 0);
        packet.push(DATAGRAM);
        packet.extend_from_slice(data);

        self.send_keys
            .crypt(number, &mut packet[SEND_HEADER_LEN..])?;
        let tag = self.send_keys.tag(&packet, SEND_HEADER_LEN)?;
        packet.extend_from_slice(&tag);
        let mask = self.send_keys.header_mask(&packet)?;
        packet[0] ^= mask[0] & 0x1f;
        for (byte, mask) in packet[PN_OFFSET..SEND_HEADER_LEN]
            .iter_mut()
            .zip(&mask[1..5])
        {
            *byte ^= mask;
        }
        Ok(packet)
    }

    pub(super) fn open(&mut self, mut packet: Vec<u8>) -> Result<Option<Zeroizing<Vec<u8>>>> {
        if destination_id(&packet) != Some(self.receive_id) {
            return Ok(None);
        }
        ensure!(
            self.bad_tags < MAX_BAD_TAGS,
            "FaceTime relay integrity limit reached"
        );
        let mask = self.receive_keys.header_mask(&packet)?;
        packet[0] ^= mask[0] & 0x1f;
        let number_len = usize::from(packet[0] & 3) + 1;
        let header_len = PN_OFFSET + number_len;
        let mut number = 0u32;
        for (byte, mask) in packet[PN_OFFSET..header_len].iter_mut().zip(&mask[1..]) {
            *byte ^= mask;
            number = (number << 8) | u32::from(*byte);
        }
        // These unacknowledged subchannels use progressively wider packet numbers.
        // Interpret the supplied value directly. Guessing a wrapped full number would
        // make the same authenticated truncated header valid with a different nonce.
        if number >= MAX_PACKET_NUMBER || self.received.contains(number) {
            return Ok(None);
        }
        let (authenticated, tag) = packet.split_at(packet.len() - TAG_LEN);
        if !memcmp::eq(&self.receive_keys.tag(authenticated, header_len)?, tag) {
            self.bad_tags += 1;
            return Ok(None);
        }
        self.received.record(number);
        // Reserved bits and a key update are unsupported for this fixed-key channel.
        if packet[0] & 0x1c != 0 {
            return Ok(None);
        }
        let mut packet = Zeroizing::new(packet);
        let payload_end = packet.len() - TAG_LEN;
        let payload = &mut packet[header_len..payload_end];
        self.receive_keys.crypt(number, payload)?;
        Ok(datagram_payload(payload).map(|range| Zeroizing::new(payload[range].to_vec())))
    }
}

#[derive(Default)]
struct ReceiveWindow {
    latest: u32,
    bits: u128,
}

impl ReceiveWindow {
    fn contains(&self, number: u32) -> bool {
        self.latest
            .checked_sub(number)
            .is_some_and(|age| age >= u128::BITS || self.bits & (1 << age) != 0)
    }

    fn record(&mut self, number: u32) {
        if number > self.latest {
            self.bits = self.bits.checked_shl(number - self.latest).unwrap_or(0);
            self.latest = number;
        }
        self.bits |= 1 << (self.latest - number);
    }
}

fn datagram_payload(clear: &[u8]) -> Option<Range<usize>> {
    let mut fields = clear;
    let mut datagram = None;
    while !fields.is_empty() {
        match take_varint(&mut fields).ok()? {
            0 | 1 => {} // Padding and ping have no body.
            0x30 | 0x31 if datagram.is_some() => return None,
            0x30 => return Some(clear.len() - fields.len()..clear.len()),
            0x31 => {
                let length = usize::try_from(take_varint(&mut fields).ok()?).ok()?;
                let start = clear.len() - fields.len();
                fields = fields.get(length..)?;
                datagram = Some(start..start + length);
            }
            _ => return None,
        }
    }
    datagram
}

struct DirectionKeys {
    header: Zeroizing<[u8; 16]>,
    payload: Zeroizing<[u8; 16]>,
    iv: Zeroizing<[u8; 12]>,
    authentication: PKey<Private>,
}

impl DirectionKeys {
    fn derive(secret: &[u8; 32]) -> Result<Self> {
        let authentication = expand_label::<16>(secret, b"qpod hmac")?;
        Ok(Self {
            header: expand_label(secret, b"quic hp")?,
            payload: expand_label(secret, b"quic key")?,
            iv: expand_label(secret, b"quic iv")?,
            authentication: PKey::hmac(authentication.as_ref())?,
        })
    }

    fn header_mask(&self, packet: &[u8]) -> Result<Zeroizing<[u8; 16]>> {
        let mut ctx = CipherCtx::new()?;
        ctx.encrypt_init(
            Some(Cipher::aes_128_ecb()),
            Some(self.header.as_ref()),
            None,
        )?;
        ctx.set_padding(false);
        let mut output = Zeroizing::new([0; 32]);
        let used = ctx.cipher_update(&packet[SAMPLE_OFFSET..SAMPLE_END], Some(output.as_mut()))?;
        ensure!(
            used == 16,
            "Invalid FaceTime relay header protection length"
        );
        let mut mask = Zeroizing::new([0; 16]);
        mask.copy_from_slice(&output[..16]);
        Ok(mask)
    }

    fn crypt(&self, number: u32, data: &mut [u8]) -> Result<()> {
        let mut counter = Zeroizing::new([0; 16]);
        counter[..12].copy_from_slice(self.iv.as_ref());
        for (byte, number) in counter[8..12].iter_mut().zip(number.to_be_bytes()) {
            *byte ^= number;
        }
        aes128_ctr(self.payload.as_ref(), &counter, data)
    }

    fn tag(&self, packet: &[u8], header_len: usize) -> Result<[u8; TAG_LEN]> {
        let mut mac = Signer::new(openssl::hash::MessageDigest::sha256(), &self.authentication)?;
        mac.update(&[u8::try_from(header_len)?])?;
        mac.update(packet)?;
        let mut digest = Zeroizing::new([0; 32]);
        ensure!(
            mac.sign(digest.as_mut())? == digest.len(),
            "Invalid FaceTime relay tag length"
        );
        Ok(digest[..TAG_LEN].try_into()?)
    }
}

fn expand_label<const N: usize>(key: &[u8; 32], label: &[u8]) -> Result<Zeroizing<[u8; N]>> {
    let mut expand = PkeyCtx::new_id(Id::HKDF)?;
    expand.derive_init()?;
    expand.set_hkdf_mode(HkdfMode::EXPAND_ONLY)?;
    expand.set_hkdf_md(Md::sha256())?;
    expand.set_hkdf_key(key)?;
    expand.add_hkdf_info(&(N as u16).to_be_bytes())?;
    expand.add_hkdf_info(&[(6 + label.len()) as u8])?;
    expand.add_hkdf_info(b"tls13 ")?;
    expand.add_hkdf_info(label)?;
    expand.add_hkdf_info(&[0])?; // Empty exporter label context.
    let mut output = Zeroizing::new([0; N]);
    ensure!(
        expand.derive(Some(output.as_mut()))? == N,
        "Invalid FaceTime relay header key length"
    );
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT: [u8; 4] = *b"clnt";
    const RELAY: [u8; 4] = [0x10, 0x20, 0x30, 0x40];
    // These captures were generated independently with Python cryptography's
    // HKDF-Expand and AES, with the RFC 9001 sample location.
    const ZERO: &str = "4710203040b708ae4be0da51145d9075ae634c91701ed7f672";
    const ONE: &str = "45102030406d94791db0adfc84134c3316d30927521147217d";
    const SHORT_ZERO: &str = "5610203040ccd1df397101947fc20f2330a784ed662f6aff71";

    #[test]
    fn matches_packet_vectors_and_rejects_modified_and_replayed_packets() -> Result<()> {
        let secret = std::array::from_fn(|i| i as u8);
        let mut send = Pod::from_keys(RELAY, CLIENT, &secret, &[9; 32])?;
        let mut recv = Pod::from_keys(CLIENT, RELAY, &[9; 32], &secret)?;
        assert_eq!(send.seal(b"hello")?.as_slice(), hex::decode(ZERO)?);
        let mut tampered = hex::decode(ONE)?;
        tampered[15] ^= 2;
        assert!(recv.open(tampered)?.is_none());
        assert_eq!(recv.open(hex::decode(ONE)?)?.unwrap().as_slice(), b"world");
        assert_eq!(recv.open(hex::decode(ZERO)?)?.unwrap().as_slice(), b"hello");
        assert!(recv.open(hex::decode(ONE)?)?.is_none());
        assert!(recv.open(hex::decode(SHORT_ZERO)?)?.is_none());

        send.next_packet = 389;
        assert!(recv.open(send.seal(b"current")?.to_vec())?.is_some());
        assert!(recv.open(hex::decode(SHORT_ZERO)?)?.is_none());
        assert_eq!(recv.received.latest, 389);
        Ok(())
    }
}
