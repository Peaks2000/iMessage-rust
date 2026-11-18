use std::sync::Arc;

use anyhow::{Context, Result, ensure};
use openssl::{
    hash::MessageDigest,
    memcmp,
    pkey::{PKey, Private},
    sign::Signer,
};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{CallMode, apple::crypto::aes128_ctr};

use super::{CallKey, CallMediaDescription, CallRtpDescription, media::CallKeyKind};

const FIXED_HEADER: usize = 12;
const MAX_PACKET: usize = 2048;
const MKI_LEN: usize = 2;
const ROC_SIZE: usize = 4;
const RTP_MAX_ROC: u32 = 0x00ff_ffff;
const BAD_TAG_LIMIT: u16 = 256;
const MEDIA_KEY_LOOKAHEAD: usize = 2;

/// One set of sequence numbers and replay windows for each negotiated stream of a call.
pub(crate) struct CallRtpProtection {
    call: Uuid,
    caller: u64,
    send: Vec<RtpSender>,
    receive: Vec<RtpReceiver>,
}

impl CallRtpProtection {
    pub(crate) fn new(
        call: Uuid,
        caller: u64,
        key: &CallKey,
        local: &CallMediaDescription,
        remote: &CallMediaDescription,
    ) -> Result<Self> {
        ensure!(
            key.kind == CallKeyKind::LocalMedia && key.call_id == call && key.participant != caller,
            "FaceTime outgoing media key belongs to a different call"
        );
        let send = streams(local, local.mode == Some(CallMode::Video))
            .map(|(track, stream)| {
                Ok::<_, anyhow::Error>(RtpSender {
                    stream: stream.clone(),
                    track,
                    keys: RtpKeys::for_stream(key, stream.ssrc)?,
                    latest: None,
                })
            })
            .collect::<Result<_>>()?;
        let receive = streams(remote, local.mode == Some(CallMode::Video))
            .map(|(track, stream)| RtpReceiver {
                stream: stream.clone(),
                track,
                anchor: None,
                candidates: Vec::new(),
                cutover: None,
                replay: PacketWindow::default(),
            })
            .collect();
        Ok(Self {
            call,
            caller,
            send,
            receive,
        })
    }

    pub(crate) fn protect(&mut self, packet: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let rtp = RtpHeader::parse(packet).context("Invalid outgoing FaceTime RTP packet")?;
        let stream = self
            .send
            .iter_mut()
            .find(|s| s.stream.ssrc == rtp.ssrc)
            .context("FaceTime RTP packet names an unnegotiated local stream")?;
        stream.protect(rtp, packet)
    }

    pub(crate) fn open(
        &mut self,
        key: Arc<CallKey>,
        packet: &[u8],
    ) -> Result<Option<Zeroizing<Vec<u8>>>> {
        ensure!(
            key.kind == CallKeyKind::PeerMedia
                && key.call_id == self.call
                && key.participant == self.caller,
            "FaceTime received a media key for a different device"
        );
        let Some(rtp) = RtpHeader::parse(packet) else {
            return Ok(None);
        };
        let Some(stream) = self.receive.iter_mut().find(|s| s.stream.ssrc == rtp.ssrc) else {
            return Ok(None);
        };
        stream.install(key)?;
        stream.open(rtp, packet)
    }
}

fn streams(
    description: &CallMediaDescription,
    video: bool,
) -> impl Iterator<Item = (CallMode, &CallRtpDescription)> {
    std::iter::once((CallMode::Audio, &description.audio)).chain(
        description
            .video
            .as_ref()
            .filter(move |_| video)
            .map(|video| (CallMode::Video, video)),
    )
}

pub(crate) struct RtpHeader {
    size: usize,
    pub(crate) ssrc: u32,
    pub(crate) sequence: u16,
    pub(crate) payload_type: u8,
    #[cfg(feature = "desktop")]
    pub(crate) marker: bool,
    #[cfg(feature = "desktop")]
    pub(crate) timestamp: u32,
}

impl RtpHeader {
    pub(crate) fn parse(bytes: &[u8]) -> Option<Self> {
        if !(FIXED_HEADER..=MAX_PACKET).contains(&bytes.len()) || bytes[0] >> 6 != 2 {
            return None;
        }
        let mut size = FIXED_HEADER + usize::from(bytes[0] & 0x0f) * 4;
        if bytes[0] & 0x10 != 0 {
            let length = u16::from_be_bytes(bytes.get(size + 2..size + 4)?.try_into().ok()?);
            size += 4 + usize::from(length) * 4;
        }
        if size > bytes.len() {
            return None;
        }
        Some(Self {
            ssrc: u32::from_be_bytes(bytes[8..12].try_into().ok()?),
            sequence: u16::from_be_bytes(bytes[2..4].try_into().ok()?),
            payload_type: bytes[1] & 0x7f,
            #[cfg(feature = "desktop")]
            marker: bytes[1] & 0x80 != 0,
            #[cfg(feature = "desktop")]
            timestamp: u32::from_be_bytes(bytes[4..8].try_into().ok()?),
            size,
        })
    }

    #[cfg(feature = "desktop")]
    pub(crate) fn payload<'a>(&self, bytes: &'a [u8]) -> Option<&'a [u8]> {
        let payload = bytes.get(self.size..)?;
        if bytes[0] & 0x20 == 0 {
            return Some(payload);
        }
        self.valid_padding(bytes)
            .then(|| &payload[..payload.len() - usize::from(bytes[bytes.len() - 1])])
    }

    #[cfg(feature = "desktop")]
    pub(crate) fn extension<'a>(&self, bytes: &'a [u8]) -> Option<(u16, &'a [u8])> {
        if bytes.first()? & 0x10 == 0 {
            return None;
        }
        let offset = FIXED_HEADER + usize::from(bytes[0] & 0x0f) * 4;
        let profile = u16::from_be_bytes(bytes.get(offset..offset + 2)?.try_into().ok()?);
        Some((profile, bytes.get(offset + 4..self.size)?))
    }

    fn valid_padding(&self, bytes: &[u8]) -> bool {
        bytes[0] & 0x20 == 0
            || bytes.last().is_some_and(|padding| {
                *padding > 0 && usize::from(*padding) <= bytes.len() - self.size
            })
    }
}

struct RtpSender {
    stream: CallRtpDescription,
    track: CallMode,
    keys: RtpKeys,
    latest: Option<u64>,
}

impl RtpSender {
    fn protect(&mut self, header: RtpHeader, packet: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        ensure!(
            self.stream.payload_types.contains(&header.payload_type)
                && header.valid_padding(packet),
            "Invalid outgoing FaceTime RTP payload"
        );
        let index =
            packet_index(self.latest, header.sequence).context("FaceTime RTP index exhausted")?;
        ensure!(
            self.latest.is_none_or(|latest| index > latest),
            "FaceTime RTP sequence number was already sent"
        );
        let tag_size = tag_length(self.track);
        let hint_size = hint_length(header.sequence);
        let capacity = packet.len() + MKI_LEN + hint_size + tag_size;
        ensure!(
            capacity <= MAX_PACKET,
            "FaceTime RTP packet exceeds the SRTP size limit"
        );

        // A retransmission can reuse an already-protected packet. Re-encrypting a different
        // packet at this index would reuse the counter.
        self.latest = Some(index);
        let mut protected = Zeroizing::new(Vec::with_capacity(capacity));
        protected.extend_from_slice(packet);
        self.keys
            .crypt(header.ssrc, index, &mut protected[header.size..])?;
        let roc = (index >> 16) as u32;
        let tag = self.keys.tag(&protected, roc)?;
        protected.extend_from_slice(&self.keys.mki);
        if hint_size > 0 {
            protected.extend_from_slice(&roc.to_be_bytes()[1..]);
            protected.push(0x20);
        }
        protected.extend_from_slice(&tag[..tag_size]);
        Ok(protected)
    }
}

struct RtpReceiver {
    stream: CallRtpDescription,
    track: CallMode,
    anchor: Option<Arc<CallKey>>,
    candidates: Vec<RtpReceiveKeys>,
    cutover: Option<(u32, u64)>,
    replay: PacketWindow,
}

struct RtpReceiveKeys {
    material: Arc<CallKey>,
    keys: RtpKeys,
    bad_tags: u16,
    last_index: Option<u64>,
}

impl RtpReceiver {
    fn install(&mut self, anchor: Arc<CallKey>) -> Result<()> {
        if self
            .anchor
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, &anchor))
        {
            return Ok(());
        }

        let mut materials = vec![anchor.clone()];
        let mut last = anchor.clone();
        for _ in 0..MEDIA_KEY_LOOKAHEAD {
            let Some(next) = last.next_media_key()? else {
                break;
            };
            last = Arc::new(next);
            materials.push(last.clone());
        }

        let mut active = Vec::with_capacity(materials.len() + 1);
        for material in materials {
            if let Some(index) = self
                .candidates
                .iter()
                .position(|key| key.material.same_material(&material))
            {
                let mut confirmed = self.candidates.swap_remove(index);
                confirmed.last_index = None;
                active.push(confirmed);
            } else {
                active.push(RtpReceiveKeys {
                    keys: RtpKeys::for_stream(&material, self.stream.ssrc)?,
                    material,
                    bad_tags: 0,
                    last_index: None,
                });
            }
        }

        // Only the immediately preceding key can survive a new signed offer. It can fill holes
        // in the replay window, and the first authenticated newer packet fixes the cutover.
        if let Some(latest) = self.replay.latest
            && let Some(index) = self.candidates.iter().position(|old| {
                old.material.generation.checked_add(1) == Some(anchor.generation)
                    && active.iter().all(|key| key.keys.mki != old.keys.mki)
            })
        {
            let mut previous = self.candidates.swap_remove(index);
            previous.last_index = Some(latest.saturating_add(u64::from(u128::BITS)));
            active.push(previous);
        }
        self.candidates = active;
        self.anchor = Some(anchor);
        Ok(())
    }

    fn open(&mut self, header: RtpHeader, packet: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>> {
        if !self.stream.payload_types.contains(&header.payload_type) {
            return Ok(None);
        }
        let tag_size = tag_length(self.track);
        let hint_size = hint_length(header.sequence);
        let Some(body_size) = packet.len().checked_sub(MKI_LEN + hint_size + tag_size) else {
            return Ok(None);
        };
        let (ciphertext, tail) = packet.split_at(body_size);
        if body_size < header.size {
            return Ok(None);
        }
        let Some(state) = self
            .candidates
            .iter_mut()
            .find(|state| memcmp::eq(&state.keys.mki, &tail[..MKI_LEN]))
        else {
            return Ok(None);
        };
        let index = if hint_size > 0 {
            let hint = &tail[MKI_LEN..MKI_LEN + ROC_SIZE];
            if hint[3] & 0x20 == 0 {
                return Ok(None);
            }
            let roc = u32::from_be_bytes([0, hint[0], hint[1], hint[2]]);
            Some((u64::from(roc) << 16) | u64::from(header.sequence))
        } else {
            packet_index(self.replay.latest, header.sequence)
        };
        let Some(index) = index.filter(|index| !self.replay.contains(*index)) else {
            return Ok(None);
        };
        let generation = state.material.generation;
        if state.last_index.is_some_and(|last| index > last)
            || self
                .cutover
                .is_some_and(|(newer, start)| generation < newer && index >= start)
        {
            return Ok(None);
        }
        ensure!(
            state.bad_tags < BAD_TAG_LIMIT,
            "FaceTime media integrity limit reached"
        );
        let tag = state.keys.tag(ciphertext, (index >> 16) as u32)?;
        if !memcmp::eq(&tag[..tag_size], &tail[MKI_LEN + hint_size..]) {
            state.bad_tags += 1;
            return Ok(None);
        }
        self.replay.record(index);
        match self.cutover {
            Some((newer, _)) if generation < newer => (),
            Some((same, start)) if generation == same => {
                self.cutover = Some((generation, start.min(index)))
            }
            _ => self.cutover = Some((generation, index)),
        }
        let mut plaintext = Zeroizing::new(ciphertext.to_vec());
        state
            .keys
            .crypt(header.ssrc, index, &mut plaintext[header.size..])?;
        Ok(header.valid_padding(&plaintext).then_some(plaintext))
    }
}

fn tag_length(track: CallMode) -> usize {
    match track {
        CallMode::Audio => 4,
        CallMode::Video => 10,
    }
}

fn hint_length(sequence: u16) -> usize {
    if sequence & 0x7f == 0 { ROC_SIZE } else { 0 }
}

fn packet_index(latest: Option<u64>, sequence: u16) -> Option<u64> {
    let mut roc = 0;
    if let Some(latest) = latest {
        roc = (latest >> 16) as u32;
        let delta = i32::from(sequence) - i32::from(latest as u16);
        if delta < -32_768 {
            roc = roc.checked_add(1)?;
        } else if delta > 32_768 {
            roc = roc.checked_sub(1)?;
        }
    }
    (roc <= RTP_MAX_ROC).then_some((u64::from(roc) << 16) | u64::from(sequence))
}

#[derive(Default)]
struct PacketWindow {
    latest: Option<u64>,
    seen: u128,
}

impl PacketWindow {
    fn contains(&self, index: u64) -> bool {
        self.latest
            .and_then(|latest| latest.checked_sub(index))
            .is_some_and(|age| age >= u64::from(u128::BITS) || self.seen & (1 << age) != 0)
    }

    fn record(&mut self, index: u64) {
        let latest = self.latest.unwrap_or(index);
        if index >= latest {
            self.seen = if index - latest >= u64::from(u128::BITS) {
                0
            } else {
                self.seen << (index - latest)
            };
            self.latest = Some(index);
        }
        self.seen |= 1 << (self.latest.unwrap_or(index) - index);
    }
}

struct RtpKeys {
    mki: [u8; MKI_LEN],
    encryption: Zeroizing<[u8; 16]>,
    authentication: PKey<Private>,
    salt: Zeroizing<[u8; 14]>,
}

impl RtpKeys {
    fn for_stream(key: &CallKey, ssrc: u32) -> Result<Self> {
        ensure!(
            key.short_identifier_len == 0 || usize::from(key.short_identifier_len) == MKI_LEN,
            "Unsupported FaceTime SRTP key identifier"
        );
        let master = key.key.srtp_key(ssrc)?;
        let mki = key.identifier[..MKI_LEN].try_into()?;
        let (master_key, master_salt) = master.split_at(16);
        Self::derive(master_key, master_salt, mki)
    }

    fn derive(master_key: &[u8], master_salt: &[u8], mki: [u8; MKI_LEN]) -> Result<Self> {
        let authentication = session_key::<32>(master_key, master_salt, 1)?;
        Ok(Self {
            mki,
            encryption: session_key(master_key, master_salt, 0)?,
            authentication: PKey::hmac(authentication.as_ref())?,
            salt: session_key(master_key, master_salt, 2)?,
        })
    }

    fn crypt(&self, ssrc: u32, index: u64, payload: &mut [u8]) -> Result<()> {
        let mut iv = Zeroizing::new([0; 16]);
        iv[4..8].copy_from_slice(&ssrc.to_be_bytes());
        iv[8..].copy_from_slice(&(index << 16).to_be_bytes());
        for (byte, salt) in iv.iter_mut().zip(self.salt.iter()) {
            *byte ^= salt;
        }
        aes128_ctr(self.encryption.as_ref(), &iv, payload)
    }

    fn tag(&self, packet: &[u8], roc: u32) -> Result<Zeroizing<[u8; 32]>> {
        let mut auth = Signer::new(MessageDigest::sha256(), &self.authentication)?;
        auth.update(packet)?;
        auth.update(&roc.to_be_bytes())?;
        let mut digest = Zeroizing::new([0; 32]);
        ensure!(
            auth.sign(digest.as_mut())? == digest.len(),
            "Unexpected SRTP authentication length"
        );
        Ok(digest)
    }
}

fn session_key<const N: usize>(
    master_key: &[u8],
    master_salt: &[u8],
    label: u8,
) -> Result<Zeroizing<[u8; N]>> {
    // RFC 3711 AES-CM KDF with a zero key derivation rate.
    let mut input = Zeroizing::new([0; 16]);
    input[..14].copy_from_slice(master_salt);
    input[7] ^= label;
    let mut output = Zeroizing::new([0; N]);
    aes128_ctr(master_key, &input, output.as_mut())?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apple::CallMediaKey;

    const CALL: Uuid = Uuid::from_u128(1);
    const LOCAL: u64 = 8;
    const PEER: u64 = 9;
    const AUDIO_SSRC: u32 = 0x1234_5678;
    const VIDEO_SSRC: u32 = 0xabcd_ef12;

    fn media_key(participant: u64, kind: CallKeyKind, generation: u32, secret: u8) -> CallKey {
        let mut identifier = [0; 16];
        identifier[1] = 0x10;
        let encoded = participant.to_be_bytes();
        identifier[2..6].copy_from_slice(&encoded[..4]);
        identifier[7..11].copy_from_slice(&encoded[4..]);
        CallKey {
            generation,
            identifier,
            short_identifier_len: 2,
            key: CallMediaKey::fixture([secret; 32], [0xaf; 16]),
            call_id: CALL,
            participant,
            kind,
        }
    }

    fn description() -> CallMediaDescription {
        CallMediaDescription {
            session_id: Uuid::new_v4(),
            mode: Some(CallMode::Video),
            audio: CallRtpDescription {
                ssrc: AUDIO_SSRC,
                payload_types: vec![104],
                hevc_features: Default::default(),
            },
            video: Some(CallRtpDescription {
                ssrc: VIDEO_SSRC,
                payload_types: vec![123],
                hevc_features: Default::default(),
            }),
        }
    }

    #[test]
    fn matches_audio_and_video_wire_vectors() -> Result<()> {
        // RFC 3711 Appendix B.3 master inputs. The packets were encoded
        // independently with Python cryptography and HMAC-SHA256.
        let key = hex::decode("e1f97a0d3e018be0d64fa32c06de4139")?;
        let salt = hex::decode("0ec675ad498afeebb6960b3aabe6")?;
        let mki = [0, 0x10];
        let cases = [
            (
                CallMode::Audio,
                "80681388010203001234567800112233445566778899af",
                "80681388010203001234567854e21a48c03a70957c92d1001036471633",
            ),
            (
                CallMode::Video,
                "90fb508001020300abcdef1230540001001122336744332291a9",
                "90fb508001020300abcdef1230540001001122339ea7b43949c80010000000207a5d4862d435272d255d",
            ),
        ];
        for (track, clear, protected) in cases {
            let clear = hex::decode(clear)?;
            let protected = hex::decode(protected)?;
            let header = RtpHeader::parse(&clear).context("Invalid RTP fixture")?;
            let ssrc = header.ssrc;
            let stream = CallRtpDescription {
                ssrc,
                payload_types: vec![header.payload_type],
                hevc_features: Default::default(),
            };
            let mut sender = RtpSender {
                stream: stream.clone(),
                track,
                keys: RtpKeys::derive(&key, &salt, mki)?,
                latest: None,
            };
            assert_eq!(sender.protect(header, &clear)?.as_slice(), protected);
            let mut receiver = RtpReceiver {
                stream,
                track,
                anchor: None,
                candidates: vec![RtpReceiveKeys {
                    material: Arc::new(media_key(PEER, CallKeyKind::PeerMedia, 1, 1)),
                    keys: RtpKeys::derive(&key, &salt, mki)?,
                    bad_tags: 0,
                    last_index: None,
                }],
                cutover: None,
                replay: PacketWindow::default(),
            };
            let opened = receiver.open(RtpHeader::parse(&protected).unwrap(), &protected)?;
            assert_eq!(
                opened
                    .context("The independent SRTP fixture was rejected")?
                    .as_slice(),
                clear
            );
        }
        Ok(())
    }

    fn audio_packet(sequence: u16) -> Vec<u8> {
        let mut packet = vec![0x80, 104];
        packet.extend_from_slice(&sequence.to_be_bytes());
        packet.extend_from_slice(&1000u32.to_be_bytes());
        packet.extend_from_slice(&AUDIO_SSRC.to_be_bytes());
        packet.extend_from_slice(b"encoded audio");
        packet
    }

    #[test]
    fn opens_audio_and_video_across_a_reordered_key_rotation() -> Result<()> {
        let local = description();
        let remote = description();
        let local_key = media_key(LOCAL, CallKeyKind::LocalMedia, 1, 0x51);
        let initial = Arc::new(media_key(PEER, CallKeyKind::PeerMedia, 1, 0x32));
        let next = Arc::new(initial.next_media_key()?.context("Missing next key")?);
        let following = next.next_media_key()?.context("Missing following key")?;
        let later = following.next_media_key()?.context("Missing later key")?;
        let mut protection = CallRtpProtection::new(CALL, PEER, &local_key, &local, &remote)?;
        let protect = |key: &CallKey, clear: &[u8], stream: &CallRtpDescription, track| {
            RtpSender {
                stream: stream.clone(),
                track,
                keys: RtpKeys::for_stream(key, stream.ssrc)?,
                latest: None,
            }
            .protect(
                RtpHeader::parse(clear).context("Invalid RTP fixture")?,
                clear,
            )
        };
        let audio =
            |key: &CallKey, clear: &[u8]| protect(key, clear, &remote.audio, CallMode::Audio);
        let first = audio_packet(4_998);
        assert_eq!(
            protection
                .open(initial.clone(), &audio(&initial, &first)?)?
                .as_deref(),
            Some(&first)
        );
        let switched = audio_packet(5_000);
        let encrypted = audio(&next, &switched)?;
        assert_eq!(
            protection.open(initial.clone(), &encrypted)?.as_deref(),
            Some(&switched)
        );

        let mut video = audio_packet(5_001);
        video[1] = 123;
        video[8..12].copy_from_slice(&VIDEO_SSRC.to_be_bytes());
        let encrypted_video = protect(
            &following,
            &video,
            remote.video.as_ref().unwrap(),
            CallMode::Video,
        )?;
        assert_eq!(
            protection
                .open(initial.clone(), &encrypted_video)?
                .as_deref(),
            Some(&video)
        );
        let future = audio_packet(5_002);
        let encrypted_future = audio(&later, &future)?;
        assert!(
            protection
                .open(initial.clone(), &encrypted_future)?
                .is_none()
        );

        // Confirmation of the ratchet must preserve per-stream replay state and allow a late
        // packet below the authenticated cutover to fill a hole in the receive window.
        assert!(protection.open(next.clone(), &encrypted)?.is_none());
        assert!(protection.open(next.clone(), &encrypted_video)?.is_none());
        let late = audio_packet(4_999);
        let encrypted_late = audio(&initial, &late)?;
        assert_eq!(
            protection.open(next.clone(), &encrypted_late)?.as_deref(),
            Some(&late)
        );
        assert!(protection.open(next.clone(), &encrypted_late)?.is_none());
        assert!(
            protection
                .open(next.clone(), &audio(&initial, &audio_packet(5_001))?)?
                .is_none()
        );
        assert_eq!(
            protection.open(next, &encrypted_future)?.as_deref(),
            Some(&future)
        );
        Ok(())
    }

    #[test]
    fn resists_replays_and_tampering_across_sequence_rollover_and_rekey() -> Result<()> {
        let local = description();
        let remote = description();
        let my_key = media_key(LOCAL, CallKeyKind::LocalMedia, 1, 0x32);
        let peer_key = Arc::new(media_key(PEER, CallKeyKind::PeerMedia, 1, 0x32));
        let mut protection = CallRtpProtection::new(CALL, PEER, &my_key, &local, &remote)?;
        let first = audio_packet(u16::MAX - 1);
        let protected_first = protection.protect(&first)?;
        assert!(protection.protect(&first).is_err());
        assert_eq!(
            protection
                .open(peer_key.clone(), &protected_first)?
                .unwrap()
                .as_slice(),
            first
        );

        let late = audio_packet(u16::MAX);
        let protected_late = protection.protect(&late)?;
        let rollover = audio_packet(0);
        let protected_rollover = protection.protect(&rollover)?;
        assert!(
            protection
                .open(peer_key.clone(), &protected_first)?
                .is_none()
        );

        let mut tampered_hint = protected_rollover.clone();
        let rollover_hint = tampered_hint.len() - 4 - ROC_SIZE;
        tampered_hint[rollover_hint + 2] ^= 0x08;
        assert!(protection.open(peer_key.clone(), &tampered_hint)?.is_none());
        assert_eq!(
            protection
                .open(peer_key.clone(), &protected_rollover)?
                .unwrap()
                .as_slice(),
            rollover
        );
        assert_eq!(
            protection
                .open(peer_key.clone(), &protected_late)?
                .unwrap()
                .as_slice(),
            late
        );
        assert!(protection.open(peer_key, &protected_rollover)?.is_none());

        let reused_key = Arc::new(media_key(PEER, CallKeyKind::PeerMedia, 2, 0x32));
        assert!(protection.open(reused_key, &protected_first)?.is_none());
        assert!(
            protection
                .open(
                    Arc::new(media_key(PEER + 1, CallKeyKind::PeerMedia, 1, 0x32)),
                    &protected_first
                )
                .is_err()
        );
        let after = audio_packet(1);
        let mut tampered = protection.protect(&after)?;
        tampered[FIXED_HEADER] ^= 1;
        let new_key = Arc::new(media_key(PEER, CallKeyKind::PeerMedia, 3, 0x41));
        assert!(protection.open(new_key.clone(), &tampered)?.is_none());
        let stream = &mut protection.send[0];
        stream.keys = RtpKeys::for_stream(&new_key, AUDIO_SSRC)?;
        let fresh = audio_packet(2);
        let protected_fresh = protection.protect(&fresh)?;
        assert_eq!(
            protection
                .open(new_key, &protected_fresh)?
                .unwrap()
                .as_slice(),
            fresh
        );
        Ok(())
    }
}
