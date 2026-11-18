use std::io::Read;

use anyhow::{Context, Result, ensure};
use flate2::read::ZlibDecoder;
use openssl::{
    memcmp,
    rand::rand_bytes,
    symm::{Cipher, decrypt_aead, encrypt_aead},
};
use plist::Data;
use prost::Message;
use serde::Deserialize;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::CallMode;

use super::media::{CallKey, CallKeyKind, CallKeyOffer};

const LIMIT: usize = 32 * 1024;
const VERSION: u8 = 1;
const HEADER_LEN: usize = 16 + 1 + 12;
const TAG_LEN: usize = 16;
const AAD: [u8; 9] = [VERSION, 0, 0, 0, 0, 0, 0, 0, 0];

/// An encrypted audio/video description for a specific participant and call.
pub struct CallAvcMaterial {
    pub(super) call_id: Uuid,
    pub(super) participant: u64,
    pub(super) material_id: [u8; 20],
    pub(super) ciphertext: Vec<u8>,
}

/// The peer's media session identifier and one-to-one RTP streams.
pub struct CallMediaDescription {
    pub session_id: Uuid,
    pub mode: Option<CallMode>,
    pub audio: CallRtpDescription,
    pub video: Option<CallRtpDescription>,
}

pub struct CallRtpDescription {
    pub ssrc: u32,
    pub payload_types: Vec<u8>,
}

impl CallKeyOffer {
    /// Seal the local AVC plist with the session key from this offer.
    pub fn seal_description(&self, avc_plist: &[u8], mode: CallMode) -> Result<CallAvcMaterial> {
        ensure!(
            self.session.kind == CallKeyKind::LocalSession,
            "Expected a local FaceTime session key"
        );
        let description = CallMediaDescription::parse(avc_plist, Some(mode))?;
        ensure!(
            mode != CallMode::Video || description.video.is_some(),
            "FaceTime video description has no camera stream"
        );
        let mut frame = ParticipantDescription {
            identifier: 0, // The relay assigns the owner's participant ID.
            avc_data: avc_plist.to_vec(),
            mode: Some(match mode {
                CallMode::Audio => 1,
                CallMode::Video => 2,
            }),
        };
        let encoded = Zeroizing::new(frame.encode_to_vec());
        frame.avc_data.zeroize();
        ensure!(
            encoded.len() <= LIMIT,
            "FaceTime media description is too large"
        );

        let mut material_id = [0; 20];
        let mut nonce = [0; 12];
        rand_bytes(&mut material_id)?;
        rand_bytes(&mut nonce)?;
        let key = description_key(&self.session)?;
        let mut tag = [0; TAG_LEN];
        let encrypted = encrypt_aead(
            Cipher::aes_256_gcm(),
            key.as_ref(),
            Some(&nonce),
            &AAD,
            &encoded,
            &mut tag,
        )?;
        let mut ciphertext = Vec::with_capacity(HEADER_LEN + encrypted.len() + TAG_LEN);
        ciphertext.extend_from_slice(&self.session.identifier);
        ciphertext.push(VERSION);
        ciphertext.extend_from_slice(&nonce);
        ciphertext.extend_from_slice(&encrypted);
        ciphertext.extend_from_slice(&tag);
        Ok(CallAvcMaterial {
            call_id: self.session.call_id,
            participant: self.session.participant,
            material_id,
            ciphertext,
        })
    }
}

pub(super) fn valid_ciphertext(bytes: &[u8]) -> bool {
    (HEADER_LEN + TAG_LEN + 1..=HEADER_LEN + LIMIT + TAG_LEN).contains(&bytes.len())
        && bytes[16] == VERSION
}

pub(super) fn open_description(
    call: Uuid,
    participant: u64,
    key: &CallKey,
    bytes: &[u8],
) -> Result<CallMediaDescription> {
    ensure!(
        key.kind == CallKeyKind::PeerSession
            && key.call_id == call
            && key.participant == participant,
        "FaceTime media description has the wrong call or participant key"
    );
    ensure!(
        valid_ciphertext(bytes),
        "Invalid encrypted FaceTime media description"
    );
    ensure!(
        memcmp::eq(&key.identifier, &bytes[..16]),
        "FaceTime media description names a different key"
    );
    let encryption = description_key(key)?;
    let end = bytes.len() - TAG_LEN;
    let plaintext = Zeroizing::new(
        decrypt_aead(
            Cipher::aes_256_gcm(),
            encryption.as_ref(),
            Some(&bytes[17..HEADER_LEN]),
            &AAD,
            &bytes[HEADER_LEN..end],
            &bytes[end..],
        )
        .context("FaceTime media description failed authentication")?,
    );
    let frame = ParticipantDescription::decode(plaintext.as_slice())
        .context("Invalid FaceTime participant description")?;
    let avc_data = Zeroizing::new(frame.avc_data);
    ensure!(
        frame.identifier == 0 || frame.identifier == participant,
        "FaceTime media description names a different participant"
    );
    let mode = match frame.mode {
        Some(1) => Some(CallMode::Audio),
        Some(2) => Some(CallMode::Video),
        _ => None,
    };
    CallMediaDescription::parse(&avc_data, mode)
}

fn description_key(key: &CallKey) -> Result<Zeroizing<[u8; 32]>> {
    let call = key.call_id.to_string().to_ascii_uppercase();
    key.key.derive(&[call.as_bytes(), b"datablob-context"])
}

impl CallMediaDescription {
    /// Parse an AVC plist received in an authenticated FaceTime signaling message.
    pub(crate) fn parse(bytes: &[u8], mode: Option<CallMode>) -> Result<Self> {
        ensure!(
            !bytes.is_empty() && bytes.len() <= LIMIT,
            "Invalid FaceTime AVC description length"
        );
        let avc: AvcPlist = plist::from_bytes(bytes).context("Invalid FaceTime AVC plist")?;
        let session_id =
            Uuid::parse_str(&avc.session_id).context("Invalid FaceTime media session ID")?;
        ensure!(!session_id.is_nil(), "Invalid FaceTime media session ID");
        let streams = if let Some(v2) = avc.b2n {
            V2Description::decode(v2.as_ref())
                .context("Invalid FaceTime V2 negotiation data")?
                .streams()?
        } else {
            let v1 = avc.legacy.context("Missing FaceTime negotiation data")?;
            let mut clear = Zeroizing::new(Vec::new());
            ZlibDecoder::new(v1.as_ref())
                .take((LIMIT + 1) as u64)
                .read_to_end(&mut clear)?;
            ensure!(
                clear.len() <= LIMIT,
                "FaceTime legacy negotiation data is too large"
            );
            let legacy = V1Description::decode(clear.as_slice())
                .context("Invalid FaceTime legacy negotiation data")?;
            (
                legacy.microphone.map(|mic| mic.stream()).transpose()?,
                legacy.camera.map(|cam| cam.stream()).transpose()?,
            )
        };
        let audio = streams
            .0
            .context("FaceTime description has no audio stream")?;
        ensure!(
            streams
                .1
                .as_ref()
                .is_none_or(|video| video.ssrc != audio.ssrc),
            "FaceTime reused a media stream SSRC"
        );
        Ok(Self {
            session_id,
            mode,
            audio,
            video: streams.1,
        })
    }
}

#[derive(Message)]
struct ParticipantDescription {
    #[prost(uint64, tag = "2")]
    identifier: u64,
    #[prost(bytes = "vec", tag = "4")]
    avc_data: Vec<u8>,
    #[prost(int32, optional, tag = "16")]
    mode: Option<i32>,
}

#[derive(Deserialize)]
struct AvcPlist {
    #[serde(rename = "vcSessionParticipantKeyUUID")]
    session_id: String,
    b2n: Option<Data>,
    #[serde(rename = "vcSessionParticipantKeyMediaBlob")]
    legacy: Option<Data>,
}

#[derive(Message)]
struct V2Description {
    #[prost(message, optional, tag = "4")]
    microphone: Option<Microphone>,
    #[prost(message, optional, tag = "5")]
    camera: Option<Camera>,
    #[prost(message, repeated, tag = "7")]
    groups: Vec<StreamGroup>,
}

impl V2Description {
    fn streams(self) -> Result<(Option<CallRtpDescription>, Option<CallRtpDescription>)> {
        let stream = |id, base: Option<CallRtpDescription>| -> Result<_> {
            let mut matching = self.groups.iter().filter(|group| group.id == id);
            let Some(group) = matching.next() else {
                return Ok(base);
            };
            ensure!(
                matching.next().is_none(),
                "Duplicate FaceTime media stream group"
            );
            let Some(settings) = &group.direct else {
                return Ok(base);
            };
            if let Some(base) = &base {
                ensure!(
                    settings.ssrc == base.ssrc,
                    "Conflicting FaceTime media stream SSRC"
                );
            }
            let payloads = group
                .payloads
                .iter()
                .filter_map(|p| u8::try_from(p.rtp).ok());
            let legacy = base
                .as_ref()
                .into_iter()
                .flat_map(|d| d.payload_types.iter().copied());
            Ok(Some(rtp_stream(settings.ssrc, payloads.chain(legacy))?))
        };
        let audio = self.microphone.map(|mic| mic.stream()).transpose()?;
        let video = self.camera.map(|cam| cam.stream()).transpose()?;
        Ok((stream(2, audio)?, stream(1, video)?))
    }
}

#[derive(Message)]
struct Microphone {
    #[prost(uint32, tag = "1")]
    ssrc: u32,
    #[prost(uint32, tag = "2")]
    payloads: u32,
}

impl Microphone {
    fn stream(self) -> Result<CallRtpDescription> {
        rtp_stream(self.ssrc, audio_payloads(self.payloads))
    }
}

#[derive(Message)]
struct Camera {
    #[prost(uint32, tag = "1")]
    ssrc: u32,
    #[prost(message, repeated, tag = "2")]
    codecs: Vec<VideoCodec>,
}

impl Camera {
    fn stream(self) -> Result<CallRtpDescription> {
        rtp_stream(
            self.ssrc,
            self.codecs
                .into_iter()
                .filter_map(|codec| video_payload(codec.kind)),
        )
    }
}

#[derive(Message)]
struct VideoCodec {
    #[prost(uint32, tag = "1")]
    kind: u32,
}

#[derive(Message)]
struct StreamGroup {
    #[prost(uint32, tag = "1")]
    id: u32,
    #[prost(message, repeated, tag = "2")]
    payloads: Vec<Payload>,
    #[prost(message, optional, tag = "4")]
    direct: Option<StreamSsrc>,
}

#[derive(Message)]
struct Payload {
    #[prost(uint32, tag = "2")]
    rtp: u32,
}

#[derive(Message)]
struct StreamSsrc {
    #[prost(uint32, tag = "1")]
    ssrc: u32,
}

#[derive(Message)]
struct V1Description {
    #[prost(message, optional, tag = "3")]
    microphone: Option<V1Microphone>,
    #[prost(message, optional, tag = "4")]
    camera: Option<V1Camera>,
}

#[derive(Message)]
struct V1Microphone {
    #[prost(uint32, tag = "1")]
    ssrc: u32,
    #[prost(uint32, tag = "4")]
    payloads: u32,
}

impl V1Microphone {
    fn stream(self) -> Result<CallRtpDescription> {
        rtp_stream(self.ssrc, audio_payloads(self.payloads))
    }
}

#[derive(Message)]
struct V1Camera {
    #[prost(uint32, tag = "1")]
    ssrc: u32,
    #[prost(message, repeated, tag = "3")]
    codecs: Vec<VideoCodec>,
}

impl V1Camera {
    fn stream(self) -> Result<CallRtpDescription> {
        rtp_stream(
            self.ssrc,
            self.codecs
                .into_iter()
                .filter_map(|codec| video_payload(codec.kind)),
        )
    }
}

fn audio_payloads(flags: u32) -> impl Iterator<Item = u8> {
    [(1, 104), (2, 108), (4, 13), (8, 20), (64, 101)]
        .into_iter()
        .filter_map(move |(flag, number)| (flags & flag != 0).then_some(number))
}

fn video_payload(kind: u32) -> Option<u8> {
    match kind {
        0 | 1 => Some(123),
        2 => Some(100),
        _ => None,
    }
}

fn rtp_stream(ssrc: u32, numbers: impl Iterator<Item = u8>) -> Result<CallRtpDescription> {
    ensure!(ssrc != 0, "Invalid FaceTime media stream SSRC");
    let mut payload_types: Vec<_> = numbers.filter(|id| *id <= 127).collect();
    payload_types.sort_unstable();
    payload_types.dedup();
    Ok(CallRtpDescription {
        ssrc,
        payload_types,
    })
}

#[cfg(test)]
pub(super) mod tests {
    use std::{io::Write, sync::Arc};

    use flate2::{Compression, write::ZlibEncoder};

    use super::*;
    use crate::apple::facetime::{CallMediaKey, CallPeerKeys};

    pub(crate) const CALL: Uuid = Uuid::from_u128(0x6159_b337_c2f2_4467_9e19_dfc6_8f4e_5659);
    pub(crate) const CALLER: u64 = 55;
    pub(crate) const LOCAL: u64 = 77;
    const MEDIA_ID: &str = "D9818136-77C4-4A54-BAEC-4CF05BE09F18";
    // Python plistlib, manually encoded Protobuf and Python cryptography's
    // HKDF-SHA256 and AESGCM produced these fixed input and wire vectors.
    const AVC: &str = concat!(
        "62706c6973743030d2010203045362326e5f101b766353657373696f6e5061727469636970616e744b657955554944",
        "4f1018220808c0e080810110412a0c0880e18183051200120208025f102444393831383133362d373743342d344135",
        "342d424145432d344346303542453039463138080d112f4a000000000000010100000000000000050000000000000",
        "0000000000000000071",
    );
    const ENCRYPTED: &str = concat!(
        "0303030303030303030303030303030301000102030405060708090a0b35cb4c777276396e05f4a90498f08d36ef",
        "8880b4e7bc4cabcfb5620191f4589fdcdf81102de562fe412dc93bd7b8c918b0af898c0721655651d63e8be03f8cd",
        "79072e3910def3b1d28988b31eb8505581e089083654be44b619eccce3eb500e00ed0bd7a0bf12289fb168c55a935",
        "bfa31d544ef2d9091f9542226a708673b4038034ee63c51d3f292b3b71bfbb8cae19a1ce18283199ba3dca88710cc",
        "91d9ea26ac56a85e9bdfe2964952eccf496",
    );

    fn fixture_key(participant: u64, kind: CallKeyKind) -> CallKey {
        CallKey {
            generation: 1,
            identifier: [3; 16],
            short_identifier_len: 0,
            key: CallMediaKey::fixture([1; 32], [2; 16]),
            call_id: CALL,
            participant,
            kind,
        }
    }

    pub(crate) fn remote_keys() -> CallPeerKeys {
        CallPeerKeys {
            session: Some(Arc::new(fixture_key(CALLER, CallKeyKind::PeerSession))),
            media: None,
        }
    }

    pub(crate) fn opaque_peer_offer() -> Result<Vec<u8>> {
        Ok(hex::decode(ENCRYPTED)?)
    }

    pub(crate) fn local_offer() -> Result<CallAvcMaterial> {
        let keys = CallKeyOffer {
            payload: Vec::new(),
            session: fixture_key(LOCAL, CallKeyKind::LocalSession),
            media: fixture_key(LOCAL, CallKeyKind::Media),
        };
        keys.seal_description(&hex::decode(AVC)?, CallMode::Video)
    }

    #[test]
    fn decrypts_the_peer_description_only_for_its_call_participant_and_session_key() -> Result<()> {
        let encrypted = opaque_peer_offer()?;
        let key = fixture_key(CALLER, CallKeyKind::PeerSession);
        let opened = open_description(CALL, CALLER, &key, &encrypted)?;
        assert_eq!(opened.mode, Some(CallMode::Video));
        assert_eq!(opened.session_id, Uuid::parse_str(MEDIA_ID)?);
        assert_eq!(opened.audio.ssrc, 0x1020_3040);
        assert_eq!(opened.audio.payload_types, [101, 104]);
        let video = opened.video.context("Missing video fixture")?;
        assert_eq!(video.ssrc, 0x5060_7080);
        assert_eq!(video.payload_types, [100, 123]);

        let mut damaged = encrypted.clone();
        *damaged.last_mut().unwrap() ^= 1;
        assert!(open_description(CALL, CALLER, &key, &damaged).is_err());
        assert!(open_description(Uuid::new_v4(), CALLER, &key, &encrypted).is_err());
        // The encrypted frame names CALLER. Even with its key, resist relabeling.
        let moved_key = fixture_key(LOCAL, CallKeyKind::PeerSession);
        assert!(open_description(CALL, LOCAL, &moved_key, &encrypted).is_err());
        let media_key = fixture_key(CALLER, CallKeyKind::Media);
        assert!(open_description(CALL, CALLER, &media_key, &encrypted).is_err());
        assert!(open_description(CALL, CALLER, &key, &encrypted[..HEADER_LEN]).is_err());
        Ok(())
    }

    #[test]
    fn outgoing_descriptions_use_fresh_nonces_and_open_with_the_exchanged_key() -> Result<()> {
        let first = local_offer()?;
        let second = local_offer()?;
        assert_ne!(first.material_id, second.material_id);
        assert_ne!(
            first.ciphertext[17..HEADER_LEN],
            second.ciphertext[17..HEADER_LEN]
        );
        let key = fixture_key(LOCAL, CallKeyKind::PeerSession);
        let result = open_description(CALL, LOCAL, &key, &first.ciphertext)?;
        assert_eq!(result.audio.ssrc, 0x1020_3040);
        assert_eq!(result.mode, Some(CallMode::Video));
        Ok(())
    }

    #[test]
    fn reads_a_zlib_legacy_description_and_bounds_decompression() -> Result<()> {
        let description = V1Description {
            microphone: Some(V1Microphone {
                ssrc: 0x1020_3040,
                payloads: 1,
            }),
            camera: None,
        };
        let encode = |raw: &[u8]| -> Result<Vec<u8>> {
            let mut compressor = ZlibEncoder::new(Vec::new(), Compression::fast());
            compressor.write_all(raw)?;
            let mut plist = Vec::new();
            plist::to_writer_binary(
                &mut plist,
                &plist::Dictionary::from_iter([
                    ("vcSessionParticipantKeyUUID", plist::Value::from(MEDIA_ID)),
                    (
                        "vcSessionParticipantKeyMediaBlob",
                        plist::Value::Data(compressor.finish()?),
                    ),
                ]),
            )?;
            Ok(plist)
        };
        let decoded = CallMediaDescription::parse(
            &encode(&description.encode_to_vec())?,
            Some(CallMode::Audio),
        )?;
        assert_eq!(decoded.audio.ssrc, 0x1020_3040);
        assert_eq!(decoded.audio.payload_types, [104]);
        assert!(decoded.video.is_none());
        assert!(CallMediaDescription::parse(&encode(&vec![0; LIMIT + 1])?, None).is_err());
        Ok(())
    }
}
