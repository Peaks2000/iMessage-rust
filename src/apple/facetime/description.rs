use std::io::Read;
#[cfg(feature = "desktop")]
use std::io::Write;
#[cfg(feature = "desktop")]
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, ensure};
use flate2::read::ZlibDecoder;
#[cfg(feature = "desktop")]
use flate2::{Compression, write::ZlibEncoder};
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

pub(crate) const AAC_ELD_PT: u8 = 104;
pub(crate) const AUDIO_RED_PT: u8 = 20;
#[cfg(feature = "desktop")]
pub(crate) const AAC_ELD_SAMPLE_RATE: u32 = 24_000;

#[cfg(feature = "desktop")]
pub(crate) struct CallDevice {
    pub(crate) relay_os_version: String,
    pub(crate) model: String,
    build: String,
}

#[cfg(feature = "desktop")]
impl CallDevice {
    pub(crate) fn from_ids_user_agent(agent: &str) -> Option<Self> {
        let mut fields = agent.strip_prefix('[')?.strip_suffix(']')?.splitn(4, ',');
        let os = fields.next()?;
        let version = fields.next()?;
        let build = fields.next()?;
        let model = fields.next()?;
        if !matches!(os, "macOS" | "Mac OS X" | "iPhone OS" | "iOS" | "iPadOS")
            || [version, build, model]
                .iter()
                .any(|part| part.trim().is_empty())
        {
            return None;
        }
        Some(Self {
            relay_os_version: format!("{os},{version},{build}"),
            model: model.into(),
            build: build.into(),
        })
    }

    pub(crate) fn audio_description(&self) -> Result<Vec<u8>> {
        let mut identifiers = [0u8; 8];
        rand_bytes(&mut identifiers)?;
        let [a, b, c, d, e, f, g, h] = identifiers;
        let audio_ssrc = u32::from_be_bytes([a, b, c, d]).max(1);
        let call_id = u32::from_be_bytes([e, f, g, h]).max(1);
        let encodable = 1; // AAC-ELD.
        let receivable = encodable | 8; // RED can carry AAC-ELD in the primary block.
        let time = SystemTime::now().duration_since(UNIX_EPOCH)?;
        let ntp_seconds = time.as_secs().wrapping_add(2_208_988_800) as u32;
        let ntp_fraction = (u64::from(time.subsec_nanos()) << 32) / 1_000_000_000;
        let ntp_time = (u64::from(ntp_seconds) << 32) | ntp_fraction;
        let v2 = V2Description {
            general: Some(V2General { ntp_time }),
            microphone: Some(Microphone {
                ssrc: audio_ssrc,
                payloads: receivable,
                cipher_suites: 5,
            }),
            groups: vec![StreamGroup {
                id: 2,
                direct: Some(StreamSsrc { ssrc: audio_ssrc }),
                payloads: [AAC_ELD_PT, AUDIO_RED_PT]
                    .into_iter()
                    .map(|pt| Payload {
                        rtp: u32::from(pt),
                        packet_time_ms: (pt == AAC_ELD_PT).then_some(20),
                        sample_rate: Some(AAC_ELD_SAMPLE_RATE),
                    })
                    .collect(),
            }],
            camera: None,
        };
        let v1 = V1Description {
            microphone: Some(V1Microphone {
                ssrc: audio_ssrc,
                support_flags: 1,
                payloads: receivable,
                use_sbr: Some(false),
            }),
            camera: None,
            user_agent: Some("Viceroy 1.7.0".into()),
            ntp_time: Some(ntp_time),
            blob_version: Some(2),
            media_control_version: Some(2),
            facetime: Some(V1FaceTime { one_to_one: true }),
        };
        let info = CallInfo {
            call_id,
            client_version: 1,
            device_type: self.model.clone(),
            os_build: self.build.clone(),
        };
        let mut compress = ZlibEncoder::new(Vec::new(), Compression::fast());
        compress.write_all(&v1.encode_to_vec())?;
        let mut avc = Vec::new();
        plist::to_writer_binary(
            &mut avc,
            &plist::Dictionary::from_iter([
                (
                    "vcSessionParticipantKeyUUID",
                    plist::Value::from(Uuid::new_v4().to_string().to_ascii_uppercase()),
                ),
                ("b2n", plist::Value::Data(v2.encode_to_vec())),
                (
                    "vcSessionParticipantKeyMediaBlob",
                    plist::Value::Data(compress.finish()?),
                ),
                (
                    "vcSessionParticipantKeyCallInfoBlob",
                    plist::Value::Data(info.encode_to_vec()),
                ),
            ]),
        )?;
        Ok(avc)
    }
}

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

#[derive(Clone)]
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
    #[prost(message, optional, tag = "1")]
    general: Option<V2General>,
    #[prost(message, optional, tag = "4")]
    microphone: Option<Microphone>,
    #[prost(message, optional, tag = "5")]
    camera: Option<Camera>,
    #[prost(message, repeated, tag = "7")]
    groups: Vec<StreamGroup>,
}

#[derive(Message)]
struct V2General {
    #[prost(uint64, tag = "1")]
    ntp_time: u64,
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
    #[prost(int32, tag = "3")]
    cipher_suites: i32,
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
    #[prost(uint32, optional, tag = "3")]
    packet_time_ms: Option<u32>,
    #[prost(uint32, optional, tag = "7")]
    sample_rate: Option<u32>,
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
    #[prost(string, optional, tag = "6")]
    user_agent: Option<String>,
    #[prost(uint64, optional, tag = "13")]
    ntp_time: Option<u64>,
    #[prost(uint32, optional, tag = "14")]
    blob_version: Option<u32>,
    #[prost(uint32, optional, tag = "16")]
    media_control_version: Option<u32>,
    #[prost(message, optional, tag = "17")]
    facetime: Option<V1FaceTime>,
}

#[derive(Message)]
struct V1FaceTime {
    #[prost(bool, tag = "3")]
    one_to_one: bool,
}

#[cfg(feature = "desktop")]
#[derive(Message)]
struct CallInfo {
    #[prost(uint32, tag = "1")]
    call_id: u32,
    #[prost(uint32, tag = "2")]
    client_version: u32,
    #[prost(string, tag = "3")]
    device_type: String,
    #[prost(string, tag = "5")]
    os_build: String,
}

#[derive(Message)]
struct V1Microphone {
    #[prost(uint32, tag = "1")]
    ssrc: u32,
    #[prost(uint32, tag = "3")]
    support_flags: u32,
    #[prost(uint32, tag = "4")]
    payloads: u32,
    #[prost(bool, optional, tag = "6")]
    use_sbr: Option<bool>,
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
    [
        (1, AAC_ELD_PT),
        (2, 108),
        (4, 13),
        (8, AUDIO_RED_PT),
        (64, 101),
    ]
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
            media: fixture_key(LOCAL, CallKeyKind::LocalMedia),
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
        let media_key = fixture_key(CALLER, CallKeyKind::PeerMedia);
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
                ..Default::default()
            }),
            ..Default::default()
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

    #[cfg(feature = "desktop")]
    #[test]
    fn creates_matching_modern_and_legacy_audio_offers_from_the_registered_device() -> Result<()> {
        let device = CallDevice::from_ids_user_agent("[macOS,15.7.5,24G624,Mac14,2]").unwrap();
        assert_eq!(device.relay_os_version, "macOS,15.7.5,24G624");
        assert_eq!(device.model, "Mac14,2");
        assert!(CallDevice::from_ids_user_agent("[macOS,15.7.5,24G624,]").is_none());
        assert!(CallDevice::from_ids_user_agent("local").is_none());
        let offer = device.audio_description()?;
        let modern = CallMediaDescription::parse(&offer, Some(CallMode::Audio))?;
        assert_ne!(modern.audio.ssrc, 0);
        assert_eq!(modern.audio.payload_types, [AUDIO_RED_PT, AAC_ELD_PT]);
        assert!(modern.video.is_none());

        let mut plist: plist::Dictionary = plist::from_bytes(&offer)?;
        let b2n = plist.remove("b2n").unwrap();
        let streams = V2Description::decode(b2n.as_data().unwrap())?;
        let mic = streams.microphone.unwrap();
        assert_eq!(mic.cipher_suites, 5);
        let group = &streams.groups[0];
        assert_eq!(group.id, 2);
        assert_eq!(group.payloads[0].packet_time_ms, Some(20));
        assert_eq!(group.payloads[0].sample_rate, Some(AAC_ELD_SAMPLE_RATE));

        let info = CallInfo::decode(
            plist["vcSessionParticipantKeyCallInfoBlob"]
                .as_data()
                .unwrap(),
        )?;
        assert_eq!(info.device_type, device.model);
        assert_eq!(info.os_build, "24G624");
        let mut legacy_avc = Vec::new();
        plist::to_writer_binary(&mut legacy_avc, &plist)?;
        let legacy = CallMediaDescription::parse(&legacy_avc, Some(CallMode::Audio))?;
        assert_eq!(legacy.session_id, modern.session_id);
        assert_eq!(legacy.audio.ssrc, modern.audio.ssrc);
        assert_eq!(legacy.audio.payload_types, modern.audio.payload_types);
        let second = CallMediaDescription::parse(&device.audio_description()?, None)?;
        assert_ne!(second.session_id, modern.session_id);
        Ok(())
    }
}
