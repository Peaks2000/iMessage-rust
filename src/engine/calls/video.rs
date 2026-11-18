//! One-to-one FaceTime HEVC media carried inside authenticated RTP.
mod format;
mod linux;
mod session;

pub use linux::{DecodedFrames, HevcCamera, HevcDecoder, VIDEO_HEIGHT, VIDEO_WIDTH, VideoFrame};
pub use session::VideoCallOptions;
pub(super) use session::VideoSession;

use std::collections::BTreeMap;

use anyhow::{Context, Result, ensure};
use openssl::rand::rand_bytes;
use zeroize::Zeroizing;

use crate::apple::CallRtpHeader as RtpHeader;

pub const HEVC_PAYLOAD_TYPE: u8 = 100;
pub const FRAME_RATE: u32 = 15;
const CLOCK_RATE: u32 = 90_000;
const MAX_PAYLOAD: usize = 1024;
const MAX_PACKETS: usize = 256;
const MAX_FRAME: usize = MAX_PACKETS * MAX_PAYLOAD;
const ANNEX_B: [u8; 4] = [0, 0, 0, 1];
const DESCRIPTION_TAG: [u8; 4] = [0x92, 0xe6, 0xc0, 0xa3];
const LANDSCAPE_VIDEO_CONTROL: u16 = 0x8301;

/// The subset of FaceTime video features supported by this HEVC driver.
#[derive(Clone, Copy, Default)]
pub struct HevcFeatures(u8);

impl HevcFeatures {
    pub const SUPPORTED: u8 = 0x3c;

    /// Intersect the peer's enabled feature byte with the locally offered features.
    pub fn negotiate(peer_features: u8) -> Self {
        Self(peer_features & Self::SUPPORTED)
    }

    fn features(self) -> impl Iterator<Item = &'static [u8]> {
        // CH1, CR, CF and FA in Viceroy's feature order.
        let fields: [&[u8]; 4] = [&[0, 0], &[0x65, 0x43, 0, 0], &[], &[0x3e, 0x3e, 0xc0, 0xc0]];
        fields
            .into_iter()
            .enumerate()
            .filter_map(move |(i, bytes)| (self.0 & (4 << i) != 0).then_some(bytes))
    }

    fn append(self, nal: &[u8]) -> Zeroizing<Vec<u8>> {
        let mut wire = Zeroizing::new(nal.to_vec());
        if self.0 == 0 {
            return wire;
        }
        let mut mask = 0;
        for (index, field) in self.features().enumerate() {
            if !field.is_empty() {
                mask |= 1 << index;
                for &byte in field {
                    append_escaped(&mut wire, byte);
                }
            }
        }
        append_escaped(&mut wire, mask);
        wire
    }

    fn strip(self, wire: &[u8]) -> Option<&[u8]> {
        if self.0 == 0 {
            return Some(wire);
        }
        let (&mask, content) = wire.split_last()?;
        if mask >> self.0.count_ones() != 0 {
            return None;
        }
        let size: usize = self
            .features()
            .map(<[u8]>::len)
            .enumerate()
            .filter_map(|(index, len)| (mask & (1 << index) != 0).then_some(len))
            .sum();
        let mut end = content.len();
        if mask <= 3 && content.ends_with(&[0, 0, 3]) {
            end -= 1;
        }
        for _ in 0..size {
            end = end.checked_sub(1)?;
            if content[..end].ends_with(&[0, 0, 3]) && content[end] <= 3 {
                end -= 1;
            }
        }
        (end >= 2).then(|| &content[..end])
    }
}

fn append_escaped(output: &mut Vec<u8>, byte: u8) {
    if byte <= 3 && output.ends_with(&[0, 0]) {
        output.push(3);
    }
    output.push(byte);
}

/// A camera access unit converted to FaceTime's HEVC RTP format.
pub struct HevcPacketizer {
    ssrc: u32,
    width: u16,
    height: u16,
    sequence: u16,
    timestamp: u32,
    frame_number: u16,
    features: HevcFeatures,
}

impl HevcPacketizer {
    pub fn new(ssrc: u32, width: u16, height: u16, features: HevcFeatures) -> Result<Self> {
        ensure!(
            ssrc != 0 && width != 0 && height != 0,
            "Invalid FaceTime camera stream"
        );
        let mut seed = [0u8; 8];
        rand_bytes(&mut seed)?;
        Ok(Self {
            ssrc,
            width,
            height,
            sequence: u16::from_be_bytes([seed[0], seed[1]]),
            timestamp: u32::from_be_bytes([seed[2], seed[3], seed[4], seed[5]]),
            frame_number: u16::from_be_bytes([seed[6], seed[7]]),
            features,
        })
    }

    /// Packetize one Annex-B frame, including a QuickTime description on keyframes.
    pub fn packetize(&mut self, frame: &[u8]) -> Result<Vec<Zeroizing<Vec<u8>>>> {
        ensure!(
            frame.len() <= MAX_FRAME,
            "FaceTime video frame is too large"
        );
        let nals = annex_b_nals(frame).collect::<Vec<_>>();
        let keyframe = nals.iter().any(|nal| is_keyframe(nal));
        let mut payloads = Vec::new();
        if keyframe {
            payloads.push(format::describe(&nals, self.width, self.height)?);
        }
        for nal in nals {
            match nal_type(nal).context("Invalid camera HEVC NAL header")? {
                35..=40 => continue, // AUD and optional metadata are not camera slices.
                32..=34 if keyframe => continue, // Sent in hvcC.
                0..=31 => split_hevc_nal(&self.features.append(nal), &mut payloads)?,
                32..=47 => split_hevc_nal(nal, &mut payloads)?,
                _ => anyhow::bail!("Invalid camera HEVC NAL type"),
            }
        }
        let count = payloads.len();
        ensure!(
            (1..=MAX_PACKETS).contains(&count),
            "Invalid FaceTime frame packet count"
        );
        let mut packets = Vec::with_capacity(count);
        for (index, payload) in payloads.into_iter().enumerate() {
            let marker = index + 1 == count;
            let mut rtp = Zeroizing::new(Vec::with_capacity(20 + payload.len()));
            rtp.extend_from_slice(&[0x90, HEVC_PAYLOAD_TYPE | (u8::from(marker) << 7)]);
            rtp.extend_from_slice(&self.sequence.to_be_bytes());
            rtp.extend_from_slice(&self.timestamp.to_be_bytes());
            rtp.extend_from_slice(&self.ssrc.to_be_bytes());
            let control = LANDSCAPE_VIDEO_CONTROL | if keyframe { 0x10 } else { 0 };
            rtp.extend_from_slice(&control.to_be_bytes());
            rtp.extend_from_slice(&1u16.to_be_bytes());
            rtp.extend_from_slice(&(count as u16).to_be_bytes());
            rtp.extend_from_slice(&self.frame_number.to_be_bytes());
            rtp.extend_from_slice(&payload);
            packets.push(rtp);
            self.sequence = self.sequence.wrapping_add(1);
        }
        self.timestamp = self.timestamp.wrapping_add(CLOCK_RATE / FRAME_RATE);
        self.frame_number = self.frame_number.wrapping_add(1);
        Ok(packets)
    }
}

fn split_hevc_nal(nal: &[u8], payloads: &mut Vec<Zeroizing<Vec<u8>>>) -> Result<()> {
    if nal.len() <= MAX_PAYLOAD {
        payloads.push(Zeroizing::new(nal.to_vec()));
    } else {
        let kind = nal_type(nal).context("Invalid HEVC fragment header")?;
        let fragments = nal[2..].chunks(MAX_PAYLOAD - 3);
        let count = fragments.len();
        for (index, data) in fragments.enumerate() {
            let mut part = Zeroizing::new(Vec::with_capacity(3 + data.len()));
            let flags = (u8::from(index == 0) << 7) | (u8::from(index + 1 == count) << 6);
            part.extend_from_slice(&[(nal[0] & 0x81) | (49 << 1), nal[1], flags | kind]);
            part.extend_from_slice(data);
            payloads.push(part);
        }
    }
    ensure!(
        payloads.len() <= MAX_PACKETS,
        "FaceTime HEVC packet count exceeds limit"
    );
    Ok(())
}

pub(super) fn nal_type(nal: &[u8]) -> Option<u8> {
    let head = nal.get(..2)?;
    (head[0] & 0x80 == 0 && head[1] & 7 != 0).then_some((head[0] >> 1) & 0x3f)
}

fn is_keyframe(nal: &[u8]) -> bool {
    matches!(nal_type(nal), Some(16..=23))
}

fn annex_b_nals(mut data: &[u8]) -> impl Iterator<Item = &[u8]> {
    std::iter::from_fn(move || {
        let start = data.windows(3).position(|bytes| bytes == [0, 0, 1])? + 3;
        data = &data[start..];
        let end = data
            .windows(3)
            .position(|bytes| bytes == [0, 0, 1])
            .unwrap_or(data.len());
        let length = data[..end]
            .iter()
            .rposition(|byte| *byte != 0)
            .map_or(0, |offset| offset + 1);
        let nal = &data[..length];
        data = &data[end..];
        Some(nal)
    })
}

/// An authenticated peer's HEVC video stream. Incomplete frames never reach the decoder.
pub struct HevcReceiver {
    ssrc: u32,
    features: HevcFeatures,
    frame: Option<VideoPackets>,
    retired: Option<u32>,
    last_sequence: Option<u16>,
    parameters: Zeroizing<Vec<u8>>,
    needs_keyframe: bool,
}

impl HevcReceiver {
    pub fn new(ssrc: u32, features: HevcFeatures) -> Self {
        Self {
            ssrc,
            features,
            frame: None,
            retired: None,
            last_sequence: None,
            parameters: Zeroizing::new(Vec::new()),
            needs_keyframe: true,
        }
    }

    /// Reassemble clear RTP produced by the call engine after it verifies the peer's SRTP.
    pub fn receive(&mut self, packet: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        let header = RtpHeader::parse(packet)?;
        if header.ssrc != self.ssrc
            || header.payload_type != HEVC_PAYLOAD_TYPE
            || self
                .retired
                .is_some_and(|old| !newer_timestamp(header.timestamp, old))
        {
            return None;
        }
        let prefix = packet_control(&header, packet)?;
        let payload = header.payload(packet)?;
        if let Some(frame) = &self.frame
            && frame.timestamp != header.timestamp
        {
            if !newer_timestamp(header.timestamp, frame.timestamp) {
                return None;
            }
            self.frame = None;
            self.needs_keyframe = true;
        }

        let frame = self.frame.get_or_insert_with(|| VideoPackets {
            timestamp: header.timestamp,
            marker: None,
            expected: prefix,
            payloads: BTreeMap::new(),
            bytes: 0,
        });
        let added = frame.insert(&header, prefix, payload);
        let Some((first, marker)) = frame.complete().filter(|_| added) else {
            if !added {
                self.retired = Some(header.timestamp);
                self.frame = None;
                self.needs_keyframe = true;
            }
            return None;
        };
        let frame = self.frame.take()?;
        self.retired = Some(frame.timestamp);
        let discontinuity = self
            .last_sequence
            .replace(marker)
            .is_some_and(|last| last.wrapping_add(1) != first);
        self.needs_keyframe |= discontinuity;
        let bytes = match reconstruct(frame, first, self.features, &mut self.parameters) {
            Some(bytes) => bytes,
            None => {
                self.needs_keyframe = true;
                return None;
            }
        };
        let mut has_picture = false;
        let mut has_keyframe = false;
        let mut flags = 0;
        for nal in annex_b_nals(&bytes) {
            match nal_type(nal) {
                Some(16..=23) => {
                    has_picture = true;
                    has_keyframe = true;
                }
                Some(0..=31) => has_picture = true,
                Some(32..=34) => flags |= 1 << (nal_type(nal)? - 32),
                _ => (),
            }
        }
        if !has_picture || (self.needs_keyframe && !(has_keyframe && flags == 7)) {
            return None;
        }
        self.needs_keyframe = false;
        Some(bytes)
    }
}

fn newer_timestamp(timestamp: u32, older: u32) -> bool {
    (1..0x8000_0000).contains(&timestamp.wrapping_sub(older))
}

fn packet_control(header: &RtpHeader, packet: &[u8]) -> Option<Option<u16>> {
    let Some((profile, bytes)) = header.extension(packet) else {
        return Some(None);
    };
    let mut offset = if profile & 2 == 0 { 0 } else { 4 };
    let expected = if profile >> 14 == 2 && profile & 1 != 0 {
        let control = bytes.get(offset..offset + 4)?;
        offset += 4;
        let count = u16::from_be_bytes([control[0], control[1]]);
        if !(1..=MAX_PACKETS as u16).contains(&count) {
            return None;
        }
        Some(count)
    } else {
        None
    };
    if profile & 4 != 0 {
        let fec = u32::from_be_bytes(bytes.get(offset..offset + 4)?.try_into().ok()?);
        let data_mask = match fec >> 30 {
            0 => 0x0080_0000,
            1 => 0x0040_0000,
            _ => return None,
        };
        if fec & data_mask == 0 {
            return None; // Parity is not a decoder input.
        }
    }
    Some(expected)
}

struct VideoPackets {
    timestamp: u32,
    marker: Option<u16>,
    expected: Option<u16>,
    payloads: BTreeMap<u16, Zeroizing<Vec<u8>>>,
    bytes: usize,
}

impl VideoPackets {
    fn insert(&mut self, header: &RtpHeader, expected: Option<u16>, payload: &[u8]) -> bool {
        if expected != self.expected
            || self.payloads.len() >= MAX_PACKETS
            || self.bytes + payload.len() > MAX_FRAME
            || (header.marker && self.marker.is_some_and(|marker| marker != header.sequence))
        {
            return false;
        }
        if header.marker {
            self.marker = Some(header.sequence);
        }
        self.payloads.entry(header.sequence).or_insert_with(|| {
            self.bytes += payload.len();
            Zeroizing::new(payload.to_vec())
        });
        true
    }

    fn complete(&self) -> Option<(u16, u16)> {
        let marker = self.marker?;
        let count = self.expected.map_or(self.payloads.len(), usize::from);
        if count == 0 || self.payloads.len() != count {
            return None;
        }
        let first = marker.wrapping_sub((count - 1) as u16);
        (0..count)
            .all(|index| {
                self.payloads
                    .contains_key(&first.wrapping_add(index as u16))
            })
            .then_some((first, marker))
    }
}

fn reconstruct(
    mut frame: VideoPackets,
    first: u16,
    features: HevcFeatures,
    parameters: &mut Zeroizing<Vec<u8>>,
) -> Option<Zeroizing<Vec<u8>>> {
    let mut annex = Zeroizing::new(Vec::new());
    let mut fragmented: Option<Zeroizing<Vec<u8>>> = None;
    for offset in 0..frame.payloads.len() {
        let payload = frame.payloads.remove(&first.wrapping_add(offset as u16))?;
        if let Some(description) = payload.strip_prefix(&DESCRIPTION_TAG) {
            if offset != 0 {
                return None;
            }
            *parameters = format::parameter_sets(description)?;
            continue;
        }
        match nal_type(&payload)? {
            49 => {
                let (header, data) = payload.split_at_checked(3)?;
                if data.is_empty() || header[2] & 0xc0 == 0xc0 || header[2] & 0x3f >= 48 {
                    return None;
                }
                if header[2] & 0x80 != 0 {
                    if fragmented.is_some() {
                        return None;
                    }
                    let first_byte = (header[0] & 0x81) | ((header[2] & 0x3f) << 1);
                    fragmented = Some(Zeroizing::new(vec![first_byte, header[1]]));
                }
                let nal = fragmented.as_mut()?;
                if nal_type(nal)? != header[2] & 0x3f || nal[1] != header[1] {
                    return None;
                }
                nal.extend_from_slice(data);
                if header[2] & 0x40 != 0 {
                    write_nal(&mut annex, &fragmented.take()?, features)?;
                }
            }
            48 if fragmented.is_none() => {
                let mut data = &payload[2..];
                while !data.is_empty() {
                    let (size, rest) = data.split_at_checked(2)?;
                    let size = u16::from_be_bytes([size[0], size[1]]) as usize;
                    let (nal, rest) = rest.split_at_checked(size)?;
                    write_nal(&mut annex, nal, features)?;
                    data = rest;
                }
            }
            0..=47 if fragmented.is_none() => write_nal(&mut annex, &payload, features)?,
            _ => return None,
        }
    }
    if fragmented.is_some() || annex.len() > MAX_FRAME {
        return None;
    }
    if !parameters.is_empty() && annex_b_nals(&annex).any(is_keyframe) {
        let mut with_config = Zeroizing::new(parameters.to_vec());
        with_config.extend_from_slice(&annex);
        return Some(with_config);
    }
    Some(annex)
}

fn write_nal(annex: &mut Vec<u8>, nal: &[u8], features: HevcFeatures) -> Option<()> {
    let wire_kind = nal_type(nal)?;
    let raw = match wire_kind {
        0..=31 => features.strip(nal)?,
        32..=47 => nal,
        _ => return None,
    };
    annex.extend_from_slice(&ANNEX_B);
    annex.extend_from_slice(raw);
    Some(())
}
