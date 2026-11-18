use anyhow::{Context, Result, ensure};
use zeroize::Zeroizing;

use super::{ANNEX_B, DESCRIPTION_TAG, MAX_PAYLOAD, nal_type};

const SAMPLE_ENTRY_HEADER: usize = 86;
const PARAMETER_SET_LIMIT: usize = 512;

pub(super) fn describe(nals: &[&[u8]], width: u16, height: u16) -> Result<Zeroizing<Vec<u8>>> {
    let parameter = |kind| {
        nals.iter()
            .copied()
            .find(|nal| nal_type(nal) == Some(kind))
            .filter(|nal| nal.len() <= PARAMETER_SET_LIMIT)
            .context("The HEVC keyframe did not contain usable parameter sets")
    };
    let sets = [parameter(32)?, parameter(33)?, parameter(34)?];
    let mut sps = sets[1][2..].iter().copied();
    let mut profile = [0u8; 13];
    let mut zeros = 0;
    for field in &mut profile {
        let mut value = sps.next().context("Truncated HEVC profile")?;
        if value == 3 && zeros == 2 {
            value = sps.next().context("Truncated HEVC profile escape")?;
            zeros = 0;
        }
        *field = value;
        zeros = if value == 0 { (zeros + 1).min(2) } else { 0 };
    }
    let mut hvcc = Zeroizing::new(vec![1]);
    hvcc.extend_from_slice(&profile[1..]); // Profile, tier, constraints and level from the SPS.
    hvcc.extend_from_slice(&[
        0xf0,
        0x00, // Unknown minimum spatial segmentation.
        0xfc, // Unknown parallelism.
        0xfd, // 4:2:0 chroma.
        0xf8,
        0xf8, // 8-bit luma and chroma.
        0,
        0, // Unspecified average frame rate.
        ((((profile[0] >> 1) & 7) + 1) << 3) | ((profile[0] & 1) << 2) | 3,
        3, // VPS, SPS and PPS arrays.
    ]);
    for (kind, nal) in (32..=34).zip(sets) {
        hvcc.push(0x80 | kind);
        hvcc.extend_from_slice(&1u16.to_be_bytes());
        hvcc.extend_from_slice(&(nal.len() as u16).to_be_bytes());
        hvcc.extend_from_slice(nal);
    }
    let mut entry = Zeroizing::new(vec![0; SAMPLE_ENTRY_HEADER]);
    entry[4..8].copy_from_slice(b"hvc1");
    entry[14..16].copy_from_slice(&u16::MAX.to_be_bytes());
    for field in [24, 28] {
        entry[field..field + 4].copy_from_slice(&512u32.to_be_bytes());
    }
    entry[32..34].copy_from_slice(&width.to_be_bytes());
    entry[34..36].copy_from_slice(&height.to_be_bytes());
    for field in [36, 40] {
        entry[field..field + 4].copy_from_slice(&0x0048_0000u32.to_be_bytes());
    }
    entry[48..50].copy_from_slice(&1u16.to_be_bytes());
    entry[50..55].copy_from_slice(b"\x04HEVC");
    entry[82..84].copy_from_slice(&24u16.to_be_bytes());
    entry[84..86].copy_from_slice(&u16::MAX.to_be_bytes());
    entry.extend_from_slice(&((8 + hvcc.len()) as u32).to_be_bytes());
    entry.extend_from_slice(b"hvcC");
    entry.extend_from_slice(&hvcc);
    entry.extend_from_slice(&[0; 4]);
    let length = entry.len() as u32;
    entry[..4].copy_from_slice(&length.to_be_bytes());
    ensure!(
        entry.len() + DESCRIPTION_TAG.len() <= MAX_PAYLOAD,
        "FaceTime HEVC image description exceeds the RTP limit"
    );
    let mut payload = Zeroizing::new(DESCRIPTION_TAG.to_vec());
    payload.extend_from_slice(&entry);
    Ok(payload)
}

pub(super) fn parameter_sets(entry: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    if entry.len() < SAMPLE_ENTRY_HEADER
        || u32::from_be_bytes(entry.get(..4)?.try_into().ok()?) as usize != entry.len()
        || !matches!(entry.get(4..8)?, b"hvc1" | b"hev1")
    {
        return None;
    }
    let mut atoms = &entry[SAMPLE_ENTRY_HEADER..];
    while atoms.len() >= 8 {
        let size = u32::from_be_bytes(atoms.get(..4)?.try_into().ok()?) as usize;
        if size < 8 {
            return None;
        }
        let (atom, rest) = atoms.split_at_checked(size)?;
        if &atom[4..8] == b"hvcC" {
            return hvcc_parameter_sets(&atom[8..]);
        }
        atoms = rest;
    }
    None
}

fn hvcc_parameter_sets(hvcc: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let (header, mut bytes) = hvcc.split_at_checked(23)?;
    if header[0] != 1 {
        return None;
    }
    let mut kinds = 0;
    let mut nals = Zeroizing::new(Vec::new());
    for _ in 0..header[22] {
        let (fields, rest) = bytes.split_at_checked(3)?;
        let kind = fields[0] & 0x3f;
        bytes = rest;
        for _ in 0..u16::from_be_bytes([fields[1], fields[2]]) {
            let (length, rest) = bytes.split_at_checked(2)?;
            let length = u16::from_be_bytes([length[0], length[1]]) as usize;
            let (nal, remaining) = rest.split_at_checked(length)?;
            if (32..=34).contains(&kind) {
                if nal_type(nal) != Some(kind) || nal.len() > PARAMETER_SET_LIMIT {
                    return None;
                }
                kinds |= 1 << (kind - 32);
                nals.extend_from_slice(&ANNEX_B);
                nals.extend_from_slice(nal);
            }
            bytes = remaining;
        }
    }
    (kinds == 7 && bytes.is_empty()).then_some(nals)
}
