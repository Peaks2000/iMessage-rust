use anyhow::{Context, Result};

pub(super) fn write_varint(output: &mut Vec<u8>, value: usize) {
    if value < 64 {
        output.push(value as u8);
    } else if value < 1 << 14 {
        output.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes());
    } else {
        debug_assert!(value < 1 << 30);
        output.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes());
    }
}

pub(super) fn take_varint(input: &mut &[u8]) -> Result<u64> {
    let first = *input.first().context("Truncated QUIC variable integer")?;
    let size = 1 << (first >> 6);
    let (encoded, rest) = input
        .split_at_checked(size)
        .context("Truncated QUIC variable integer")?;
    *input = rest;
    Ok(encoded[1..]
        .iter()
        .fold(u64::from(first & 0x3f), |number, byte| {
            (number << 8) | u64::from(*byte)
        }))
}
