use anyhow::{Context, Result, bail, ensure};
use bytes::{Buf, Bytes, BytesMut};

use super::{
    CallRelayConnection, CallRelayStream, DATA, HEADERS, MAX_BODY, MAX_FIELDS, decode_fields,
    take_varint,
};

pub(super) struct Indications {
    stream: CallRelayStream,
    frames: IndicationFrames,
}

pub(in crate::apple::facetime::relay) enum IndicationRead {
    Message(Bytes),
    Progress,
    Pending,
    Closed,
}

impl Indications {
    pub(super) fn new(stream: CallRelayStream) -> Self {
        Self {
            stream,
            frames: IndicationFrames::default(),
        }
    }

    pub(super) fn poll_message(
        &mut self,
        transport: &mut CallRelayConnection,
    ) -> Result<IndicationRead> {
        if let Some(message) = self.frames.next_message()? {
            return Ok(IndicationRead::Message(message));
        }
        let mut chunk = [0; 8192];
        match transport.read_available(&mut self.stream, &mut chunk)? {
            Some(0) => {
                self.frames.finish()?;
                Ok(IndicationRead::Closed)
            }
            Some(size) => {
                self.frames.wire.extend_from_slice(&chunk[..size]);
                Ok(self
                    .frames
                    .next_message()?
                    .map_or(IndicationRead::Progress, IndicationRead::Message))
            }
            None => Ok(IndicationRead::Pending),
        }
    }
}

/// Each QuickRelay record starts with a two-byte prefix and a big-endian
/// length. HTTP/3 DATA frame and QUIC stream boundaries are independent of it.
#[derive(Default)]
struct IndicationFrames {
    wire: BytesMut,
    body: BytesMut,
    received_headers: bool,
    trailers: bool,
    declared_size: Option<usize>,
    body_size: usize,
}

impl IndicationFrames {
    fn next_message(&mut self) -> Result<Option<Bytes>> {
        loop {
            if self.body.len() >= 4 {
                let size = usize::from(u16::from_be_bytes([self.body[2], self.body[3]]));
                if self.body.len() >= 4 + size {
                    self.body.advance(4);
                    return Ok(Some(self.body.split_to(size).freeze()));
                }
            }
            let mut input = &self.wire[..];
            let Some(kind) = available_varint(&mut input)? else {
                return Ok(None);
            };
            let Some(length) = available_varint(&mut input)? else {
                return Ok(None);
            };
            let limit = if kind == HEADERS {
                MAX_FIELDS
            } else {
                MAX_BODY
            };
            ensure!(
                length <= limit as u64,
                "FaceTime relay indication frame is too large"
            );
            let length = usize::try_from(length)?;
            if input.len() < length {
                return Ok(None);
            }
            self.wire.advance(self.wire.len() - input.len());
            let payload = self.wire.split_to(length);
            match kind {
                HEADERS => self.headers(&payload)?,
                DATA => {
                    ensure!(
                        self.received_headers && !self.trailers,
                        "Misplaced FaceTime relay indication data"
                    );
                    self.body_size = self.body_size.saturating_add(length);
                    ensure!(
                        self.declared_size.is_none_or(|size| self.body_size <= size),
                        "Unexpected FaceTime relay indication length"
                    );
                    self.body.extend_from_slice(&payload);
                }
                2..=9 | 0x0d => bail!("Unexpected frame in FaceTime relay indication stream"),
                _ => (),
            }
        }
    }

    fn headers(&mut self, payload: &[u8]) -> Result<()> {
        ensure!(
            !self.trailers,
            "Duplicate FaceTime relay indication trailers"
        );
        let (status, size) = decode_fields(payload)?;
        if self.received_headers {
            ensure!(
                status.is_none() && size.is_none(),
                "Invalid FaceTime relay indication trailers"
            );
            self.trailers = true;
        } else {
            let status = status.context("Missing FaceTime relay indication status")?;
            if !status.is_informational() {
                ensure!(
                    status.is_success(),
                    "FaceTime relay indications returned HTTP {status}"
                );
                self.received_headers = true;
                self.declared_size = size;
            }
        }
        Ok(())
    }

    fn finish(&self) -> Result<()> {
        ensure!(
            self.received_headers
                && self.wire.is_empty()
                && self.body.is_empty()
                && self.declared_size.is_none_or(|size| size == self.body_size),
            "Truncated FaceTime relay indication stream"
        );
        Ok(())
    }
}

fn available_varint(input: &mut &[u8]) -> Result<Option<u64>> {
    let Some(&first) = input.first() else {
        return Ok(None);
    };
    if input.len() < 1 << (first >> 6) {
        return Ok(None);
    }
    take_varint(input).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apple::facetime::relay::http3::write_frame;

    #[test]
    fn records_survive_partial_http_frames_and_shared_data_frames() -> Result<()> {
        let mut wire = Vec::new();
        write_frame(&mut wire, 1, &[0, 0, 0xd9]); // QPACK :status 200.
        write_frame(&mut wire, 0, &[0, 0, 0]);
        write_frame(
            &mut wire,
            0,
            &[3, b'o', b'n', b'e', 0, 0, 0, 3, b't', b'w', b'o'],
        );
        let mut frames = IndicationFrames::default();
        let mut messages = Vec::new();
        for byte in wire {
            frames.wire.extend_from_slice(&[byte]);
            while let Some(payload) = frames.next_message()? {
                messages.push(payload);
            }
        }
        frames.finish()?;
        assert_eq!(
            messages,
            [Bytes::from_static(b"one"), Bytes::from_static(b"two")]
        );
        Ok(())
    }
}
