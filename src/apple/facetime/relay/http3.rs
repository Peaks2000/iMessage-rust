use std::collections::HashSet;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use bytes::Bytes;
use compcol::{
    hpack::HeaderField,
    qpack::{QpackDecoder, QpackEncoder},
};
use reqwest::{
    StatusCode,
    header::{HeaderName, HeaderValue},
};
use tokio::time::timeout;
use zeroize::Zeroizing;

use super::{
    CallRelayConnection, CallRelayStream, RelayStreamDirection,
    wire::{take_varint, write_varint},
};

mod indications;
pub(super) use indications::IndicationRead;
use indications::Indications;

const HEADERS: u64 = 1;
const DATA: u64 = 0;
const SETTINGS: u64 = 4;
const MAX_FIELDS: usize = 8 * 1024;
const MAX_BODY: usize = 64 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(12);

pub(super) struct RelayHttp3 {
    pub(super) transport: CallRelayConnection,
    _local_control: CallRelayStream,
    _peer_streams: Vec<CallRelayStream>,
    peer_max_fields: u64,
    indications: Option<Indications>,
}

impl RelayHttp3 {
    pub(super) async fn start(mut transport: CallRelayConnection) -> Result<Self> {
        timeout(REQUEST_TIMEOUT, async {
            let mut local_control = transport
                .open_stream(RelayStreamDirection::Unidirectional)
                .await?;
            // Control stream, SETTINGS_MAX_FIELD_SECTION_SIZE. The QPACK dynamic table and
            // blocked streams default to zero. We never create a server push credit.
            let mut settings = vec![0];
            let mut field_limit = vec![0x06];
            write_varint(&mut field_limit, MAX_FIELDS);
            write_frame(&mut settings, SETTINGS as u8, &field_limit);
            transport.write_all(&mut local_control, &settings).await?;

            let mut peer_streams = Vec::new();
            let mut qpack_streams = HashSet::new();
            for _ in 0..8 {
                let mut stream = transport.accept_stream().await?;
                ensure!(
                    transport.stream_id(&stream)? % 4 == 3,
                    "Unexpected relay stream"
                );
                let stream_type = require_varint(&mut transport, &mut stream).await?;
                match stream_type {
                    0 => {
                        let limit = read_settings(&mut transport, &mut stream).await?;
                        peer_streams.push(stream);
                        return Ok(Self {
                            transport,
                            _local_control: local_control,
                            _peer_streams: peer_streams,
                            peer_max_fields: limit,
                            indications: None,
                        });
                    }
                    1 => bail!("Unexpected HTTP/3 push stream from relay"),
                    2 | 3 => {
                        ensure!(
                            qpack_streams.insert(stream_type),
                            "Duplicate relay QPACK stream"
                        );
                        peer_streams.push(stream);
                    }
                    // Reserved and unknown stream types have no effect on our requests.
                    _ => {}
                }
            }
            bail!("Missing HTTP/3 control stream from relay")
        })
        .await
        .context("Timed out opening relay HTTP/3 control streams")?
    }

    pub(super) async fn put(&mut self, path: &str, body: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        timeout(REQUEST_TIMEOUT, async {
            let mut stream = self.request(path, Some(body)).await?;
            read_response(&mut self.transport, &mut stream).await
        })
        .await
        .context("FaceTime relay HTTP/3 request timed out")?
    }

    pub(super) async fn open_indications(&mut self) -> Result<()> {
        let stream = timeout(REQUEST_TIMEOUT, self.request("/QR/Indications", None))
            .await
            .context("FaceTime relay indication subscription timed out")??;
        self.indications = Some(Indications::new(stream));
        Ok(())
    }

    pub(super) async fn next_indication(&mut self) -> Result<Option<Bytes>> {
        loop {
            match self.poll_indication()? {
                IndicationRead::Message(message) => return Ok(Some(message)),
                IndicationRead::Progress => tokio::task::consume_budget().await,
                IndicationRead::Pending => self.transport.wait_for_progress().await?,
                IndicationRead::Closed => return Ok(None),
            }
        }
    }

    pub(super) fn poll_indication(&mut self) -> Result<IndicationRead> {
        let Some(indications) = self.indications.as_mut() else {
            return Ok(IndicationRead::Closed);
        };
        let result = indications.poll_message(&mut self.transport);
        if matches!(result, Ok(IndicationRead::Closed) | Err(_)) {
            self.indications = None;
        }
        result
    }

    async fn request(&mut self, path: &str, body: Option<&[u8]>) -> Result<CallRelayStream> {
        ensure!(
            body.is_none_or(|body| body.len() <= MAX_BODY),
            "FaceTime relay request is too large"
        );
        let mut txn = [0; 4];
        openssl::rand::rand_bytes(&mut txn)?;
        let txn = u32::from_be_bytes(txn).to_string();
        let authority = self.transport.peer_addr()?.to_string();
        let method: &[u8] = if body.is_some() { b"PUT" } else { b"GET" };
        let mut fields = vec![
            HeaderField::new(b":method", method),
            HeaderField::new(b":scheme", b"https"),
            HeaderField::new(b":authority", authority.as_bytes()),
            HeaderField::new(b":path", path.as_bytes()),
            HeaderField::new(b"version", b"1.1"),
            HeaderField::new(b"user-agent", b"GFT/2.0"),
            HeaderField::new(b"accept", b"*/*"),
            HeaderField::new(b"txn_id", txn.as_bytes()),
        ];
        if let Some(body) = body {
            fields.push(HeaderField::new(
                b"content-length",
                body.len().to_string().as_bytes(),
            ));
        }
        ensure!(
            field_size(&fields) as u64 <= self.peer_max_fields,
            "FaceTime relay cannot accept these HTTP/3 fields"
        );
        let mut message = Zeroizing::new(Vec::new());
        let block = QpackEncoder::new().encode_field_section(&fields);
        write_frame(&mut message, HEADERS as u8, &block);
        if let Some(body) = body {
            write_frame(&mut message, DATA as u8, body);
        }
        let mut stream = self
            .transport
            .open_stream(RelayStreamDirection::Bidirectional)
            .await?;
        self.transport.write_all(&mut stream, &message).await?;
        self.transport.finish_stream(&mut stream)?;
        Ok(stream)
    }
}

fn field_size(fields: &[HeaderField]) -> usize {
    fields
        .iter()
        .map(|field| 32 + field.name.len() + field.value.len())
        .sum()
}

async fn read_settings(
    conn: &mut CallRelayConnection,
    stream: &mut CallRelayStream,
) -> Result<u64> {
    ensure!(
        require_varint(conn, stream).await? == SETTINGS,
        "Missing relay HTTP/3 settings"
    );
    let frame = read_frame_payload(conn, stream, MAX_FIELDS).await?;
    let mut data = frame.as_slice();
    let mut seen = HashSet::new();
    let mut max = u64::MAX;
    while !data.is_empty() {
        let key = take_varint(&mut data)?;
        let value = take_varint(&mut data)?;
        ensure!(
            !matches!(key, 2..=5) && seen.insert(key),
            "Invalid relay HTTP/3 settings"
        );
        if key == 6 {
            max = value;
        }
    }
    Ok(max)
}

async fn read_response(
    conn: &mut CallRelayConnection,
    stream: &mut CallRelayStream,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut body = Zeroizing::new(Vec::new());
    let mut final_headers = false;
    let mut trailers = false;
    let mut expected_size = None;
    let mut remaining = MAX_BODY + MAX_FIELDS;
    for _ in 0..64 {
        let Some(kind) = read_varint(conn, stream).await? else {
            ensure!(
                final_headers,
                "Missing FaceTime relay HTTP/3 response status"
            );
            ensure!(
                expected_size.is_none_or(|size| size == body.len()),
                "Truncated relay response"
            );
            return Ok(body);
        };
        let limit = match kind {
            HEADERS => MAX_FIELDS,
            DATA => MAX_BODY - body.len(),
            // HTTP/2 frames, HTTP/3 control-only frames, and PUSH_PROMISE (push disabled).
            2..=9 | 0x0d => bail!("Unexpected frame in FaceTime relay HTTP/3 response"),
            _ => remaining,
        };
        let payload = read_frame_payload(conn, stream, limit.min(remaining)).await?;
        remaining -= payload.len();
        match kind {
            HEADERS => {
                ensure!(!trailers, "Duplicate FaceTime relay HTTP/3 trailers");
                let (status, length) = decode_fields(&payload)?;
                if final_headers {
                    ensure!(
                        status.is_none() && length.is_none(),
                        "Invalid relay HTTP/3 trailers"
                    );
                    trailers = true;
                } else {
                    let status = status.context("Missing FaceTime relay HTTP/3 status")?;
                    if !status.is_informational() {
                        ensure!(status.is_success(), "FaceTime relay returned HTTP {status}");
                        expected_size = length;
                        final_headers = true;
                    }
                }
            }
            DATA => {
                ensure!(
                    final_headers && !trailers,
                    "Misplaced FaceTime relay HTTP/3 data"
                );
                body.extend_from_slice(&payload);
                ensure!(
                    expected_size.is_none_or(|size| body.len() <= size),
                    "Unexpected relay response length"
                );
            }
            _ => {}
        }
    }
    bail!("Too many FaceTime relay HTTP/3 response frames")
}

fn decode_fields(block: &[u8]) -> Result<(Option<StatusCode>, Option<usize>)> {
    let fields = QpackDecoder::with_max_table_capacity(0)
        .decode_field_section(block)
        .map_err(|_| anyhow::anyhow!("Invalid FaceTime relay QPACK fields"))?;
    ensure!(
        field_size(&fields) <= MAX_FIELDS,
        "FaceTime relay HTTP/3 response fields are too large"
    );
    let mut status = None;
    let mut length = None;
    let mut regular = false;
    for field in fields {
        if !regular && status.is_none() && field.name == b":status" {
            status = Some(StatusCode::from_bytes(&field.value)?);
            continue;
        }
        regular = true;
        let name = HeaderName::from_lowercase(&field.name)?;
        let value = HeaderValue::from_bytes(&field.value)?;
        match name.as_str() {
            "content-length" => {
                let value = value.to_str()?;
                ensure!(!value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()));
                let size = value.parse::<usize>()?;
                ensure!(length.is_none_or(|previous| size == previous) && size <= MAX_BODY);
                length = Some(size);
            }
            "connection" | "keep-alive" | "proxy-connection" | "transfer-encoding" | "upgrade" => {
                bail!("Invalid FaceTime relay HTTP/3 field")
            }
            _ => {}
        }
    }
    Ok((status, length))
}

fn write_frame(output: &mut Vec<u8>, kind: u8, payload: &[u8]) {
    output.push(kind);
    write_varint(output, payload.len());
    output.extend_from_slice(payload);
}

async fn read_varint(
    conn: &mut CallRelayConnection,
    stream: &mut CallRelayStream,
) -> Result<Option<u64>> {
    let mut encoded = [0; 8];
    if conn.read(stream, &mut encoded[..1]).await? == 0 {
        return Ok(None);
    }
    let size = 1 << (encoded[0] >> 6);
    read_exact(conn, stream, &mut encoded[1..size]).await?;
    Ok(Some(take_varint(&mut &encoded[..size])?))
}

async fn require_varint(
    conn: &mut CallRelayConnection,
    stream: &mut CallRelayStream,
) -> Result<u64> {
    read_varint(conn, stream)
        .await?
        .context("Truncated FaceTime relay HTTP/3 stream")
}

async fn read_frame_payload(
    conn: &mut CallRelayConnection,
    stream: &mut CallRelayStream,
    limit: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let length = require_varint(conn, stream).await?;
    ensure!(
        length <= limit as u64,
        "FaceTime relay HTTP/3 frame is too large"
    );
    let mut data = Zeroizing::new(vec![0; length as usize]);
    read_exact(conn, stream, &mut data).await?;
    Ok(data)
}

async fn read_exact(
    conn: &mut CallRelayConnection,
    stream: &mut CallRelayStream,
    mut bytes: &mut [u8],
) -> Result<()> {
    while !bytes.is_empty() {
        let n = conn.read(stream, bytes).await?;
        ensure!(n != 0, "Truncated FaceTime relay HTTP/3 frame");
        bytes = &mut bytes[n..];
    }
    Ok(())
}
