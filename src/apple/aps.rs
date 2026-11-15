use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result, ensure};
use openssl::{rand::rand_bytes, sha::sha1};
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, ServerName},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, WriteHalf},
    net::TcpStream,
    sync::mpsc,
    task::JoinHandle,
    time::timeout,
};
use tokio_rustls::{TlsConnector, client::TlsStream};

use super::{Identity, nonce, rsa_signature};

pub(super) const TOPIC: &str = "com.apple.madrid";
const MAX_FRAME: usize = 256 * 1024;
const COURIER_NAME: &str = "courier.push.apple.com";
pub(super) const CERTIFICATES: &[&[u8]] = &[
    include_bytes!("../../assets/AppleIncRootCertificate.cer"),
    include_bytes!("../../assets/AppleRootCA-G2.cer"),
    include_bytes!("../../assets/AppleRootCA-G3.cer"),
];

#[derive(Debug, PartialEq)]
pub(super) struct Frame {
    pub(super) code: u8,
    fields: Vec<(u8, Vec<u8>)>,
}

impl Frame {
    pub(super) fn field(&self, code: u8) -> Option<&[u8]> {
        self.fields
            .iter()
            .find(|(key, _)| *key == code)
            .map(|(_, bytes)| bytes.as_slice())
    }

    async fn read(reader: &mut (impl AsyncRead + Unpin)) -> Result<Self> {
        let code = reader.read_u8().await?;
        let size = reader.read_u32().await? as usize;
        ensure!(size <= MAX_FRAME, "APNs frame exceeds size limit");
        let mut buffer = vec![0; size];
        reader.read_exact(&mut buffer).await?;
        let mut fields = Vec::new();
        let mut tail = buffer.as_slice();
        while !tail.is_empty() {
            ensure!(tail.len() >= 3, "Truncated APNs field");
            let size = u16::from_be_bytes([tail[1], tail[2]]) as usize;
            ensure!(tail.len() >= 3 + size, "Truncated APNs field value");
            fields.push((tail[0], tail[3..3 + size].to_vec()));
            tail = &tail[3 + size..];
        }
        Ok(Self { code, fields })
    }
}

async fn write_frame(
    socket: &mut (impl AsyncWrite + Unpin),
    code: u8,
    fields: &[(u8, &[u8])],
) -> Result<()> {
    let mut packet = vec![code, 0, 0, 0, 0];
    for (kind, value) in fields {
        packet.push(*kind);
        packet.extend_from_slice(&u16::try_from(value.len())?.to_be_bytes());
        packet.extend_from_slice(value);
    }
    let length = packet.len() - 5;
    ensure!(length <= MAX_FRAME, "APNs frame exceeds size limit");
    packet[1..5].copy_from_slice(&(length as u32).to_be_bytes());
    socket.write_all(&packet).await?;
    socket.flush().await?;
    Ok(())
}

pub(super) struct Courier {
    write: WriteHalf<TlsStream<TcpStream>>,
    frames: mpsc::Receiver<Result<Frame>>,
    reader: JoinHandle<()>,
    pub(super) token: [u8; 32],
}

impl Drop for Courier {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

impl Courier {
    pub(super) async fn connect(identity: &Identity) -> Result<Self> {
        timeout(Duration::from_secs(12), Self::handshake(identity))
            .await
            .context("Apple courier connection timed out")?
    }

    async fn handshake(identity: &Identity) -> Result<Self> {
        let mut roots = RootCertStore::empty();
        for certificate in CERTIFICATES {
            roots.add(CertificateDer::from(*certificate))?;
        }
        let mut config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"apns-security-v3".to_vec()];
        let tcp = TcpStream::connect((COURIER_NAME, 5223))
            .await
            .context("Could not reach Apple courier on TCP port 5223")?;
        tcp.set_nodelay(true)?;
        let mut stream = TlsConnector::from(Arc::new(config))
            .connect(ServerName::try_from(COURIER_NAME)?, tcp)
            .await
            .context("Apple courier TLS handshake failed")?;
        ensure!(
            stream
                .get_ref()
                .1
                .alpn_protocol()
                .is_none_or(|protocol| protocol == b"apns-security-v3"),
            "Apple courier did not select the supported APNs protocol"
        );
        let nonce = nonce(0)?;
        let signature = rsa_signature(&identity.push_key, &nonce)?;
        write_frame(
            &mut stream,
            0x07,
            &[
                (1, &identity.token),
                (2, &[1]),
                (5, &0x41u32.to_be_bytes()),
                (12, &identity.push_cert),
                (13, &nonce),
                (14, &signature),
                (16, &9u16.to_be_bytes()),
            ],
        )
        .await?;
        let reply = Frame::read(&mut stream).await?;
        ensure!(
            reply.code == 0x08 && reply.field(1) == Some(&[0]),
            "Apple rejected the provisioned APNs session"
        );
        let token = match reply.field(3) {
            Some(token) => <[u8; 32]>::try_from(token).context("Invalid Apple push token")?,
            None => identity.token,
        };
        ensure!(
            token == identity.token,
            "Apple issued a different push token. Provision a matching IDS session"
        );
        write_frame(
            &mut stream,
            0x14,
            &[(1, &[1]), (2, &i32::MAX.to_be_bytes())],
        )
        .await?;
        write_frame(
            &mut stream,
            0x09,
            &[(1, &token), (2, &sha1(TOPIC.as_bytes()))],
        )
        .await?;
        let (mut read, write) = tokio::io::split(stream);
        let (send, frames) = mpsc::channel(32);
        let reader = tokio::spawn(async move {
            loop {
                let frame = Frame::read(&mut read).await;
                let finished = frame.is_err();
                if send.send(frame).await.is_err() || finished {
                    break;
                }
            }
        });
        Ok(Self {
            write,
            frames,
            reader,
            token,
        })
    }

    pub(super) async fn next(&mut self) -> Result<Frame> {
        self.frames
            .recv()
            .await
            .context("Apple courier disconnected")?
    }

    pub(super) async fn push(&mut self, id: [u8; 4], payload: &[u8]) -> Result<()> {
        let token = self.token;
        self.write(
            0x0a,
            &[
                (1, &sha1(TOPIC.as_bytes())),
                (2, &token),
                (3, payload),
                (4, &id),
            ],
        )
        .await
    }

    pub(super) async fn ack(&mut self, id: [u8; 4]) -> Result<()> {
        let token = self.token;
        self.write(0x0b, &[(1, &token), (4, &id), (8, &[0])]).await
    }

    pub(super) async fn ping(&mut self) -> Result<()> {
        self.write(0x0c, &[]).await
    }

    async fn write(&mut self, code: u8, fields: &[(u8, &[u8])]) -> Result<()> {
        timeout(
            Duration::from_secs(5),
            write_frame(&mut self.write, code, fields),
        )
        .await
        .context("Apple courier write timed out")?
    }
}

pub(super) fn push_id() -> Result<[u8; 4]> {
    let mut id = [0; 4];
    rand_bytes(&mut id)?;
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn frame_interoperable_layout_and_truncation() -> Result<()> {
        let mut bytes = Vec::new();
        write_frame(&mut bytes, 9, &[(1, &[1, 2]), (2, &[3]), (2, &[4])]).await?;
        assert_eq!(
            bytes,
            [9, 0, 0, 0, 13, 1, 0, 2, 1, 2, 2, 0, 1, 3, 2, 0, 1, 4]
        );
        let parsed = Frame::read(&mut bytes.as_slice()).await?;
        assert_eq!(parsed.field(1), Some([1, 2].as_slice()));
        assert_eq!(parsed.fields.len(), 3);
        assert!(
            Frame::read(&mut [9, 0, 0, 0, 4, 1, 0, 7, 0].as_slice())
                .await
                .is_err()
        );
        assert!(
            Frame::read(&mut [9, 0xff, 0xff, 0xff, 0xff].as_slice())
                .await
                .is_err()
        );
        Ok(())
    }
}
