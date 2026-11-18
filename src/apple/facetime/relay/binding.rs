use anyhow::{Context, Result, ensure};
use openssl::rand::rand_bytes;
use prost::Message;
use zeroize::Zeroizing;

use super::{
    CallRelayConnection,
    http3::RelayHttp3,
    pod::{Pod, RelayDatagramChannel},
};

const SERVICE_ID: u32 = 4096;
const WILDCARD_CHANNEL_BINDING: u32 = 512;
const AVC: i32 = 0;
const IDS: i32 = 1;

/// Device and media capabilities advertised during this call's registration.
pub struct CallRelayProfile<'a> {
    pub os_version: &'a str,
    pub hardware_version: &'a str,
    pub capabilities: u64,
}

#[derive(Clone, Copy)]
pub struct RelayChannel {
    pub client_connection_id: [u8; 4],
    pub server_connection_id: [u8; 4],
}

pub struct CallRelayBinding {
    control: RelayHttp3,
    media: Pod,
    signaling: Pod,
    pub channel_id: u16,
    pub link_id: u32,
    pub avc: RelayChannel,
    pub ids: RelayChannel,
}

impl CallRelayBinding {
    /// Use the TLS exporter of the connection that authenticated and bound these channels.
    pub fn export_keying_material(&self, output: &mut [u8], label: &str) -> Result<()> {
        self.control.transport.export_keying_material(output, label)
    }

    /// Send a call-protocol datagram over the relay. The call layer encrypts peer payloads.
    pub async fn send_datagram(
        &mut self,
        channel: RelayDatagramChannel,
        data: &[u8],
    ) -> Result<()> {
        let packet = self.pod(channel).seal(data)?;
        self.control.transport.send_datagram(&packet).await
    }

    /// Receive a datagram authenticated by the relay. The call layer authenticates the peer.
    pub async fn receive_datagram(&mut self) -> Result<(RelayDatagramChannel, Zeroizing<Vec<u8>>)> {
        loop {
            let (channel, packet) = self.control.transport.receive_datagram().await?;
            if let Some(data) = self.pod(channel).open(packet)? {
                return Ok((channel, data));
            }
        }
    }

    fn pod(&mut self, channel: RelayDatagramChannel) -> &mut Pod {
        match channel {
            RelayDatagramChannel::Media => &mut self.media,
            RelayDatagramChannel::Signaling => &mut self.signaling,
        }
    }
}

impl CallRelayConnection {
    /// Bind one authenticated connection to the relay's audio/video and signaling channels.
    pub async fn bind(mut self, profile: CallRelayProfile<'_>) -> Result<CallRelayBinding> {
        ensure!(
            !profile.os_version.is_empty()
                && profile.os_version.len() <= 128
                && !profile.hardware_version.is_empty()
                && profile.hardware_version.len() <= 128,
            "Invalid FaceTime relay device profile"
        );
        let avc = new_connection_id(AVC)?;
        let ids = new_connection_id(IDS)?;
        // The relay may send its first datagram as soon as it writes the binding
        // response. Keep a bounded queue until its channel keys have been derived.
        self.route_datagrams(avc, ids)?;
        let request = BindEnvelope {
            request: Some(BindRequest {
                service_id: SERVICE_ID,
                os_version: profile.os_version.to_owned(),
                hardware_version: profile.hardware_version.to_owned(),
                capabilities: profile.capabilities,
                subscription: Some(Subscription { wildcard: true }),
                max_concurrent_streams: 6,
                channel_binding: WILDCARD_CHANNEL_BINDING,
                connections: vec![
                    ConnectionInfo {
                        kind: AVC,
                        id: avc.to_vec(),
                    },
                    ConnectionInfo {
                        kind: IDS,
                        id: ids.to_vec(),
                    },
                ],
                state_flags: 6,
                reason: 1,
            }),
            response: None,
        };
        let mut control = RelayHttp3::start(self).await?;
        let response = control
            .put("/QR/AllocBind", &request.encode_to_vec())
            .await?;
        let envelope = BindEnvelope::decode(response.as_slice())
            .context("Invalid FaceTime AllocBind response")?;
        ensure!(
            envelope.request.is_none(),
            "Unexpected AllocBind request from relay"
        );
        let binding = envelope
            .response
            .context("Missing FaceTime relay binding")?;
        let channel_id = binding
            .channel_id
            .and_then(|channel| u16::try_from(channel).ok())
            .context("Invalid FaceTime relay channel")?;
        let link_id = binding.link_id.context("Missing FaceTime relay link ID")?;
        let (avc, ids) = bound_channels(&binding.connections, avc, ids)?;
        let media = Pod::new(&control.transport, avc, RelayDatagramChannel::Media)?;
        let signaling = Pod::new(&control.transport, ids, RelayDatagramChannel::Signaling)?;
        Ok(CallRelayBinding {
            control,
            media,
            signaling,
            channel_id,
            link_id,
            avc,
            ids,
        })
    }
}

fn new_connection_id(kind: i32) -> Result<[u8; 4]> {
    let mut bytes = [0; 4];
    rand_bytes(&mut bytes)?;
    let id = (u32::from_be_bytes(bytes) & 0x0fff_ffff) | ((kind as u32) << 28) | 0x0080_0000;
    Ok(id.to_be_bytes())
}

fn bound_channels(
    connections: &[ConnectionInfo],
    client_avc: [u8; 4],
    client_ids: [u8; 4],
) -> Result<(RelayChannel, RelayChannel)> {
    let channel = |kind, client_connection_id| {
        let mut matches = connections.iter().filter(|info| info.kind == kind);
        let info = matches
            .next()
            .context("Missing FaceTime media relay channel")?;
        ensure!(
            matches.next().is_none(),
            "Duplicate FaceTime media relay channel"
        );
        let server_connection_id = info
            .id
            .as_slice()
            .try_into()
            .ok()
            .context("Invalid FaceTime relay connection ID")?;
        Ok::<_, anyhow::Error>(RelayChannel {
            client_connection_id,
            server_connection_id,
        })
    };
    let avc = channel(AVC, client_avc)?;
    let ids = channel(IDS, client_ids)?;
    ensure!(
        avc.server_connection_id != ids.server_connection_id,
        "FaceTime relay reused a connection ID"
    );
    Ok((avc, ids))
}

// Subset of the QuickRelay H3 envelope used for initial channel binding.
#[derive(Message)]
struct BindEnvelope {
    #[prost(message, optional, tag = "1")]
    request: Option<BindRequest>,
    #[prost(message, optional, tag = "2")]
    response: Option<BindResponse>,
}

#[derive(Message)]
struct BindRequest {
    #[prost(uint32, tag = "1")]
    service_id: u32,
    #[prost(string, tag = "2")]
    os_version: String,
    #[prost(string, tag = "3")]
    hardware_version: String,
    #[prost(uint64, tag = "4")]
    capabilities: u64,
    #[prost(message, optional, tag = "6")]
    subscription: Option<Subscription>,
    #[prost(uint32, tag = "8")]
    max_concurrent_streams: u32,
    #[prost(uint32, tag = "9")]
    channel_binding: u32,
    #[prost(message, repeated, tag = "11")]
    connections: Vec<ConnectionInfo>,
    #[prost(uint32, tag = "12")]
    state_flags: u32,
    #[prost(int32, tag = "14")]
    reason: i32,
}

#[derive(Message)]
struct BindResponse {
    #[prost(uint32, optional, tag = "2")]
    channel_id: Option<u32>,
    #[prost(uint32, optional, tag = "6")]
    link_id: Option<u32>,
    #[prost(message, repeated, tag = "11")]
    connections: Vec<ConnectionInfo>,
}

#[derive(Message)]
struct Subscription {
    #[prost(bool, tag = "1")]
    wildcard: bool,
}

#[derive(Message)]
struct ConnectionInfo {
    #[prost(int32, tag = "1")]
    kind: i32,
    #[prost(bytes = "vec", tag = "2")]
    id: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_missing_duplicate_and_malformed_channel_identifiers() {
        let channel = |kind, id: &[u8]| ConnectionInfo {
            kind,
            id: id.to_vec(),
        };
        let avc = || channel(AVC, b"AVC1");
        let ids = || channel(IDS, b"IDS1");
        let validate = |entries: &[ConnectionInfo]| bound_channels(entries, *b"avc0", *b"ids0");

        assert!(validate(&[avc(), ids()]).is_ok());
        assert!(validate(&[avc()]).is_err());
        assert!(validate(&[avc(), ids(), channel(IDS, b"IDS2")]).is_err());
        assert!(validate(&[avc(), channel(IDS, b"short")]).is_err());
        assert!(validate(&[avc(), channel(IDS, b"AVC1")]).is_err());
    }
}
