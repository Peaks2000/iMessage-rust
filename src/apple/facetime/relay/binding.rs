use anyhow::{Context, Result, ensure};
use openssl::rand::rand_bytes;
use prost::Message;
use zeroize::Zeroizing;

use crate::apple::facetime::{
    CallAvcMaterial, CallMediaDescription, CallPeerKeys,
    description::{open_description, valid_ciphertext},
};

use super::{
    CallRelayConnection,
    http3::RelayHttp3,
    pod::{Pod, RelayDatagramChannel},
};

const SERVICE_ID: u32 = 4096;
const WILDCARD_CHANNEL_BINDING: u32 = 512;
const AVC: i32 = 0;
const IDS: i32 = 1;
const AVC_MATERIAL: i32 = 12;
const MAX_PEER_DESCRIPTIONS: usize = 8;

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
    peer_descriptions: Vec<MaterialInfo>,
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

    /// Read the description matching the caller's current authenticated session key.
    pub fn peer_description(&self, keys: &CallPeerKeys) -> Result<Option<CallMediaDescription>> {
        let Some(key) = keys.session.as_ref() else {
            return Ok(None);
        };
        let mut matching = self
            .peer_descriptions
            .iter()
            .filter(|material| material.content.starts_with(&key.identifier));
        let Some(description) = matching.next() else {
            return Ok(None);
        };
        ensure!(
            matching.next().is_none(),
            "Ambiguous FaceTime peer descriptions for this key"
        );
        let call = self.control.transport.call;
        open_description(call.id, call.peer, key, &description.content).map(Some)
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
    pub async fn bind(self, profile: CallRelayProfile<'_>) -> Result<CallRelayBinding> {
        self.bind_channels(profile, Vec::new()).await
    }

    /// Bind and publish this device's encrypted media description in the same request.
    pub async fn bind_with_description(
        self,
        profile: CallRelayProfile<'_>,
        offer: &CallAvcMaterial,
    ) -> Result<CallRelayBinding> {
        ensure!(
            self.call.id == offer.call_id && self.call.local == offer.participant,
            "FaceTime relay and media description belong to different calls"
        );
        self.bind_channels(
            profile,
            vec![Material {
                owner: Some(0),    // Apple resolves zero to this connection's participant ID.
                receiver: Some(0), // Visible to the call, encrypted to the authenticated peer.
                entries: vec![MaterialInfo {
                    id: offer.material_id.to_vec(),
                    kind: AVC_MATERIAL,
                    content: offer.ciphertext.clone(),
                }],
            }],
        )
        .await
    }

    async fn bind_channels(
        mut self,
        profile: CallRelayProfile<'_>,
        materials: Vec<Material>,
    ) -> Result<CallRelayBinding> {
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
                materials,
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
        let call = control.transport.call;
        let peer_descriptions =
            collect_peer_descriptions(binding.materials, call.peer, call.local)?;
        let media = Pod::new(&control.transport, avc, RelayDatagramChannel::Media)?;
        let signaling = Pod::new(&control.transport, ids, RelayDatagramChannel::Signaling)?;
        Ok(CallRelayBinding {
            control,
            media,
            signaling,
            peer_descriptions,
            channel_id,
            link_id,
            avc,
            ids,
        })
    }
}

fn collect_peer_descriptions(
    materials: Vec<Material>,
    peer: u64,
    local: u64,
) -> Result<Vec<MaterialInfo>> {
    let mut accepted: Vec<MaterialInfo> = Vec::new();
    for group in materials {
        if group.owner != Some(peer)
            || !matches!(group.receiver, None | Some(0)) && group.receiver != Some(local)
        {
            continue;
        }
        for entry in group.entries {
            if entry.kind != AVC_MATERIAL {
                continue;
            }
            ensure!(
                entry.id.len() == 20 && valid_ciphertext(&entry.content),
                "Invalid FaceTime relay description material"
            );
            if let Some(previous) = accepted.iter().find(|previous| previous.id == entry.id) {
                ensure!(
                    previous.content == entry.content,
                    "Conflicting FaceTime relay description material"
                );
            } else {
                ensure!(
                    accepted.len() < MAX_PEER_DESCRIPTIONS,
                    "Too many FaceTime relay descriptions"
                );
                accepted.push(entry);
            }
        }
    }
    Ok(accepted)
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
    #[prost(message, repeated, tag = "15")]
    materials: Vec<Material>,
}

#[derive(Message)]
struct BindResponse {
    #[prost(uint32, optional, tag = "2")]
    channel_id: Option<u32>,
    #[prost(uint32, optional, tag = "6")]
    link_id: Option<u32>,
    #[prost(message, repeated, tag = "11")]
    connections: Vec<ConnectionInfo>,
    #[prost(message, repeated, tag = "15")]
    materials: Vec<Material>,
}

#[derive(Message)]
struct Material {
    #[prost(uint64, optional, tag = "1")]
    owner: Option<u64>,
    #[prost(uint64, optional, tag = "2")]
    receiver: Option<u64>,
    #[prost(message, repeated, tag = "3")]
    entries: Vec<MaterialInfo>,
}

#[derive(Message)]
struct MaterialInfo {
    #[prost(bytes = "vec", tag = "1")]
    id: Vec<u8>,
    #[prost(int32, tag = "2")]
    kind: i32,
    #[prost(bytes = "vec", tag = "3")]
    content: Vec<u8>,
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
