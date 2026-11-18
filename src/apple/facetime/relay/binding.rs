use std::{
    collections::VecDeque,
    time::{Duration, SystemTime},
};

use anyhow::{Context, Result, ensure};
use openssl::rand::rand_bytes;
use prost::Message;
use zeroize::Zeroizing;

use crate::apple::facetime::{
    CallAvcMaterial, CallEndpoint, CallMediaDescription, CallPeerKeys, PeerKeyOffer, PeerPrekey,
    description::{open_description, valid_ciphertext},
};

use super::{
    CallRelayAllocation, CallRelayConnection,
    http3::RelayHttp3,
    one_to_one::OneToOnePath,
    pod::{Pod, RelayDatagramChannel},
    quic::RelayWireDatagram,
};

const SERVICE_ID: u32 = 4096;
const WILDCARD_CHANNEL_BINDING: u32 = 512;
const AVC: i32 = 0;
const IDS: i32 = 1;
const AVC_MATERIAL: i32 = 12;
const PREKEY_MATERIAL: i32 = 11;
const MEDIA_KEY_MATERIAL: i32 = 13;
const SESSION_KEY_MATERIAL: i32 = 14;
const MAX_PEER_DESCRIPTIONS: usize = 8;
const MAX_PENDING_PEER_KEYS: usize = 16;

/// Device and media capabilities advertised during this call's registration.
#[derive(Clone, Copy)]
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
    one_to_one: Option<OneToOnePath>,
    peer_descriptions: Vec<MaterialInfo>,
    peer_keys: VecDeque<PeerKeyOffer>,
    peer_prekey: Option<PeerPrekey>,
    pub channel_id: u16,
    pub link_id: u32,
    pub avc: RelayChannel,
    pub ids: RelayChannel,
}

pub(crate) enum RelayPeerUpdate {
    Description,
    Keys(Box<PeerKeyOffer>),
}

/// An authenticated local relay binding that has no peer or media keys yet.
pub(crate) struct RingingRelay {
    binding: CallRelayBinding,
    eligible: Vec<CallEndpoint>,
}

impl RingingRelay {
    pub(super) async fn bind(
        connection: CallRelayConnection,
        profile: CallRelayProfile<'_>,
        eligible: Vec<CallEndpoint>,
    ) -> Result<Self> {
        ensure!(
            connection.call.peer == 0,
            "FaceTime relay already has a peer"
        );
        let mut binding = connection.bind_channels(profile, Vec::new()).await?;
        binding.subscribe_to_descriptions().await?;
        Ok(Self { binding, eligible })
    }

    pub(crate) async fn keepalive(&mut self) -> Result<()> {
        // QuickRelay uses the middle 32 bits of an NTP timestamp.
        let unix = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?;
        let seconds = (unix.as_secs() + 2_208_988_800) as u32;
        let fraction = ((u64::from(unix.subsec_nanos()) << 16) / 1_000_000_000) as u32;
        let request = StatsEnvelope {
            request: Some(StatsRequest {
                timestamp: (seconds << 16) | fraction,
            }),
        };
        self.binding
            .control
            .put("/QR/Stats", &request.encode_to_vec())
            .await?;
        Ok(())
    }

    pub(crate) async fn service_during_ring(&mut self) -> Result<()> {
        // The transport queues datagrams until IDS authenticates the selected participant.
        self.binding.control.transport.service_during_ring().await
    }

    pub(crate) async fn unbind(self) -> Result<()> {
        self.binding.unbind().await
    }

    pub(crate) fn select_peer(
        &mut self,
        selected: CallEndpoint,
        allocation: &CallRelayAllocation,
    ) -> Result<()> {
        ensure!(
            self.eligible.contains(&selected),
            "Unexpected FaceTime answering device"
        );
        let peer = selected
            .participant()
            .context("Missing FaceTime answering participant")?;
        let call = self.binding.control.transport.call;
        ensure!(
            call.peer == 0
                && call.local != peer
                && allocation.call_id == call.id
                && allocation.local_participant == call.local
                && allocation.caller_participant == peer
                && allocation.endpoint == self.binding.control.transport.peer_addr()?,
            "FaceTime relay and answering device belong to different calls"
        );
        self.binding.control.transport.call.peer = peer;
        self.binding.control.transport.device_key = allocation.device_key.clone();
        Ok(())
    }

    pub(crate) async fn wait_for_peer_prekey(&mut self) -> Result<Option<PeerPrekey>> {
        self.binding.wait_for_peer_prekey().await
    }

    pub(crate) async fn join(mut self, offer: &CallAvcMaterial) -> Result<CallRelayBinding> {
        self.binding.publish_description(offer).await?;
        Ok(self.binding)
    }
}

impl CallRelayBinding {
    pub(crate) async fn publish_description(&mut self, offer: &CallAvcMaterial) -> Result<()> {
        let call = self.control.transport.call;
        ensure!(
            call.peer != 0 && call.id == offer.call_id && call.local == offer.participant,
            "FaceTime relay and media description belong to different calls"
        );
        let request = PutMaterialEnvelope {
            request: Some(PutMaterialRequest {
                materials: vec![avc_material(offer, call.peer)],
            }),
        };
        let response = self
            .control
            .put("/QR/Material", &request.encode_to_vec())
            .await?;
        let response = PutMaterialResponseEnvelope::decode(response.as_slice())
            .context("Invalid FaceTime relay material response")?;
        ensure!(
            response.response.is_some(),
            "Missing FaceTime relay material acknowledgement"
        );
        Ok(())
    }

    /// Release an established relay binding and close its socket.
    pub async fn unbind(mut self) -> Result<()> {
        let envelope = UnbindRequestEnvelope {
            request: Some(UnbindRequest { reason: 1 }),
        };
        let response = self
            .control
            .put("/QR/UnAllocBind", &envelope.encode_to_vec())
            .await?;
        let response = UnbindResponseEnvelope::decode(response.as_slice())
            .context("Invalid FaceTime relay release response")?;
        ensure!(
            response.response.is_some(),
            "Missing FaceTime relay release response"
        );
        Ok(())
    }

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

    pub(crate) async fn subscribe_to_descriptions(&mut self) -> Result<()> {
        self.control.open_indications().await
    }

    pub(crate) async fn next_peer_update(&mut self) -> Result<Option<RelayPeerUpdate>> {
        ensure!(
            self.control.transport.call.peer != 0,
            "Missing authenticated FaceTime participant"
        );
        if let Some(offer) = self.peer_keys.pop_front() {
            return Ok(Some(RelayPeerUpdate::Keys(Box::new(offer))));
        }
        while let Some(description) = self.read_peer_materials().await? {
            if let Some(offer) = self.peer_keys.pop_front() {
                return Ok(Some(RelayPeerUpdate::Keys(Box::new(offer))));
            }
            if description {
                return Ok(Some(RelayPeerUpdate::Description));
            }
        }
        Ok(None)
    }

    pub(crate) async fn wait_for_peer_prekey(&mut self) -> Result<Option<PeerPrekey>> {
        if self.control.transport.device_key.is_none() {
            return Ok(None);
        }
        while self.peer_prekey.is_none() && self.read_peer_materials().await?.is_some() {}
        Ok(self.peer_prekey.clone())
    }

    async fn read_peer_materials(&mut self) -> Result<Option<bool>> {
        while let Some(payload) = self.control.next_indication().await? {
            let indication = PutMaterialIndicationEnvelope::decode(payload)
                .context("Invalid FaceTime relay indication")?;
            if let Some(update) = indication.indication {
                return self.record_peer_materials(update.materials).map(Some);
            }
        }
        Ok(None)
    }

    fn record_peer_materials(&mut self, materials: Vec<Material>) -> Result<bool> {
        let call = self.control.transport.call;
        if call.peer == 0 {
            return Ok(false);
        }
        let previous_count = self.peer_descriptions.len();
        for group in materials {
            if group.owner != Some(call.peer)
                || !matches!(group.receiver, None | Some(0)) && group.receiver != Some(call.local)
            {
                continue;
            }
            for entry in group.entries {
                match entry.kind {
                    PREKEY_MATERIAL if entry.id.len() == 20 && self.peer_prekey.is_none() => {
                        if let Some(signing) = &self.control.transport.device_key
                            && let Ok(payload) = signing.verify_material(call.id, &entry.content)
                            && let Ok(prekey) = PeerPrekey::from_relay(&payload)
                        {
                            self.peer_prekey = Some(prekey);
                        }
                    }
                    AVC_MATERIAL => append_peer_description(&mut self.peer_descriptions, entry)?,
                    MEDIA_KEY_MATERIAL | SESSION_KEY_MATERIAL
                        if group.receiver == Some(call.local)
                            && self.peer_keys.len() < MAX_PENDING_PEER_KEYS =>
                    {
                        if let Some(signing) = &self.control.transport.device_key
                            && let Ok(payload) = signing.verify_material(call.id, &entry.content)
                            && let Some(offer) = PeerKeyOffer::from_relay(
                                &payload,
                                entry.kind == MEDIA_KEY_MATERIAL,
                                &entry.id,
                                call.peer,
                            )
                        {
                            self.peer_keys.push_back(offer);
                        }
                    }
                    _ => (),
                }
            }
        }
        Ok(self.peer_descriptions.len() != previous_count)
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
            let RelayWireDatagram::Pod(channel, packet) =
                self.control.transport.receive_datagram(false).await?
            else {
                continue;
            };
            if let Some(data) = self.pod(channel).open(packet)? {
                return Ok((channel, data));
            }
        }
    }

    pub(crate) async fn negotiate_media_path(&mut self) -> Result<()> {
        if self.one_to_one.as_ref().is_some_and(OneToOnePath::ready) {
            return Ok(());
        }
        let transport = &mut self.control.transport;
        let ipv6 = transport.peer_addr()?.is_ipv6();
        let path = OneToOnePath::new(
            transport.call,
            transport.relay_keys(),
            self.channel_id,
            self.link_id,
        )?;
        transport.route_turn(path.channel())?;
        let announcement = path.announce(ipv6)?;
        self.one_to_one = Some(path);

        let mut retries = tokio::time::interval(Duration::from_millis(500));
        retries.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        tokio::time::timeout(Duration::from_secs(12), async {
            while self.one_to_one.as_ref().is_some_and(|path| !path.ready()) {
                tokio::select! {
                    _ = retries.tick() => self.send_datagram(RelayDatagramChannel::Signaling, &announcement).await?,
                    received = self.receive_datagram() => {
                        let (channel, payload) = received?;
                        if channel == RelayDatagramChannel::Signaling {
                            self.accept_route_message(&payload).await?;
                        }
                    }
                }
            }
            Ok(())
        }).await.context("The FaceTime caller did not confirm a media route")?
    }

    async fn accept_route_message(&mut self, payload: &[u8]) -> Result<()> {
        let path = self
            .one_to_one
            .as_mut()
            .context("Missing FaceTime media route")?;
        if let Some(reply) = path.accept_control(payload)? {
            self.send_datagram(RelayDatagramChannel::Signaling, &reply)
                .await?;
        }
        Ok(())
    }

    pub(crate) async fn send_routed_rtp(&mut self, protected_rtp: &[u8]) -> Result<()> {
        let path = self
            .one_to_one
            .as_ref()
            .context("Missing FaceTime media route")?;
        let packet = path.wrap_media(protected_rtp)?;
        self.control.transport.send_datagram(&packet).await
    }

    pub(crate) async fn receive_routed_rtp(&mut self) -> Result<Zeroizing<Vec<u8>>> {
        ensure!(
            self.one_to_one.as_ref().is_some_and(OneToOnePath::ready),
            "Missing FaceTime media route"
        );
        loop {
            let received = self.control.transport.receive_datagram(true).await?;
            let packet = match received {
                RelayWireDatagram::Turn(packet) => Zeroizing::new(packet),
                RelayWireDatagram::Pod(channel, packet) => {
                    let Some(payload) = self.pod(channel).open(packet)? else {
                        continue;
                    };
                    if channel == RelayDatagramChannel::Signaling {
                        self.accept_route_message(&payload).await?;
                        continue;
                    }
                    payload
                }
            };
            if let Some(media) = self
                .one_to_one
                .as_ref()
                .and_then(|path| path.open_media(&packet))
            {
                return Ok(Zeroizing::new(media.to_vec()));
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
        ensure!(
            self.call.peer != 0,
            "FaceTime relay has no authenticated peer"
        );
        self.bind_channels(profile, Vec::new()).await
    }

    /// Bind and publish this device's encrypted media description in the same request.
    pub async fn bind_with_description(
        self,
        profile: CallRelayProfile<'_>,
        offer: &CallAvcMaterial,
    ) -> Result<CallRelayBinding> {
        ensure!(
            self.call.peer != 0
                && self.call.id == offer.call_id
                && self.call.local == offer.participant,
            "FaceTime relay and media description belong to different calls"
        );
        self.bind_channels(profile, vec![avc_material(offer, 0)])
            .await
    }

    async fn bind_channels(
        mut self,
        profile: CallRelayProfile<'_>,
        mut materials: Vec<Material>,
    ) -> Result<CallRelayBinding> {
        ensure!(
            !profile.os_version.is_empty()
                && profile.os_version.len() <= 128
                && !profile.hardware_version.is_empty()
                && profile.hardware_version.len() <= 128,
            "Invalid FaceTime relay device profile"
        );
        if let Some(prekey) = self.local_prekey.take() {
            ensure!(
                prekey.call == self.call.id,
                "FaceTime relay prekey belongs to another call"
            );
            materials.push(Material {
                owner: Some(0),
                receiver: Some(0),
                entries: vec![MaterialInfo {
                    id: prekey.material_id.to_vec(),
                    kind: PREKEY_MATERIAL,
                    content: prekey.contents,
                }],
            });
        }
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
        let media = Pod::new(&control.transport, avc, RelayDatagramChannel::Media)?;
        let signaling = Pod::new(&control.transport, ids, RelayDatagramChannel::Signaling)?;
        let mut bound = CallRelayBinding {
            control,
            media,
            signaling,
            one_to_one: None,
            peer_descriptions: Vec::new(),
            peer_keys: VecDeque::new(),
            peer_prekey: None,
            channel_id,
            link_id,
            avc,
            ids,
        };
        bound.record_peer_materials(binding.materials)?;
        Ok(bound)
    }
}

fn avc_material(offer: &CallAvcMaterial, receiver: u64) -> Material {
    Material {
        owner: Some(0), // The relay resolves zero to this connection's participant ID.
        receiver: Some(receiver),
        entries: vec![MaterialInfo {
            id: offer.material_id.to_vec(),
            kind: AVC_MATERIAL,
            content: offer.ciphertext.clone(),
        }],
    }
}

fn append_peer_description(accepted: &mut Vec<MaterialInfo>, entry: MaterialInfo) -> Result<()> {
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
    Ok(())
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
struct UnbindRequestEnvelope {
    #[prost(message, optional, tag = "22")]
    request: Option<UnbindRequest>,
}

#[derive(Message)]
struct UnbindRequest {
    #[prost(int32, tag = "1")]
    reason: i32,
}

#[derive(Message)]
struct UnbindResponseEnvelope {
    #[prost(message, optional, tag = "23")]
    response: Option<UnbindResponse>,
}

#[derive(Message)]
struct UnbindResponse {}

#[derive(Message)]
struct StatsEnvelope {
    #[prost(message, optional, tag = "18")]
    request: Option<StatsRequest>,
}

#[derive(Message)]
struct StatsRequest {
    #[prost(uint32, tag = "1")]
    timestamp: u32,
}

#[derive(Message)]
struct PutMaterialEnvelope {
    #[prost(message, optional, tag = "24")]
    request: Option<PutMaterialRequest>,
}

#[derive(Message)]
struct PutMaterialRequest {
    #[prost(message, repeated, tag = "1")]
    materials: Vec<Material>,
}

#[derive(Message)]
struct PutMaterialResponseEnvelope {
    #[prost(message, optional, tag = "25")]
    response: Option<PutMaterialResponse>,
}

#[derive(Message)]
struct PutMaterialResponse {}

#[derive(Message)]
struct PutMaterialIndicationEnvelope {
    #[prost(message, optional, tag = "26")]
    indication: Option<PutMaterialIndication>,
}

#[derive(Message)]
struct PutMaterialIndication {
    #[prost(message, repeated, tag = "1")]
    materials: Vec<Material>,
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
