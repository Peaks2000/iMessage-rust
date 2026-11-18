use std::{
    collections::{HashMap, HashSet, VecDeque},
    io::{Read, Write},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use flate2::{Compression, read::GzDecoder, write::GzEncoder};
use openssl::pkey::Public;
use plist::{Data, Dictionary, Value};
use serde::Deserialize;
use tokio::time::{Instant, timeout};
use uuid::Uuid;

use crate::media::{MediaReference, MediaSource};
use crate::{CallMode, Delivery, IncomingCall, Message, SendText, TapbackEvent, address, now_ms};

use super::{
    Identity,
    aps::{Courier, Frame, TOPIC, push_id},
    crypto::KeyPair,
    facetime,
    http::plist_xml_gzip,
    message_content, mmcs, nonce, rsa_signature, tapback,
};

const QUERY_URL: &str = "https://query.ess.apple.com/WebObjects/QueryService.woa/wa/query";
const QUERY_KEY: &[u8] = b"id-query";
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(12);
const MAX_PLIST: usize = 1024 * 1024;
const MAX_QUEUE: usize = 64;
const MAX_BATCH: usize = 10_000;

pub(crate) struct Madrid {
    courier: Courier,
    queued: VecDeque<Notification>,
    cached: HashMap<(&'static str, String), (Instant, Vec<Destination>)>,
    keepalive: Instant,
}

pub(crate) struct Notification {
    pub id: [u8; 4],
    topic: &'static str,
    data: Dictionary,
}

pub(crate) enum Incoming {
    Message(Message, Vec<MediaSource>),
    Tapback(TapbackEvent),
    Call(facetime::CallSignal),
}

struct Destination {
    push: Vec<u8>,
    session: Vec<u8>,
    public_key: KeyPair<Public>,
    device_key: Option<facetime::PeerDeviceKey>,
}

pub(crate) struct OutgoingCallTargets {
    pub(crate) relay: Arc<facetime::OutgoingRelay>,
    targets: HashMap<String, Vec<Destination>>,
}

impl OutgoingCallTargets {
    pub(crate) fn allocation_for_peer(
        &self,
        caller: &str,
        endpoint: facetime::CallEndpoint,
    ) -> Result<facetime::CallRelayAllocation> {
        let device = self
            .targets
            .get(caller)
            .into_iter()
            .flatten()
            .find(|device| device.push == endpoint.push_token())
            .context("The FaceTime answering device is unavailable")?;
        Ok(self
            .relay
            .for_peer(endpoint)?
            .with_device_key(device.device_key.clone()))
    }
}

struct DeliveryPayload<'a> {
    recipient: &'a str,
    guid: Uuid,
    bytes: &'a [u8],
    request_receipt: bool,
    kind: DeliveryKind,
}

#[derive(Clone, Copy)]
enum DeliveryKind {
    Message,
    CallInvitation(u64),
    CallParticipant {
        joined: bool,
        initiator: bool,
    },
    CallMaterial {
        command: u64,
        expires_at: Option<u64>,
    },
}

impl DeliveryPayload<'_> {
    fn topic(&self) -> &'static str {
        match self.kind {
            DeliveryKind::Message => TOPIC,
            _ => facetime::SIGNALING,
        }
    }
}

#[derive(Deserialize)]
struct LookupResponse {
    status: u64,
    results: Option<HashMap<String, LookupAddress>>,
}

#[derive(Deserialize)]
struct LookupAddress {
    identities: Vec<LookupDevice>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
struct LookupDevice {
    push_token: Data,
    session_token: Data,
    client_data: LookupClient,
    kt_loggable_data: Option<Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
struct LookupClient {
    public_message_identity_key: Option<Data>,
    ngm_public_identity: Option<Value>,
}

impl Madrid {
    pub(crate) async fn connect(identity: &Identity) -> Result<Self> {
        Ok(Self {
            courier: Courier::connect(identity).await?,
            queued: VecDeque::new(),
            cached: HashMap::new(),
            keepalive: Instant::now(),
        })
    }

    pub(crate) async fn next_notification(&mut self) -> Result<Notification> {
        if let Some(notification) = self.queued.pop_front() {
            return Ok(notification);
        }
        loop {
            match tokio::time::timeout_at(
                self.keepalive + Duration::from_secs(90),
                self.courier.next(),
            )
            .await
            {
                Ok(frame) => {
                    if let Some(notification) = self.notification(frame?).await? {
                        return Ok(notification);
                    }
                }
                Err(_) => {
                    self.ping().await?;
                    if let Some(notification) = self.queued.pop_front() {
                        return Ok(notification);
                    }
                }
            }
        }
    }

    pub(crate) fn take_queued(&mut self) -> VecDeque<Notification> {
        std::mem::take(&mut self.queued)
    }

    pub(crate) async fn acknowledge(&mut self, id: [u8; 4]) -> Result<()> {
        self.courier.ack(id).await
    }

    async fn ping(&mut self) -> Result<()> {
        self.courier.ping().await?;
        timeout(RESPONSE_TIMEOUT, async {
            loop {
                let frame = self.courier.next().await?;
                if frame.code == 0x0d {
                    self.keepalive = Instant::now();
                    return Ok(());
                }
                self.queue(frame).await?;
            }
        })
        .await
        .context("Apple courier did not respond to keepalive")?
    }

    async fn notification(&mut self, frame: Frame) -> Result<Option<Notification>> {
        if frame.code != 0x0a {
            return Ok(None);
        }
        let id = frame
            .field(4)
            .context("Missing Apple push identifier")?
            .try_into()?;
        if let Some(topic) = frame.field(2).and_then(|digest| self.courier.topic(digest))
            && let Some(bytes) = frame.field(3)
            && let Ok(data) = plist::from_bytes(bytes)
        {
            return Ok(Some(Notification { id, topic, data }));
        }
        self.courier.ack(id).await?;
        Ok(None)
    }

    async fn queue(&mut self, frame: Frame) -> Result<()> {
        if let Some(notification) = self.notification(frame).await? {
            ensure!(
                self.queued.len() < MAX_QUEUE,
                "Apple notification queue is full"
            );
            self.queued.push_back(notification);
        }
        Ok(())
    }

    async fn send_push(&mut self, id: [u8; 4], payload: &[u8]) -> Result<bool> {
        self.send_push_on(TOPIC, id, payload).await
    }

    async fn send_push_on(&mut self, topic: &str, id: [u8; 4], payload: &[u8]) -> Result<bool> {
        self.courier.push(topic, id, payload).await?;
        timeout(RESPONSE_TIMEOUT, async {
            loop {
                let frame = self.courier.next().await?;
                if frame.code == 0x0b && frame.field(4) == Some(id.as_slice()) {
                    return Ok(frame.field(8) == Some(&[0]));
                }
                self.queue(frame).await?;
            }
        })
        .await
        .context("Apple push acknowledgment timed out")?
    }

    async fn wait_for_push(
        &mut self,
        matches: impl Fn(&Notification) -> bool,
        timeout_message: &'static str,
    ) -> Result<Dictionary> {
        timeout(RESPONSE_TIMEOUT, async {
            loop {
                let item = if let Some(index) = self.queued.iter().position(&matches) {
                    self.queued.remove(index)
                } else {
                    let frame = self.courier.next().await?;
                    self.notification(frame).await?
                };
                if let Some(item) = item {
                    if matches(&item) {
                        self.acknowledge(item.id).await?;
                        return Ok(item.data);
                    }
                    ensure!(
                        self.queued.len() < MAX_QUEUE,
                        "Apple notification queue is full"
                    );
                    self.queued.push_back(item);
                }
            }
        })
        .await
        .context(timeout_message)?
    }

    async fn query(
        &mut self,
        identity: &Identity,
        topic: &'static str,
        targets: &[&str],
        required: bool,
    ) -> Result<HashMap<String, Vec<Destination>>> {
        let body = lookup_body(targets)?;
        let nonce = nonce(1)?;
        let mut signed = nonce.to_vec();
        for field in [QUERY_KEY, b"", &body, &identity.token] {
            signed.extend_from_slice(&u32::try_from(field.len())?.to_be_bytes());
            signed.extend_from_slice(field);
        }
        let mut headers = dictionary([
            ("x-id-self-uri", value(&identity.handle)),
            ("x-push-token", value(STANDARD.encode(identity.token))),
            (
                "x-protocol-version",
                value(identity.protocol_version.to_string()),
            ),
            (
                "user-agent",
                value(format!("com.apple.madrid-lookup {}", identity.user_agent)),
            ),
            ("x-id-nonce", value(STANDARD.encode(nonce))),
            (
                "x-id-sig",
                value(STANDARD.encode(rsa_signature(&identity.ids_key, &signed)?)),
            ),
            (
                "x-id-cert",
                value(
                    STANDARD.encode(
                        identity
                            .ids_certificate(topic)
                            .context("No IDS registration for this Apple service")?,
                    ),
                ),
            ),
        ]);
        if required {
            headers.insert("x-required-for-message".into(), value("true"));
            headers.insert("x-result-expected".into(), value("true"));
        }
        if topic == facetime::VIDEO {
            headers.insert("x-id-sub-service".into(), value(topic));
        }
        let correlation = Uuid::new_v4();
        let wire = binary(&dictionary([
            ("c", 96.into()),
            ("cT", value("application/x-apple-plist")),
            ("U", data(correlation.as_bytes())),
            ("u", value(QUERY_URL)),
            ("v", 2.into()),
            ("h", Value::Dictionary(headers)),
            ("b", data(&body)),
        ]))?;
        ensure!(
            self.send_push_on(topic, push_id()?, &wire).await?,
            "Apple rejected the IDS directory request"
        );
        let response = self
            .wait_for_push(
                |item| {
                    item.topic == topic
                        && field_data(&item.data, "U") == Some(correlation.as_bytes())
                },
                "Apple IDS lookup timed out",
            )
            .await?;
        let bytes = field_data(&response, "b").with_context(|| {
            format!(
                "Apple rejected the IDS lookup (status {})",
                response
                    .get("s")
                    .and_then(Value::as_signed_integer)
                    .unwrap_or(-1)
            )
        })?;
        let decoded: LookupResponse = plist::from_bytes(&decompress(bytes)?)?;
        ensure!(
            decoded.status == 0,
            "Apple IDS lookup returned status {}",
            decoded.status
        );
        let source = decoded
            .results
            .context("Apple IDS returned no directory results")?;
        let mut results = HashMap::new();
        for (uri, result) in source {
            let mut destinations = Vec::new();
            for device in result.identities {
                let Some(key) = device.client_data.public_message_identity_key else {
                    continue;
                };
                if device.push_token.as_ref().len() != 32
                    || device.session_token.as_ref().is_empty()
                    || device.session_token.as_ref().len() > 4096
                {
                    continue;
                }
                if let Ok(public_key) = KeyPair::decode(key.as_ref()) {
                    let device_key = if matches!(topic, facetime::SIGNALING | facetime::VIDEO) {
                        device
                            .kt_loggable_data
                            .iter()
                            .chain(&device.client_data.ngm_public_identity)
                            .filter_map(Value::as_data)
                            .find_map(|bytes| facetime::PeerDeviceKey::from_directory(bytes).ok())
                    } else {
                        None
                    };
                    destinations.push(Destination {
                        push: device.push_token.into(),
                        session: device.session_token.into(),
                        public_key,
                        device_key,
                    });
                }
            }
            results.insert(uri, destinations);
        }
        Ok(results)
    }

    pub(crate) async fn send(
        &mut self,
        identity: &Identity,
        message: &SendText,
    ) -> Result<Delivery> {
        let participants = [&identity.handle[..], &message.address[..]];
        let targets = self
            .message_destinations(identity, TOPIC, &message.address)
            .await?;
        let plain = format!("{}{}", "\u{fffc}".repeat(message.files.len()), message.body);
        let mut content = dictionary([
            ("t", value(plain)),
            (
                "p",
                Value::Array(participants.iter().map(|uri| value(*uri)).collect()),
            ),
            ("pv", 0.into()),
            ("gv", value("8")),
            ("v", value("1")),
        ]);
        let text = if message.files.is_empty() {
            compress(&binary(&content)?)?
        } else {
            let mut files = Vec::with_capacity(message.files.len());
            for file in &message.files {
                let reference = mmcs::upload(self, identity, &file.bytes).await?;
                files.push((file.info.clone(), reference));
            }
            content.insert(
                "x".into(),
                value(message_content::encode(&message.body, files.into_iter())?),
            );
            binary(&content)?
        };
        self.deliver_message(
            identity,
            DeliveryPayload {
                recipient: &message.address,
                guid: message.id,
                bytes: &text,
                request_receipt: true,
                kind: DeliveryKind::Message,
            },
            &targets,
        )
        .await
    }

    pub(crate) async fn send_tapback(
        &mut self,
        identity: &Identity,
        target: &Message,
        event: &TapbackEvent,
    ) -> Result<Delivery> {
        let payload = tapback_payload(event, target, &identity.handle)?;
        let targets = self
            .message_destinations(identity, TOPIC, &event.chat)
            .await?;
        self.deliver_message(
            identity,
            DeliveryPayload {
                recipient: &event.chat,
                guid: event.id,
                bytes: &payload,
                request_receipt: false,
                kind: DeliveryKind::Message,
            },
            &targets,
        )
        .await
    }

    pub(crate) async fn decline_call(
        &mut self,
        identity: &Identity,
        call: &IncomingCall,
    ) -> Result<()> {
        let bytes = compress(&facetime::decline(call.id))?;
        let targets = self
            .message_destinations(identity, facetime::SIGNALING, &call.caller)
            .await?;
        ensure!(call.expires_ms > now_ms(), "This FaceTime call has ended");
        let result = self
            .deliver_message(
                identity,
                DeliveryPayload {
                    recipient: &call.caller,
                    guid: Uuid::new_v4(),
                    bytes: &bytes,
                    request_receipt: false,
                    kind: DeliveryKind::CallInvitation(facetime::DECLINE),
                },
                &targets,
            )
            .await?;
        ensure!(
            result == Delivery::Accepted,
            "Apple did not confirm the call decline"
        );
        Ok(())
    }

    /// Send a prekey followed by wrapped session and media keys to the ringing device.
    pub(crate) async fn publish_call_keys(
        &mut self,
        identity: &Identity,
        handshake: &facetime::CallMediaHandshake,
        endpoint: facetime::CallEndpoint,
        offer: &facetime::CallKeyOffer,
    ) -> Result<()> {
        let call = handshake.call();
        let remaining = call.expires_ms.saturating_sub(now_ms());
        ensure!(remaining > 0, "This FaceTime call has ended");
        timeout(Duration::from_millis(remaining as u64), async {
            let targets = self
                .call_destination(identity, &call.caller, endpoint)
                .await?;

            let id = call.id.to_string().to_ascii_uppercase();
            let prekey = binary(&dictionary([
                ("s", value(&id)),
                ("fanout-groupID-key", value(&id)),
                ("rtmpk", data(handshake.public_prekey())),
                ("rtmpwm", 1.into()),
            ]))?;
            let mut keys: Dictionary = plist::from_bytes(&offer.payload)?;
            keys.insert(
                "rtallmkmuri".into(),
                Value::Array(vec![value(&identity.handle), value(&call.caller)]),
            );
            let key_bytes = binary(&keys)?;
            let expiry = u64::try_from(call.expires_ms.saturating_add(999) / 1000)?;
            for (command, expires_at, bytes) in [
                (facetime::PREKEY_COMMAND, None, prekey.as_slice()),
                (
                    facetime::KEY_MATERIAL_COMMAND,
                    Some(expiry),
                    key_bytes.as_slice(),
                ),
            ] {
                ensure!(call.expires_ms > now_ms(), "This FaceTime call has ended");
                let sent = self
                    .deliver_message(
                        identity,
                        DeliveryPayload {
                            recipient: &call.caller,
                            guid: Uuid::new_v4(),
                            bytes,
                            request_receipt: false,
                            kind: DeliveryKind::CallMaterial {
                                command,
                                expires_at,
                            },
                        },
                        &targets,
                    )
                    .await?;
                ensure!(
                    sent == Delivery::Accepted,
                    "Apple did not confirm the FaceTime key transmission"
                );
            }
            Ok(())
        })
        .await
        .context("The FaceTime call ended while publishing keys")?
    }

    async fn call_destination(
        &mut self,
        identity: &Identity,
        caller: &str,
        endpoint: facetime::CallEndpoint,
    ) -> Result<HashMap<String, Vec<Destination>>> {
        ensure!(
            endpoint.participant().is_some(),
            "The caller has not joined FaceTime yet"
        );
        ensure!(
            *endpoint.push_token() != identity.token,
            "Invalid FaceTime recipient"
        );
        let mut targets = self
            .query(identity, facetime::SIGNALING, &[caller], true)
            .await?;
        let devices = targets
            .get_mut(caller)
            .context("The FaceTime caller device is no longer in the IDS directory")?;
        devices.retain(|device| device.push == endpoint.push_token());
        ensure!(
            devices.len() == 1,
            "The FaceTime caller device could not be identified"
        );
        Ok(targets)
    }

    pub(crate) async fn update_call_participant(
        &mut self,
        identity: &Identity,
        call: &IncomingCall,
        endpoint: facetime::CallEndpoint,
        allocation: &facetime::CallRelayAllocation,
        join: Option<(&[u8], &[u8; 65], CallMode)>,
        initiator: bool,
    ) -> Result<()> {
        ensure!(
            call.id == allocation.call_id
                && endpoint.participant() == Some(allocation.caller_participant),
            "FaceTime relay no longer matches the caller"
        );
        let setup_timeout = if join.is_some() {
            let remaining = call.expires_ms.saturating_sub(now_ms());
            ensure!(remaining > 0, "This FaceTime call has ended");
            Duration::from_millis(remaining as u64).min(RESPONSE_TIMEOUT)
        } else {
            RESPONSE_TIMEOUT
        };
        timeout(setup_timeout, async {
            let targets = self
                .call_destination(identity, &call.caller, endpoint)
                .await?;
            let payload = facetime::participant_update(
                allocation,
                &identity.handle,
                &call.caller,
                join,
                initiator,
            );
            let bytes = binary(&payload)?;
            let sent = self
                .deliver_message(
                    identity,
                    DeliveryPayload {
                        recipient: &call.caller,
                        guid: Uuid::new_v4(),
                        request_receipt: false,
                        bytes: &bytes,
                        kind: DeliveryKind::CallParticipant {
                            joined: join.is_some(),
                            initiator,
                        },
                    },
                    &targets,
                )
                .await?;
            ensure!(
                sent == Delivery::Accepted,
                "Apple did not confirm the FaceTime participant update"
            );
            Ok(())
        })
        .await
        .context("FaceTime participant update timed out")?
    }

    pub(crate) async fn allocate_call_relay(
        &mut self,
        identity: &Identity,
        call: &IncomingCall,
        endpoint: facetime::CallEndpoint,
    ) -> Result<facetime::CallRelayAllocation> {
        let remaining = call.expires_ms.saturating_sub(now_ms());
        ensure!(remaining > 0, "This FaceTime call has ended");
        ensure!(
            endpoint.participant().is_some(),
            "The caller has not joined FaceTime yet"
        );
        timeout(Duration::from_millis(remaining as u64), async {
            let targets = self
                .call_destination(identity, &call.caller, endpoint)
                .await?;
            let caller = targets
                .get(&call.caller)
                .into_iter()
                .flatten()
                .next()
                .context("The FaceTime caller device is no longer in the IDS directory")?;
            ensure!(call.expires_ms > now_ms(), "This FaceTime call has ended");
            let (request, response) = self
                .request_call_relay(
                    identity,
                    call.id,
                    [(
                        call.caller.as_str(),
                        caller.push.as_slice(),
                        caller.session.as_slice(),
                    )],
                )
                .await?;
            Ok(facetime::CallRelayAllocation::parse(
                response,
                request,
                call.id,
                (&identity.handle, &identity.token),
                (&call.caller, endpoint),
            )?
            .with_device_key(caller.device_key.clone()))
        })
        .await
        .context("The FaceTime call ended while waiting for a relay")?
    }

    pub(crate) async fn outgoing_call_targets(
        &mut self,
        identity: &Identity,
        call: &IncomingCall,
    ) -> Result<OutgoingCallTargets> {
        ensure!(
            call.caller != identity.handle,
            "Choose a FaceTime recipient"
        );
        let mut targets = self
            .query(identity, facetime::SIGNALING, &[&call.caller], true)
            .await?;
        let devices = targets
            .get_mut(&call.caller)
            .context("Apple IDS could not find the FaceTime recipient")?;
        let mut seen = HashSet::new();
        devices.retain(|device| device.push != identity.token && seen.insert(device.push.clone()));
        ensure!(
            (1..64).contains(&devices.len()),
            "Apple IDS returned an invalid number of FaceTime devices"
        );
        ensure!(call.expires_ms > now_ms(), "This FaceTime call has ended");
        let (request, response) = self
            .request_call_relay(
                identity,
                call.id,
                devices.iter().map(|device| {
                    (
                        call.caller.as_str(),
                        device.push.as_slice(),
                        device.session.as_slice(),
                    )
                }),
            )
            .await?;
        let relay = facetime::OutgoingRelay::parse(
            response,
            request,
            call.id,
            (&identity.handle, &identity.token),
            &call.caller,
            devices
                .iter()
                .filter_map(|device| device.push.as_slice().try_into().ok()),
        )?;
        devices.retain(|device| {
            relay
                .endpoints()
                .iter()
                .any(|endpoint| endpoint.push_token() == device.push.as_slice())
        });
        Ok(OutgoingCallTargets {
            relay: Arc::new(relay),
            targets,
        })
    }

    pub(crate) async fn send_outgoing_call(
        &mut self,
        identity: &Identity,
        call: &IncomingCall,
        target: &OutgoingCallTargets,
        join: Option<(&[u8], &[u8; 65], CallMode)>,
    ) -> Result<()> {
        ensure!(
            target.relay.call_id() == call.id,
            "FaceTime relay belongs to a different call"
        );
        ensure!(
            join.is_none() || call.expires_ms > now_ms(),
            "This FaceTime call has ended"
        );
        let payload = binary(&facetime::outgoing_invitation(
            &target.relay,
            &identity.handle,
            &call.caller,
            join,
        ))?;
        let result = self
            .deliver_message(
                identity,
                DeliveryPayload {
                    recipient: &call.caller,
                    guid: Uuid::new_v4(),
                    bytes: &payload,
                    request_receipt: false,
                    kind: DeliveryKind::CallParticipant {
                        joined: join.is_some(),
                        initiator: true,
                    },
                },
                &target.targets,
            )
            .await?;
        ensure!(
            result == Delivery::Accepted,
            "Apple did not confirm the FaceTime call invitation"
        );
        Ok(())
    }

    async fn request_call_relay<'a>(
        &mut self,
        identity: &Identity,
        call: Uuid,
        devices: impl IntoIterator<Item = (&'a str, &'a [u8], &'a [u8])>,
    ) -> Result<(Uuid, Dictionary)> {
        let request = Uuid::new_v4();
        let id = push_id()?;
        let bytes = binary(&facetime::relay::allocation_request(
            request,
            call,
            id,
            &identity.handle,
            &identity.user_agent,
            devices,
        ))?;
        ensure!(
            bytes.len() <= MAX_BATCH,
            "FaceTime relay request exceeds the device limit"
        );
        let topic = facetime::relay::RELAY_TOPIC;
        ensure!(
            self.send_push_on(topic, id, &bytes).await?,
            "Apple rejected the FaceTime relay request"
        );
        let response = self
            .wait_for_push(
                |item| {
                    item.topic == topic
                        && field_data(&item.data, "U") == Some(request.as_bytes())
                        && item.data.get("c").and_then(Value::as_unsigned_integer) != Some(255)
                },
                "Apple returned no FaceTime relay allocation",
            )
            .await?;
        Ok((request, response))
    }

    async fn message_destinations(
        &mut self,
        identity: &Identity,
        topic: &'static str,
        recipient: &str,
    ) -> Result<HashMap<String, Vec<Destination>>> {
        let targets = self
            .query(identity, topic, &[&identity.handle, recipient], true)
            .await?;
        let entries = targets
            .get(recipient)
            .context("Apple IDS has no result for this recipient")?;
        ensure!(
            entries.iter().any(|device| device.push != identity.token),
            "Apple IDS returned no compatible devices for this recipient"
        );
        Ok(targets)
    }

    async fn deliver_message(
        &mut self,
        identity: &Identity,
        payload: DeliveryPayload<'_>,
        targets: &HashMap<String, Vec<Destination>>,
    ) -> Result<Delivery> {
        let mut batches = vec![Vec::new()];
        let mut batch_bytes = 0;
        let mut seen = HashSet::new();
        for uri in [payload.recipient, identity.handle.as_str()] {
            for device in targets.get(uri).into_iter().flatten() {
                if device.push == identity.token || !seen.insert(device.push.as_slice()) {
                    continue;
                }
                let encrypted = identity
                    .message_keys
                    .seal(&device.public_key, payload.bytes)?;
                let cost = encrypted.len() + device.session.len() + 512;
                ensure!(
                    cost <= MAX_BATCH && seen.len() <= 64,
                    "Too many Apple device endpoints"
                );
                if batch_bytes + cost > MAX_BATCH {
                    batches.push(Vec::new());
                    batch_bytes = 0;
                }
                batch_bytes += cost;
                batches
                    .last_mut()
                    .expect("A batch always exists")
                    .push(Value::Dictionary(dictionary([
                        ("tP", value(uri)),
                        (
                            "D",
                            Value::Boolean(payload.request_receipt && uri == payload.recipient),
                        ),
                        ("sT", data(&device.session)),
                        ("P", data(&encrypted)),
                        ("t", data(&device.push)),
                    ])));
            }
        }

        let payloads = batches
            .into_iter()
            .enumerate()
            .map(|(index, bundle)| {
                let id = push_id()?;
                let mut wire = dictionary([
                    (
                        "c",
                        match payload.kind {
                            DeliveryKind::Message => 100,
                            DeliveryKind::CallInvitation(_) => facetime::INVITATION_COMMAND,
                            DeliveryKind::CallMaterial { command, .. } => command,
                            DeliveryKind::CallParticipant { joined: true, .. } => {
                                facetime::JOIN_COMMAND
                            }
                            DeliveryKind::CallParticipant { joined: false, .. } => {
                                facetime::LEAVE_COMMAND
                            }
                        }
                        .into(),
                    ),
                    ("E", value("pair")),
                    ("ua", value(&identity.user_agent)),
                    ("v", 8.into()),
                    ("i", i32::from_be_bytes(id).into()),
                    ("U", data(payload.guid.as_bytes())),
                    ("sP", value(&identity.handle)),
                    ("fcn", (index as u32 + 1).into()),
                    ("dtl", Value::Array(bundle)),
                ]);
                match payload.kind {
                    DeliveryKind::Message => {}
                    DeliveryKind::CallInvitation(context) => {
                        wire.insert("cc".into(), context.into());
                    }
                    DeliveryKind::CallMaterial { expires_at, .. } => {
                        wire.insert("siu".into(), Value::Boolean(false));
                        if let Some(expires_at) = expires_at {
                            wire.insert("eX".into(), expires_at.into());
                        }
                    }
                    DeliveryKind::CallParticipant { joined, initiator } => {
                        wire.insert("is-initiator-key".into(), Value::Boolean(initiator));
                        wire.insert("up1".into(), Value::Boolean(!joined));
                        if !joined {
                            wire.insert("cc".into(), 1.into());
                            wire.insert("H".into(), 3.into());
                        }
                    }
                }
                Ok((id, binary(&wire)?))
            })
            .collect::<Result<Vec<_>>>()?;

        let mut pushed = false;
        for (id, wire) in payloads {
            match self.send_push_on(payload.topic(), id, &wire).await {
                Ok(true) => pushed = true,
                Ok(false) if !pushed => return Ok(Delivery::Failed),
                Ok(false) | Err(_) => return Ok(Delivery::Unknown),
            }
        }
        Ok(Delivery::Accepted)
    }

    pub(crate) async fn download(
        &mut self,
        identity: &Identity,
        reference: &MediaReference,
        size: usize,
    ) -> Result<bytes::Bytes> {
        mmcs::download(self, identity, reference, size).await
    }

    pub(super) async fn media_request<const N: usize>(
        &mut self,
        identity: &Identity,
        command: u64,
        fields: [(&str, Value); N],
    ) -> Result<Dictionary> {
        let id = push_id()?;
        let message_id = i32::from_be_bytes(id);
        let mut payload = dictionary(fields);
        payload.extend(dictionary([
            ("c", command.into()),
            ("cV", 2.into()),
            ("i", message_id.into()),
            ("ua", value(&identity.user_agent)),
        ]));
        ensure!(
            self.send_push(id, &binary(&payload)?).await?,
            "Apple rejected the MMCS request"
        );
        let matches = |item: &Notification| {
            item.data.get("c").and_then(Value::as_unsigned_integer) == Some(command)
                && item
                    .data
                    .get("i")
                    .and_then(Value::as_signed_integer)
                    .is_some_and(|value| value as i32 == message_id)
        };
        self.wait_for_push(matches, "Apple MMCS authorization timed out")
            .await
    }

    pub(crate) async fn decode(
        &mut self,
        identity: &Identity,
        notice: &Notification,
    ) -> Result<Option<Incoming>> {
        let wire = &notice.data;
        let command = wire.get("c").and_then(Value::as_unsigned_integer);
        let encryption = field_str(wire, "E");
        let call = command.filter(|command| {
            matches!(notice.topic, facetime::SIGNALING | facetime::VIDEO)
                && matches!(
                    *command,
                    facetime::INVITATION_COMMAND
                        | facetime::JOIN_COMMAND
                        | facetime::LEAVE_COMMAND
                        | facetime::PREKEY_COMMAND
                        | facetime::KEY_MATERIAL_COMMAND
                )
                && encryption == Some("pair")
        });
        let message = notice.topic == TOPIC
            && command == Some(100)
            && encryption.is_none_or(|name| name == "pair");
        if call.is_none() && !message {
            return Ok(None);
        }
        let (Some(sender), Some(target), Some(token), Some(envelope), Some(guid)) = (
            field_str(wire, "sP"),
            field_str(wire, "tP"),
            field_data(wire, "t"),
            field_data(wire, "P"),
            field_data(wire, "U"),
        ) else {
            return Ok(None);
        };
        let (Ok(sender), Ok(target), Ok(guid), Ok(push_token)) = (
            address(sender),
            address(target),
            Uuid::from_slice(guid),
            token.try_into(),
        ) else {
            return Ok(None);
        };
        if target != identity.handle {
            return Ok(None);
        }

        let cache_key = (notice.topic, sender.clone());
        self.cached
            .retain(|_, (deadline, _)| *deadline > Instant::now());
        if !self
            .cached
            .get(&cache_key)
            .is_some_and(|(_, keys)| keys.iter().any(|key| key.push == token))
        {
            let mut keys = self
                .query(identity, notice.topic, &[&sender], false)
                .await?;
            if self.cached.len() >= 128 {
                self.cached.clear();
            }
            self.cached.insert(
                cache_key.clone(),
                (
                    Instant::now() + Duration::from_secs(120),
                    keys.remove(&sender).unwrap_or_default(),
                ),
            );
        }
        let Some((_, devices)) = self.cached.get(&cache_key) else {
            return Ok(None);
        };
        let Some(device) = devices.iter().find(|entry| entry.push == token) else {
            return Ok(None);
        };
        let decoded = (|| -> Result<Option<Incoming>> {
            let plaintext = identity.message_keys.open(&device.public_key, envelope)?;
            if let Some(command) = call {
                let Some(received_ms) = wire
                    .get("e")
                    .and_then(Value::as_unsigned_integer)
                    .map(|published| {
                        wire.get("oe")
                            .and_then(Value::as_unsigned_integer)
                            .map_or(published, |original| original.min(published))
                    })
                    .and_then(|ns| i64::try_from(ns / 1_000_000).ok())
                else {
                    return Ok(None);
                };
                return Ok(facetime::decode(
                    command,
                    &decompress(&plaintext)?,
                    sender,
                    &identity.handle,
                    push_token,
                    received_ms,
                )
                .map(Incoming::Call));
            }
            let body: Dictionary = plist::from_bytes(&decompress(&plaintext)?)?;
            let Some(participants) = body
                .get("p")
                .and_then(Value::as_array)
                .filter(|list| list.len() == 2)
            else {
                return Ok(None);
            };
            let participants = participants
                .iter()
                .map(|part| address(part.as_string().unwrap_or_default()))
                .collect::<Result<HashSet<_>>>()?;
            if participants.len() != 2
                || !participants.contains(&sender)
                || !participants.contains(&identity.handle)
            {
                return Ok(None);
            }
            let peer = participants
                .into_iter()
                .find(|part| *part != identity.handle)
                .context("Missing conversation recipient")?;
            let outgoing = sender == identity.handle;
            let timestamp_ns = message_timestamp(wire, crate::now_ns());
            if body.contains_key("amk")
                && matches!(
                    body.get("amt").and_then(Value::as_unsigned_integer),
                    Some(2000..=2007 | 3000..=3007)
                )
            {
                return Ok(tapback::decode(&body, guid, peer, outgoing, timestamp_ns)
                    .map(Incoming::Tapback));
            }
            let message_content::Content {
                text,
                text_part,
                files,
            } = message_content::decode(&body);
            if text.trim().is_empty() && files.is_empty() {
                return Ok(None);
            }
            let (attachments, sources) = files.into_iter().unzip();
            Ok(Some(Incoming::Message(
                Message {
                    id: guid.to_string(),
                    address: peer,
                    body: text,
                    text_part,
                    attachments,
                    outgoing,
                    timestamp_ms: timestamp_ns / 1_000_000,
                    tapbacks: Vec::new(),
                    status: if sender == identity.handle {
                        Delivery::Accepted
                    } else {
                        Delivery::Received
                    },
                },
                sources,
            )))
        })();
        // Invalid or unsupported payloads cannot be retried into validity.
        Ok(decoded.unwrap_or(None))
    }
}

fn message_timestamp(wire: &Dictionary, now: i64) -> i64 {
    // On retry, the original send time precedes the new APNs delivery time.
    ["e", "oe"]
        .into_iter()
        .filter_map(|field| wire.get(field)?.as_unsigned_integer()?.try_into().ok())
        .filter(|ns: &i64| *ns > 0 && *ns <= now.saturating_add(120_000_000_000))
        .min()
        .unwrap_or(now)
}

fn tapback_payload(event: &TapbackEvent, target: &Message, sender: &str) -> Result<Vec<u8>> {
    let payload = binary(&tapback::encode(event, target, sender)?)?;
    // The message body appears in both the fallback text and the notification summary.
    let gzipped = compress(&payload)?;
    Ok(if gzipped.len() < payload.len() {
        gzipped
    } else {
        payload
    })
}

fn lookup_body(targets: &[&str]) -> Result<Vec<u8>> {
    // The IDS endpoint requires XML, even though the APNs envelope uses binary plists.
    plist_xml_gzip(&dictionary([(
        "uris",
        Value::Array(targets.iter().map(|uri| value(*uri)).collect()),
    )]))
}

fn binary(value: &Dictionary) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    plist::to_writer_binary(&mut bytes, value)?;
    Ok(bytes)
}

fn dictionary<const N: usize>(pairs: [(&str, Value); N]) -> Dictionary {
    pairs
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .collect()
}

fn field_data<'a>(value: &'a Dictionary, key: &str) -> Option<&'a [u8]> {
    value.get(key)?.as_data()
}

fn field_str<'a>(value: &'a Dictionary, key: &str) -> Option<&'a str> {
    value.get(key)?.as_string()
}

fn value(text: impl Into<String>) -> Value {
    Value::String(text.into())
}

fn data(bytes: &[u8]) -> Value {
    Value::Data(bytes.to_vec())
}

fn compress(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(bytes)?;
    Ok(encoder.finish()?)
}

pub(super) fn decompress(bytes: &[u8]) -> Result<Vec<u8>> {
    if !bytes.starts_with(&[0x1f, 0x8b]) {
        ensure!(bytes.len() <= MAX_PLIST, "Apple plist exceeds size limit");
        return Ok(bytes.to_vec());
    }
    let mut out = Vec::new();
    GzDecoder::new(bytes)
        .take(MAX_PLIST as u64 + 1)
        .read_to_end(&mut out)?;
    ensure!(
        out.len() <= MAX_PLIST,
        "Compressed Apple plist exceeds size limit"
    );
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        TEXT_LIMIT, Tapback, TapbackKind,
        apple::{
            aps::write_frame,
            facetime::relay::tests::{CALLER, CALLER_ID, LOCAL, LOCAL_ID, allocation_fixture},
        },
    };
    use openssl::{
        bn::BigNumContext,
        ec::{EcGroup, EcKey, PointConversionForm},
        nid::Nid,
        pkey::PKey,
        rsa::Rsa,
        sha::sha1,
    };

    #[test]
    fn encrypted_tapbacks_on_long_messages_fit_the_courier_budget() -> Result<()> {
        let sender = "mailto:sender@example.org";
        let chat = "mailto:recipient@example.org";
        let target = Uuid::new_v4();
        let text = "Here’s a note: café. 🍰\n";
        let original = Message {
            id: target.to_string(),
            address: chat.into(),
            body: text.repeat(TEXT_LIMIT / text.len()),
            text_part: None,
            outgoing: false,
            timestamp_ms: 0,
            status: Delivery::Received,
            attachments: Vec::new(),
            tapbacks: Vec::new(),
        };
        let key = || -> Result<_> {
            let curve = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
            let signing = PKey::from_ec_key(EcKey::generate(&curve)?)?;
            let encryption = PKey::from_rsa(Rsa::generate(1280)?)?;
            KeyPair::private(
                &signing.private_key_to_der()?,
                &encryption.private_key_to_der()?,
            )
        };
        let sender_keys = key()?;
        let recipient_keys = key()?;
        let sender_public = KeyPair::decode(&sender_keys.public_der()?)?;
        let recipient_public = KeyPair::decode(&recipient_keys.public_der()?)?;

        for (kind, removed) in [
            (TapbackKind::Like, false),
            (TapbackKind::Emoji("🎉".into()), true),
        ] {
            let event = TapbackEvent {
                id: Uuid::new_v4(),
                target,
                chat: chat.into(),
                timestamp_ns: 1,
                removed,
                tapback: Tapback {
                    kind,
                    outgoing: true,
                    part: 0,
                },
            };
            assert!(binary(&tapback::encode(&event, &original, sender)?)?.len() > MAX_BATCH);
            let payload = tapback_payload(&event, &original, sender)?;
            let sealed = sender_keys.seal(&recipient_public, &payload)?;
            // A device can have an IDS session token up to 4096 bytes.
            assert!(sealed.len() + 4096 + 512 <= MAX_BATCH);
            let plaintext = recipient_keys.open(&sender_public, &sealed)?;
            let decoded: Dictionary = plist::from_bytes(&decompress(&plaintext)?)?;
            let summary: Dictionary = plist::from_bytes(
                field_data(&decoded, "msi").context("Missing reaction summary")?,
            )?;
            assert_eq!(field_str(&summary, "ams"), Some(original.body.as_str()));
            let received = tapback::decode(&decoded, event.id, chat.into(), true, 1)
                .context("Missing reaction after opening encrypted packet")?;
            assert_eq!(received.target, target);
            assert_eq!(received.removed, removed);
            assert_eq!(received.tapback, event.tapback);
        }
        Ok(())
    }

    #[test]
    fn retried_messages_keep_their_original_timestamp() {
        let original = 1_700_000_000_000_000_000_i64;
        let delivered = original + 2_000_000_000;
        let now = delivered + 1_000_000_000;
        let mut wire = dictionary([("e", delivered.into()), ("oe", original.into())]);
        assert_eq!(message_timestamp(&wire, now), original);
        wire.insert("oe".into(), (now + 121_000_000_000).into());
        assert_eq!(message_timestamp(&wire, now), delivered);
        wire.remove("e");
        assert_eq!(message_timestamp(&wire, now), now);
    }

    #[test]
    fn ids_queries_encode_recipients_as_gzipped_xml() -> Result<()> {
        let targets = ["mailto:sender@example.org", "tel:+15550100123"];
        let body = lookup_body(&targets)?;
        assert!(body.starts_with(&[0x1f, 0x8b]));
        let xml = decompress(&body)?;
        assert!(xml.starts_with(b"<?xml "));
        let document: Dictionary = plist::from_bytes(&xml)?;
        assert_eq!(
            document["uris"],
            Value::Array(targets.iter().map(|uri| value(*uri)).collect())
        );
        Ok(())
    }

    async fn answer_directory_lookup(
        mock: &mut tokio::io::DuplexStream,
        recipient_key: &[u8],
    ) -> Result<()> {
        let query_frame = Frame::read(mock).await?;
        assert_eq!(
            query_frame.field(1),
            Some(sha1(facetime::SIGNALING.as_bytes()).as_slice())
        );
        let query: Dictionary =
            plist::from_bytes(query_frame.field(3).context("Missing IDS query")?)?;
        assert_eq!(query["c"].as_unsigned_integer(), Some(96));
        let credential = |token| {
            Value::Dictionary(dictionary([
                ("push-token", data(&[token; 32])),
                ("session-token", data(&[token; 20])),
                (
                    "client-data",
                    Value::Dictionary(dictionary([(
                        "public-message-identity-key",
                        data(recipient_key),
                    )])),
                ),
            ]))
        };
        let body = binary(&dictionary([
            ("status", Value::from(0)),
            (
                "results",
                Value::Dictionary(dictionary([(
                    CALLER,
                    Value::Dictionary(dictionary([(
                        "identities",
                        Value::Array(vec![credential(3), credential(2)]),
                    )])),
                )])),
            ),
        ]))?;
        let directory = binary(&dictionary([("U", query["U"].clone()), ("b", data(&body))]))?;
        let query_id = query_frame.field(4).context("Missing IDS push ID")?;
        write_frame(mock, 0x0b, &[(4, query_id), (8, &[0])]).await?;
        write_frame(
            mock,
            0x0a,
            &[
                (2, &sha1(facetime::SIGNALING.as_bytes())),
                (3, &directory),
                (4, &[1; 4]),
            ],
        )
        .await?;
        assert_eq!(Frame::read(mock).await?.field(4), Some([1; 4].as_slice()));
        Ok(())
    }

    #[tokio::test]
    async fn relay_and_call_keys_use_the_caller_device_and_preserve_unrelated_pushes() -> Result<()>
    {
        let (client, mut mock) = tokio::io::duplex(16 * 1024);
        let relay_topic = facetime::relay::RELAY_TOPIC;
        let courier = Courier::attach(
            client,
            [1; 32],
            [TOPIC, facetime::SIGNALING, relay_topic]
                .map(|topic| (topic, sha1(topic.as_bytes())))
                .to_vec(),
        );
        let mut madrid = Madrid {
            courier,
            queued: VecDeque::new(),
            cached: HashMap::new(),
            keepalive: Instant::now(),
        };
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let signing = EcKey::generate(&group)?;
        let rsa = Rsa::generate(2048)?;
        let identity = Identity {
            handle: LOCAL.into(),
            token: [1; 32],
            push_cert: Vec::new(),
            push_key: PKey::from_rsa(rsa.clone())?,
            ids_cert: Vec::new(),
            ids_key: PKey::from_rsa(rsa)?,
            facetime_certificates: [(facetime::SIGNALING.to_owned(), b"fixture".to_vec())].into(),
            message_keys: KeyPair::private(
                &signing.private_key_to_der()?,
                &Rsa::generate(1280)?.private_key_to_der()?,
            )?,
            protocol_version: 17,
            user_agent: "mock".into(),
        };
        let recipient = KeyPair::private(
            &EcKey::generate(&group)?.private_key_to_der()?,
            &Rsa::generate(1280)?.private_key_to_der()?,
        )?;
        let recipient_key = recipient.public_der()?;
        let sender_key = KeyPair::decode(&identity.message_keys.public_der()?)?;
        let call = IncomingCall {
            id: Uuid::new_v4(),
            caller: CALLER.into(),
            mode: None,
            received_ms: now_ms(),
            expires_ms: now_ms() + 45_000,
        };
        let selected_device = facetime::CallEndpoint::new([2; 32], Some(CALLER_ID));
        let simulate = async {
            answer_directory_lookup(&mut mock, &recipient_key).await?;

            let allocation_frame = Frame::read(&mut mock).await?;
            let relay_digest = sha1(relay_topic.as_bytes());
            assert_eq!(allocation_frame.field(1), Some(relay_digest.as_slice()));
            let request: Dictionary =
                plist::from_bytes(allocation_frame.field(3).context("Missing relay request")?)?;
            assert_eq!(request["c"].as_unsigned_integer(), Some(200));
            assert_eq!(
                request["qids"].as_data(),
                Some(call.id.as_bytes().as_slice())
            );
            assert_eq!(request["qai"].as_string(), Some(facetime::SIGNALING));
            assert_eq!(request["qgmc"].as_unsigned_integer(), Some(2));
            assert!(request.get("E").is_none());
            let targets = request["dtl"].as_array().context("Missing relay targets")?;
            assert_eq!(targets.len(), 1);
            let target = targets[0].as_dictionary().context("Invalid relay target")?;
            assert_eq!(target["tP"].as_string(), Some(CALLER));
            assert_eq!(target["t"].as_data(), Some([2; 32].as_slice()));
            assert_eq!(target["sT"].as_data(), Some([2; 20].as_slice()));
            assert!(target.get("P").is_none());
            let request_id =
                Uuid::from_slice(request["U"].as_data().context("Invalid relay request ID")?)?;
            let unrelated = binary(&dictionary([("c", Value::from(100))]))?;
            let uncorrelated = binary(&allocation_fixture(Uuid::new_v4(), call.id))?;
            let allocated = binary(&allocation_fixture(request_id, call.id))?;
            write_frame(
                &mut mock,
                0x0a,
                &[(2, &sha1(TOPIC.as_bytes())), (3, &unrelated), (4, &[2; 4])],
            )
            .await?;
            write_frame(
                &mut mock,
                0x0a,
                &[(2, &relay_digest), (3, &uncorrelated), (4, &[3; 4])],
            )
            .await?;
            write_frame(
                &mut mock,
                0x0a,
                &[(2, &relay_digest), (3, &allocated), (4, &[4; 4])],
            )
            .await?;
            write_frame(
                &mut mock,
                0x0b,
                &[
                    (
                        4,
                        allocation_frame.field(4).context("Missing relay push ID")?,
                    ),
                    (8, &[0]),
                ],
            )
            .await?;
            assert_eq!(
                Frame::read(&mut mock).await?.field(4),
                Some([4; 4].as_slice())
            );
            Ok::<_, anyhow::Error>(())
        };
        let (relay, ()) = tokio::try_join!(
            madrid.allocate_call_relay(&identity, &call, selected_device),
            simulate
        )?;
        assert_eq!(relay.call_id, call.id);
        assert_eq!(relay.local_participant, LOCAL_ID);
        assert_eq!(relay.caller_participant, CALLER_ID);
        assert_eq!(madrid.next_notification().await?.id, [2; 4]);
        assert_eq!(madrid.next_notification().await?.id, [3; 4]);

        let mut bignum = BigNumContext::new()?;
        let initial_peer = signing.public_key().to_bytes(
            &group,
            PointConversionForm::UNCOMPRESSED,
            &mut bignum,
        )?;
        let peer = facetime::CallMediaExchange::prepare(
            call.clone(),
            b"fixture",
            &facetime::PeerPrekey::parse(1, &initial_peer)?,
        )?;
        let local = facetime::CallMediaExchange::prepare(
            call.clone(),
            b"fixture",
            &facetime::PeerPrekey::parse(1, peer.handshake.public_prekey())?,
        )?;
        let key_offer = local.handshake.build_key_offer(relay.local_participant)?;
        let simulate_keys = async {
            answer_directory_lookup(&mut mock, &recipient_key).await?;
            for command in [facetime::PREKEY_COMMAND, facetime::KEY_MATERIAL_COMMAND] {
                let frame = Frame::read(&mut mock).await?;
                assert_eq!(
                    frame.field(1),
                    Some(sha1(facetime::SIGNALING.as_bytes()).as_slice())
                );
                let wire: Dictionary =
                    plist::from_bytes(frame.field(3).context("Missing FaceTime payload")?)?;
                assert_eq!(wire["c"].as_unsigned_integer(), Some(command));
                assert_eq!(wire["E"].as_string(), Some("pair"));
                assert_eq!(wire["siu"].as_boolean(), Some(false));
                assert_eq!(
                    wire.get("eX").and_then(Value::as_unsigned_integer),
                    (command == facetime::KEY_MATERIAL_COMMAND)
                        .then_some(u64::try_from((call.expires_ms + 999) / 1000)?),
                );
                let [target] = wire["dtl"]
                    .as_array()
                    .context("Missing FaceTime key recipient")?
                    .as_slice()
                else {
                    anyhow::bail!("FaceTime key material went to more than one device");
                };
                let target = target.as_dictionary().context("Invalid key recipient")?;
                assert_eq!(target["tP"].as_string(), Some(CALLER));
                assert_eq!(target["t"].as_data(), Some([2; 32].as_slice()));
                assert_eq!(target["sT"].as_data(), Some([2; 20].as_slice()));
                let clear = recipient.open(
                    &sender_key,
                    target["P"]
                        .as_data()
                        .context("Expected encrypted key material")?,
                )?;
                let signal =
                    facetime::decode(command, &clear, LOCAL.to_owned(), CALLER, [1; 32], now_ms())
                        .context(
                            "The addressed recipient could not decode the FaceTime key message",
                        )?;
                match signal {
                    facetime::CallSignal::Prekey { id, key, .. } => {
                        assert_eq!(id, call.id);
                        assert!(key.same_as(&facetime::PeerPrekey::parse(
                            1,
                            local.handshake.public_prekey()
                        )?));
                    }
                    facetime::CallSignal::MediaKeys { id, offer, .. } => {
                        assert_eq!(id, call.id);
                        assert_eq!(offer.participant, LOCAL_ID);
                        peer.receive(*offer)?;
                        let keys = peer.handshake.watch_peer_keys();
                        let keys = keys.borrow();
                        let opened = keys
                            .media
                            .as_ref()
                            .context("Missing caller's unwrapped media key")?;
                        assert_eq!(opened.identifier, key_offer.media.identifier);
                        assert_eq!(
                            opened.key.srtp_key(456)?.as_ref(),
                            key_offer.media.key.srtp_key(456)?.as_ref()
                        );
                    }
                    _ => anyhow::bail!("Unexpected FaceTime call signal"),
                }
                write_frame(
                    &mut mock,
                    0x0b,
                    &[
                        (4, frame.field(4).context("Missing FaceTime key push ID")?),
                        (8, &[0]),
                    ],
                )
                .await?;
            }
            Ok::<_, anyhow::Error>(())
        };
        tokio::try_join!(
            madrid.publish_call_keys(&identity, &local.handshake, selected_device, &key_offer),
            simulate_keys
        )?;
        for joined in [true, false] {
            let description = b"local media description";
            let simulate_update = async {
                answer_directory_lookup(&mut mock, &recipient_key).await?;
                let frame = Frame::read(&mut mock).await?;
                let wire: Dictionary =
                    plist::from_bytes(frame.field(3).context("Missing call update")?)?;
                assert_eq!(
                    frame.field(1),
                    Some(sha1(facetime::SIGNALING.as_bytes()).as_slice())
                );
                let command = if joined {
                    facetime::JOIN_COMMAND
                } else {
                    facetime::LEAVE_COMMAND
                };
                assert_eq!(wire["c"].as_unsigned_integer(), Some(command));
                assert_eq!(wire["is-initiator-key"].as_boolean(), Some(false));
                assert_eq!(wire["up1"].as_boolean(), Some(!joined));
                let targets = wire["dtl"].as_array().context("Missing call targets")?;
                assert_eq!(targets.len(), 1);
                let target = targets[0].as_dictionary().context("Invalid call target")?;
                assert_eq!(field_data(target, "t"), Some([2; 32].as_slice()));
                let clear = recipient.open(
                    &sender_key,
                    field_data(target, "P").context("Missing call ciphertext")?,
                )?;
                let update: Dictionary = plist::from_bytes(&clear)?;
                assert_eq!(
                    field_str(&update, "s"),
                    Some(call.id.to_string().to_ascii_uppercase().as_str())
                );
                assert_eq!(
                    update["participant-id-key"].as_unsigned_integer(),
                    Some(LOCAL_ID)
                );
                assert_eq!(
                    update["join-notification-key"].as_unsigned_integer(),
                    Some(if joined { 1 } else { 2 })
                );
                if joined {
                    assert_eq!(
                        field_data(&update, "participant-data-key"),
                        Some(description.as_slice())
                    );
                    assert_eq!(
                        field_data(&update, "rtmpk"),
                        Some(local.handshake.public_prekey().as_slice())
                    );
                } else {
                    assert!(update.get("participant-data-key").is_none());
                    assert_eq!(
                        field_data(&update, "client-context-data-key"),
                        Some([16, 0].as_slice())
                    );
                }
                write_frame(
                    &mut mock,
                    0x0b,
                    &[
                        (4, frame.field(4).context("Missing call update push ID")?),
                        (8, &[0]),
                    ],
                )
                .await?;
                Ok::<_, anyhow::Error>(())
            };
            tokio::try_join!(
                madrid.update_call_participant(
                    &identity,
                    &call,
                    selected_device,
                    &relay,
                    joined.then_some((
                        description.as_slice(),
                        local.handshake.public_prekey(),
                        CallMode::Audio
                    )),
                    false,
                ),
                simulate_update,
            )?;
        }
        let local_prekey = facetime::LocalCallPrekey::generate()?;
        let description = crate::apple::signed_avc_fixture()?;
        let call = IncomingCall {
            mode: Some(CallMode::Audio),
            ..call
        };
        let simulate_outgoing = async {
            answer_directory_lookup(&mut mock, &recipient_key).await?;
            let frame = Frame::read(&mut mock).await?;
            let request: Dictionary =
                plist::from_bytes(frame.field(3).context("Missing relay request")?)?;
            let mut tokens = request["dtl"]
                .as_array()
                .context("Missing allocated devices")?
                .iter()
                .filter_map(Value::as_dictionary)
                .filter_map(|device| field_data(device, "t"))
                .collect::<Vec<_>>();
            tokens.sort_unstable();
            assert_eq!(tokens, vec![[2; 32].as_slice(), [3; 32].as_slice()]);
            let request_id =
                Uuid::from_slice(field_data(&request, "U").context("Missing relay request ID")?)?;
            let mut response = allocation_fixture(request_id, call.id);
            let Some(Value::Array(allocations)) = response.get_mut("qal") else {
                anyhow::bail!("Missing relay allocations");
            };
            let other_participant = CALLER_ID + 1;
            allocations.push(Value::Dictionary(dictionary([
                ("qri", other_participant.into()),
                ("tP", value(CALLER)),
                ("t", data(&[3; 32])),
            ])));
            write_frame(
                &mut mock,
                0x0b,
                &[(4, frame.field(4).context("Missing push ID")?), (8, &[0])],
            )
            .await?;
            write_frame(
                &mut mock,
                0x0a,
                &[
                    (2, &sha1(relay_topic.as_bytes())),
                    (3, &binary(&response)?),
                    (4, &[6; 4]),
                ],
            )
            .await?;
            assert_eq!(
                Frame::read(&mut mock).await?.field(4),
                Some([6; 4].as_slice())
            );
            for command in [facetime::JOIN_COMMAND, facetime::LEAVE_COMMAND] {
                let frame = Frame::read(&mut mock).await?;
                let delivery: Dictionary =
                    plist::from_bytes(frame.field(3).context("Missing invitation")?)?;
                assert_eq!(delivery["c"].as_unsigned_integer(), Some(command));
                assert_eq!(delivery["is-initiator-key"].as_boolean(), Some(true));
                let devices = delivery["dtl"]
                    .as_array()
                    .context("Missing call recipients")?;
                assert_eq!(devices.len(), 2);
                for device in devices {
                    let device = device.as_dictionary().context("Invalid call recipient")?;
                    assert_eq!(field_str(device, "tP"), Some(CALLER));
                    let sealed = field_data(device, "P").context("Missing signed invitation")?;
                    let invitation = recipient.open(&sender_key, sealed)?;
                    let signal = facetime::decode(
                        command,
                        &invitation,
                        LOCAL.into(),
                        CALLER,
                        [1; 32],
                        now_ms(),
                    );
                    if command == facetime::JOIN_COMMAND {
                        assert!(
                            matches!(signal, Some(facetime::CallSignal::Ring { call: ring, media: Some(media), .. }) if ring.id == call.id && ring.mode == Some(CallMode::Audio) && media.prekey.is_some())
                        );
                    } else {
                        assert!(
                            matches!(signal, Some(facetime::CallSignal::End { id, .. }) if id == call.id)
                        );
                    }
                }
                write_frame(
                    &mut mock,
                    0x0b,
                    &[(4, frame.field(4).context("Missing push ID")?), (8, &[0])],
                )
                .await?;
            }
            Ok::<_, anyhow::Error>(())
        };
        let outgoing = async {
            let targets = madrid.outgoing_call_targets(&identity, &call).await?;
            let second = facetime::CallEndpoint::new([3; 32], Some(CALLER_ID + 1));
            assert!(targets.relay.for_peer(second).is_ok());
            assert!(
                targets
                    .relay
                    .for_peer(facetime::CallEndpoint::new([3; 32], Some(CALLER_ID)))
                    .is_err()
            );
            madrid
                .send_outgoing_call(
                    &identity,
                    &call,
                    &targets,
                    Some((&description, local_prekey.public(), CallMode::Audio)),
                )
                .await?;
            madrid
                .send_outgoing_call(&identity, &call, &targets, None)
                .await
        };
        tokio::try_join!(outgoing, simulate_outgoing)?;
        Ok(())
    }
}
