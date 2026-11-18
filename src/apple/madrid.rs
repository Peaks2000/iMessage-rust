use std::{
    collections::{HashMap, HashSet, VecDeque},
    io::{Read, Write},
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
use crate::{Delivery, IncomingCall, Message, SendText, TapbackEvent, address, now_ms};

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
}

struct DeliveryPayload<'a> {
    recipient: &'a str,
    guid: Uuid,
    bytes: &'a [u8],
    request_receipt: bool,
    invite_context: Option<u64>,
}

impl DeliveryPayload<'_> {
    fn topic(&self) -> &'static str {
        if self.invite_context.is_some() {
            facetime::SIGNALING
        } else {
            TOPIC
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
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
struct LookupClient {
    public_message_identity_key: Option<Data>,
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
        let response = timeout(RESPONSE_TIMEOUT, async {
            loop {
                let candidate = if let Some(index) = self.queued.iter().position(|item| {
                    item.topic == topic
                        && field_data(&item.data, "U") == Some(correlation.as_bytes())
                }) {
                    self.queued.remove(index)
                } else {
                    let frame = self.courier.next().await?;
                    self.notification(frame).await?
                };
                if let Some(item) = candidate {
                    if item.topic == topic
                        && field_data(&item.data, "U") == Some(correlation.as_bytes())
                    {
                        self.courier.ack(item.id).await?;
                        return Ok::<_, anyhow::Error>(item.data);
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
        .context("Apple IDS lookup timed out")??;
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
                    destinations.push(Destination {
                        push: device.push_token.into(),
                        session: device.session_token.into(),
                        public_key,
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
                invite_context: None,
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
        let payload = binary(&tapback::encode(event, target, &identity.handle)?)?;
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
                invite_context: None,
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
                    invite_context: Some(facetime::DECLINE),
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
                        if payload.invite_context.is_some() {
                            facetime::INVITATION_COMMAND
                        } else {
                            100
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
                if let Some(context) = payload.invite_context {
                    wire.insert("cc".into(), context.into());
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
        .context("Apple MMCS authorization timed out")?
    }

    pub(crate) async fn decode(
        &mut self,
        identity: &Identity,
        notice: &Notification,
    ) -> Result<Option<Incoming>> {
        let wire = &notice.data;
        let command = wire.get("c").and_then(Value::as_unsigned_integer);
        let call = notice.topic == facetime::SIGNALING
            && command == Some(facetime::INVITATION_COMMAND)
            && field_str(wire, "E") == Some("pair");
        let message = notice.topic == TOPIC
            && command == Some(100)
            && field_str(wire, "E").is_none_or(|name| name == "pair");
        if !call && !message {
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
        let (Ok(sender), Ok(target), Ok(guid)) =
            (address(sender), address(target), Uuid::from_slice(guid))
        else {
            return Ok(None);
        };
        if target != identity.handle || token.len() != 32 {
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
            if call {
                let Some(received_ms) = wire
                    .get("e")
                    .and_then(Value::as_unsigned_integer)
                    .and_then(|ns| i64::try_from(ns / 1_000_000).ok())
                else {
                    return Ok(None);
                };
                return Ok(facetime::decode(
                    &decompress(&plaintext)?,
                    sender,
                    &identity.handle,
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
            let timestamp_ns = wire
                .get("e")
                .and_then(Value::as_unsigned_integer)
                .and_then(|ns| i64::try_from(ns).ok())
                .filter(|ns| *ns > 0 && *ns / 1_000_000 <= now_ms() + 120_000)
                .unwrap_or_else(crate::now_ns);
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
}
