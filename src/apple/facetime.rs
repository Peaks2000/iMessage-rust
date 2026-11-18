mod description;
mod media;
pub(super) mod relay;
mod signed_material;
mod srtp;

use plist::Value;
use prost::Message as _;
use serde::Deserialize;
use uuid::Uuid;

use crate::{CallMode, IncomingCall, address, now_ms};

#[cfg(test)]
pub(crate) use description::tests::signed_avc_fixture;
#[cfg(feature = "desktop")]
pub(crate) use description::{
    AAC_ELD_PT, AAC_ELD_SAMPLE_RATE, AUDIO_RED_PT, CAMERA_HEIGHT, CAMERA_WIDTH, CallDevice,
    HEVC_FEATURE_BITS, HEVC_PT,
};
pub use description::{CallAvcMaterial, CallMediaDescription, CallRtpDescription};
pub use media::{CallKey, CallKeyOffer, CallMediaHandshake, CallMediaKey, CallPeerKeys};
pub(crate) use media::{
    CallMediaExchange, LocalCallPrekey, PeerKeyOffer, PeerMediaOffer, PeerPrekey,
};
pub use relay::{
    CallRelayAllocation, CallRelayBinding, CallRelayConnection, CallRelayKeys, CallRelayProfile,
    CallRelayStream, RelayChannel, RelayDatagramChannel, RelayStreamDirection,
};
pub(crate) use relay::{OutgoingRelay, RelayPeerUpdate, RingingRelay};
pub(crate) use signed_material::PeerDeviceKey;
pub(crate) use srtp::CallRtpProtection;
#[cfg(feature = "desktop")]
pub(crate) use srtp::RtpHeader;

pub(super) const SIGNALING: &str = "com.apple.private.alloy.facetime.multi";
pub(super) const VIDEO: &str = "com.apple.private.alloy.facetime.video";
pub(super) const VIDEO_SERVICE: &str = "com.apple.ess";
pub(super) const INVITATION_COMMAND: u64 = 242;
pub(super) const JOIN_COMMAND: u64 = 207;
pub(super) const LEAVE_COMMAND: u64 = 208;
pub(super) const PREKEY_COMMAND: u64 = 210;
pub(super) const KEY_MATERIAL_COMMAND: u64 = 211;
pub(super) const DECLINE: u64 = 9;
pub(crate) const RING_TIMEOUT_MS: i64 = 45_000;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct CallEndpoint {
    push_token: [u8; 32],
    participant: Option<u64>,
}

impl CallEndpoint {
    pub(crate) fn new(push_token: [u8; 32], participant: Option<u64>) -> Self {
        Self {
            push_token,
            participant,
        }
    }

    pub(crate) fn matches(self, other: Self) -> bool {
        self.same_device(other)
            && self
                .participant
                .is_none_or(|id| other.participant == Some(id))
    }

    pub(crate) fn same_device(self, other: Self) -> bool {
        self.push_token == other.push_token
    }

    pub(crate) fn participant(self) -> Option<u64> {
        self.participant
    }

    pub(super) fn push_token(&self) -> &[u8; 32] {
        &self.push_token
    }
}

pub(crate) enum CallSignal {
    Ring {
        call: IncomingCall,
        endpoint: CallEndpoint,
        media: Option<PeerMediaOffer>,
    },
    Accepted {
        call: IncomingCall,
        endpoint: CallEndpoint,
        media: PeerMediaOffer,
    },
    Prekey {
        id: Uuid,
        sender: String,
        endpoint: CallEndpoint,
        key: PeerPrekey,
    },
    MediaKeys {
        id: Uuid,
        sender: String,
        endpoint: CallEndpoint,
        offer: Box<PeerKeyOffer>,
    },
    End {
        id: Uuid,
        sender: String,
        received_ms: i64,
        endpoint: Option<CallEndpoint>,
    },
}

impl CallSignal {
    pub(crate) fn id(&self) -> Uuid {
        match self {
            Self::Ring { call, .. } | Self::Accepted { call, .. } => call.id,
            Self::Prekey { id, .. } | Self::MediaKeys { id, .. } | Self::End { id, .. } => *id,
        }
    }
}

#[derive(prost::Message)]
struct ConversationSignal {
    #[prost(int32, tag = "2")]
    kind: i32,
    #[prost(bool, tag = "3")]
    suppress_ui: bool,
    #[prost(message, repeated, tag = "4")]
    participants: Vec<Participant>,
    #[prost(string, tag = "5")]
    group_id: String,
    #[prost(message, repeated, tag = "19")]
    invitation_preferences: Vec<InvitationPreference>,
    #[prost(int32, optional, tag = "28")]
    mode: Option<i32>,
}

#[derive(prost::Message)]
struct InvitationPreference {
    #[prost(int32, tag = "2")]
    handle_kind: i32,
    #[prost(uint32, tag = "3")]
    notification_style: u32,
}

#[derive(prost::Message)]
struct Participant {
    #[prost(int32, optional, tag = "16")]
    mode: Option<i32>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
struct ParticipantSignal {
    #[serde(rename = "s")]
    session: String,
    #[serde(rename = "fanout-groupID-key")]
    fanout_group: Option<String>,
    participant_id_key: Option<Value>,
    participant_data_key: Option<plist::Data>,
    client_context_data_key: Option<plist::Data>,
    is_initiator_key: Option<bool>,
    #[serde(rename = "rtmpk")]
    prekey: Option<plist::Data>,
    #[serde(rename = "rtmpwm")]
    wrap_mode: Option<u32>,
    #[serde(rename = "rtskm")]
    session_key: Option<plist::Dictionary>,
    #[serde(rename = "rtmkm")]
    media_key: Option<plist::Dictionary>,
}

impl ParticipantSignal {
    fn media_prekey(&self) -> Option<PeerPrekey> {
        PeerPrekey::parse(self.wrap_mode?, self.prekey.as_ref()?.as_ref()).ok()
    }
}

#[derive(prost::Message)]
struct JoinContext {
    #[prost(message, repeated, tag = "2")]
    members: Vec<ConversationMember>,
    #[prost(message, optional, tag = "3")]
    message: Option<ConversationSignal>,
    #[prost(bool, optional, tag = "8")]
    video: Option<bool>,
    #[prost(string, tag = "10")]
    provider: String,
    #[prost(message, repeated, tag = "11")]
    other_invited_handles: Vec<Handle>,
    #[prost(bool, optional, tag = "16")]
    video_enabled: Option<bool>,
    #[prost(bool, optional, tag = "18")]
    supports_one_to_one: Option<bool>,
    #[prost(bool, optional, tag = "22")]
    supports_leave: Option<bool>,
}

#[derive(prost::Message)]
struct ConversationMember {
    #[prost(message, optional, tag = "2")]
    handle: Option<Handle>,
}

#[derive(prost::Message)]
struct Handle {
    #[prost(int32, tag = "1")]
    kind: i32,
    #[prost(string, tag = "2")]
    value: String,
    #[prost(string, tag = "3")]
    normalized_value: String,
}

impl Handle {
    fn from_address(uri: &str) -> Self {
        let (kind, value) = if let Some(phone) = uri.strip_prefix("tel:") {
            (2, phone)
        } else {
            (3, uri.strip_prefix("mailto:").unwrap_or(uri))
        };
        Self {
            kind,
            value: value.to_owned(),
            normalized_value: value.to_owned(),
        }
    }

    fn matches(&self, expected: &str) -> bool {
        let matches_kind = match self.kind {
            2 => expected.starts_with("tel:"),
            3 => expected.starts_with("mailto:"),
            _ => false,
        };
        matches_kind
            && [&self.normalized_value, &self.value]
                .iter()
                .any(|value| address(value).is_ok_and(|handle| handle == expected))
    }
}

pub(super) fn participant_update(
    allocation: &CallRelayAllocation,
    own: &str,
    caller: &str,
    join: Option<(&[u8], &[u8; 65], CallMode)>,
    initiator: bool,
) -> plist::Dictionary {
    participant_payload(
        allocation.call_id,
        own,
        caller,
        allocation.local_participant,
        [allocation.caller_participant],
        initiator,
        join,
    )
}

pub(super) fn outgoing_invitation(
    allocation: &OutgoingRelay,
    own: &str,
    recipient: &str,
    join: Option<(&[u8], &[u8; 65], CallMode)>,
) -> plist::Dictionary {
    participant_payload(
        allocation.call_id(),
        own,
        recipient,
        allocation.local_participant(),
        allocation
            .endpoints()
            .iter()
            .filter_map(|endpoint| endpoint.participant()),
        true,
        join,
    )
}

fn participant_payload(
    session: Uuid,
    own: &str,
    caller: &str,
    local_participant: u64,
    recipient_participants: impl IntoIterator<Item = u64>,
    initiator: bool,
    join: Option<(&[u8], &[u8; 65], CallMode)>,
) -> plist::Dictionary {
    let call = session.to_string().to_ascii_uppercase();
    let members = [own, caller];
    let participants = plist::Dictionary::from_iter([
        (own, Value::Array(vec![Value::from(local_participant)])),
        (
            caller,
            Value::Array(
                recipient_participants
                    .into_iter()
                    .map(Value::from)
                    .collect(),
            ),
        ),
    ]);
    let mut update = plist::Dictionary::from_iter([
        ("s", Value::from(call.as_str())),
        ("fanout-groupID-key", Value::from(call.as_str())),
        ("is-initiator-key", Value::Boolean(initiator)),
        ("is-u-plus-one-key", Value::Boolean(join.is_none())),
        (
            "join-notification-key",
            Value::from(if join.is_some() { 1 } else { 2 }),
        ),
        ("participant-id-key", Value::from(local_participant)),
        (
            "fanout-groupMembers-key",
            Value::Array(members.into_iter().map(Value::from).collect()),
        ),
        ("uri-to-participant-id-key", Value::Dictionary(participants)),
    ]);
    let client_context = if let Some((description, prekey, mode)) = join {
        let video = mode == CallMode::Video;
        let context = JoinContext {
            members: members
                .into_iter()
                .map(|uri| ConversationMember {
                    handle: Some(Handle::from_address(uri)),
                })
                .collect(),
            message: Some(ConversationSignal {
                kind: i32::from(initiator),
                group_id: call.clone(),
                invitation_preferences: if initiator {
                    [2, 1, 3]
                        .into_iter()
                        .map(|handle_kind| InvitationPreference {
                            handle_kind,
                            notification_style: 1,
                        })
                        .collect()
                } else {
                    Vec::new()
                },
                mode: Some(if video { 2 } else { 1 }),
                ..Default::default()
            }),
            video: Some(video),
            provider: "com.apple.telephonyutilities.callservicesd.FaceTimeProvider".to_owned(),
            other_invited_handles: Vec::new(),
            video_enabled: Some(video),
            supports_one_to_one: Some(true),
            supports_leave: Some(true),
        };
        update.insert(
            "participant-data-key".to_owned(),
            Value::Data(description.to_vec()),
        );
        update.insert("rtmpk".to_owned(), Value::Data(prekey.to_vec()));
        update.insert("rtmpwm".to_owned(), Value::from(1));
        context.encode_to_vec()
    } else {
        vec![16, 0]
    };
    update.insert(
        "client-context-data-key".to_owned(),
        Value::Data(client_context),
    );
    update
}

pub(super) fn decline(id: Uuid) -> Vec<u8> {
    ConversationSignal {
        kind: DECLINE as i32,
        group_id: id.to_string().to_ascii_uppercase(),
        ..Default::default()
    }
    .encode_to_vec()
}

/// Interpret call signaling after IDS has authenticated and decrypted its sender.
pub(crate) fn decode(
    command: u64,
    payload: &[u8],
    sender: String,
    own: &str,
    push_token: [u8; 32],
    received_ms: i64,
) -> Option<CallSignal> {
    if payload.len() > 64 * 1024 {
        return None;
    }
    let now = now_ms();
    let expires_ms = received_ms.checked_add(RING_TIMEOUT_MS)?;
    if received_ms <= 0 || received_ms > now + 5_000 || now >= expires_ms {
        return None;
    }
    let ring = |id, caller, mode, endpoint, media| CallSignal::Ring {
        call: IncomingCall {
            id,
            caller,
            mode,
            received_ms,
            expires_ms,
        },
        endpoint,
        media,
    };
    if command == INVITATION_COMMAND {
        let offer = ConversationSignal::decode(payload).ok()?;
        let id = Uuid::parse_str(&offer.group_id).ok()?;
        return match offer.kind {
            1 if sender != own && !offer.suppress_ui => Some(ring(
                id,
                sender,
                offer.call_mode(),
                CallEndpoint::new(push_token, None),
                None,
            )),
            6 if sender == own => Some(CallSignal::End {
                id,
                sender,
                received_ms,
                endpoint: None,
            }),
            9 => Some(CallSignal::End {
                id,
                sender,
                received_ms,
                endpoint: Some(CallEndpoint::new(push_token, None)),
            }),
            _ => None,
        };
    }

    let participant: ParticipantSignal = plist::from_bytes(payload).ok()?;
    let id = Uuid::parse_str(&participant.session).ok()?;
    if participant
        .fanout_group
        .as_deref()
        .is_some_and(|group| Uuid::parse_str(group).ok() != Some(id))
    {
        return None;
    }
    if sender == own {
        return None;
    }
    if command == PREKEY_COMMAND {
        return Some(CallSignal::Prekey {
            id,
            sender,
            endpoint: CallEndpoint::new(push_token, None),
            key: participant.media_prekey()?,
        });
    }
    if command == KEY_MATERIAL_COMMAND {
        let offer = PeerKeyOffer::parse(
            participant.session_key.as_ref(),
            participant.media_key.as_ref(),
        )?;
        return Some(CallSignal::MediaKeys {
            id,
            sender,
            endpoint: CallEndpoint::new(push_token, Some(offer.participant)),
            offer: Box::new(offer),
        });
    }
    let participant_id = participant_id(participant.participant_id_key.as_ref()?)?;
    let endpoint = CallEndpoint::new(push_token, Some(participant_id));
    match command {
        JOIN_COMMAND => {
            let prekey = participant.media_prekey();
            let description = participant
                .participant_data_key
                .map(Vec::<u8>::from)
                .unwrap_or_default();
            let context =
                JoinContext::decode(participant.client_context_data_key?.as_ref()).ok()?;
            let offer = context.message.as_ref()?;
            if offer.suppress_ui
                || (!offer.group_id.is_empty() && Uuid::parse_str(&offer.group_id).ok() != Some(id))
                || !matches!(offer.kind, 0 | 1)
            {
                return None;
            }
            let members = || {
                context
                    .members
                    .iter()
                    .filter_map(|member| member.handle.as_ref())
            };
            if !members().any(|handle| handle.matches(&sender))
                || !members()
                    .chain(&context.other_invited_handles)
                    .any(|handle| handle.matches(own))
            {
                return None;
            }
            let mode = offer.call_mode().or_else(|| {
                context.video.or(context.video_enabled).map(|video| {
                    if video {
                        CallMode::Video
                    } else {
                        CallMode::Audio
                    }
                })
            });
            let media = PeerMediaOffer {
                description,
                prekey,
            };
            if offer.kind == 1 || participant.is_initiator_key == Some(true) {
                Some(ring(id, sender, mode, endpoint, Some(media)))
            } else {
                Some(CallSignal::Accepted {
                    call: IncomingCall {
                        id,
                        caller: sender,
                        mode,
                        received_ms,
                        expires_ms,
                    },
                    endpoint,
                    media,
                })
            }
        }
        LEAVE_COMMAND => Some(CallSignal::End {
            id,
            sender,
            received_ms,
            endpoint: Some(endpoint),
        }),
        _ => None,
    }
}

fn participant_id(value: &Value) -> Option<u64> {
    value
        .as_unsigned_integer()
        .or_else(|| value.as_signed_integer().map(|id| id as u64))
        .filter(|id| *id != 0)
}

impl ConversationSignal {
    fn call_mode(&self) -> Option<CallMode> {
        match self
            .mode
            .or_else(|| self.participants.iter().find_map(|member| member.mode))
        {
            Some(1) => Some(CallMode::Audio),
            Some(2) => Some(CallMode::Video),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_expired_and_suppressed_rings_and_keeps_audio_and_video_distinct() {
        let id = Uuid::new_v4();
        let now = now_ms();
        let mut offer = ConversationSignal {
            group_id: id.to_string(),
            kind: 1,
            mode: Some(1),
            ..Default::default()
        };
        let peer = "mailto:peer@example.org";
        let own = "mailto:own@example.org";
        let parse = |offer: &ConversationSignal, peer: &str, time| {
            decode(
                INVITATION_COMMAND,
                &offer.encode_to_vec(),
                peer.into(),
                own,
                [1; 32],
                time,
            )
        };
        assert!(matches!(
            parse(&offer, peer, now),
            Some(CallSignal::Ring {
                call: IncomingCall {
                    mode: Some(CallMode::Audio),
                    ..
                },
                ..
            })
        ));
        offer.mode = None;
        offer.participants = vec![Participant { mode: Some(2) }];
        assert!(matches!(
            parse(&offer, peer, now),
            Some(CallSignal::Ring {
                call: IncomingCall {
                    mode: Some(CallMode::Video),
                    ..
                },
                ..
            })
        ));
        assert!(parse(&offer, peer, now - RING_TIMEOUT_MS).is_none());
        assert!(parse(&offer, own, now).is_none());
        offer.suppress_ui = true;
        assert!(parse(&offer, peer, now).is_none());
    }

    #[test]
    fn accepts_the_callers_join_only_for_its_bound_session_and_recipient() -> anyhow::Result<()> {
        let id = Uuid::new_v4();
        let peer = "mailto:peer@example.org";
        let own = "tel:+15550100123";
        let now = now_ms();
        let mut wire = plist::Dictionary::from_iter([
            ("s", Value::from(id.to_string().to_uppercase())),
            ("fanout-groupID-key", Value::from(id.to_string())),
            ("participant-id-key", Value::from(-11_i64)),
            ("participant-data-key", Value::Data(vec![1, 2, 3])),
        ]);
        let mut context = JoinContext {
            members: vec![ConversationMember {
                handle: Some(Handle {
                    kind: 3,
                    value: "PEER@example.org".into(),
                    ..Default::default()
                }),
            }],
            other_invited_handles: vec![Handle {
                kind: 2,
                value: "555 010 0123".into(),
                normalized_value: "+15550100123".into(),
            }],
            message: Some(ConversationSignal {
                kind: 1,
                ..Default::default()
            }),
            video: Some(true),
            ..Default::default()
        };
        let parse = |command,
                     context: &JoinContext,
                     mut wire: plist::Dictionary,
                     sender: &str,
                     recipient: &str|
         -> anyhow::Result<_> {
            wire.insert(
                "client-context-data-key".into(),
                Value::Data(context.encode_to_vec()),
            );
            let mut bytes = Vec::new();
            plist::to_writer_binary(&mut bytes, &wire)?;
            Ok(decode(
                command,
                &bytes,
                sender.into(),
                recipient,
                [7; 32],
                now,
            ))
        };
        assert!(
            matches!(parse(JOIN_COMMAND, &context, wire.clone(), peer, own)?,
            Some(CallSignal::Ring { call, endpoint, media: Some(media) }) if call.id == id && call.mode == Some(CallMode::Video)
                && media.description == [1, 2, 3]
                && endpoint == CallEndpoint::new([7; 32], Some(-11_i64 as u64)))
        );
        assert!(
            parse(
                JOIN_COMMAND,
                &context,
                wire.clone(),
                peer,
                "tel:+15550100124"
            )?
            .is_none()
        );
        assert!(
            parse(
                JOIN_COMMAND,
                &context,
                wire.clone(),
                "mailto:other@example.org",
                own
            )?
            .is_none()
        );
        context.message.as_mut().unwrap().group_id = Uuid::new_v4().to_string();
        assert!(parse(JOIN_COMMAND, &context, wire.clone(), peer, own)?.is_none());
        context.message.as_mut().unwrap().group_id.clear();
        context.message.as_mut().unwrap().kind = 0;
        assert!(
            matches!(parse(JOIN_COMMAND, &context, wire.clone(), peer, own)?,
            Some(CallSignal::Accepted { call, endpoint, .. }) if call.id == id
                && endpoint == CallEndpoint::new([7; 32], Some(-11_i64 as u64)))
        );
        wire.remove("participant-data-key");
        wire.insert("is-initiator-key".into(), Value::Boolean(true));
        context.video = Some(false);
        assert!(
            matches!(parse(JOIN_COMMAND, &context, wire.clone(), peer, own)?,
            Some(CallSignal::Ring { call, media: Some(media), .. }) if call.mode == Some(CallMode::Audio)
                && media.description.is_empty())
        );
        assert!(
            matches!(parse(LEAVE_COMMAND, &context, wire.clone(), peer, own)?,
            Some(CallSignal::End { id: call_id, endpoint: Some(endpoint), .. }) if call_id == id
            && endpoint == CallEndpoint::new([7; 32], Some(-11_i64 as u64)))
        );
        wire.insert(
            "fanout-groupID-key".into(),
            Value::from(Uuid::new_v4().to_string()),
        );
        assert!(parse(LEAVE_COMMAND, &context, wire, peer, own)?.is_none());
        Ok(())
    }

    #[test]
    fn accepts_a_separate_prekey_without_a_participant_id() -> anyhow::Result<()> {
        let id = Uuid::new_v4();
        let peer = "mailto:peer@example.org";
        let own = "mailto:own@example.org";
        let point = hex::decode(concat!(
            "043ed113b7883b4c590638379db0c21cda16742ed0255048bf433391d374bc21d190",
            "99209accc4c8a224c843afa4f4c68a090d04da5e9889dae2f8eefce82a3740"
        ))?;
        let mut payload = plist::Dictionary::from_iter([
            ("s", Value::from(id.to_string())),
            ("fanout-groupID-key", Value::from(id.to_string())),
            ("rtmpk", Value::Data(point.clone())),
            ("rtmpwm", Value::from(1)),
        ]);
        let parse = |payload: &plist::Dictionary| -> anyhow::Result<_> {
            let mut bytes = Vec::new();
            plist::to_writer_binary(&mut bytes, payload)?;
            Ok(decode(
                PREKEY_COMMAND,
                &bytes,
                peer.into(),
                own,
                [7; 32],
                now_ms(),
            ))
        };
        assert!(
            matches!(parse(&payload)?, Some(CallSignal::Prekey { id: parsed, sender, endpoint, key })
            if parsed == id && sender == peer && endpoint.same_device(CallEndpoint::new([7; 32], Some(2)))
                && key.same_as(&PeerPrekey::parse(1, &point)?))
        );
        payload.insert("rtmpwm".into(), Value::from(9));
        assert!(parse(&payload)?.is_none());
        Ok(())
    }
}
