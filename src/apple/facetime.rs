use prost::Message as _;
use uuid::Uuid;

use crate::{CallMode, IncomingCall, now_ms};

pub(super) const SIGNALING: &str = "com.apple.private.alloy.facetime.multi";
pub(super) const VIDEO: &str = "com.apple.private.alloy.facetime.video";
pub(super) const VIDEO_SERVICE: &str = "com.apple.ess";
pub(super) const INVITATION_COMMAND: u64 = 242;
pub(super) const DECLINE: u64 = 9;
const RING_TIMEOUT_MS: i64 = 45_000;

pub(crate) enum CallSignal {
    Ring(IncomingCall),
    End {
        id: Uuid,
        sender: String,
        received_ms: i64,
    },
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
    #[prost(int32, optional, tag = "28")]
    mode: Option<i32>,
}

#[derive(prost::Message)]
struct Participant {
    #[prost(int32, optional, tag = "16")]
    mode: Option<i32>,
}

pub(super) fn decline(id: Uuid) -> Vec<u8> {
    ConversationSignal {
        kind: DECLINE as i32,
        group_id: id.to_string().to_ascii_uppercase(),
        ..Default::default()
    }
    .encode_to_vec()
}

/// Parse an invitation only after IDS has authenticated and decrypted its sender.
pub(super) fn decode(
    payload: &[u8],
    sender: String,
    own: &str,
    received_ms: i64,
) -> Option<CallSignal> {
    if payload.len() > 64 * 1024 {
        return None;
    }
    let offer = ConversationSignal::decode(payload).ok()?;
    let id = Uuid::parse_str(&offer.group_id).ok()?;
    let now = now_ms();
    let expires_ms = received_ms.checked_add(RING_TIMEOUT_MS)?;
    if received_ms <= 0 || received_ms > now + 5_000 || now >= expires_ms {
        return None;
    }
    match offer.kind {
        1 if sender != own && !offer.suppress_ui => {
            let mode = offer
                .mode
                .or_else(|| offer.participants.iter().find_map(|member| member.mode));
            Some(CallSignal::Ring(IncomingCall {
                id,
                caller: sender,
                mode: match mode {
                    Some(1) => Some(CallMode::Audio),
                    Some(2) => Some(CallMode::Video),
                    _ => None,
                },
                received_ms,
                expires_ms,
            }))
        }
        6 if sender == own => Some(CallSignal::End {
            id,
            sender,
            received_ms,
        }),
        9 => Some(CallSignal::End {
            id,
            sender,
            received_ms,
        }),
        _ => None,
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
        assert!(matches!(
            decode(&offer.encode_to_vec(), peer.into(), own, now),
            Some(CallSignal::Ring(IncomingCall {
                mode: Some(CallMode::Audio),
                ..
            }))
        ));
        offer.mode = None;
        offer.participants = vec![Participant { mode: Some(2) }];
        assert!(matches!(
            decode(&offer.encode_to_vec(), peer.into(), own, now),
            Some(CallSignal::Ring(IncomingCall {
                mode: Some(CallMode::Video),
                ..
            }))
        ));
        assert!(
            decode(
                &offer.encode_to_vec(),
                peer.into(),
                own,
                now - RING_TIMEOUT_MS
            )
            .is_none()
        );
        assert!(decode(&offer.encode_to_vec(), own.into(), own, now).is_none());
        offer.suppress_ui = true;
        assert!(decode(&offer.encode_to_vec(), peer.into(), own, now).is_none());
    }
}
