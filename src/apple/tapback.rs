use anyhow::Result;
use plist::{Dictionary, Value};
use uuid::Uuid;

use crate::{Message, Tapback, TapbackEvent, TapbackKind};

pub(super) fn decode(
    payload: &Dictionary,
    id: Uuid,
    chat: String,
    outgoing: bool,
    timestamp_ns: i64,
) -> Option<TapbackEvent> {
    let code = payload.get("amt")?.as_unsigned_integer()?;
    let key = payload.get("amk")?.as_string()?;
    let (part, target) = if let Some((index, guid)) = key
        .strip_prefix("p:")
        .or_else(|| key.strip_prefix("bp:"))
        .and_then(|key| key.split_once('/'))
    {
        (index.parse().ok()?, guid)
    } else if let Some(guid) = key.strip_prefix("bp:") {
        (0, guid)
    } else {
        (0, key)
    };
    let target = Uuid::parse_str(target).ok()?;
    let (index, removed) = match code {
        2000..=2006 => (code - 2000, false),
        3000..=3006 => (code - 3000, true),
        _ => return None,
    };
    let kind = match index {
        0 => TapbackKind::Heart,
        1 => TapbackKind::Like,
        2 => TapbackKind::Dislike,
        3 => TapbackKind::Laugh,
        4 => TapbackKind::Emphasize,
        5 => TapbackKind::Question,
        6 => TapbackKind::Emoji(payload.get("ame")?.as_string()?.to_owned()),
        _ => return None,
    };
    kind.validate().ok()?;
    Some(TapbackEvent {
        id,
        target,
        chat,
        timestamp_ns,
        removed,
        tapback: Tapback {
            kind,
            outgoing,
            part,
        },
    })
}

pub(super) fn encode(event: &TapbackEvent, original: &Message, sender: &str) -> Result<Dictionary> {
    let (index, addition, removal) = match &event.tapback.kind {
        TapbackKind::Heart => (0, "Loved", "a heart"),
        TapbackKind::Like => (1, "Liked", "a like"),
        TapbackKind::Dislike => (2, "Disliked", "a dislike"),
        TapbackKind::Laugh => (3, "Laughed at", "a laugh"),
        TapbackKind::Emphasize => (4, "Emphasized", "an exclamation"),
        TapbackKind::Question => (5, "Questioned", "a question mark"),
        TapbackKind::Emoji(emoji) => (6, emoji.as_str(), emoji.as_str()),
    };
    let quoted = if original.attachments.is_empty() || event.tapback.part != 0 {
        original.body.as_str()
    } else {
        "\u{fffc}"
    };
    let mut summary = Vec::new();
    plist::to_writer_binary(
        &mut summary,
        &Dictionary::from_iter([("ams", Value::from(quoted)), ("amc", Value::from(1))]),
    )?;
    let text = if event.removed {
        format!("Removed {removal} from “{quoted}”")
    } else if matches!(&event.tapback.kind, TapbackKind::Emoji(_)) {
        format!("Reacted {addition} to “{quoted}”")
    } else {
        format!("{addition} “{quoted}”")
    };
    let mut payload = Dictionary::from_iter([
        (
            "p",
            Value::Array(vec![sender.into(), event.chat.as_str().into()]),
        ),
        ("t", text.into()),
        (
            "amk",
            format!(
                "p:{}/{}",
                event.tapback.part,
                event.target.hyphenated().to_string().to_ascii_uppercase()
            )
            .into(),
        ),
        (
            "amt",
            Value::from(if event.removed { 3000u64 } else { 2000u64 } + index),
        ),
        ("amrlc", 0.into()),
        ("amrln", (quoted.encode_utf16().count() as u64).into()),
        ("msi", Value::Data(summary)),
        ("pv", 0.into()),
        ("gv", "8".into()),
        ("v", "1".into()),
    ]);
    if let TapbackKind::Emoji(emoji) = &event.tapback.kind {
        payload.insert("ame".into(), emoji.as_str().into());
    }
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Delivery;

    #[test]
    fn emoji_tapback_round_trips_as_an_associated_removal() -> Result<()> {
        let message = Message {
            id: "76ab2a9b-903d-48a0-9de5-2df815ce3c71".into(),
            body: "Hi 👋".into(),
            address: "mailto:peer@example.org".into(),
            outgoing: false,
            timestamp_ms: 0,
            status: Delivery::Received,
            attachments: Vec::new(),
            tapbacks: Vec::new(),
        };
        let event = TapbackEvent {
            id: Uuid::new_v4(),
            target: Uuid::parse_str(&message.id)?,
            chat: message.address.clone(),
            timestamp_ns: 1,
            removed: true,
            tapback: Tapback {
                kind: TapbackKind::Emoji("🎉".into()),
                outgoing: true,
                part: 0,
            },
        };
        let payload = encode(&event, &message, "mailto:me@example.org")?;
        assert_eq!(
            payload["amk"].as_string(),
            Some("p:0/76AB2A9B-903D-48A0-9DE5-2DF815CE3C71")
        );
        assert_eq!(payload["amt"].as_unsigned_integer(), Some(3006));
        assert_eq!(payload["amrln"].as_unsigned_integer(), Some(5));
        let decoded = decode(&payload, event.id, event.chat, true, 1).unwrap();
        assert!(decoded.removed);
        assert_eq!(decoded.target, event.target);
        assert_eq!(decoded.tapback, event.tapback);
        Ok(())
    }
}
