use std::path::Path;

use anyhow::{Result, ensure};
use rusqlite::{Connection, OptionalExtension, params};

use crate::media::MediaSource;
use crate::{Attachment, Conversation, Delivery, Message, PAGE_SIZE, Tapback, TapbackEvent};

pub struct History(Connection);

impl History {
    pub fn open(root: &Path, profile: &str) -> Result<Self> {
        let db = Connection::open(root.join(format!("{profile}.sqlite")))?;
        db.busy_timeout(std::time::Duration::from_secs(2))?;
        db.execute_batch("
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = FULL;
            PRAGMA foreign_keys = ON;
            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                address TEXT NOT NULL,
                body TEXT NOT NULL,
                text_part INTEGER,
                outgoing INTEGER NOT NULL,
                timestamp_ms INTEGER NOT NULL,
                status TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS recent_messages ON messages(address, timestamp_ms DESC, id DESC);
            CREATE TABLE IF NOT EXISTS deleted_messages (id TEXT PRIMARY KEY);
            CREATE TABLE IF NOT EXISTS attachments (
                message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
                position INTEGER NOT NULL,
                info TEXT NOT NULL,
                bytes BLOB,
                reference TEXT,
                CHECK ((bytes IS NULL) != (reference IS NULL)),
                PRIMARY KEY (message_id, position)
            );
            CREATE TABLE IF NOT EXISTS tapback_events (
                id TEXT PRIMARY KEY,
                message_id TEXT NOT NULL,
                address TEXT NOT NULL,
                timestamp_ns INTEGER NOT NULL,
                part INTEGER NOT NULL,
                outgoing INTEGER NOT NULL,
                kind TEXT NOT NULL,
                removed INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS tapbacks_for_message
                ON tapback_events(address, message_id, timestamp_ns, id);
        ")?;
        let has_text_part = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('messages') WHERE name = 'text_part')",
            [],
            |row| row.get::<_, bool>(0),
        )?;
        if !has_text_part {
            db.execute("ALTER TABLE messages ADD COLUMN text_part INTEGER", [])?;
        }
        Ok(Self(db))
    }

    pub fn chats(&self) -> Result<Vec<Conversation>> {
        let mut query = self.0.prepare("
            SELECT address, CASE WHEN TRIM(body) = '' THEN (
                SELECT CASE WHEN json_extract(info, '$.mime') LIKE 'image/%' THEN 'Photo' ELSE 'Attachment' END
                FROM attachments WHERE message_id = messages.id ORDER BY position LIMIT 1
            ) ELSE body END, timestamp_ms
            FROM (SELECT *, ROW_NUMBER() OVER (PARTITION BY address ORDER BY timestamp_ms DESC, id DESC) AS rank FROM messages)
                AS messages
            WHERE rank = 1 ORDER BY timestamp_ms DESC, id DESC LIMIT 300
        ")?;
        let rows = query.query_map([], |row| {
            Ok(Conversation {
                address: row.get(0)?,
                preview: row.get::<_, Option<String>>(1)?.unwrap_or_default(),
                updated_ms: row.get(2)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn messages(&self, address: &str, offset: u32) -> Result<Vec<Message>> {
        let mut query = self.0.prepare(
            "
            SELECT id, address, body, outgoing, timestamp_ms, status, text_part FROM messages
            WHERE address = ?1 ORDER BY timestamp_ms DESC, id DESC LIMIT ?2 OFFSET ?3
        ",
        )?;
        let mut rows = query
            .query_map(params![address, PAGE_SIZE, offset], read_message)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for row in &mut rows {
            row.attachments = self.attachment_info(&row.id)?;
            row.tapbacks = self.tapbacks(&row.id, &row.address)?;
        }
        rows.reverse();
        Ok(rows)
    }

    pub fn delete_conversation(&self, address: &str) -> Result<()> {
        let transaction = self.0.unchecked_transaction()?;
        let sending: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM messages WHERE address = ?1 AND status = 'pending')",
            [address],
            |row| row.get(0),
        )?;
        ensure!(!sending, "A message in this conversation is still sending");
        transaction.execute(
            "INSERT OR IGNORE INTO deleted_messages (id) SELECT id FROM messages WHERE address = ?1",
            [address],
        )?;
        transaction.execute("DELETE FROM messages WHERE address = ?1", [address])?;
        transaction.execute("DELETE FROM tapback_events WHERE address = ?1", [address])?;
        transaction.commit()?;
        Ok(())
    }

    pub fn was_deleted(&self, id: &str) -> Result<bool> {
        Ok(self.0.query_row(
            "SELECT EXISTS(SELECT 1 FROM deleted_messages WHERE id = ?1)",
            [id],
            |row| row.get(0),
        )?)
    }

    pub fn get(&self, id: &str) -> Result<Option<Message>> {
        let mut row = self.0.query_row("SELECT id, address, body, outgoing, timestamp_ms, status, text_part FROM messages WHERE id = ?1",
            [id], read_message).optional()?;
        if let Some(row) = &mut row {
            row.attachments = self.attachment_info(id)?;
            row.tapbacks = self.tapbacks(id, &row.address)?;
        }
        Ok(row)
    }

    pub fn insert_tapback(&self, event: &TapbackEvent) -> Result<()> {
        self.0.execute(
            "INSERT INTO tapback_events (id, message_id, address, timestamp_ns, part, outgoing, kind, removed)
             SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8
             WHERE NOT EXISTS (SELECT 1 FROM deleted_messages WHERE id = ?2)
             ON CONFLICT(id) DO NOTHING",
            params![event.id.to_string(), event.target.to_string(), event.chat, event.timestamp_ns,
                event.tapback.part, event.tapback.outgoing, serde_json::to_string(&event.tapback.kind)?,
                event.removed],
        )?;
        Ok(())
    }

    pub fn tapbacks(&self, id: &str, address: &str) -> Result<Vec<Tapback>> {
        let mut query = self.0.prepare_cached(
            "SELECT part, outgoing, kind, removed FROM tapback_events
             WHERE address = ?1 AND message_id = ?2 ORDER BY timestamp_ns, id",
        )?;
        let mut rows = query.query(params![address, id])?;
        let mut active = std::collections::BTreeMap::new();
        while let Some(row) = rows.next()? {
            let part = row.get(0)?;
            let outgoing = row.get(1)?;
            let kind = serde_json::from_str(&row.get::<_, String>(2)?)?;
            let removed: bool = row.get(3)?;
            if !removed {
                active.insert((part, outgoing), kind);
            } else if active.get(&(part, outgoing)) == Some(&kind) {
                active.remove(&(part, outgoing));
            }
        }
        Ok(active
            .into_iter()
            .map(|((part, outgoing), kind)| Tapback {
                kind,
                outgoing,
                part,
            })
            .collect())
    }

    fn attachment_info(&self, id: &str) -> Result<Vec<Attachment>> {
        let mut query = self.0.prepare_cached(
            "SELECT info FROM attachments WHERE message_id = ?1 ORDER BY position",
        )?;
        let rows = query.query_map([id], |row| row.get::<_, String>(0))?;
        rows.map(|row| Ok(serde_json::from_str(&row?)?)).collect()
    }

    pub fn attachment(&self, id: uuid::Uuid, index: usize) -> Result<(Attachment, MediaSource)> {
        let (metadata, bytes, reference): (String, Option<Vec<u8>>, Option<String>) =
            self.0.query_row(
                "SELECT info, bytes, reference FROM attachments WHERE message_id = ?1 AND position = ?2",
                params![id.to_string(), index],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )?;
        let source = if let Some(bytes) = bytes {
            MediaSource::Local(bytes.into())
        } else {
            let reference =
                reference.ok_or_else(|| anyhow::anyhow!("Missing attachment reference"))?;
            MediaSource::Apple(Box::new(serde_json::from_str(&reference)?))
        };
        Ok((serde_json::from_str(&metadata)?, source))
    }

    pub fn cache_attachment(&self, id: uuid::Uuid, index: usize, bytes: &[u8]) -> Result<()> {
        self.0.execute(
            "UPDATE attachments SET bytes = ?3, reference = NULL WHERE message_id = ?1 AND position = ?2",
            params![id.to_string(), index, bytes],
        )?;
        Ok(())
    }

    pub fn insert(
        &self,
        message: &Message,
        sources: impl IntoIterator<Item = MediaSource>,
    ) -> Result<()> {
        let transaction = self.0.unchecked_transaction()?;
        let inserted = transaction.execute(
            "INSERT INTO messages (id, address, body, outgoing, timestamp_ms, status, text_part)
            SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7
            WHERE NOT EXISTS (SELECT 1 FROM deleted_messages WHERE id = ?1)
            ON CONFLICT(id) DO NOTHING",
            params![
                message.id,
                message.address,
                message.body,
                message.outgoing,
                message.timestamp_ms,
                status_value(message.status),
                message.text_part,
            ],
        )? > 0;
        if inserted {
            let mut count = 0;
            for (position, source) in sources.into_iter().enumerate() {
                let info = message
                    .attachments
                    .get(position)
                    .ok_or_else(|| anyhow::anyhow!("Missing attachment metadata"))?;
                let (bytes, reference) = match source {
                    MediaSource::Local(bytes) => (Some(bytes), None),
                    MediaSource::Apple(reference) => {
                        (None, Some(serde_json::to_string(&reference)?))
                    }
                };
                transaction.execute(
                    "INSERT INTO attachments (message_id, position, info, bytes, reference) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![message.id, position, serde_json::to_string(info)?, bytes.as_deref(), reference],
                )?;
                count += 1;
            }
            ensure!(
                count == message.attachments.len(),
                "Missing attachment contents"
            );
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn update(&self, id: &str, status: Delivery) -> Result<()> {
        ensure!(
            self.0.execute(
                "UPDATE messages SET status = ?2 WHERE id = ?1",
                params![id, status_value(status)]
            )? == 1,
            "Message disappeared from local history"
        );
        Ok(())
    }

    pub fn recover(&self) -> Result<()> {
        self.0.execute(
            "UPDATE messages SET status = 'unknown' WHERE status = 'pending'",
            [],
        )?;
        Ok(())
    }
}

fn status_value(status: Delivery) -> &'static str {
    match status {
        Delivery::Received => "received",
        Delivery::Pending => "pending",
        Delivery::Accepted => "accepted",
        Delivery::Failed => "failed",
        Delivery::Unknown => "unknown",
    }
}

fn read_message(row: &rusqlite::Row<'_>) -> rusqlite::Result<Message> {
    Ok(Message {
        id: row.get(0)?,
        address: row.get(1)?,
        body: row.get(2)?,
        text_part: row.get(6)?,
        outgoing: row.get(3)?,
        timestamp_ms: row.get(4)?,
        status: match row.get_ref(5)?.as_str()? {
            "received" => Delivery::Received,
            "pending" => Delivery::Pending,
            "accepted" => Delivery::Accepted,
            "failed" => Delivery::Failed,
            _ => Delivery::Unknown,
        },
        attachments: Vec::new(),
        tapbacks: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TapbackKind;

    #[test]
    fn opening_older_history_keeps_messages_and_saves_part_indices() -> Result<()> {
        let folder = tempfile::tempdir()?;
        let old = Connection::open(folder.path().join("old.sqlite"))?;
        old.execute_batch("CREATE TABLE messages (
            id TEXT PRIMARY KEY, address TEXT NOT NULL, body TEXT NOT NULL,
            outgoing INTEGER NOT NULL, timestamp_ms INTEGER NOT NULL, status TEXT NOT NULL
        ); INSERT INTO messages VALUES ('old', 'mailto:peer@example.org', 'hello', 0, 1, 'received');")?;
        drop(old);
        let history = History::open(folder.path(), "old")?;
        let mut message = history.get("old")?.unwrap();
        assert_eq!(message.body_part(), 0);
        message.id = "new".into();
        message.text_part = Some(4);
        message.attachments.push(Attachment {
            name: "photo.png".into(),
            mime: "image/png".into(),
            size: 1,
            width: 1,
            height: 1,
            part: Some(7),
        });
        history.insert(
            &message,
            [MediaSource::Local(bytes::Bytes::from_static(b"a"))],
        )?;
        drop(history);
        let history = History::open(folder.path(), "old")?;
        let messages = history.messages(&message.address, 0)?;
        assert_eq!(messages.len(), 2);
        assert_eq!(
            messages
                .iter()
                .find(|row| row.id == "new")
                .unwrap()
                .body_part(),
            4
        );
        assert_eq!(history.get("new")?.unwrap().attachment_part(0), 7);
        Ok(())
    }
    use uuid::Uuid;

    #[test]
    fn tapbacks_survive_out_of_order_delivery_and_stay_in_the_right_conversation() -> Result<()> {
        let folder = tempfile::tempdir()?;
        let history = History::open(folder.path(), "reactions")?;
        let target = Uuid::new_v4();
        let chat = "mailto:friend@example.org";
        let make = |timestamp_ns, kind, removed| TapbackEvent {
            id: Uuid::new_v4(),
            target,
            chat: chat.into(),
            timestamp_ns,
            removed,
            tapback: Tapback {
                part: 0,
                outgoing: false,
                kind,
            },
        };
        history.insert_tapback(&make(3, TapbackKind::Like, true))?;
        history.insert_tapback(&make(1, TapbackKind::Heart, false))?;
        history.insert_tapback(&make(2, TapbackKind::Like, false))?;
        assert!(history.tapbacks(&target.to_string(), chat)?.is_empty());
        let latest = make(5, TapbackKind::Laugh, false);
        history.insert_tapback(&latest)?;
        history.insert_tapback(&latest)?;
        history.insert_tapback(&make(6, TapbackKind::Heart, true))?;
        assert_eq!(
            history.tapbacks(&target.to_string(), chat)?,
            vec![latest.tapback]
        );
        assert!(
            history
                .tapbacks(&target.to_string(), "mailto:other@example.org")?
                .is_empty()
        );
        history.delete_conversation(chat)?;
        assert!(history.tapbacks(&target.to_string(), chat)?.is_empty());
        Ok(())
    }
}
