use std::path::Path;

use anyhow::{Result, ensure};
use rusqlite::{Connection, OptionalExtension, params};

use crate::media::MediaSource;
use crate::{Attachment, Conversation, Delivery, Message, PAGE_SIZE};

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
        ")?;
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
            SELECT id, address, body, outgoing, timestamp_ms, status FROM messages
            WHERE address = ?1 ORDER BY timestamp_ms DESC, id DESC LIMIT ?2 OFFSET ?3
        ",
        )?;
        let mut rows = query
            .query_map(params![address, PAGE_SIZE, offset], read_message)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for row in &mut rows {
            row.attachments = self.attachment_info(&row.id)?;
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
        let mut row = self.0.query_row("SELECT id, address, body, outgoing, timestamp_ms, status FROM messages WHERE id = ?1",
            [id], read_message).optional()?;
        if let Some(row) = &mut row {
            row.attachments = self.attachment_info(id)?;
        }
        Ok(row)
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
            "INSERT INTO messages (id, address, body, outgoing, timestamp_ms, status)
            SELECT ?1, ?2, ?3, ?4, ?5, ?6
            WHERE NOT EXISTS (SELECT 1 FROM deleted_messages WHERE id = ?1)
            ON CONFLICT(id) DO NOTHING",
            params![
                message.id,
                message.address,
                message.body,
                message.outgoing,
                message.timestamp_ms,
                status_value(message.status)
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
    })
}
