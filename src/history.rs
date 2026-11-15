use std::path::Path;

use anyhow::{Result, ensure};
use rusqlite::{Connection, OptionalExtension, params};

use crate::{Conversation, Delivery, Message, PAGE_SIZE};

pub struct History(Connection);

impl History {
    pub fn open(root: &Path, profile: &str) -> Result<Self> {
        let db = Connection::open(root.join(format!("{profile}.sqlite")))?;
        db.busy_timeout(std::time::Duration::from_secs(2))?;
        db.execute_batch("
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = FULL;
            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                address TEXT NOT NULL,
                body TEXT NOT NULL,
                outgoing INTEGER NOT NULL,
                timestamp_ms INTEGER NOT NULL,
                status TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS recent_messages ON messages(address, timestamp_ms DESC, id DESC);
        ")?;
        Ok(Self(db))
    }

    pub fn chats(&self) -> Result<Vec<Conversation>> {
        let mut query = self.0.prepare("
            SELECT address, body, timestamp_ms
            FROM (SELECT *, ROW_NUMBER() OVER (PARTITION BY address ORDER BY timestamp_ms DESC, id DESC) AS rank FROM messages)
            WHERE rank = 1 ORDER BY timestamp_ms DESC, id DESC LIMIT 300
        ")?;
        let rows = query.query_map([], |row| {
            Ok(Conversation {
                address: row.get(0)?,
                preview: row.get(1)?,
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
        rows.reverse();
        Ok(rows)
    }

    pub fn get(&self, id: &str) -> Result<Option<Message>> {
        Ok(self.0.query_row("SELECT id, address, body, outgoing, timestamp_ms, status FROM messages WHERE id = ?1",
            [id], read_message).optional()?)
    }

    pub fn insert(&self, message: &Message) -> Result<()> {
        self.0.execute(
            "INSERT INTO messages VALUES (?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT(id) DO NOTHING",
            params![
                message.id,
                message.address,
                message.body,
                message.outgoing,
                message.timestamp_ms,
                status_value(message.status)
            ],
        )?;
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
        Delivery::Demo => "demo",
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
            "demo" => Delivery::Demo,
            _ => Delivery::Unknown,
        },
    })
}
