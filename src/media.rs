use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

pub const FILE_LIMIT: usize = 32 * 1024 * 1024;
pub const MAX_ATTACHMENTS: usize = 8;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Attachment {
    pub name: String,
    pub mime: String,
    pub size: usize,
    #[serde(default)]
    pub width: u32,
    #[serde(default)]
    pub height: u32,
}

impl Attachment {
    pub fn is_image(&self) -> bool {
        self.mime.starts_with("image/")
    }

    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            !self.name.trim().is_empty()
                && self.name.len() <= 255
                && !self
                    .name
                    .chars()
                    .any(|c| c.is_control() || matches!(c, '/' | '\\')),
            "Invalid attachment name"
        );
        ensure!(
            self.mime.len() <= 127
                && self.mime.split_once('/').is_some_and(|(kind, subtype)| {
                    [kind, subtype].into_iter().all(|part| {
                        !part.is_empty()
                            && part
                                .bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b"+-._".contains(&b))
                    })
                }),
            "Invalid attachment type"
        );
        ensure!(
            (1..=FILE_LIMIT).contains(&self.size),
            "Attachment exceeds the 32 MiB limit or is empty"
        );
        Ok(())
    }
}

// Attachment bytes travel only when sending a file or opening an attachment.
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct Upload {
    pub info: Attachment,
    #[serde(with = "base64_data")]
    pub bytes: bytes::Bytes,
}

impl std::fmt::Debug for Upload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Upload")
            .field("info", &self.info)
            .finish_non_exhaustive()
    }
}

impl Upload {
    pub(crate) fn validate(&self) -> Result<()> {
        self.info.validate()?;
        ensure!(
            self.bytes.len() == self.info.size,
            "Attachment size differs from its contents"
        );
        Ok(())
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct MediaReference {
    pub url: url::Url,
    pub object: String,
    pub signature: [u8; 21],
    pub key: [u8; 32],
}

pub(crate) enum MediaSource {
    Local(bytes::Bytes),
    Apple(Box<MediaReference>),
}

mod base64_data {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub(super) fn serialize<S: Serializer>(
        bytes: &bytes::Bytes,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&base64::display::Base64Display::new(
            bytes.as_ref(),
            &STANDARD,
        ))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<bytes::Bytes, D::Error> {
        let encoded = <&str>::deserialize(deserializer)?;
        STANDARD
            .decode(encoded)
            .map(Into::into)
            .map_err(D::Error::custom)
    }
}
