use std::io::Cursor;

use anyhow::{Context, Result};
use plist::{Dictionary, Value};
use quick_xml::{
    Reader, Writer,
    events::{BytesEnd, BytesStart, BytesText, Event},
};
use url::Url;

use crate::{
    Attachment, MAX_ATTACHMENTS, TEXT_LIMIT,
    media::{MediaReference, MediaSource},
};

use super::mmcs;

pub(super) fn encode(
    text: &str,
    files: impl Iterator<Item = (Attachment, MediaReference)>,
) -> Result<String> {
    let mut writer = Writer::new(Cursor::new(Vec::new()));
    writer.write_event(Event::Start(BytesStart::new("html")))?;
    writer.write_event(Event::Start(BytesStart::new("body")))?;
    let mut next_index = 0;
    for (info, media) in files {
        let index = next_index.to_string();
        next_index += 1;
        let len = info.size.to_string();
        let width = info.width.to_string();
        let height = info.height.to_string();
        let signature = hex::encode_upper(media.signature);
        let key = format!("00{}", hex::encode(media.key));
        let uti = match info.mime.as_str() {
            "image/jpeg" => "public.jpeg",
            "image/png" => "public.png",
            "image/heic" | "image/heif" => "public.heic",
            "image/gif" => "com.compuserve.gif",
            "image/webp" => "org.webmproject.webp",
            "image/tiff" => "public.tiff",
            "image/bmp" => "com.microsoft.bmp",
            "image/avif" => "public.avif",
            "application/pdf" => "com.adobe.pdf",
            _ => "public.data",
        };
        let file = BytesStart::new("FILE").with_attributes([
            ("name", info.name.as_str()),
            ("width", width.as_str()),
            ("height", height.as_str()),
            ("datasize", len.as_str()),
            ("file-size", len.as_str()),
            ("mime-type", info.mime.as_str()),
            ("uti-type", uti),
            ("message-part", index.as_str()),
            ("mmcs-signature-hex", signature.as_str()),
            ("mmcs-url", media.url.as_str()),
            ("mmcs-owner", media.object.as_str()),
            ("decryption-key", key.as_str()),
        ]);
        writer.write_event(Event::Empty(file))?;
    }
    if !text.is_empty() {
        let index = next_index.to_string();
        writer.write_event(Event::Start(
            BytesStart::new("span").with_attributes([("message-part", index.as_str())]),
        ))?;
        for (index, line) in text.split('\n').enumerate() {
            if index != 0 {
                writer.write_event(Event::Empty(BytesStart::new("br")))?;
            }
            writer.write_event(Event::Text(BytesText::new(line)))?;
        }
        writer.write_event(Event::End(BytesEnd::new("span")))?;
    }
    writer.write_event(Event::End(BytesEnd::new("body")))?;
    writer.write_event(Event::End(BytesEnd::new("html")))?;
    Ok(String::from_utf8(writer.into_inner().into_inner())?)
}

pub(super) fn decode(body: &Dictionary) -> (String, Vec<(Attachment, MediaSource)>) {
    let mut rich_text = String::new();
    let mut media = Vec::new();
    if let Some(xml) = body.get("x").and_then(Value::as_string) {
        let mut reader = Reader::from_str(xml);
        loop {
            match reader.read_event() {
                Ok(Event::Start(element) | Event::Empty(element)) => {
                    let name = element.local_name();
                    if name.as_ref().eq_ignore_ascii_case(b"file")
                        && media.len() < MAX_ATTACHMENTS
                        && let Ok(file) = parse_file(&element, body, reader.decoder())
                    {
                        media.push(file);
                    }
                    if name.as_ref().eq_ignore_ascii_case(b"br") {
                        rich_text.push('\n');
                    }
                }
                Ok(Event::Text(text)) if rich_text.len() <= TEXT_LIMIT => {
                    if let Ok(text) = text.xml_content() {
                        rich_text.push_str(&text);
                    }
                }
                Ok(Event::GeneralRef(entity)) if rich_text.len() <= TEXT_LIMIT => {
                    if let Ok(Some(character)) = entity.resolve_char_ref() {
                        rich_text.push(character);
                    } else if let Ok(name) = entity.decode()
                        && let Some(escaped) = quick_xml::escape::resolve_xml_entity(&name)
                    {
                        rich_text.push_str(escaped);
                    }
                }
                Ok(Event::Eof) | Err(_) => break,
                _ => (),
            }
        }
    }
    let clean = |text: &str| text.replace(['\u{fffc}', '\0'], "");
    let mut text = body
        .get("t")
        .and_then(Value::as_string)
        .map(clean)
        .unwrap_or_default();
    if text.trim_matches(['\u{fffd}', ' ', '\n']).is_empty() {
        text = clean(&rich_text);
    }
    if body.get("bid").and_then(Value::as_string) == Some("com.apple.messages.URLBalloonProvider")
        && let Some(data) = body.get("bp").and_then(Value::as_data)
        && let Ok(decoded) = super::madrid::decompress(data)
        && let Some(url) = preview_url(&decoded)
        && !text.contains(url.as_str())
        && !text.contains("://")
    {
        if text.trim_matches(['\u{fffd}', ' ', '\n']).is_empty() {
            text = url.to_string();
        } else {
            text.push('\n');
            text.push_str(url.as_str());
        }
    }
    if text.len() > TEXT_LIMIT {
        let end = (TEXT_LIMIT - 3..=TEXT_LIMIT)
            .rev()
            .find(|index| text.is_char_boundary(*index))
            .expect("UTF-8 characters are no longer than four bytes");
        text.truncate(end);
    }
    (text, media)
}

fn parse_file(
    element: &BytesStart<'_>,
    body: &Dictionary,
    decoder: quick_xml::encoding::Decoder,
) -> Result<(Attachment, MediaSource)> {
    let attributes = element
        .attributes()
        .map(|attribute| {
            let attribute = attribute?;
            let name = String::from_utf8(attribute.key.as_ref().to_vec())?;
            Ok((
                name,
                attribute.decode_and_unescape_value(decoder)?.into_owned(),
            ))
        })
        .collect::<Result<std::collections::HashMap<_, _>>>()?;
    let value = |key: &str| attributes.get(key).map(String::as_str);
    let name = value("name")
        .filter(|name| !name.is_empty())
        .unwrap_or("Attachment")
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or("Attachment")
        .chars()
        .filter(|c| !c.is_control())
        .collect::<String>();
    let kind = match value("uti-type") {
        Some("public.jpeg") => "image/jpeg",
        Some("public.png") => "image/png",
        Some("public.heic" | "public.heif") => "image/heic",
        Some("com.compuserve.gif") => "image/gif",
        Some("org.webmproject.webp") => "image/webp",
        Some("public.tiff") => "image/tiff",
        Some("com.microsoft.bmp") => "image/bmp",
        _ => "application/octet-stream",
    };
    let mime = value("mime-type")
        .filter(|mime| !mime.is_empty() && !mime.eq_ignore_ascii_case("application/octet-stream"))
        .unwrap_or(kind)
        .to_ascii_lowercase();
    let (size, source) = if let Some(inline @ ("ia-0" | "ia-1")) = value("inline-attachment") {
        let bytes = body
            .get(inline)
            .and_then(Value::as_data)
            .context("Missing inline attachment")?;
        (
            bytes.len(),
            MediaSource::Local(bytes::Bytes::copy_from_slice(bytes)),
        )
    } else {
        let (size, reference) = media_reference(value)?;
        (size, MediaSource::Apple(Box::new(reference)))
    };
    let info = Attachment {
        name,
        mime,
        size,
        width: value("width")
            .and_then(|value| value.parse().ok())
            .unwrap_or(0),
        height: value("height")
            .and_then(|value| value.parse().ok())
            .unwrap_or(0),
    };
    info.validate()?;
    Ok((info, source))
}

fn media_reference<'a>(value: impl Fn(&str) -> Option<&'a str>) -> Result<(usize, MediaReference)> {
    let mut best = None;
    for index in 0..MAX_ATTACHMENTS {
        let get = |field: &str| {
            if index == 0 {
                value(field)
            } else {
                value(&format!("{field}-{index}"))
            }
        };
        let parse = || -> Option<(usize, MediaReference)> {
            let url = Url::parse(get("mmcs-url")?).ok()?;
            mmcs::validate_url(&url, false).ok()?;
            let object = get("mmcs-owner")?;
            let key = hex::decode(get("decryption-key")?).ok()?;
            let (0, key) = key.split_first()? else {
                return None;
            };
            let signature = hex::decode(get("mmcs-signature-hex")?).ok()?;
            let size: usize = get("file-size")?.parse().ok()?;
            if !mmcs::valid_object(object) || size == 0 || size > crate::FILE_LIMIT {
                return None;
            }
            Some((
                size,
                MediaReference {
                    url,
                    object: object.to_owned(),
                    signature: signature.try_into().ok()?,
                    key: key.try_into().ok()?,
                },
            ))
        };
        if let Some(candidate) = parse()
            && best.as_ref().is_none_or(|(size, _)| candidate.0 > *size)
        {
            best = Some(candidate);
        }
    }
    best.context("Attachment has no supported MMCS reference")
}

fn preview_url(decoded: &[u8]) -> Option<Url> {
    let value: Dictionary = plist::from_bytes(decoded).ok()?;
    let archive: Dictionary;
    let root = if let Some(wrapped) = value.get("__payload__").and_then(Value::as_data) {
        archive = plist::from_bytes(wrapped).ok()?;
        &archive
    } else {
        &value
    };
    let objects = root.get("$objects")?.as_array()?;
    let resolve = |value: &Value| value.as_uid().and_then(|id| objects.get(id.get() as usize));
    let top = root.get("$top")?.as_dictionary()?.get("root")?;
    let rich_link = resolve(top)?.as_dictionary()?;
    let metadata = resolve(rich_link.get("richLinkMetadata")?)?.as_dictionary()?;
    for key in ["originalURL", "URL"] {
        let Some(uri) = metadata.get(key).and_then(resolve) else {
            continue;
        };
        let text = uri.as_string().or_else(|| {
            let ns = uri.as_dictionary()?;
            let relative = ns.get("NS.relative")?;
            resolve(relative).unwrap_or(relative).as_string()
        });
        if let Some(url) = text.and_then(|text| Url::parse(text).ok()).filter(|url| {
            matches!(url.scheme(), "http" | "https")
                && url.host().is_some()
                && url.username().is_empty()
                && url.password().is_none()
        }) {
            return Some(url);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression, write::GzEncoder};

    #[test]
    fn decodes_apple_inline_photo_without_mime_type() {
        let body = Dictionary::from_iter([
            ("t", Value::String("\u{fffc}".into())),
            ("x", Value::String(r#"<html><body><FILE name="Photo &amp; notes.png" uti-type="public.png" width="800" height="600" inline-attachment="ia-0"/><span>Photo &amp; notes<br/>for tomorrow</span></body></html>"#.into())),
            ("ia-0", Value::Data(vec![1, 2, 3, 4])),
        ]);
        let (text, files) = decode(&body);
        assert_eq!(text, "Photo & notes\nfor tomorrow");
        let [(info, MediaSource::Local(bytes))] = &files[..] else {
            panic!("Missing inline photo")
        };
        assert_eq!(info.name, "Photo & notes.png");
        assert_eq!(info.mime, "image/png");
        assert_eq!((info.width, info.height), (800, 600));
        assert_eq!(bytes.as_ref(), [1, 2, 3, 4]);
    }

    #[test]
    fn recovers_the_original_url_from_an_apple_link_balloon() -> Result<()> {
        let uid = |value| Value::Uid(plist::Uid::new(value));
        let dict = |fields: &[(&str, Value)]| {
            Value::Dictionary(Dictionary::from_iter(fields.iter().cloned()))
        };
        let objects = vec![
            Value::String("$null".into()),
            dict(&[("richLinkMetadata", uid(2))]),
            dict(&[("originalURL", uid(3))]),
            dict(&[("NS.relative", uid(4))]),
            Value::String("https://example.com/article".into()),
        ];
        let archive = dict(&[
            ("$top", dict(&[("root", uid(1))])),
            ("$objects", Value::Array(objects)),
        ]);
        let mut encoded = GzEncoder::new(Vec::new(), Compression::default());
        plist::to_writer_binary(&mut encoded, &archive)?;
        let body = Dictionary::from_iter([
            ("t", Value::String("\u{fffc}".into())),
            (
                "bid",
                Value::String("com.apple.messages.URLBalloonProvider".into()),
            ),
            ("bp", Value::Data(encoded.finish()?)),
        ]);
        assert_eq!(decode(&body).0, "https://example.com/article");
        Ok(())
    }
}
