use std::{
    collections::{HashMap, HashSet},
    ops::Range,
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use bytes::{BufMut, Bytes, BytesMut};
use openssl::{
    hash::{MessageDigest, hash},
    rand::rand_bytes,
    sha::{Sha1, sha256},
    symm::{Cipher, decrypt, encrypt},
};
use plist::Value;
use prost::Message as _;
use reqwest::{Body, Client, Method, Response, header};
use url::Url;
use uuid::Uuid;

use crate::{FILE_LIMIT, media::MediaReference};

use super::{Identity, madrid::Madrid, mmcs_wire::*};

const CHUNK_SIZE: usize = 5 * 1024 * 1024;
const MAX_RESPONSE: usize = FILE_LIMIT + 2 * CHUNK_SIZE;
const CONTENT_TYPE: &str = "application/vnd.com.apple.me.ubchunk+protobuf";

pub(super) struct Session {
    client: Client,
    info: String,
    agent: String,
}

impl Session {
    fn new(identity: &Identity) -> Result<Self> {
        let client = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(8))
            .timeout(Duration::from_secs(40))
            .build()?;
        let mut fields = identity.user_agent.trim_matches(['[', ']']).splitn(4, ',');
        let platform = fields.next().unwrap_or_default();
        let version = fields.next().unwrap_or_default();
        let build = fields.next().unwrap_or_default();
        let model = fields.next().unwrap_or_default();
        Ok(Self {
            client,
            info: format!(
                "<{model}> <{platform};{version};{build}> <com.apple.icloud.content/1950.19 (com.apple.Messenger/1.0)>"
            ),
            agent: format!("IMTransferAgent/1000 {platform}/{version}"),
        })
    }

    fn headers(&self) -> [(&str, &str); 4] {
        [
            ("x-apple-mmcs-proto-version", "5.0"),
            (
                "x-apple-mmcs-plist-sha256",
                "fvj0Y/Ybu1pq0r4NxXw3eP51exujUkEAd7LllbkTdK8=",
            ),
            ("x-apple-mmcs-plist-version", "v1.0"),
            ("x-mme-client-info", &self.info),
        ]
    }

    fn push_headers(&self) -> Value {
        self.headers()
            .into_iter()
            .map(|(k, v)| format!("{k}:{v}\n"))
            .collect::<String>()
            .into()
    }

    async fn edge(
        &self,
        edge: &EdgeRequest,
        method: Method,
        body: Option<Body>,
    ) -> Result<(Response, Url)> {
        ensure!(
            edge.method == method.as_str(),
            "Unexpected MMCS transfer method"
        );
        ensure!(
            edge.path.starts_with('/') && !edge.path.starts_with("//"),
            "Invalid MMCS storage path"
        );
        let origin = Url::parse(&format!("{}://{}:{}", edge.scheme, edge.host, edge.port))?;
        ensure!(
            origin.path() == "/" && origin.query().is_none(),
            "Invalid MMCS storage origin"
        );
        let url = origin.join(&edge.path)?;
        validate_url(&url, true)?;
        let mut request = self
            .client
            .request(method, url.clone())
            .header(
                "x-apple-request-uuid",
                Uuid::new_v4().to_string().to_uppercase(),
            )
            .header(header::USER_AGENT, &self.agent);
        for field in &edge.headers {
            let name = header::HeaderName::from_bytes(field.name.as_bytes())?;
            if name == header::HOST
                || name == header::CONTENT_LENGTH
                || name == header::TRANSFER_ENCODING
            {
                continue;
            }
            request = request.header(name, &field.value);
        }
        if let Some(body) = body {
            request = request.body(body);
        }
        let response = request.send().await.map_err(reqwest::Error::without_url)?;
        ensure!(
            response.status().is_success(),
            "MMCS storage returned HTTP {}",
            response.status().as_u16()
        );
        Ok((response, url))
    }

    async fn complete(
        &self,
        reference: &MediaReference,
        endpoint: &str,
        auth: String,
        dsid: &str,
        completion: Completion,
    ) -> Result<()> {
        let mut url = reference.url.clone();
        url.path_segments_mut()
            .map_err(|_| anyhow::anyhow!("Invalid MMCS completion URL"))?
            .pop_if_empty()
            .push(endpoint);
        validate_url(&url, false)?;
        let mut request = self
            .client
            .post(url)
            .header(
                "x-apple-request-uuid",
                Uuid::new_v4().to_string().to_uppercase(),
            )
            .header("x-apple-mmcs-dataclass", "com.apple.Dataclass.Messenger")
            .header("x-apple-mmcs-auth", auth)
            .header("x-apple-mme-dsid", dsid)
            .header(header::ACCEPT, CONTENT_TYPE)
            .header(header::CONTENT_TYPE, CONTENT_TYPE)
            .header(header::USER_AGENT, &self.agent);
        for (name, value) in self.headers() {
            request = request.header(name, value);
        }
        let response = request
            .body(completion.encode_to_vec())
            .send()
            .await
            .map_err(reqwest::Error::without_url)?;
        ensure!(
            response.status().is_success(),
            "MMCS completion returned HTTP {}",
            response.status().as_u16()
        );
        let _ = read_body(response, 256 * 1024).await?;
        Ok(())
    }
}

pub(super) async fn upload(
    madrid: &mut Madrid,
    identity: &Identity,
    input: &[u8],
) -> Result<MediaReference> {
    let session = Session::new(identity)?;
    let mut key = [0; 32];
    rand_bytes(&mut key)?;
    let encrypted = Bytes::from(crypt(&key, input)?);
    let signature = file_signature(0x81, &encrypted);
    let chunks: Vec<_> = encrypted
        .chunks(CHUNK_SIZE)
        .map(|part| UploadChunk {
            signature: chunk_signature(1, part).into(),
            size: part.len() as u32,
        })
        .collect();
    let manifest = UploadManifest {
        kind: 81,
        files: vec![UploadFile {
            signature: signature.into(),
            object: Some(String::new()),
            profile: Some(ChunkProfile {
                count: chunks.len() as u32,
                name: "kCKProfileTypeFixed".into(),
                flags: Some(0),
            }),
            chunks,
        }],
    };
    let response = madrid
        .media_request(
            identity,
            150,
            [
                ("v", 3.into()),
                ("mL", (input.len() as u64).into()),
                ("mS", Value::Data(signature.to_vec())),
                ("cH", session.push_headers()),
                ("cB", Value::Data(manifest.encode_to_vec())),
            ],
        )
        .await?;
    let object = response
        .get("mU")
        .and_then(Value::as_string)
        .context("Missing MMCS object ID")?
        .to_owned();
    let mut url = Url::parse(
        response
            .get("mR")
            .and_then(Value::as_string)
            .context("Missing MMCS URL")?,
    )?;
    validate_url(&url, false)?;
    ensure!(valid_object(&object), "Invalid MMCS object ID");
    url.path_segments_mut()
        .map_err(|_| anyhow::anyhow!("Invalid MMCS object URL"))?
        .pop_if_empty()
        .push(&object);
    let reference = MediaReference {
        url,
        object,
        signature,
        key,
    };
    let authorization = UploadAuthorization::decode(
        response
            .get("cB")
            .and_then(Value::as_data)
            .context("Missing MMCS upload authorization")?,
    )?;
    let existing = authorization
        .existing
        .iter()
        .any(|file| file.signature == signature && !file.receipt.is_empty());
    ensure!(
        existing || !authorization.targets.is_empty(),
        "MMCS returned no upload locations"
    );
    ensure!(
        authorization.targets.len() <= 16,
        "Too many MMCS upload locations"
    );

    let data: HashMap<_, _> = manifest.files[0]
        .chunks
        .iter()
        .enumerate()
        .map(|(index, chunk)| {
            let start = index * CHUNK_SIZE;
            (
                chunk.signature.as_slice(),
                encrypted.slice(start..start + chunk.size as usize),
            )
        })
        .collect();
    let mut sent = HashSet::new();
    for target in authorization.targets {
        let edge = target.request.context("Missing MMCS upload request")?;
        ensure!(
            !target.chunks.is_empty() && target.chunks.len() <= data.len(),
            "Invalid MMCS upload chunk list"
        );
        let mut buffer = BytesMut::new();
        for chunk in &target.chunks {
            let part = data
                .get(chunk.checksum.as_slice())
                .context("MMCS requested an unknown chunk")?;
            buffer.extend_from_slice(part);
            sent.insert(chunk.checksum.clone());
        }
        let length = buffer.len();
        let md5 = hash(MessageDigest::md5(), &buffer)?.to_vec();
        let finish_at_edge = edge.headers.iter().any(|field| {
            field
                .name
                .eq_ignore_ascii_case("x-apple-put-complete-at-edge-version")
                && field.value == "2"
        });
        let body = if finish_at_edge {
            let footer = EdgeFooter {
                md5: md5.clone(),
                completion_data: authorization.completion_data.clone(),
            }
            .encode_to_vec();
            buffer.put_u32(footer.len() as u32);
            buffer.extend_from_slice(&footer);
            Body::wrap_stream(futures_util::stream::once(async {
                Ok::<_, std::io::Error>(buffer.freeze())
            }))
        } else {
            Body::from(buffer.freeze())
        };
        let (response, url) = session.edge(&edge, Method::PUT, Some(body)).await?;
        let receipt = make_receipt(&response, &url, &target.token, Some(md5));
        let _ = read_body(response, 256 * 1024).await?;
        if !finish_at_edge {
            let completion = Completion {
                requests: vec![receipt],
                data: authorization.completion_data.clone(),
            };
            session
                .complete(
                    &reference,
                    "putComplete",
                    format!("{} {} {}", target.authorization, length, target.token),
                    &reference.object,
                    completion,
                )
                .await?;
        }
    }
    ensure!(
        existing || sent.len() == data.len(),
        "MMCS did not accept every attachment chunk"
    );
    Ok(reference)
}

pub(crate) struct AuthorizedDownload {
    session: Session,
    reference: Box<MediaReference>,
    dsid: String,
    catalogue: DownloadCatalogue,
}

pub(super) async fn authorize_download(
    madrid: &mut Madrid,
    identity: &Identity,
    reference: Box<MediaReference>,
) -> Result<AuthorizedDownload> {
    let session = Session::new(identity)?;
    validate_url(&reference.url, false)?;
    ensure!(
        valid_object(&reference.object),
        "Invalid attachment reference"
    );
    let mut base = reference.url.clone();
    if base
        .path_segments()
        .and_then(|mut segments| segments.next_back())
        == Some(&reference.object)
    {
        base.path_segments_mut()
            .map_err(|_| anyhow::anyhow!("Invalid MMCS object URL"))?
            .pop();
    }
    let response = madrid
        .media_request(
            identity,
            151,
            [
                ("v", 8.into()),
                ("mO", reference.object.as_str().into()),
                ("mR", base.as_str().trim_end_matches('/').into()),
                ("mS", Value::Data(reference.signature.to_vec())),
                ("cH", session.push_headers()),
            ],
        )
        .await?;
    let dsid = response
        .get("mU")
        .and_then(Value::as_string)
        .context("Missing MMCS download token")?;
    let catalogue = DownloadAuthorization::decode(
        response
            .get("cB")
            .and_then(Value::as_data)
            .context("Missing MMCS download authorization")?,
    )?
    .catalogue
    .context("Apple could not authorize this download")?;
    Ok(AuthorizedDownload {
        session,
        reference,
        dsid: dsid.to_owned(),
        catalogue,
    })
}

impl AuthorizedDownload {
    pub(crate) async fn transfer(self) -> Result<Bytes> {
        let Self {
            session,
            reference,
            dsid,
            catalogue,
        } = self;
        let file = catalogue
            .files
            .iter()
            .find(|file| file.signature == reference.signature)
            .context("MMCS returned a different file")?;
        ensure!(
            !file.chunks.is_empty() && file.chunks.len() <= 64,
            "Invalid MMCS download chunk list"
        );
        let mut encrypted = Vec::new();
        let mut containers = HashMap::new();
        let mut receipts = Vec::new();
        let mut downloaded = 0;
        for index in &file.chunks {
            let container = catalogue
                .containers
                .get(index.container as usize)
                .context("Missing MMCS storage container")?;
            let chunk = container
                .chunks
                .get(index.index as usize)
                .and_then(|chunk| chunk.data.as_ref())
                .context("Missing MMCS download chunk")?;
            let range = download_chunk_range(chunk, encrypted.len())?;
            if let std::collections::hash_map::Entry::Vacant(entry) =
                containers.entry(index.container)
            {
                let request = container
                    .request
                    .as_ref()
                    .context("Missing MMCS storage request")?;
                let (response, url) = session.edge(request, Method::GET, None).await?;
                receipts.push(make_receipt(&response, &url, &container.token, None));
                let data = read_body(response, MAX_RESPONSE - downloaded).await?;
                downloaded += data.len();
                entry.insert(data);
            }
            let part = containers[&index.container]
                .get(range)
                .context("Apple returned an incomplete attachment")?;
            append_verified_chunk(&mut encrypted, chunk, part)?;
        }
        ensure!(
            file_signature(reference.signature[0], &encrypted) == reference.signature,
            "Apple returned an attachment with an invalid signature"
        );
        let first = catalogue
            .containers
            .get(file.chunks[0].container as usize)
            .context("Missing MMCS storage container")?;
        let completion = Completion {
            requests: receipts,
            data: None,
        };
        session
            .complete(
                &reference,
                "getComplete",
                format!("{} {}", first.authorization, first.token),
                &dsid,
                completion,
            )
            .await?;
        Ok(crypt(&reference.key, &encrypted)?.into())
    }
}

fn download_chunk_range(chunk: &ChunkData, assembled: usize) -> Result<Range<usize>> {
    // The message's advertised file size can differ from the authorized transfer.
    ensure!(
        chunk.size > 0 && chunk.size <= FILE_LIMIT.saturating_sub(assembled) as u64,
        "Invalid MMCS chunk size"
    );
    let end = chunk
        .offset
        .checked_add(chunk.size)
        .filter(|end| *end <= MAX_RESPONSE as u64)
        .context("Invalid MMCS chunk offset")?;
    Ok(chunk.offset as usize..end as usize)
}

fn make_receipt(
    response: &Response,
    url: &Url,
    token: &str,
    upload_md5: Option<Vec<u8>>,
) -> Receipt {
    let keys = ["Etag", "x-apple-edge-info"];
    let headers = keys
        .into_iter()
        .filter(|name| *name != "Etag" || upload_md5.is_some())
        .filter_map(|name| {
            let value = response.headers().get(name)?.to_str().ok()?;
            Some(Header {
                name: name.into(),
                value: value.into(),
            })
        })
        .collect();
    Receipt {
        url: url.as_str().into(),
        status: response.status().as_u16().into(),
        headers,
        upload_md5,
        token: token.into(),
    }
}

async fn read_body(mut response: Response, limit: usize) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(reqwest::Error::without_url)?
    {
        ensure!(
            data.len() + chunk.len() <= limit,
            "MMCS response exceeds its size limit"
        );
        data.extend_from_slice(&chunk);
    }
    Ok(data)
}

fn crypt(key: &[u8; 32], bytes: &[u8]) -> Result<Vec<u8>> {
    Ok(encrypt(Cipher::aes_256_ctr(), key, Some(&[0; 16]), bytes)?)
}

fn file_signature(prefix: u8, bytes: &[u8]) -> [u8; 21] {
    let mut digest = Sha1::new();
    digest.update(b"com.apple.XattrObjectSalt\0com.apple.DataObjectSalt\0");
    digest.update(bytes);
    let mut signature = [prefix; 21];
    signature[1..].copy_from_slice(&digest.finish());
    signature
}

fn chunk_signature(prefix: u8, bytes: &[u8]) -> [u8; 21] {
    let mut signature = [prefix; 21];
    signature[1..].copy_from_slice(&sha256(&sha256(bytes))[..20]);
    signature
}

fn append_verified_chunk(output: &mut Vec<u8>, chunk: &ChunkData, data: &[u8]) -> Result<()> {
    let plain;
    let data = if let Some(key) = &chunk.key {
        ensure!(
            key.len() == 17 && key[0] == 1,
            "Unsupported MMCS chunk encryption"
        );
        plain = decrypt(Cipher::aes_128_cfb128(), &key[1..], Some(&[0; 16]), data)?;
        &plain[..]
    } else {
        data
    };
    let prefix = chunk.checksum.first().context("Missing MMCS checksum")?;
    ensure!(
        chunk_signature(*prefix, data).as_slice() == chunk.checksum,
        "Invalid MMCS chunk checksum"
    );
    output.extend_from_slice(data);
    Ok(())
}

pub(super) fn validate_url(url: &Url, delegated: bool) -> Result<()> {
    ensure!(
        url.scheme() == "https"
            && url.port_or_known_default() == Some(443)
            && url.password().is_none()
            && url.username().is_empty()
            && url.fragment().is_none(),
        "Invalid MMCS HTTPS URL"
    );
    let host = url.domain().context("Unknown MMCS storage host")?;
    let matches = |suffix: &str| {
        host == suffix
            || host
                .strip_suffix(suffix)
                .is_some_and(|root| root.ends_with('.'))
    };
    let apple = [
        "apple.com",
        "icloud.com",
        "icloud-content.com",
        "cdn-apple.com",
    ];
    let storage = [
        "amazonaws.com",
        "storage.googleapis.com",
        "blob.core.windows.net",
    ];
    ensure!(
        apple.iter().any(|suffix| matches(suffix))
            || (delegated && storage.iter().any(|suffix| matches(suffix))),
        "Unknown MMCS storage host"
    );
    Ok(())
}

pub(super) fn valid_object(object: &str) -> bool {
    !object.is_empty()
        && object.len() <= 256
        && object != "."
        && object != ".."
        && object
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.+=%".contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_download_ranges_against_transfer_limits() -> Result<()> {
        let mut chunk = ChunkData {
            size: 2 * 1024 * 1024,
            offset: 1024,
            ..Default::default()
        };
        assert_eq!(
            download_chunk_range(&chunk, 0)?,
            1024..1024 + 2 * 1024 * 1024
        );
        assert!(download_chunk_range(&chunk, FILE_LIMIT - 1024).is_err());

        chunk.offset = MAX_RESPONSE as u64;
        assert!(download_chunk_range(&chunk, 0).is_err());
        chunk.offset = u64::MAX;
        assert!(download_chunk_range(&chunk, 0).is_err());
        chunk.offset = 0;
        chunk.size = 0;
        assert!(download_chunk_range(&chunk, 0).is_err());
        Ok(())
    }
}
