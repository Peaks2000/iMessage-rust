// Protobuf fields used by the iMessage MMCS v5 catalogue and storage edge.
use prost::Message;

#[derive(Clone, PartialEq, Message)]
pub(super) struct UploadManifest {
    #[prost(message, repeated, tag = "1")]
    pub files: Vec<UploadFile>,
    #[prost(uint32, tag = "3")]
    pub kind: u32,
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct UploadFile {
    #[prost(bytes, tag = "1")]
    pub signature: Vec<u8>,
    #[prost(string, optional, tag = "2")]
    pub object: Option<String>,
    #[prost(message, repeated, tag = "3")]
    pub chunks: Vec<UploadChunk>,
    #[prost(message, optional, tag = "8")]
    pub profile: Option<ChunkProfile>,
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct UploadChunk {
    #[prost(bytes, tag = "1")]
    pub signature: Vec<u8>,
    #[prost(uint32, tag = "3")]
    pub size: u32,
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct ChunkProfile {
    #[prost(uint32, tag = "1")]
    pub count: u32,
    #[prost(string, tag = "101")]
    pub name: String,
    #[prost(uint32, optional, tag = "103")]
    pub flags: Option<u32>,
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct UploadAuthorization {
    #[prost(message, repeated, tag = "1")]
    pub targets: Vec<UploadTarget>,
    #[prost(message, repeated, tag = "4")]
    pub existing: Vec<ExistingFile>,
    #[prost(bytes, optional, tag = "6")]
    pub completion_data: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct UploadTarget {
    #[prost(string, tag = "1")]
    pub authorization: String,
    #[prost(message, optional, tag = "2")]
    pub request: Option<EdgeRequest>,
    #[prost(string, tag = "4")]
    pub token: String,
    #[prost(message, repeated, tag = "5")]
    pub chunks: Vec<ChunkId>,
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct ChunkId {
    #[prost(bytes, tag = "1")]
    pub checksum: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct ExistingFile {
    #[prost(bytes, tag = "1")]
    pub signature: Vec<u8>,
    #[prost(string, tag = "3")]
    pub receipt: String,
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct DownloadAuthorization {
    #[prost(message, optional, tag = "1")]
    pub catalogue: Option<DownloadCatalogue>,
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct DownloadCatalogue {
    #[prost(message, repeated, tag = "1")]
    pub containers: Vec<DownloadContainer>,
    #[prost(message, repeated, tag = "2")]
    pub files: Vec<FileLocation>,
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct DownloadContainer {
    #[prost(message, optional, tag = "1")]
    pub request: Option<EdgeRequest>,
    #[prost(string, tag = "3")]
    pub authorization: String,
    #[prost(string, tag = "4")]
    pub token: String,
    #[prost(message, repeated, tag = "5")]
    pub chunks: Vec<ChunkLocation>,
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct FileLocation {
    #[prost(bytes, tag = "1")]
    pub signature: Vec<u8>,
    #[prost(message, repeated, tag = "2")]
    pub chunks: Vec<ChunkIndex>,
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct ChunkIndex {
    #[prost(uint32, tag = "1")]
    pub container: u32,
    #[prost(uint32, tag = "2")]
    pub index: u32,
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct ChunkLocation {
    #[prost(message, optional, tag = "1")]
    pub data: Option<ChunkData>,
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct ChunkData {
    #[prost(bytes, tag = "1")]
    pub checksum: Vec<u8>,
    #[prost(bytes, optional, tag = "2")]
    pub key: Option<Vec<u8>>,
    #[prost(uint64, tag = "3")]
    pub size: u64,
    #[prost(uint64, tag = "4")]
    pub offset: u64,
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct EdgeRequest {
    #[prost(string, tag = "1")]
    pub host: String,
    #[prost(uint32, tag = "2")]
    pub port: u32,
    #[prost(string, tag = "3")]
    pub method: String,
    #[prost(string, tag = "4")]
    pub path: String,
    #[prost(string, tag = "7")]
    pub scheme: String,
    #[prost(message, repeated, tag = "8")]
    pub headers: Vec<Header>,
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct Header {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(string, tag = "2")]
    pub value: String,
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct Completion {
    #[prost(message, repeated, tag = "1")]
    pub requests: Vec<Receipt>,
    #[prost(bytes, optional, tag = "2")]
    pub data: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct Receipt {
    #[prost(string, tag = "1")]
    pub url: String,
    #[prost(uint32, tag = "2")]
    pub status: u32,
    #[prost(message, repeated, tag = "4")]
    pub headers: Vec<Header>,
    #[prost(bytes, optional, tag = "7")]
    pub upload_md5: Option<Vec<u8>>,
    #[prost(string, tag = "10")]
    pub token: String,
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct EdgeFooter {
    #[prost(bytes, tag = "1")]
    pub md5: Vec<u8>,
    #[prost(bytes, optional, tag = "2")]
    pub completion_data: Option<Vec<u8>>,
}
