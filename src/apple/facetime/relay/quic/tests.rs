use super::super::{CallRelayProfile, pod::Pod};
use super::*;
use crate::apple::facetime::description::tests as description;
use compcol::qpack::QpackDecoder;
use openssl::{
    memcmp,
    ssl::{AlpnError, select_next_proto},
};
use prost::Message;
use std::os::fd::AsRawFd;

type ServerPsk = unsafe extern "C" fn(SslPtr, *const u8, usize, *mut SessionPtr) -> c_int;
type Method = unsafe extern "C" fn() -> *const ffi::SSL_METHOD;
type SetServerPsk = unsafe extern "C" fn(*mut ffi::SSL_CTX, ServerPsk);
type ListenerCall = unsafe extern "C" fn(SslPtr, u64) -> SslPtr;
type NewListener = unsafe extern "C" fn(*mut ffi::SSL_CTX, u64) -> SslPtr;

unsafe extern "C" fn find_test_psk(
    ssl: SslPtr,
    identity: *const u8,
    len: usize,
    out: *mut SessionPtr,
) -> c_int {
    let Some(Ok(index)) = PSK_SLOT.get() else {
        return 0;
    };
    let Some(Ok(api)) = QUIC_API.get() else {
        return 0;
    };
    // SAFETY: OpenSSL supplies the live SSL, an identity of len bytes and a writable slot.
    unsafe {
        let Some(psk) = SslRef::from_ptr(ssl).ssl_context().ex_data(*index) else {
            return 0;
        };
        if identity.is_null()
            || len != psk.identity.len()
            || !memcmp::eq(std::slice::from_raw_parts(identity, len), &psk.identity)
        {
            *out = ptr::null_mut();
            return 1;
        }
        *out = new_psk_session(api, ssl, &psk.key);
        i32::from(!(*out).is_null())
    }
}

fn test_keys() -> CallRelayKeys {
    CallRelayKeys {
        identity: Zeroizing::new(b"\0fixture-identity".to_vec()),
        tls_psk: Zeroizing::new([0x25; 32]),
        hop_keys: Zeroizing::new([0; 64]),
        session_keys: Zeroizing::new([0; 48]),
    }
}

fn test_call() -> RelayCall {
    RelayCall {
        id: description::CALL,
        local: description::LOCAL,
        peer: description::CALLER,
    }
}

fn require_send<T: Send>(future: T) -> T {
    future
}

fn loopback_listener() -> Result<Option<(SocketAddr, CallRelayConnection, ListenerCall)>> {
    let library = Library::this();
    let api = match quic_api() {
        Ok(api) => api,
        Err(_) => return Ok(None),
    };
    let (method, set_psk, new_listener, listen, accept_connection) = unsafe {
        let Ok(method) = library.get::<Method>(b"OSSL_QUIC_server_method\0") else {
            // Older OpenSSL builds still support messaging and may only ship a QUIC client.
            return Ok(None);
        };
        (
            *method,
            *library.get::<SetServerPsk>(b"SSL_CTX_set_psk_find_session_callback\0")?,
            *library.get::<NewListener>(b"SSL_new_listener\0")?,
            *library.get::<unsafe extern "C" fn(SslPtr) -> c_int>(b"SSL_listen\0")?,
            *library.get::<ListenerCall>(b"SSL_accept_connection\0")?,
        )
    };
    let index = PSK_SLOT
        .get_or_init(SslContext::new_ex_index)
        .as_ref()
        .context("Could not initialize the test PSK index")?;
    let mut ctx = SslContextBuilder::new(unsafe { SslMethod::from_ptr(method()) })?;
    ctx.set_alpn_select_callback(|_, offered| {
        select_next_proto(b"\x02h3", offered).ok_or(AlpnError::ALERT_FATAL)
    });
    ctx.set_ciphersuites("TLS_AES_128_GCM_SHA256")?;
    let keys = test_keys();
    ctx.set_ex_data(
        *index,
        RelayPsk {
            identity: keys.identity.clone(),
            key: keys.tls_psk.clone(),
        },
    );
    unsafe { set_psk(ctx.as_ptr(), find_test_psk) };
    let ctx = ctx.build();
    let socket = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let endpoint = socket.local_addr()?;
    let socket = register_socket(socket)?;
    let listener = unsafe {
        let listener = new_listener(ctx.as_ptr(), 0);
        ensure!(
            !listener.is_null(),
            "Could not start the test QUIC listener"
        );
        let listener = Ssl::from_ptr(listener);
        let bio = (api.udp_bio)(socket.get_ref().as_raw_fd(), 0);
        ensure!(!bio.is_null(), "Could not open the test UDP socket");
        ffi::SSL_set_bio(listener.as_ptr(), bio, bio);
        ensure!((api.blocking_mode)(listener.as_ptr(), 0) == 1);
        ensure!(
            listen(listener.as_ptr()) == 1,
            "Could not listen on the test QUIC socket"
        );
        listener
    };
    Ok(Some((
        endpoint,
        CallRelayConnection {
            ssl: listener,
            bridge: None,
            socket,
            api,
            keys,
            call: test_call(),
        },
        accept_connection,
    )))
}

async fn accept_relay(
    relay: &mut CallRelayConnection,
    accept_connection: ListenerCall,
) -> Result<Ssl> {
    let accepted = relay
        .retry(STREAM_TIMEOUT, |ssl| {
            take_stream(
                unsafe { accept_connection(ssl, 1) },
                "Accept test QUIC connection",
            )
        })
        .await
        .context("Waiting for test QUIC connection")?;
    let listener = std::mem::replace(&mut relay.ssl, accepted);
    ensure!(
        unsafe { (relay.api.stream_mode)(relay.ssl.as_ptr(), SSL_DEFAULT_STREAM_MODE_NONE) } == 1
    );
    relay
        .retry(STREAM_TIMEOUT, |ssl| {
            let result = unsafe { ffi::SSL_accept(ssl) };
            retry_ssl(ssl, result, "Relay accepting TLS", ())
        })
        .await
        .context("Test relay TLS handshake")?;
    Ok(listener)
}

async fn read_exact(
    conn: &mut CallRelayConnection,
    stream: &mut CallRelayStream,
    mut target: &mut [u8],
) -> Result<()> {
    while !target.is_empty() {
        let count = conn.read(stream, target).await?;
        ensure!(count > 0, "Unexpected end of QUIC stream");
        target = &mut target[count..];
    }
    Ok(())
}

#[derive(Message)]
struct TestBindEnvelope {
    #[prost(message, optional, tag = "1")]
    request: Option<TestBindRequest>,
    #[prost(message, optional, tag = "2")]
    response: Option<TestBindResponse>,
}

#[derive(Message)]
struct TestBindRequest {
    #[prost(uint32, tag = "1")]
    service: u32,
    #[prost(uint64, tag = "4")]
    capabilities: u64,
    #[prost(message, repeated, tag = "11")]
    connections: Vec<TestBindConnection>,
    #[prost(message, repeated, tag = "15")]
    materials: Vec<TestParticipantMaterial>,
}

#[derive(Message)]
struct TestBindResponse {
    #[prost(uint32, tag = "2")]
    channel: u32,
    #[prost(uint32, tag = "6")]
    link: u32,
    #[prost(message, repeated, tag = "11")]
    connections: Vec<TestBindConnection>,
    #[prost(message, repeated, tag = "15")]
    materials: Vec<TestParticipantMaterial>,
}

#[derive(Message)]
struct TestParticipantMaterial {
    #[prost(uint64, optional, tag = "1")]
    owner: Option<u64>,
    #[prost(uint64, optional, tag = "2")]
    receiver: Option<u64>,
    #[prost(message, repeated, tag = "3")]
    entries: Vec<TestAvcMaterial>,
}

#[derive(Message)]
struct TestAvcMaterial {
    #[prost(bytes = "vec", tag = "1")]
    id: Vec<u8>,
    #[prost(int32, tag = "2")]
    kind: i32,
    #[prost(bytes = "vec", tag = "3")]
    ciphertext: Vec<u8>,
}

#[derive(Message)]
struct TestBindConnection {
    #[prost(int32, tag = "1")]
    kind: i32,
    #[prost(bytes = "vec", tag = "2")]
    id: Vec<u8>,
}

async fn read_fixture_frame(
    relay: &mut CallRelayConnection,
    request: &mut CallRelayStream,
    kind: u8,
) -> Result<Vec<u8>> {
    let mut prefix = [0; 2];
    read_exact(relay, request, &mut prefix).await?;
    assert_eq!(prefix[0], kind);
    let length = match prefix[1] >> 6 {
        0 => usize::from(prefix[1]),
        1 => {
            let mut tail = [0];
            read_exact(relay, request, &mut tail).await?;
            usize::from(u16::from_be_bytes([prefix[1] & 0x3f, tail[0]]))
        }
        _ => anyhow::bail!("Unexpected fixture frame length"),
    };
    let mut payload = vec![0; length];
    read_exact(relay, request, &mut payload).await?;
    Ok(payload)
}

#[tokio::test]
async fn exchanges_media_and_signaling_on_the_bound_http3_socket() -> Result<()> {
    let Some((endpoint, mut relay, accept_connection)) = loopback_listener()? else {
        return Ok(());
    };
    const CLIENT_SETTINGS: &[u8] = &[0, 4, 3, 6, 0x60, 0];
    const SERVER_SETTINGS: &[u8] = &[0, 4, 0];
    const SERVER_AVC: [u8; 4] = [0, 0x90, 0, 1];
    const SERVER_IDS: [u8; 4] = [0x10, 0x90, 0, 2];
    let incoming = |owner, receiver, ciphertext| TestParticipantMaterial {
        owner: Some(owner),
        receiver: Some(receiver),
        entries: vec![TestAvcMaterial {
            id: vec![7; 20],
            kind: 12,
            ciphertext,
        }],
    };
    let body = TestBindEnvelope {
        request: None,
        response: Some(TestBindResponse {
            channel: 0x4008,
            link: 1,
            connections: vec![
                TestBindConnection {
                    kind: 0,
                    id: SERVER_AVC.to_vec(),
                },
                TestBindConnection {
                    kind: 1,
                    id: SERVER_IDS.to_vec(),
                },
            ],
            materials: vec![
                incoming(description::LOCAL, 0, vec![0]),
                incoming(description::CALLER, 123, vec![0]),
                incoming(
                    description::CALLER,
                    description::LOCAL,
                    description::opaque_peer_offer()?,
                ),
            ],
        }),
    }
    .encode_to_vec();
    // Static QPACK :status 200 followed by one DATA frame.
    let mut response = vec![1, 3, 0, 0, 0xd9, 0];
    super::super::wire::write_varint(&mut response, body.len());
    response.extend_from_slice(&body);
    let local_description = description::local_offer()?;

    let (local_address, received_address) = tokio::sync::oneshot::channel();
    let server = async {
        let _listener = accept_relay(&mut relay, accept_connection).await?;
        let mut control = relay
            .accept_stream()
            .await
            .context("Relay waiting for client settings stream")?;
        assert_eq!(relay.stream_id(&control)? % 4, 2);
        let mut settings = [0; CLIENT_SETTINGS.len()];
        read_exact(&mut relay, &mut control, &mut settings).await?;
        assert_eq!(settings, CLIENT_SETTINGS);
        assert!(relay.ssl.session_reused());
        let mut server_encoder = relay
            .open_stream(RelayStreamDirection::Unidirectional)
            .await?;
        relay.write_all(&mut server_encoder, &[2]).await?;
        let mut response_control = relay
            .open_stream(RelayStreamDirection::Unidirectional)
            .await?;
        relay
            .write_all(&mut response_control, SERVER_SETTINGS)
            .await?;

        let mut request = relay.accept_stream().await?;
        assert_eq!(relay.stream_id(&request)? % 4, 0);
        let header_block = read_fixture_frame(&mut relay, &mut request, 1).await?;
        let fields = QpackDecoder::with_max_table_capacity(0)
            .decode_field_section(&header_block)
            .expect("valid fixture QPACK block");
        let field = |name: &[u8]| {
            fields
                .iter()
                .find(|f| f.name == name)
                .map(|f| f.value.as_slice())
        };
        assert_eq!(field(b":method"), Some(b"PUT".as_slice()));
        assert_eq!(field(b":scheme"), Some(b"https".as_slice()));
        assert_eq!(field(b":path"), Some(b"/QR/AllocBind".as_slice()));
        assert_eq!(field(b":authority"), Some(endpoint.to_string().as_bytes()));
        assert_eq!(field(b"version"), Some(b"1.1".as_slice()));
        assert_eq!(field(b"user-agent"), Some(b"GFT/2.0".as_slice()));
        let payload = read_fixture_frame(&mut relay, &mut request, 0).await?;
        assert_eq!(
            field(b"content-length"),
            Some(payload.len().to_string().as_bytes())
        );
        let bind = TestBindEnvelope::decode(payload.as_slice())?
            .request
            .context("No bind request")?;
        assert_eq!(bind.service, 4096);
        assert_eq!(bind.capabilities, 0x1234);
        let [material] = bind.materials.as_slice() else {
            anyhow::bail!("The client did not publish one local description");
        };
        let [entry] = material.entries.as_slice() else {
            anyhow::bail!("Unexpected description material");
        };
        assert_eq!(material.owner, Some(0));
        assert_eq!(material.receiver, Some(0));
        assert_eq!(entry.kind, 12);
        assert_eq!(entry.id, local_description.material_id);
        assert_eq!(entry.ciphertext, local_description.ciphertext);
        assert_eq!(bind.connections.len(), 2);
        assert_eq!(bind.connections[0].kind, 0);
        assert_eq!(bind.connections[1].kind, 1);
        let avc: [u8; 4] = bind.connections[0].id.as_slice().try_into()?;
        let ids: [u8; 4] = bind.connections[1].id.as_slice().try_into()?;
        assert_eq!(u32::from_be_bytes(avc) & 0xf080_0000, 0x0080_0000);
        assert_eq!(u32::from_be_bytes(ids) & 0xf080_0000, 0x1080_0000);
        let mut end = [0; 1];
        assert_eq!(relay.read(&mut request, &mut end).await?, 0);

        let peer = received_address.await?;
        let mut avc_client_secret = Zeroizing::new([0; 32]);
        let mut avc_server_secret = Zeroizing::new([0; 32]);
        let mut ids_client_secret = Zeroizing::new([0; 32]);
        let mut ids_server_secret = Zeroizing::new([0; 32]);
        relay.export_keying_material(avc_client_secret.as_mut(), "AVC client")?;
        relay.export_keying_material(avc_server_secret.as_mut(), "AVC server")?;
        relay.export_keying_material(ids_client_secret.as_mut(), "IDS client")?;
        relay.export_keying_material(ids_server_secret.as_mut(), "IDS server")?;
        let mut avc_pod = Pod::from_keys(avc, SERVER_AVC, &avc_server_secret, &avc_client_secret)?;
        let mut ids_pod = Pod::from_keys(ids, SERVER_IDS, &ids_server_secret, &ids_client_secret)?;
        let media = avc_pod.seal(b"relay media")?;
        let control = ids_pod.seal(b"relay signaling")?;
        let mut damaged = ids_pod.seal(b"tampered")?;
        damaged[15] ^= 1;
        for data in [&media, &damaged, &control, &control] {
            // The first channel packets can already be queued while the bind is completing.
            let sent = relay
                .socket
                .async_io(Interest::WRITABLE, |socket| socket.send_to(data, peer))
                .await?;
            assert_eq!(sent, data.len());
        }
        require_send(relay.write_all(&mut request, &response)).await?;
        relay.finish_stream(&mut request)?;

        let mut buffer = [0; 2048];
        let mut got_media = false;
        let mut got_signal = false;
        while !got_media || !got_signal {
            let (size, source) = relay
                .socket
                .async_io(Interest::READABLE, |socket| socket.recv_from(&mut buffer))
                .await?;
            assert_eq!(source, peer);
            let packet = &buffer[..size];
            // OpenSSL already queued the bind response. In this fixture the
            // remaining socket traffic can include the client's QUIC ACKs.
            match super::super::pod::destination_id(packet) {
                Some(SERVER_AVC) => {
                    let data = avc_pod
                        .open(packet.to_vec())?
                        .context("Invalid fixture media packet")?;
                    assert_eq!(data.as_slice(), b"client media");
                    got_media = true;
                }
                Some(SERVER_IDS) => {
                    let data = ids_pod
                        .open(packet.to_vec())?
                        .context("Invalid fixture signaling packet")?;
                    assert_eq!(data.as_slice(), b"client signaling");
                    got_signal = true;
                }
                _ => {}
            }
        }
        Ok::<_, anyhow::Error>(())
    };

    let client = async {
        let conn = require_send(CallRelayConnection::connect(
            endpoint,
            test_keys(),
            test_call(),
        ))
        .await?;
        local_address
            .send(conn.socket.get_ref().local_addr()?)
            .map_err(|_| anyhow::anyhow!("Fixture relay dropped the address channel"))?;
        let profile = CallRelayProfile {
            os_version: "testOS,0.0,fixture",
            hardware_version: "fixture",
            capabilities: 0x1234,
        };
        let mut binding =
            require_send(conn.bind_with_description(profile, &local_description)).await?;
        assert_eq!(binding.channel_id, 0x4008);
        assert_eq!(binding.link_id, 1);
        assert_eq!(binding.avc.server_connection_id, SERVER_AVC);
        assert_eq!(binding.ids.server_connection_id, SERVER_IDS);
        assert!(binding.peer_description(&Default::default())?.is_none());
        let peer = binding
            .peer_description(&description::remote_keys())?
            .context("The caller description was not received")?;
        assert_eq!(peer.audio.ssrc, 0x1020_3040);
        assert_eq!(
            peer.video.context("Missing camera offer")?.ssrc,
            0x5060_7080
        );
        let (kind, data) = require_send(binding.receive_datagram()).await?;
        assert_eq!(kind, RelayDatagramChannel::Signaling);
        assert_eq!(data.as_slice(), b"relay signaling");
        let (kind, data) = binding.receive_datagram().await?;
        assert_eq!(kind, RelayDatagramChannel::Media);
        assert_eq!(data.as_slice(), b"relay media");
        require_send(binding.send_datagram(RelayDatagramChannel::Media, b"client media")).await?;
        binding
            .send_datagram(RelayDatagramChannel::Signaling, b"client signaling")
            .await?;
        Ok::<_, anyhow::Error>(())
    };
    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::try_join!(server, client)
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn rejects_a_relay_with_a_different_key() -> Result<()> {
    let Some((endpoint, mut relay, accept_connection)) = loopback_listener()? else {
        return Ok(());
    };
    let mut wrong_keys = test_keys();
    wrong_keys.tls_psk[0] ^= 1;
    let (server, client) = tokio::join!(
        accept_relay(&mut relay, accept_connection),
        CallRelayConnection::connect(endpoint, wrong_keys, test_call())
    );
    let Err(server_failure) = server else {
        anyhow::bail!("The mock relay accepted the wrong key")
    };
    assert!(format!("{server_failure:#}").contains("binder does not verify"));
    assert!(
        client.is_err(),
        "The client accepted a relay without the right key"
    );
    Ok(())
}
