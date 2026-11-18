use super::super::{CallRelayProfile, pod::Pod};
use super::*;
use crate::apple::facetime::description::tests as description;
use crate::apple::facetime::relay::one_to_one::{
    tests::{forwarded_control, forwarded_media},
    turn_payload,
};
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
            device_key: None,
            local_prekey: None,
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

async fn fixture_request(
    relay: &mut CallRelayConnection,
    path: &[u8],
) -> Result<(CallRelayStream, Vec<u8>)> {
    let mut stream = relay.accept_stream().await?;
    let qpack = read_fixture_frame(relay, &mut stream, 1).await?;
    let fields = QpackDecoder::new()
        .decode_field_section(&qpack)
        .expect("valid fixture request");
    assert!(
        fields
            .iter()
            .any(|field| field.name == b":method" && field.value == b"PUT")
    );
    assert!(
        fields
            .iter()
            .any(|field| field.name == b":path" && field.value == path)
    );
    let body = read_fixture_frame(relay, &mut stream, 0).await?;
    let mut end = [0];
    assert_eq!(relay.read(&mut stream, &mut end).await?, 0);
    Ok((stream, body))
}

async fn fixture_response(
    relay: &mut CallRelayConnection,
    mut stream: CallRelayStream,
    body: &[u8],
) -> Result<()> {
    let mut response = vec![1, 3, 0, 0, 0xd9, 0];
    super::super::wire::write_varint(&mut response, body.len());
    response.extend_from_slice(body);
    relay.write_all(&mut stream, &response).await?;
    relay.finish_stream(&mut stream)
}

#[derive(Message)]
struct TestMaterialEnvelope {
    #[prost(message, optional, tag = "24")]
    request: Option<TestPutMaterial>,
}
#[derive(Message)]
struct TestPutMaterial {
    #[prost(message, repeated, tag = "1")]
    materials: Vec<TestParticipantMaterial>,
}
#[derive(Message)]
struct TestIndication {
    #[prost(message, optional, tag = "26")]
    material: Option<TestPutMaterial>,
}

fn indication(owner: u64, receiver: u64, entry: TestAvcMaterial) -> Vec<u8> {
    let payload = TestIndication {
        material: Some(TestPutMaterial {
            materials: vec![TestParticipantMaterial {
                owner: Some(owner),
                receiver: Some(receiver),
                entries: vec![entry],
            }],
        }),
    }
    .encode_to_vec();
    let mut framed = vec![0, 0];
    framed.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    framed.extend_from_slice(&payload);
    framed
}

async fn indication_chunk(
    relay: &mut CallRelayConnection,
    stream: &mut CallRelayStream,
    payload: &[u8],
) -> Result<()> {
    let mut frame = vec![0]; // HTTP/3 DATA.
    super::super::wire::write_varint(&mut frame, payload.len());
    frame.extend_from_slice(payload);
    relay.write_all(stream, &frame).await
}

async fn fixture_indications(relay: &mut CallRelayConnection) -> Result<CallRelayStream> {
    let mut indications = relay.accept_stream().await?;
    let headers = read_fixture_frame(relay, &mut indications, 1).await?;
    let headers = QpackDecoder::new()
        .decode_field_section(&headers)
        .expect("valid indication request");
    assert!(
        headers
            .iter()
            .any(|field| field.name == b":method" && field.value == b"GET")
    );
    assert!(
        headers
            .iter()
            .any(|field| field.name == b":path" && field.value == b"/QR/Indications")
    );
    assert_eq!(relay.read(&mut indications, &mut [0]).await?, 0);
    relay
        .write_all(&mut indications, &[1, 3, 0, 0, 0xd9])
        .await?;
    Ok(indications)
}

#[tokio::test]
async fn outgoing_relay_binds_before_the_invite_and_publishes_only_to_the_answering_device()
-> Result<()> {
    use super::super::{CallRelayAllocation, RelayPeerUpdate, RingingRelay};
    use crate::{
        CallMode, IncomingCall,
        apple::{
            CallEndpoint, CallMediaExchange, LocalCallPrekey, PeerPrekey,
            facetime::{
                PeerDeviceKey, RelaySigningKey,
                signed_material::tests::{fixture_signer, signed_key},
            },
        },
    };

    let Some((endpoint, mut relay, accept_connection)) = loopback_listener()? else {
        return Ok(());
    };
    let answered = CallEndpoint::new([7; 32], Some(description::CALLER));
    let other = CallEndpoint::new([8; 32], Some(description::CALLER + 1));
    let (signing, verification) = fixture_signer()?;
    let call = IncomingCall {
        id: description::CALL,
        caller: "mailto:caller@example.org".to_owned(),
        mode: Some(CallMode::Video),
        received_ms: 1,
        expires_ms: 45_001,
    };
    let local_prekey = LocalCallPrekey::generate()?;
    let local_public = *local_prekey.public();
    let relay_signer = RelaySigningKey::generate()?;
    let local_relay_prekey = relay_signer.sign_prekey(description::CALL, &local_public)?;
    let local_relay_id = local_relay_prekey.material_id;
    let our_directory_key = PeerDeviceKey::from_directory(&relay_signer.directory_data()?)?;
    let remote = CallMediaExchange::prepare(
        call.clone(),
        &[],
        &PeerPrekey::parse(1, local_prekey.public())?,
    )?;
    let local_exchange = CallMediaExchange::with_prekey(
        call,
        &[],
        &PeerPrekey::parse(1, remote.handshake.public_prekey())?,
        local_prekey,
    );
    let local_keys = local_exchange
        .handshake
        .build_key_offer(description::LOCAL)?;
    let offer =
        local_keys.seal_description(&description::signed_avc_fixture()?, CallMode::Video)?;
    let signed_keys = relay_signer.sign_keys(&local_keys, description::CALLER)?;
    let wrong_target = relay_signer.sign_keys(&local_keys, description::CALLER + 1)?;
    let remote_offer = remote.handshake.build_key_offer(description::CALLER)?;
    let payload: plist::Dictionary = plist::from_bytes(&remote_offer.payload)?;
    let mut media_key = Vec::new();
    plist::to_writer_binary(&mut media_key, &payload["rtmkm"])?;
    let mut session_key = Vec::new();
    plist::to_writer_binary(&mut session_key, &payload["rtskm"])?;
    let encode_prekey = |mode: u32| -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        let wire = plist::Dictionary::from_iter([
            (
                "public-prekey",
                plist::Value::Data(remote.handshake.public_prekey().to_vec()),
            ),
            ("wrap-mode", plist::Value::from(mode)),
            ("creation-date", plist::Value::Real(1_700_000_000.0)),
        ]);
        plist::to_writer_binary(&mut bytes, &wire)?;
        Ok(bytes)
    };
    let wrong_group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1)?;
    let wrong_signing =
        openssl::pkey::PKey::from_ec_key(openssl::ec::EcKey::generate(&wrong_group)?)?;
    let media_key_record = |signed| TestAvcMaterial {
        id: remote_offer.media.identifier.to_vec(),
        kind: 13,
        ciphertext: signed,
    };
    let description_record = |ciphertext| TestAvcMaterial {
        id: vec![7; 20],
        kind: 12,
        ciphertext,
    };
    let prekey_record = |ciphertext| TestAvcMaterial {
        id: vec![8; 20],
        kind: 11,
        ciphertext,
    };
    let (started, has_partial_frame) = tokio::sync::oneshot::channel();
    let (paused, continue_indications) = tokio::sync::oneshot::channel();
    let server = async {
        let _listener = accept_relay(&mut relay, accept_connection).await?;
        let mut client_settings = relay.accept_stream().await?;
        let mut bytes = [0; 6];
        read_exact(&mut relay, &mut client_settings, &mut bytes).await?;
        assert_eq!(bytes, [0, 4, 3, 6, 0x60, 0]);
        let mut server_settings = relay
            .open_stream(RelayStreamDirection::Unidirectional)
            .await?;
        relay.write_all(&mut server_settings, &[0, 4, 0]).await?;
        let (bind, body) = fixture_request(&mut relay, b"/QR/AllocBind").await?;
        let request = TestBindEnvelope::decode(body.as_slice())?
            .request
            .context("Missing AllocBind request")?;
        let [publication] = request.materials.as_slice() else {
            anyhow::bail!("Missing local relay prekey publication");
        };
        assert_eq!(
            (publication.owner, publication.receiver),
            (Some(0), Some(0))
        );
        let [entry] = publication.entries.as_slice() else {
            anyhow::bail!("Missing local relay prekey");
        };
        assert_eq!(entry.id, local_relay_id);
        assert_eq!(entry.kind, 11);
        let signed = our_directory_key.verify_material(description::CALL, &entry.ciphertext)?;
        assert!(PeerPrekey::from_relay(&signed)?.same_as(&PeerPrekey::parse(1, &local_public)?));
        assert_eq!(request.connections.len(), 2);
        let response = TestBindEnvelope {
            request: None,
            response: Some(TestBindResponse {
                channel: 0x4008,
                link: 1,
                connections: vec![
                    TestBindConnection {
                        kind: 0,
                        id: vec![0, 0x90, 0, 1],
                    },
                    TestBindConnection {
                        kind: 1,
                        id: vec![0x10, 0x90, 0, 2],
                    },
                ],
                materials: Vec::new(),
            }),
        };
        fixture_response(&mut relay, bind, &response.encode_to_vec()).await?;

        let mut indications = fixture_indications(&mut relay).await?;

        let (stats, body) = fixture_request(&mut relay, b"/QR/Stats").await?;
        assert_eq!(body[..2], [0x92, 1]); // QuickRelay envelope field 18.
        fixture_response(&mut relay, stats, &[0x9a, 1, 0]).await?;

        let wrong_device = indication(
            description::CALLER + 1,
            description::LOCAL,
            description_record(vec![0]),
        );
        indication_chunk(&mut relay, &mut indications, &wrong_device).await?;
        let wrong_signer = indication(
            description::CALLER,
            description::LOCAL,
            media_key_record(signed_key(&wrong_signing, description::CALL, &media_key)?),
        );
        indication_chunk(&mut relay, &mut indications, &wrong_signer).await?;
        let wrong_receiver = indication(
            description::CALLER,
            description::LOCAL + 1,
            media_key_record(signed_key(&signing, description::CALL, &media_key)?),
        );
        indication_chunk(&mut relay, &mut indications, &wrong_receiver).await?;
        let mut wrong_identifier =
            media_key_record(signed_key(&signing, description::CALL, &media_key)?);
        wrong_identifier.id[0] ^= 1;
        let wrong_identifier =
            indication(description::CALLER, description::LOCAL, wrong_identifier);
        indication_chunk(&mut relay, &mut indications, &wrong_identifier).await?;
        let prekey = encode_prekey(1)?;
        let wrong_call = indication(
            description::CALLER,
            0,
            prekey_record(signed_key(&signing, uuid::Uuid::new_v4(), &prekey)?),
        );
        indication_chunk(&mut relay, &mut indications, &wrong_call).await?;
        let wrong_signer = indication(
            description::CALLER,
            0,
            prekey_record(signed_key(&wrong_signing, description::CALL, &prekey)?),
        );
        indication_chunk(&mut relay, &mut indications, &wrong_signer).await?;
        let wrong_owner = indication(
            description::CALLER + 1,
            0,
            prekey_record(signed_key(&signing, description::CALL, &prekey)?),
        );
        indication_chunk(&mut relay, &mut indications, &wrong_owner).await?;
        let wrong_mode = indication(
            description::CALLER,
            0,
            prekey_record(signed_key(&signing, description::CALL, &encode_prekey(8)?)?),
        );
        indication_chunk(&mut relay, &mut indications, &wrong_mode).await?;
        let valid_prekey = indication(
            description::CALLER,
            0,
            prekey_record(signed_key(&signing, description::CALL, &prekey)?),
        );
        let media = indication(
            description::CALLER,
            description::LOCAL,
            description_record(description::opaque_peer_offer()?),
        );
        indication_chunk(&mut relay, &mut indications, &valid_prekey[..3]).await?;
        started
            .send(())
            .map_err(|_| anyhow::anyhow!("Waiting call ended early"))?;
        continue_indications.await?;
        indication_chunk(&mut relay, &mut indications, &valid_prekey[3..]).await?;

        let (publish, body) = fixture_request(&mut relay, b"/QR/Material").await?;
        let submitted = TestMaterialEnvelope::decode(body.as_slice())?
            .request
            .context("Missing PutMaterial")?;
        let [material, media_key_material, session_key_material] = submitted.materials.as_slice()
        else {
            anyhow::bail!("Expected one encrypted description and two wrapped keys");
        };
        let [entry] = material.entries.as_slice() else {
            anyhow::bail!("Expected one encrypted AVC description");
        };
        assert_eq!(material.owner, Some(0));
        assert_eq!(material.receiver, Some(description::CALLER));
        assert_eq!(entry.id, offer.material_id);
        assert_eq!(entry.kind, 12);
        assert_eq!(entry.ciphertext, offer.ciphertext);
        for (record, kind, identifier) in [
            (media_key_material, 13, local_keys.media.identifier),
            (session_key_material, 14, local_keys.session.identifier),
        ] {
            assert_eq!(
                (record.owner, record.receiver),
                (Some(0), Some(description::CALLER))
            );
            let [entry] = record.entries.as_slice() else {
                anyhow::bail!("Missing wrapped key in relay request");
            };
            assert_eq!(entry.kind, kind);
            assert_eq!(entry.id, identifier);
            let body = our_directory_key.verify_material(description::CALL, &entry.ciphertext)?;
            let key = crate::apple::PeerKeyOffer::from_relay(
                &body,
                kind == 13,
                &entry.id,
                description::LOCAL,
            )
            .context("Could not read the signed wrapped key")?;
            remote.receive(key)?;
        }
        {
            let received = remote.handshake.watch_peer_keys();
            let keys = received.borrow();
            assert_eq!(
                keys.media
                    .as_ref()
                    .context("Missing local sender's media key")?
                    .identifier,
                local_keys.media.identifier
            );
            let session = keys
                .session
                .as_ref()
                .context("Missing local sender's session key")?;
            let opened = crate::apple::facetime::description::open_description(
                description::CALL,
                description::LOCAL,
                session,
                &offer.ciphertext,
            )?;
            assert_eq!(opened.audio.ssrc, 0x1020_3040);
            assert_eq!(
                opened
                    .video
                    .context("Missing local sender's video stream")?
                    .ssrc,
                0x5060_7080
            );
        }
        fixture_response(&mut relay, publish, &[0xca, 1, 0]).await?;

        indication_chunk(&mut relay, &mut indications, &media).await?;
        let valid_key = indication(
            description::CALLER,
            description::LOCAL,
            media_key_record(signed_key(&signing, description::CALL, &media_key)?),
        );
        indication_chunk(&mut relay, &mut indications, &valid_key).await?;
        let valid_session = indication(
            description::CALLER,
            description::LOCAL,
            TestAvcMaterial {
                id: remote_offer.session.identifier.to_vec(),
                kind: 14,
                ciphertext: signed_key(&signing, description::CALL, &session_key)?,
            },
        );
        indication_chunk(&mut relay, &mut indications, &valid_session).await?;
        relay.finish_stream(&mut indications)?;

        let (release, _) = fixture_request(&mut relay, b"/QR/UnAllocBind").await?;
        fixture_response(&mut relay, release, &[0xba, 1, 0]).await
    };
    let client = async {
        let mut wire = CallRelayConnection::connect(
            endpoint,
            test_keys(),
            RelayCall {
                peer: 0,
                ..test_call()
            },
        )
        .await?;
        wire.local_prekey = Some(local_relay_prekey);
        let profile = CallRelayProfile {
            os_version: "testOS,0.0,fixture",
            hardware_version: "fixture",
            capabilities: 0x1234,
        };
        let mut waiting = RingingRelay::bind(wire, profile, vec![answered, other]).await?;
        waiting.keepalive().await?;
        let allocation = CallRelayAllocation {
            call_id: description::CALL,
            endpoint,
            local_participant: description::LOCAL,
            caller_participant: description::CALLER,
            relay_id: Vec::new(),
            token: Zeroizing::default(),
            shared_key: Zeroizing::default(),
            device_key: Some(verification),
            local_prekey: None,
        };
        assert!(waiting.select_peer(other, &allocation).is_err());
        waiting.select_peer(answered, &allocation)?;
        has_partial_frame.await?;
        assert!(
            tokio::time::timeout(Duration::from_millis(40), waiting.wait_for_peer_prekey())
                .await
                .is_err()
        );
        paused
            .send(())
            .map_err(|_| anyhow::anyhow!("Relay stopped sending indications"))?;
        let prekey = waiting
            .wait_for_peer_prekey()
            .await?
            .context("Missing relay-signed prekey")?;
        assert!(prekey.same_as(&PeerPrekey::parse(1, remote.handshake.public_prekey())?));
        let mut connection = waiting.into_bound()?;
        assert!(
            connection
                .publish_media(&offer, Some(&wrong_target))
                .await
                .is_err()
        );
        connection.publish_media(&offer, Some(&signed_keys)).await?;
        assert_eq!(connection.channel_id, 0x4008);

        assert!(matches!(
            connection.next_peer_update().await?,
            Some(RelayPeerUpdate::Description)
        ));
        let media = connection
            .peer_description(&description::remote_keys())?
            .context("Missing authenticated late media offer")?;
        assert_eq!(media.audio.ssrc, 0x1020_3040);
        assert_eq!(
            media.video.context("Missing late video stream")?.ssrc,
            0x5060_7080
        );
        let Some(RelayPeerUpdate::Keys(offer)) = connection.next_peer_update().await? else {
            anyhow::bail!("Missing relay-signed media key");
        };
        local_exchange.receive(*offer)?;
        let Some(RelayPeerUpdate::Keys(offer)) = connection.next_peer_update().await? else {
            anyhow::bail!("Missing relay-signed session key");
        };
        local_exchange.receive(*offer)?;
        {
            let received = local_exchange.handshake.watch_peer_keys();
            let received = received.borrow();
            assert_eq!(
                received
                    .media
                    .as_ref()
                    .context("Media key was not unwrapped")?
                    .identifier,
                remote_offer.media.identifier,
            );
            assert_eq!(
                received
                    .session
                    .as_ref()
                    .context("Session key was not unwrapped")?
                    .identifier,
                remote_offer.session.identifier,
            );
        }
        connection.unbind().await
    };
    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::try_join!(server, client)
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn exchanges_media_and_signaling_on_the_bound_http3_socket() -> Result<()> {
    use crate::{
        CallMode, IncomingCall,
        apple::{
            CallMediaDescription, CallMediaExchange, CallRtpProtection, LocalCallPrekey,
            PeerPrekey, RelayMediaEvent, facetime::RelaySigningKey,
        },
    };

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
    let (packets_received, pods_verified) = tokio::sync::oneshot::channel();
    let (routed_received, ready_to_unbind) = tokio::sync::oneshot::channel();
    let (first_packet, first_received) = tokio::sync::oneshot::channel();
    let (key_installed, key_received) = tokio::sync::oneshot::channel();
    let call = IncomingCall {
        id: description::CALL,
        caller: "mailto:peer@example.org".into(),
        mode: Some(CallMode::Video),
        received_ms: 1,
        expires_ms: 45_001,
    };
    let local = LocalCallPrekey::generate()?;
    let other =
        CallMediaExchange::prepare(call.clone(), &[], &PeerPrekey::parse(1, local.public())?)?;
    let local = CallMediaExchange::with_prekey(
        call,
        &[],
        &PeerPrekey::parse(1, other.handshake.public_prekey())?,
        local,
    );
    let local_offer = local.handshake.build_key_offer(description::LOCAL)?;
    let initial = other.handshake.build_key_offer(description::CALLER)?;
    let initial_fields: plist::Dictionary = plist::from_bytes(&initial.payload)?;
    local.receive(
        crate::apple::PeerKeyOffer::parse(None, initial_fields["rtmkm"].as_dictionary())
            .context("Missing fixture initial media key")?,
    )?;
    let mut rotated = other.handshake.build_key_offer(description::CALLER)?;
    rotated.media.identifier[1] = 0x11;
    let mut wrapped: plist::Dictionary = plist::from_bytes(&rotated.payload)?;
    let media = wrapped
        .get_mut("rtmkm")
        .and_then(plist::Value::as_dictionary_mut)
        .context("Missing fixture media key")?;
    media.insert("mkgc".into(), 2.into());
    media.insert(
        "mki".into(),
        plist::Value::Data(rotated.media.identifier.to_vec()),
    );
    rotated.payload.clear();
    plist::to_writer_binary(&mut rotated.payload, &wrapped)?;
    let signer = RelaySigningKey::generate()?;
    let verification =
        crate::apple::facetime::PeerDeviceKey::from_directory(&signer.directory_data()?)?;
    let directory_signed = signer.sign_keys(&rotated, description::LOCAL)?;
    let advertise = |receiver| {
        indication(
            description::CALLER,
            receiver,
            TestAvcMaterial {
                id: directory_signed.media.id.to_vec(),
                kind: 13,
                ciphertext: directory_signed.media.contents.clone(),
            },
        )
    };
    let stream =
        CallMediaDescription::parse(&description::signed_avc_fixture()?, Some(CallMode::Video))?;
    let mut send = CallRtpProtection::new(
        description::CALL,
        description::LOCAL,
        &rotated.media,
        &stream,
        &stream,
    )?;
    let mut receive = CallRtpProtection::new(
        description::CALL,
        description::CALLER,
        &local_offer.media,
        &stream,
        &stream,
    )?;
    let mut clear = hex::decode("8068138901020300")?;
    clear.extend_from_slice(&stream.audio.ssrc.to_be_bytes());
    clear.extend_from_slice(b"Encoded AAC frame");
    let mut first_clear = clear.clone();
    first_clear[3] = 0x88;
    let mut first_send = CallRtpProtection::new(
        description::CALL,
        description::LOCAL,
        &initial.media,
        &stream,
        &stream,
    )?;
    let srtp = first_send.protect(&first_clear)?.to_vec();
    let protected_rotated = send.protect(&clear)?;
    let video = stream
        .video
        .as_ref()
        .context("Missing fixture video stream")?;
    let mut clear_video = hex::decode("8064138901020300")?;
    clear_video[1] = video.payload_types[0];
    clear_video.extend_from_slice(&video.ssrc.to_be_bytes());
    clear_video.extend_from_slice(b"Encoded HEVC packet");
    let protected_video = send.protect(&clear_video)?;
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
        packets_received
            .send(())
            .map_err(|_| anyhow::anyhow!("Missing relay media task"))?;
        loop {
            let (size, source) = relay
                .socket
                .async_io(Interest::READABLE, |socket| socket.recv_from(&mut buffer))
                .await?;
            assert_eq!(source, peer);
            if super::super::pod::destination_id(&buffer[..size]) == Some(SERVER_IDS) {
                let packet = ids_pod
                    .open(buffer[..size].to_vec())?
                    .context("Invalid media path control")?;
                assert_eq!(packet[4..6], [0, 6], "expected link interface announcement");
                break;
            }
        }
        let peer_interface = forwarded_control(test_call(), &relay.keys, false)?;
        let announcement_ack = forwarded_control(test_call(), &relay.keys, true)?;
        for frame in [peer_interface, announcement_ack] {
            let packet = ids_pod.seal(&frame)?;
            relay
                .socket
                .async_io(Interest::WRITABLE, |socket| socket.send_to(&packet, peer))
                .await?;
        }
        loop {
            let (size, source) = relay
                .socket
                .async_io(Interest::READABLE, |socket| socket.recv_from(&mut buffer))
                .await?;
            assert_eq!(source, peer);
            let packet = &buffer[..size];
            if super::super::pod::destination_id(packet) == Some(SERVER_IDS)
                && let Some(control) = ids_pod.open(packet.to_vec())?
                && control.get(4..6) == Some(&[0x80, 6])
            {
                break;
            }
        }
        let caller_media = forwarded_media(test_call(), &relay.keys, &srtp)?;
        let mut wrong_sender = caller_media.clone();
        wrong_sender[6] ^= 1;
        // Use another ciphertext for a wrong participant so passing it as media would fail the test.
        *wrong_sender.last_mut().unwrap() ^= 1;
        for frame in [wrong_sender, caller_media] {
            relay
                .socket
                .async_io(Interest::WRITABLE, |socket| socket.send_to(&frame, peer))
                .await?;
        }
        first_received.await?;
        let mut indications = fixture_indications(&mut relay).await?;
        indication_chunk(
            &mut relay,
            &mut indications,
            &advertise(description::LOCAL + 1),
        )
        .await?;
        indication_chunk(&mut relay, &mut indications, &advertise(description::LOCAL)).await?;
        relay.finish_stream(&mut indications)?;
        key_received.await?;
        for protected in [&protected_rotated, &protected_video] {
            let refreshed = forwarded_media(test_call(), &relay.keys, protected)?;
            relay
                .socket
                .async_io(Interest::WRITABLE, |socket| {
                    socket.send_to(&refreshed, peer)
                })
                .await?;
        }
        let mut got_routed_media = false;
        while !got_routed_media {
            let (size, source) = relay
                .socket
                .async_io(Interest::READABLE, |socket| socket.recv_from(&mut buffer))
                .await?;
            assert_eq!(source, peer);
            let packet = &buffer[..size];
            if let Some(frame) = turn_payload(packet, 0x4008) {
                assert_eq!(frame[..4], [0x20, 0x40, 0x12, 0x34]);
                assert_eq!(frame[4..], srtp);
                got_routed_media = true;
            }
        }
        routed_received
            .send(())
            .map_err(|_| anyhow::anyhow!("Missing relay release task"))?;
        let mut unbind = relay.accept_stream().await?;
        let headers = read_fixture_frame(&mut relay, &mut unbind, 1).await?;
        let headers = QpackDecoder::new()
            .decode_field_section(&headers)
            .expect("valid release headers");
        assert!(
            headers
                .iter()
                .any(|field| field.name == b":path" && field.value == b"/QR/UnAllocBind")
        );
        assert_eq!(
            read_fixture_frame(&mut relay, &mut unbind, 0).await?,
            [0xb2, 1, 2, 8, 1]
        );
        assert_eq!(relay.read(&mut unbind, &mut end).await?, 0);
        // Static :status 200 with a protobuf field 23 carrying an empty release acknowledgment.
        relay
            .write_all(&mut unbind, &[1, 3, 0, 0, 0xd9, 0, 3, 0xba, 1, 0])
            .await?;
        relay.finish_stream(&mut unbind)?;
        Ok::<_, anyhow::Error>(())
    };

    let client = async {
        let mut conn = require_send(CallRelayConnection::connect(
            endpoint,
            test_keys(),
            test_call(),
        ))
        .await?;
        conn.device_key = Some(verification);
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
        pods_verified.await?;
        require_send(binding.negotiate_media_path()).await?;
        let RelayMediaEvent::Rtp(packet) = require_send(binding.receive_media_event()).await?
        else {
            anyhow::bail!("Expected the initial routed media");
        };
        assert_eq!(packet.as_slice(), srtp);
        let installed = local.handshake.watch_peer_keys();
        let first_key = installed
            .borrow()
            .media
            .clone()
            .context("Missing initial media key")?;
        assert_eq!(first_key.generation, 1);
        assert_eq!(
            receive
                .open(first_key, &packet)?
                .context("Could not open pre-rotation media")?
                .as_slice(),
            first_clear
        );
        first_packet
            .send(())
            .map_err(|_| anyhow::anyhow!("The fixture relay closed"))?;
        binding.subscribe_to_descriptions().await?;
        let RelayMediaEvent::Keys(offer) = require_send(binding.receive_media_event()).await?
        else {
            anyhow::bail!("Expected a signed mid-call media key");
        };
        local.receive(*offer)?;
        let keys = local.handshake.watch_peer_keys();
        let key = keys
            .borrow()
            .media
            .clone()
            .context("Missing installed key")?;
        assert_eq!(key.generation, 2);
        key_installed
            .send(())
            .map_err(|_| anyhow::anyhow!("The fixture relay closed"))?;
        for expected in [&clear, &clear_video] {
            let RelayMediaEvent::Rtp(packet) = require_send(binding.receive_media_event()).await?
            else {
                anyhow::bail!("Expected media protected by the new key");
            };
            let opened = receive
                .open(key.clone(), &packet)?
                .context("Could not authenticate the rekeyed media")?;
            assert_eq!(opened.as_slice(), expected);
        }
        require_send(binding.send_routed_rtp(&srtp)).await?;
        ready_to_unbind.await?;
        require_send(binding.unbind()).await?;
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
