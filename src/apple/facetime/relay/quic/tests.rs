use super::*;
use openssl::{
    memcmp,
    ssl::{AlpnError, select_next_proto},
};

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
            socket,
            api,
            keys,
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

#[tokio::test]
async fn negotiates_external_psk_and_exchanges_http3_streams() -> Result<()> {
    let Some((endpoint, mut relay, accept_connection)) = loopback_listener()? else {
        return Ok(());
    };
    // HTTP/3 unidirectional control stream followed by a SETTINGS frame with an empty body.
    const SETTINGS: &[u8] = &[0, 4, 0];
    // HEADERS with static QPACK :method GET, :scheme https, :path / and literal :authority.
    const REQUEST: &[u8] = &[
        1, 16, 0, 0, 0xd1, 0xd7, 0xc1, 0x50, 9, b'l', b'o', b'c', b'a', b'l', b'h', b'o', b's',
        b't',
    ];
    // HEADERS with static QPACK :status 200, followed by a DATA frame.
    const RESPONSE: &[u8] = &[1, 3, 0, 0, 0xd9, 0, 2, b'o', b'k'];

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

    let server = async {
        let _listener = accept_relay(&mut relay, accept_connection).await?;
        let mut control = relay
            .accept_stream()
            .await
            .context("Relay waiting for client settings stream")?;
        assert_eq!(relay.stream_id(&control)? % 4, 2);
        let mut settings = [0; SETTINGS.len()];
        read_exact(&mut relay, &mut control, &mut settings).await?;
        assert_eq!(settings, SETTINGS);
        assert!(relay.ssl.session_reused());
        let mut response_control = relay
            .open_stream(RelayStreamDirection::Unidirectional)
            .await?;
        relay.write_all(&mut response_control, SETTINGS).await?;

        let mut request = relay.accept_stream().await?;
        assert_eq!(relay.stream_id(&request)? % 4, 0);
        let mut data = [0; REQUEST.len()];
        read_exact(&mut relay, &mut request, &mut data).await?;
        assert_eq!(data, REQUEST);
        let mut end = [0; 1];
        assert_eq!(relay.read(&mut request, &mut end).await?, 0);
        relay.write_all(&mut request, RESPONSE).await?;
        relay.finish_stream(&mut request)?;
        let mut material = Zeroizing::new([0; 32]);
        relay.export_keying_material(material.as_mut(), "AVC client")?;
        Ok::<_, anyhow::Error>(material)
    };

    let client = async {
        let mut conn = require_send(CallRelayConnection::connect(endpoint, test_keys())).await?;
        let mut control = conn
            .open_stream(RelayStreamDirection::Unidirectional)
            .await?;
        conn.write_all(&mut control, SETTINGS).await?;
        let mut response_control = conn
            .accept_stream()
            .await
            .context("Client waiting for relay settings stream")?;
        assert_eq!(conn.stream_id(&response_control)? % 4, 3);
        let mut settings = [0; SETTINGS.len()];
        read_exact(&mut conn, &mut response_control, &mut settings).await?;
        assert_eq!(settings, SETTINGS);
        let mut request = conn
            .open_stream(RelayStreamDirection::Bidirectional)
            .await?;
        require_send(conn.write_all(&mut request, REQUEST)).await?;
        conn.finish_stream(&mut request)?;
        let mut response = [0; RESPONSE.len()];
        read_exact(&mut conn, &mut request, &mut response).await?;
        assert_eq!(response, RESPONSE);
        let mut material = Zeroizing::new([0; 32]);
        conn.export_keying_material(material.as_mut(), "AVC client")?;
        Ok::<_, anyhow::Error>(material)
    };
    let (server_export, client_export) = tokio::try_join!(server, client)?;
    assert!(memcmp::eq(server_export.as_ref(), client_export.as_ref()));
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
        CallRelayConnection::connect(endpoint, wrong_keys)
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
