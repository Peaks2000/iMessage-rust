use std::{
    ffi::{c_int, c_uint, c_void},
    net::{IpAddr, SocketAddr, UdpSocket},
    os::fd::AsRawFd,
    ptr,
    sync::{Arc, OnceLock},
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use foreign_types::{ForeignType, ForeignTypeRef};
use libloading::os::unix::Library;
use openssl::{
    error::ErrorStack,
    ex_data::Index,
    ssl::{
        Ssl, SslContext, SslContextBuilder, SslMethod, SslMode, SslOptions, SslRef,
        SslSessionCacheMode, SslVerifyMode,
    },
};
use openssl_sys as ffi;
use tokio::{
    io::unix::AsyncFd,
    time::{Instant, sleep, timeout_at},
};
use zeroize::Zeroizing;

use super::{CallRelayAllocation, CallRelayKeys};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(8);
const STREAM_TIMEOUT: Duration = Duration::from_secs(8);
const ALPN: &[u8] = b"h3";
const SSL_DEFAULT_STREAM_MODE_NONE: c_uint = 0;
const SSL_STREAM_FLAG_UNI: u64 = 1;
const SSL_STREAM_FLAG_NO_BLOCK: u64 = 2;
const SSL_ACCEPT_STREAM_NO_BLOCK: u64 = 1;
const BIO_CTRL_DGRAM_SET_CONNECTED: c_int = 32;

type SslPtr = *mut ffi::SSL;
type SessionPtr = *mut ffi::SSL_SESSION;
enum BioAddress {}
type PskCallback = unsafe extern "C" fn(
    SslPtr,
    *const ffi::EVP_MD,
    *mut *const u8,
    *mut usize,
    *mut SessionPtr,
) -> c_int;

struct QuicApi {
    client_method: unsafe extern "C" fn() -> *const ffi::SSL_METHOD,
    set_peer: unsafe extern "C" fn(SslPtr, *const BioAddress) -> c_int,
    blocking_mode: unsafe extern "C" fn(SslPtr, c_int) -> c_int,
    stream_mode: unsafe extern "C" fn(SslPtr, c_uint) -> c_int,
    event_timeout: unsafe extern "C" fn(SslPtr, *mut libc::timeval, *mut c_int) -> c_int,
    read_desired: unsafe extern "C" fn(SslPtr) -> c_int,
    write_desired: unsafe extern "C" fn(SslPtr) -> c_int,
    new_stream: unsafe extern "C" fn(SslPtr, u64) -> SslPtr,
    accept_stream: unsafe extern "C" fn(SslPtr, u64) -> SslPtr,
    stream_id: unsafe extern "C" fn(SslPtr) -> u64,
    conclude: unsafe extern "C" fn(SslPtr, u64) -> c_int,
    handle_events: unsafe extern "C" fn(SslPtr) -> c_int,
    udp_bio: unsafe extern "C" fn(c_int, c_int) -> *mut ffi::BIO,
    address_new: unsafe extern "C" fn() -> *mut BioAddress,
    address_free: unsafe extern "C" fn(*mut BioAddress),
    address_make: unsafe extern "C" fn(*mut BioAddress, c_int, *const c_void, usize, u16) -> c_int,
    set_psk_callback: unsafe extern "C" fn(*mut ffi::SSL_CTX, PskCallback),
    new_session: unsafe extern "C" fn() -> SessionPtr,
    cipher_find: unsafe extern "C" fn(SslPtr, *const u8) -> *const ffi::SSL_CIPHER,
    session_key: unsafe extern "C" fn(SessionPtr, *const u8, usize) -> c_int,
    session_cipher: unsafe extern "C" fn(SessionPtr, *const ffi::SSL_CIPHER) -> c_int,
    session_version: unsafe extern "C" fn(SessionPtr, c_int) -> c_int,
}

static QUIC_API: OnceLock<Result<QuicApi, libloading::Error>> = OnceLock::new();
static PSK_SLOT: OnceLock<Result<Index<SslContext, RelayPsk>, ErrorStack>> = OnceLock::new();

fn quic_api() -> Result<&'static QuicApi> {
    QUIC_API
        .get_or_init(|| {
            // Use the same libssl and libcrypto already linked by the openssl crate. Resolving QUIC
            // symbols at runtime keeps messaging available on older Linux libraries.
            let library = Library::this();
            // SAFETY: The names and C signatures below match the OpenSSL public headers.
            unsafe {
                Ok(QuicApi {
                    client_method: *library.get(b"OSSL_QUIC_client_method\0")?,
                    set_peer: *library.get(b"SSL_set1_initial_peer_addr\0")?,
                    blocking_mode: *library.get(b"SSL_set_blocking_mode\0")?,
                    stream_mode: *library.get(b"SSL_set_default_stream_mode\0")?,
                    event_timeout: *library.get(b"SSL_get_event_timeout\0")?,
                    read_desired: *library.get(b"SSL_net_read_desired\0")?,
                    write_desired: *library.get(b"SSL_net_write_desired\0")?,
                    new_stream: *library.get(b"SSL_new_stream\0")?,
                    accept_stream: *library.get(b"SSL_accept_stream\0")?,
                    stream_id: *library.get(b"SSL_get_stream_id\0")?,
                    conclude: *library.get(b"SSL_stream_conclude\0")?,
                    handle_events: *library.get(b"SSL_handle_events\0")?,
                    udp_bio: *library.get(b"BIO_new_dgram\0")?,
                    address_new: *library.get(b"BIO_ADDR_new\0")?,
                    address_free: *library.get(b"BIO_ADDR_free\0")?,
                    address_make: *library.get(b"BIO_ADDR_rawmake\0")?,
                    set_psk_callback: *library.get(b"SSL_CTX_set_psk_use_session_callback\0")?,
                    new_session: *library.get(b"SSL_SESSION_new\0")?,
                    cipher_find: *library.get(b"SSL_CIPHER_find\0")?,
                    session_key: *library.get(b"SSL_SESSION_set1_master_key\0")?,
                    session_cipher: *library.get(b"SSL_SESSION_set_cipher\0")?,
                    session_version: *library.get(b"SSL_SESSION_set_protocol_version\0")?,
                })
            }
        })
        .as_ref()
        .map_err(|error| {
            anyhow::anyhow!("FaceTime requires an OpenSSL installation with QUIC support: {error}")
        })
}

struct RelayPsk {
    identity: Zeroizing<Vec<u8>>,
    key: Zeroizing<[u8; 32]>,
}

unsafe extern "C" fn use_relay_psk(
    ssl: SslPtr,
    _digest: *const ffi::EVP_MD,
    identity: *mut *const u8,
    identity_len: *mut usize,
    out: *mut SessionPtr,
) -> c_int {
    let Some(Ok(index)) = PSK_SLOT.get() else {
        return 0;
    };
    let Some(Ok(api)) = QUIC_API.get() else {
        return 0;
    };
    // SAFETY: OpenSSL calls this on a live SSL and its context owns the extra data through the
    // handshake. The returned identity points into that extra data and the session is transferred.
    unsafe {
        let Some(psk) = SslRef::from_ptr(ssl).ssl_context().ex_data(*index) else {
            return 0;
        };
        let session = new_psk_session(api, ssl, &psk.key);
        if session.is_null() {
            return 0;
        }
        *identity = psk.identity.as_ptr();
        *identity_len = psk.identity.len();
        *out = session;
        1
    }
}

unsafe fn new_psk_session(api: &QuicApi, ssl: SslPtr, key: &[u8; 32]) -> SessionPtr {
    // SAFETY: The caller provides a live SSL. The new, configured session is transferred on
    // success or freed locally on failure.
    unsafe {
        let cipher = (api.cipher_find)(ssl, [0x13, 0x01].as_ptr());
        if cipher.is_null() {
            return ptr::null_mut();
        }
        let session = (api.new_session)();
        if session.is_null() {
            return ptr::null_mut();
        }
        if (api.session_key)(session, key.as_ptr(), key.len()) != 1
            || (api.session_cipher)(session, cipher) != 1
            || (api.session_version)(session, ffi::TLS1_3_VERSION) != 1
        {
            ffi::SSL_SESSION_free(session);
            return ptr::null_mut();
        }
        session
    }
}

fn register_socket(socket: UdpSocket) -> Result<Arc<AsyncFd<UdpSocket>>> {
    socket.set_nonblocking(true)?;
    // SAFETY: UdpSocket owns a stable descriptor until deregistration. The SSL BIO borrows it
    // with BIO_NOCLOSE and cannot close the socket.
    Ok(Arc::new(unsafe { AsyncFd::register(socket)? }))
}

#[derive(Clone, Copy)]
pub enum RelayStreamDirection {
    Bidirectional,
    Unidirectional,
}

pub struct CallRelayConnection {
    // Release the SSL object before the UDP socket whose file descriptor its BIO borrows.
    ssl: Ssl,
    socket: Arc<AsyncFd<UdpSocket>>,
    api: &'static QuicApi,
    keys: CallRelayKeys,
}

pub struct CallRelayStream {
    ssl: Ssl,
    socket: Arc<AsyncFd<UdpSocket>>,
    write_pending: bool,
}

impl CallRelayAllocation {
    /// Connect to the allocated relay using the per-call external PSK and HTTP/3 ALPN.
    pub async fn connect(&self) -> Result<CallRelayConnection> {
        CallRelayConnection::connect(self.endpoint, self.derive_keys()?).await
    }
}

impl CallRelayConnection {
    async fn connect(peer: SocketAddr, keys: CallRelayKeys) -> Result<Self> {
        let api = quic_api()?;
        let index = PSK_SLOT
            .get_or_init(SslContext::new_ex_index)
            .as_ref()
            .context("Could not initialize relay TLS credentials")?;
        // SAFETY: quic_api resolved the OpenSSL method function from the linked library.
        let method = unsafe { (api.client_method)() };
        ensure!(!method.is_null(), "OpenSSL has no QUIC client method");
        let mut context = SslContextBuilder::new(unsafe { SslMethod::from_ptr(method) })?;
        context.set_verify(SslVerifyMode::PEER);
        context.set_session_cache_mode(SslSessionCacheMode::OFF);
        context.set_options(SslOptions::NO_TICKET);
        context.set_mode(SslMode::ACCEPT_MOVING_WRITE_BUFFER);
        context.set_ciphersuites("TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256")?;
        context.set_alpn_protos(b"\x02h3")?;
        context.set_ex_data(
            *index,
            RelayPsk {
                identity: keys.identity.clone(),
                key: keys.tls_psk.clone(),
            },
        );
        // SAFETY: The callback and context extra data remain valid as long as SSL holds the context.
        unsafe { (api.set_psk_callback)(context.as_ptr(), use_relay_psk) };
        let ssl = Ssl::new(&context.build())?;
        let bind = if peer.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(bind)?;
        socket.connect(peer)?;
        let socket = register_socket(socket)?;

        // SAFETY: SSL owns the BIO after SSL_set_bio. BIO_NOCLOSE preserves ownership of the
        // descriptor in socket, which outlives SSL and any of its streams.
        unsafe {
            let bio = (api.udp_bio)(socket.get_ref().as_raw_fd(), 0);
            ensure!(!bio.is_null(), "Could not create the relay UDP BIO");
            ffi::SSL_set_bio(ssl.as_ptr(), bio, bio);
            let address = (api.address_new)();
            ensure!(
                !address.is_null(),
                "Could not create the relay peer address"
            );
            let ok = match peer.ip() {
                IpAddr::V4(ip) => (api.address_make)(
                    address,
                    libc::AF_INET,
                    ip.octets().as_ptr().cast(),
                    4,
                    peer.port().to_be(),
                ),
                IpAddr::V6(ip) => (api.address_make)(
                    address,
                    libc::AF_INET6,
                    ip.octets().as_ptr().cast(),
                    16,
                    peer.port().to_be(),
                ),
            };
            let set = ok == 1
                && (api.set_peer)(ssl.as_ptr(), address) == 1
                && ffi::BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, address.cast()) == 1;
            (api.address_free)(address);
            ensure!(set, "Could not configure the relay peer address");
            ensure!(
                (api.blocking_mode)(ssl.as_ptr(), 0) == 1,
                "Could not enable nonblocking QUIC"
            );
            ensure!(
                (api.stream_mode)(ssl.as_ptr(), SSL_DEFAULT_STREAM_MODE_NONE) == 1,
                "Could not configure QUIC streams"
            );
        }

        let mut connection = Self {
            ssl,
            socket,
            api,
            keys,
        };
        connection
            .retry(HANDSHAKE_TIMEOUT, |ssl| {
                let result = unsafe { ffi::SSL_connect(ssl) };
                retry_ssl(ssl, result, "FaceTime relay TLS handshake", ())
            })
            .await
            .context("Could not establish QUIC with the FaceTime relay")?;
        ensure!(
            connection.ssl.session_reused() && connection.ssl.peer_certificate().is_none(),
            "The FaceTime relay did not authenticate with the supplied PSK"
        );
        ensure!(
            connection.ssl.selected_alpn_protocol() == Some(ALPN),
            "The FaceTime relay did not negotiate HTTP/3"
        );
        Ok(connection)
    }

    pub fn relay_keys(&self) -> &CallRelayKeys {
        &self.keys
    }

    pub(super) fn peer_addr(&self) -> Result<SocketAddr> {
        Ok(self.socket.get_ref().peer_addr()?)
    }

    pub fn export_keying_material(&self, output: &mut [u8], label: &str) -> Result<()> {
        self.ssl.export_keying_material(output, label, None)?;
        Ok(())
    }

    pub async fn open_stream(
        &mut self,
        direction: RelayStreamDirection,
    ) -> Result<CallRelayStream> {
        let api = self.api;
        let flags = SSL_STREAM_FLAG_NO_BLOCK
            | match direction {
                RelayStreamDirection::Bidirectional => 0,
                RelayStreamDirection::Unidirectional => SSL_STREAM_FLAG_UNI,
            };
        let ssl = self
            .retry(STREAM_TIMEOUT, |ssl| {
                take_stream(unsafe { (api.new_stream)(ssl, flags) }, "Open relay stream")
            })
            .await?;
        Ok(CallRelayStream {
            ssl,
            socket: self.socket.clone(),
            write_pending: false,
        })
    }

    pub async fn accept_stream(&mut self) -> Result<CallRelayStream> {
        let api = self.api;
        let ssl = self
            .retry(STREAM_TIMEOUT, |ssl| {
                take_stream(
                    unsafe { (api.accept_stream)(ssl, SSL_ACCEPT_STREAM_NO_BLOCK) },
                    "Accept relay stream",
                )
            })
            .await?;
        Ok(CallRelayStream {
            ssl,
            socket: self.socket.clone(),
            write_pending: false,
        })
    }

    pub async fn write_all(
        &mut self,
        stream: &mut CallRelayStream,
        mut bytes: &[u8],
    ) -> Result<()> {
        self.check_stream(stream)?;
        ensure!(
            !stream.write_pending,
            "A relay stream write was interrupted"
        );
        // A canceled or timed out OpenSSL write may have pending bytes. Do not let a later write
        // reuse the stream with different data.
        stream.write_pending = true;
        self.retry(STREAM_TIMEOUT, |_| {
            let ssl = stream.ssl.as_ptr();
            if bytes.is_empty() {
                return Ok(Some(()));
            }
            loop {
                let mut written = 0;
                let result = unsafe {
                    ffi::SSL_write_ex(ssl, bytes.as_ptr().cast(), bytes.len(), &mut written)
                };
                let Some(written) = retry_ssl(ssl, result, "Write to relay stream", written)?
                else {
                    return Ok(None);
                };
                ensure!(
                    written > 0 && written <= bytes.len(),
                    "Invalid relay write length"
                );
                bytes = &bytes[written..];
                if bytes.is_empty() {
                    return Ok(Some(()));
                }
            }
        })
        .await?;
        stream.write_pending = false;
        Ok(())
    }

    pub fn finish_stream(&mut self, stream: &mut CallRelayStream) -> Result<()> {
        self.check_stream(stream)?;
        ensure!(
            !stream.write_pending,
            "A relay stream write was interrupted"
        );
        let ok = unsafe { (self.api.conclude)(stream.ssl.as_ptr(), 0) };
        ensure!(
            ok == 1,
            "Could not finish the relay stream: {}",
            ErrorStack::get()
        );
        self.flush()
    }

    pub async fn read(&mut self, stream: &mut CallRelayStream, bytes: &mut [u8]) -> Result<usize> {
        self.check_stream(stream)?;
        ensure!(!bytes.is_empty(), "A relay stream read needs a buffer");
        self.retry(STREAM_TIMEOUT, |_| {
            let ssl = stream.ssl.as_ptr();
            let mut used = 0;
            let result =
                unsafe { ffi::SSL_read_ex(ssl, bytes.as_mut_ptr().cast(), bytes.len(), &mut used) };
            if result == 0
                && unsafe { ffi::SSL_get_error(ssl, result) } == ffi::SSL_ERROR_ZERO_RETURN
            {
                return Ok(Some(0));
            }
            retry_ssl(ssl, result, "Read relay stream", used)
        })
        .await
    }

    pub fn stream_id(&self, stream: &CallRelayStream) -> Result<u64> {
        self.check_stream(stream)?;
        Ok(unsafe { (self.api.stream_id)(stream.ssl.as_ptr()) })
    }

    fn check_stream(&self, stream: &CallRelayStream) -> Result<()> {
        ensure!(
            Arc::ptr_eq(&self.socket, &stream.socket),
            "Relay stream belongs to a different connection"
        );
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        let ok = unsafe { (self.api.handle_events)(self.ssl.as_ptr()) };
        ensure!(ok == 1, "Relay connection failed: {}", ErrorStack::get());
        Ok(())
    }

    async fn retry<T>(
        &mut self,
        limit: Duration,
        mut attempt: impl FnMut(SslPtr) -> Result<Option<T>>,
    ) -> Result<T> {
        let deadline = Instant::now() + limit;
        loop {
            let _ = ErrorStack::get();
            if let Some(value) = attempt(self.ssl.as_ptr())? {
                return Ok(value);
            }
            timeout_at(deadline, self.wait_for_progress())
                .await
                .context("FaceTime relay operation timed out")??;
            ensure!(
                Instant::now() < deadline,
                "FaceTime relay operation timed out"
            );
            self.flush()?;
        }
    }

    async fn wait_for_progress(&self) -> Result<()> {
        let mut timeout = libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        };
        let mut infinite = 0;
        // SAFETY: The socket, SSL and output storage are live. No other future operates on them.
        let (read, write) = unsafe {
            let connection = self.ssl.as_ptr();
            let ok = (self.api.event_timeout)(connection, &mut timeout, &mut infinite);
            ensure!(ok == 1, "Could not read the relay's QUIC timer");
            (
                (self.api.read_desired)(connection) == 1,
                (self.api.write_desired)(connection) == 1,
            )
        };
        let delay = Duration::from_secs(timeout.tv_sec.max(0) as u64)
            + Duration::from_micros(timeout.tv_usec.max(0) as u64);
        ensure!(
            read || write || infinite == 0,
            "FaceTime relay connection stopped"
        );
        tokio::select! {
            readable = self.socket.readable(), if read => readable?.clear_ready(),
            writable = self.socket.writable(), if write => writable?.clear_ready(),
            _ = sleep(delay), if infinite == 0 => (),
        }
        Ok(())
    }
}

fn retry_ssl<T>(ssl: SslPtr, result: c_int, operation: &str, success: T) -> Result<Option<T>> {
    if result == 1 {
        return Ok(Some(success));
    }
    match unsafe { ffi::SSL_get_error(ssl, result) } {
        ffi::SSL_ERROR_WANT_READ | ffi::SSL_ERROR_WANT_WRITE => Ok(None),
        code => anyhow::bail!(
            "{operation} failed (OpenSSL error {code}): {}",
            ErrorStack::get()
        ),
    }
}

fn take_stream(stream: SslPtr, operation: &str) -> Result<Option<Ssl>> {
    if !stream.is_null() {
        // SAFETY: SSL_new_stream/SSL_accept_stream transfer ownership of the new SSL reference.
        return Ok(Some(unsafe { Ssl::from_ptr(stream) }));
    }
    let error = ErrorStack::get();
    ensure!(error.errors().is_empty(), "{operation} failed: {error}");
    Ok(None)
}

#[cfg(test)]
mod tests;
