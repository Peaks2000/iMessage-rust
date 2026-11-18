use std::{
    collections::VecDeque,
    io::ErrorKind,
    net::{IpAddr, SocketAddr, UdpSocket},
    ptr,
};

use anyhow::{Context, Result, ensure};
use foreign_types::ForeignTypeRef;
use openssl::{error::ErrorStack, ssl::SslRef};
use openssl_sys as ffi;
use tokio::io::{Interest, unix::AsyncFd};

use super::{BioAddress, QuicApi};
use crate::apple::facetime::relay::pod::{RelayDatagramChannel, destination_id};

const BIO_CTRL_PENDING: i32 = 10;
const BIO_CTRL_DGRAM_SET_CAPS: i32 = 87;
const BIO_DGRAM_CAP_HANDLES_DST_ADDR: libc::c_long = 1 << 1;
const BIO_QUEUE_SIZE: usize = 128 * 1024;
const MAX_UDP: usize = 65_536;
const MAX_BATCH: usize = 32;
const POD_QUEUE: usize = 32;

pub(super) struct DatagramBridge {
    // This end of the pair stays owned here. SSL owns its opposite end.
    bio: *mut ffi::BIO,
    peer: *mut BioAddress,
    api: &'static QuicApi,
    buffer: Box<[u8]>,
    sending: Vec<u8>,
    routes: Option<[[u8; 4]; 2]>,
    media: VecDeque<Vec<u8>>,
    signaling: VecDeque<Vec<u8>>,
}

// SAFETY: Both raw handles are OpenSSL objects without thread affinity. All access
// to the bridge and to its owning SSL connection is serialized by &mut self.
unsafe impl Send for DatagramBridge {}

impl Drop for DatagramBridge {
    fn drop(&mut self) {
        // SAFETY: The bridge owns only these two allocations. Either may be null
        // if initialization stopped before the corresponding allocation.
        unsafe {
            ffi::BIO_free_all(self.bio);
            if !self.peer.is_null() {
                (self.api.address_free)(self.peer);
            }
        }
    }
}

impl DatagramBridge {
    pub(super) fn attach(api: &'static QuicApi, ssl: &SslRef, peer: SocketAddr) -> Result<Self> {
        let mut bridge = Self {
            bio: ptr::null_mut(),
            peer: ptr::null_mut(),
            api,
            buffer: vec![0; MAX_UDP].into_boxed_slice(),
            sending: Vec::new(),
            routes: None,
            media: VecDeque::new(),
            signaling: VecDeque::new(),
        };
        // SAFETY: The functions use the live SSL and separately allocated BIO and
        // address handles. SSL_set_bio takes ownership of ssl_bio.
        unsafe {
            let mut ssl_bio = ptr::null_mut();
            ensure!(
                (api.datagram_pair)(
                    &mut ssl_bio,
                    BIO_QUEUE_SIZE,
                    &mut bridge.bio,
                    BIO_QUEUE_SIZE
                ) == 1,
                "Could not create the FaceTime datagram BIO: {}",
                ErrorStack::get()
            );
            ffi::SSL_set_bio(ssl.as_ptr(), ssl_bio, ssl_bio);
            // The socket is pinned to the relay address. Every datagram written by
            // SSL goes there, regardless of ordinary QUIC path migration hints.
            ensure!(
                ffi::BIO_ctrl(
                    bridge.bio,
                    BIO_CTRL_DGRAM_SET_CAPS,
                    BIO_DGRAM_CAP_HANDLES_DST_ADDR,
                    ptr::null_mut()
                ) == 1,
                "Could not configure the FaceTime datagram BIO"
            );
            bridge.peer = (api.address_new)();
            ensure!(
                !bridge.peer.is_null(),
                "Could not create the FaceTime relay address"
            );
            let port = peer.port().to_be();
            let made = match peer.ip() {
                IpAddr::V4(ip) => (api.address_make)(
                    bridge.peer,
                    libc::AF_INET,
                    ip.octets().as_ptr().cast(),
                    4,
                    port,
                ),
                IpAddr::V6(ip) => (api.address_make)(
                    bridge.peer,
                    libc::AF_INET6,
                    ip.octets().as_ptr().cast(),
                    16,
                    port,
                ),
            };
            ensure!(
                made == 1 && (api.set_peer)(ssl.as_ptr(), bridge.peer) == 1,
                "Could not configure the FaceTime relay address"
            );
        }
        Ok(bridge)
    }

    pub(super) fn route(&mut self, media: [u8; 4], signaling: [u8; 4]) {
        self.routes = Some([media, signaling]);
    }

    pub(super) fn pop(&mut self) -> Option<(RelayDatagramChannel, Vec<u8>)> {
        if let Some(bytes) = self.signaling.pop_front() {
            return Some((RelayDatagramChannel::Signaling, bytes));
        }
        self.media
            .pop_front()
            .map(|bytes| (RelayDatagramChannel::Media, bytes))
    }

    pub(super) fn receive(&mut self, socket: &AsyncFd<UdpSocket>, ssl: &SslRef) -> Result<()> {
        for _ in 0..MAX_BATCH {
            let size = match socket.try_io(Interest::READABLE, |sock| sock.recv(&mut self.buffer)) {
                Ok(0) => continue,
                Ok(size) => size,
                Err(err) if err.kind() == ErrorKind::WouldBlock => return Ok(()),
                Err(err) => return Err(err).context("Read FaceTime relay datagram"),
            };
            let packet = &self.buffer[..size];
            if let Some([media, signaling]) = self.routes {
                let target = match destination_id(packet) {
                    Some(id) if id == signaling => Some(&mut self.signaling),
                    Some(id) if id == media => Some(&mut self.media),
                    _ => None,
                };
                if let Some(queue) = target {
                    if queue.len() < POD_QUEUE {
                        queue.push_back(packet.to_vec());
                    }
                    continue;
                }
            }
            // SAFETY: OpenSSL makes its own copy before returning. The source is
            // the connected UDP peer, whose address this bridge owns.
            let result = unsafe {
                (self.api.inject)(
                    ssl.as_ptr(),
                    packet.as_ptr(),
                    packet.len(),
                    self.peer,
                    ptr::null(),
                )
            };
            ensure!(
                result == 1,
                "Could not process a FaceTime relay datagram: {}",
                ErrorStack::get()
            );
        }
        Ok(())
    }

    pub(super) fn pending(&self) -> bool {
        !self.sending.is_empty() || self.bio_pending() > 0
    }

    fn bio_pending(&self) -> usize {
        // SAFETY: The live BIO is accessed serially by its owning connection.
        unsafe { ffi::BIO_ctrl(self.bio, BIO_CTRL_PENDING, 0, ptr::null_mut()) }.max(0) as usize
    }

    pub(super) fn send(&mut self, socket: &AsyncFd<UdpSocket>) -> Result<()> {
        for _ in 0..MAX_BATCH {
            if self.sending.is_empty() {
                let size = self.bio_pending();
                if size == 0 {
                    return Ok(());
                }
                ensure!(size <= MAX_UDP, "FaceTime relay datagram too large");
                self.sending.resize(size, 0);
                // SAFETY: The buffer has room for one complete pending datagram.
                let read = unsafe {
                    ffi::BIO_read(self.bio, self.sending.as_mut_ptr().cast(), size as i32)
                };
                ensure!(
                    read == size as i32,
                    "Could not read a pending FaceTime relay datagram"
                );
            }
            match socket.try_io(Interest::WRITABLE, |sock| sock.send(&self.sending)) {
                Ok(sent) => ensure!(
                    sent == self.sending.len(),
                    "Incomplete FaceTime relay datagram"
                ),
                Err(err) if err.kind() == ErrorKind::WouldBlock => return Ok(()),
                Err(err) => return Err(err).context("Write FaceTime relay datagram"),
            }
            self.sending.clear();
        }
        Ok(())
    }
}
