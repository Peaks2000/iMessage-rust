use anyhow::{Context, Result, ensure};
use openssl::{hash::MessageDigest, memcmp, pkey::PKey, sign::Signer};

use super::{CallRelayKeys, RelayCall};

const INTERFACE: u16 = 6;
const ACK: u16 = 0x8000;
const COUNTER: u16 = 0x01;
const DIGEST: u16 = 0x09;
const CAPABILITY: u16 = 0x0c;
const ACCEPT_DELAY: u16 = 0x07;
const RELAY_INTERFACE: u16 = 0x15;
const ANNOUNCEMENT_COUNTER: u16 = 1;
const CONTROL_HEADER_LEN: usize = 20;
const CONTROL_DIGEST_LEN: usize = 20;
const MAX_UDP: usize = 2048;
const MAX_OUTGOING_UDP: usize = 1200;
const RTP_START: usize = 12;

pub(super) struct OneToOnePath {
    call: RelayCall,
    caller_route: u64,
    channel: u16,
    local_link: u16,
    caller_link: Option<(u16, u16)>,
    confirmed: bool,
}

impl OneToOnePath {
    pub(super) fn new(
        call: RelayCall,
        keys: &CallRelayKeys,
        channel: u16,
        link_id: u32,
    ) -> Result<Self> {
        // QuickRelay uses the TURN ChannelData layout and a link ID local to the relay.
        ensure!(
            valid_turn_channel(channel),
            "Invalid FaceTime relay media channel"
        );
        let local_link = link_id as u16;
        ensure!(
            local_link != 0,
            "Missing FaceTime relay media link identifier"
        );
        let caller_route = route_identifier(keys, call.peer)?;
        Ok(Self {
            call,
            caller_route,
            channel,
            local_link,
            caller_link: None,
            confirmed: false,
        })
    }

    pub(super) fn channel(&self) -> u16 {
        self.channel
    }

    pub(super) fn ready(&self) -> bool {
        self.confirmed && self.caller_link.is_some()
    }

    pub(super) fn announce(&self, ipv6: bool) -> Result<Vec<u8>> {
        let mut interface = [0; 14];
        // Tag 1, one 12-byte interface, relayed UDP transport.
        interface[..2].copy_from_slice(&0x2001u16.to_be_bytes());
        let family = if ipv6 { 0x8000u16 } else { 0 };
        interface[2..4].copy_from_slice(&(family | 0x1900).to_be_bytes());
        interface[4..6].copy_from_slice(&self.local_link.to_be_bytes());
        interface[6..8].copy_from_slice(&(MAX_OUTGOING_UDP as u16).to_be_bytes());
        encode_control(self.call, INTERFACE, ANNOUNCEMENT_COUNTER, Some(&interface))
    }

    pub(super) fn accept_control(&mut self, frame: &[u8]) -> Result<Option<Vec<u8>>> {
        let Some(relay) =
            parse_relay(frame).filter(|relay| relay.participant == Some(self.caller_route))
        else {
            return Ok(None);
        };
        let Some(control) = parse_control(self.call, relay.payload)? else {
            return Ok(None);
        };
        if control.command == INTERFACE | ACK {
            if control.counter == ANNOUNCEMENT_COUNTER {
                self.confirmed = true;
            }
            return Ok(None);
        }
        if control.command != INTERFACE {
            return Ok(None);
        }
        let Some(link) = control.interface.and_then(interface_link) else {
            return Ok(None);
        };
        match self.caller_link {
            Some((last, known)) if control.counter == last && link != known => return Ok(None),
            Some((last, _)) if control.counter <= last => {}
            _ => self.caller_link = Some((control.counter, link)),
        }
        encode_control(self.call, INTERFACE | ACK, control.counter, None).map(Some)
    }

    pub(super) fn wrap_media(&self, rtp: &[u8]) -> Result<Vec<u8>> {
        ensure!(self.ready(), "FaceTime has not negotiated its media path");
        ensure!(
            rtp.len() >= RTP_START && rtp.len() + 8 <= MAX_OUTGOING_UDP,
            "FaceTime media packet has an invalid size"
        );
        let (_, destination) = self
            .caller_link
            .context("Missing FaceTime media destination")?;
        let length = u16::try_from(rtp.len() + 4)?;
        let mut packet = Vec::with_capacity(usize::from(length) + 4);
        packet.extend_from_slice(&self.channel.to_be_bytes());
        packet.extend_from_slice(&length.to_be_bytes());
        packet.extend_from_slice(&[0x20, 0x40]); // Destination link present, count the media packet.
        packet.extend_from_slice(&destination.to_be_bytes());
        packet.extend_from_slice(rtp);
        Ok(packet)
    }

    pub(super) fn open_media<'a>(&self, frame: &'a [u8]) -> Option<&'a [u8]> {
        let relay = parse_relay(frame)?;
        if self.ready()
            && relay.participant == Some(self.caller_route)
            && relay.payload.len() >= RTP_START
            && relay.payload[0] >> 6 == 2
        {
            return Some(relay.payload);
        }
        None
    }
}

pub(super) fn valid_turn_channel(channel: u16) -> bool {
    channel & 0xc000 == 0x4000
}

/// Recognize packets only on the media channel returned by the authenticated bind.
pub(super) fn turn_payload(bytes: &[u8], channel: u16) -> Option<&[u8]> {
    if !(4..=MAX_UDP).contains(&bytes.len()) || bytes[..2] != channel.to_be_bytes() {
        return None;
    }
    let length = usize::from(u16::from_be_bytes(bytes[2..4].try_into().ok()?));
    let end = length + 4;
    if bytes.len() == end || bytes.len() == end.next_multiple_of(4) {
        Some(&bytes[4..end])
    } else {
        None
    }
}

struct RelayPayload<'a> {
    participant: Option<u64>,
    payload: &'a [u8],
}

fn parse_relay(mut frame: &[u8]) -> Option<RelayPayload<'_>> {
    let [first, second] = take(&mut frame)?;
    // Transition streams add another envelope around their bodies. Decode the
    // one-to-one packet and leave those other media modes to their own parser.
    if first & 0x18 != 0 {
        return None;
    }
    let attrs = if first & 0x80 != 0 {
        take_u16(&mut frame)?
    } else {
        0
    };
    if attrs & 1 != 0 {
        return None; // Hop-encrypted relay control has a different payload layout.
    }
    if second & 0x01 != 0 {
        take::<2>(&mut frame)?;
    }
    if second & 0x02 != 0 {
        skip_list(&mut frame)?;
    }
    let participant = if second & 0x04 != 0 {
        Some(u64::from_be_bytes(take(&mut frame)?))
    } else {
        None
    };
    if attrs & 0x30 == 0x10 {
        take::<2>(&mut frame)?;
    }
    if second & 0x09 == 0x09 {
        take::<1>(&mut frame)?;
    }
    if second & 0x10 != 0 {
        take::<2>(&mut frame)?;
    }
    if second & 0x20 != 0 {
        take::<1>(&mut frame)?;
    }
    let length = if second & 0x80 != 0 {
        Some(usize::from(take_u16(&mut frame)?))
    } else {
        None
    };
    if first & 0x02 != 0 {
        take::<2>(&mut frame)?;
    }
    if first & 0x04 != 0 {
        take::<12>(&mut frame)?;
    }
    if first & 0x20 != 0 {
        take::<2>(&mut frame)?;
    }
    if first & 0x40 != 0 {
        skip_list(&mut frame)?;
    }
    if attrs & 0x02 != 0 {
        take::<1>(&mut frame)?;
    }
    let payload = frame.get(..length.unwrap_or(frame.len()))?;
    Some(RelayPayload {
        participant,
        payload,
    })
}

fn take<const N: usize>(input: &mut &[u8]) -> Option<[u8; N]> {
    let (value, tail) = input.split_at_checked(N)?;
    *input = tail;
    value.try_into().ok()
}

fn take_u16(input: &mut &[u8]) -> Option<u16> {
    Some(u16::from_be_bytes(take(input)?))
}

fn skip_list(input: &mut &[u8]) -> Option<()> {
    let [length] = take(input)?;
    *input = input.get(usize::from(length) * 2..)?;
    Some(())
}

fn route_identifier(keys: &CallRelayKeys, participant: u64) -> Result<u64> {
    let key = PKey::hmac(&keys.session_keys[32..])?;
    let mac = Signer::new(MessageDigest::sha256(), &key)?
        .sign_oneshot_to_vec(&participant.to_be_bytes())?;
    Ok(u64::from_be_bytes(mac[..8].try_into()?))
}

struct Control<'a> {
    command: u16,
    counter: u16,
    interface: Option<&'a [u8]>,
}

fn parse_control(call: RelayCall, bytes: &[u8]) -> Result<Option<Control<'_>>> {
    let Some(mut body) = bytes.get(CONTROL_HEADER_LEN..) else {
        return Ok(None);
    };
    if usize::from(u16::from_be_bytes([bytes[2], bytes[3]])) != body.len() {
        return Ok(None);
    }
    let command = u16::from_be_bytes([bytes[0], bytes[1]]);
    let mut counter = None;
    let mut interface = None;
    while !body.is_empty() {
        let offset = bytes.len() - body.len();
        let Some((kind, parameter, tail)) = next_parameter(body) else {
            return Ok(None);
        };
        body = tail;
        match kind {
            COUNTER if counter.is_none() && parameter.len() == 2 => {
                let value = u16::from_be_bytes([parameter[0], parameter[1]]);
                if value == 0 {
                    return Ok(None);
                }
                counter = Some(value);
            }
            RELAY_INTERFACE if interface.is_none() => interface = Some(parameter),
            DIGEST if parameter.len() == CONTROL_DIGEST_LEN && body.is_empty() => {
                let signature = link_mac(call, &bytes[..offset])?;
                if !memcmp::eq(&signature, parameter) {
                    return Ok(None);
                }
                return Ok(counter.map(|counter| Control {
                    command,
                    counter,
                    interface,
                }));
            }
            COUNTER | RELAY_INTERFACE | DIGEST => return Ok(None),
            _ => {}
        }
    }
    Ok(None)
}

fn next_parameter(mut bytes: &[u8]) -> Option<(u16, &[u8], &[u8])> {
    let kind = take_u16(&mut bytes)?;
    let len = usize::from(take_u16(&mut bytes)?);
    let (parameter, tail) = bytes.split_at_checked(len)?;
    Some((kind, parameter, tail))
}

fn interface_link(mut interfaces: &[u8]) -> Option<u16> {
    let header = take_u16(&mut interfaces)?;
    let count = usize::from(header & 0x1fff);
    if header >> 13 != 1 || !(1..=8).contains(&count) || interfaces.len() != count * 12 {
        return None;
    }
    interfaces.as_chunks::<12>().0.iter().find_map(|item| {
        let layout = u16::from_be_bytes([item[0], item[1]]);
        let link = u16::from_be_bytes([item[2], item[3]]);
        (((layout >> 11) & 0x0f == 3) && ((layout >> 7) & 0x0f == 2) && link != 0).then_some(link)
    })
}

fn encode_control(
    call: RelayCall,
    command: u16,
    counter: u16,
    interface: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let mut message = vec![0; CONTROL_HEADER_LEN];
    message[..2].copy_from_slice(&command.to_be_bytes());
    if let Some(interface) = interface {
        parameter(&mut message, RELAY_INTERFACE, interface);
    }
    parameter(&mut message, CAPABILITY, &1u16.to_be_bytes());
    parameter(&mut message, ACCEPT_DELAY, &157_977u32.to_be_bytes());
    parameter(&mut message, COUNTER, &counter.to_be_bytes());
    let length = u16::try_from(message.len() - CONTROL_HEADER_LEN + 4 + CONTROL_DIGEST_LEN)?;
    message[2..4].copy_from_slice(&length.to_be_bytes());
    let mac = link_mac(call, &message)?;
    parameter(&mut message, DIGEST, &mac);

    let mut frame = Vec::with_capacity(4 + message.len());
    frame.extend_from_slice(&[0x80, 0, 0, 0x20]); // QuickRelay IDS datagram attributes.
    frame.extend_from_slice(&message);
    Ok(frame)
}

fn parameter(output: &mut Vec<u8>, kind: u16, parameter: &[u8]) {
    output.extend_from_slice(&kind.to_be_bytes());
    output.extend_from_slice(&(parameter.len() as u16).to_be_bytes());
    output.extend_from_slice(parameter);
}

fn link_mac(call: RelayCall, bytes: &[u8]) -> Result<[u8; CONTROL_DIGEST_LEN]> {
    // The room ID binds the wire message to this session. Peer identity
    // comes from the mapped sender on the authenticated relay datagram.
    let key = PKey::hmac(call.id.as_bytes())?;
    let mut mac = Signer::new(MessageDigest::sha1(), &key)?;
    let mut digest = [0; CONTROL_DIGEST_LEN];
    mac.sign_oneshot(&mut digest, bytes)?;
    Ok(digest)
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use uuid::Uuid;
    use zeroize::Zeroizing;

    // Inject the sender ID that the relay adds when forwarding the protected IDS packet.
    pub(in crate::apple::facetime::relay) fn forwarded_control(
        call: RelayCall,
        keys: &CallRelayKeys,
        for_ack: bool,
    ) -> Result<Vec<u8>> {
        let frame = if for_ack {
            encode_control(call, INTERFACE | ACK, ANNOUNCEMENT_COUNTER, None)?
        } else {
            OneToOnePath::new(call, keys, 0x4008, 0x1234)?.announce(false)?
        };
        let mut forwarded = vec![0x80, 0x04, 0, 0x20];
        forwarded.extend_from_slice(&route_identifier(keys, call.peer)?.to_be_bytes());
        forwarded.extend_from_slice(&frame[4..]);
        Ok(forwarded)
    }

    pub(in crate::apple::facetime::relay) fn forwarded_media(
        call: RelayCall,
        keys: &CallRelayKeys,
        rtp: &[u8],
    ) -> Result<Vec<u8>> {
        let mut frame = vec![0x40, 0x08];
        frame.extend_from_slice(&u16::try_from(rtp.len() + 10)?.to_be_bytes());
        frame.extend_from_slice(&[0, 0x44]);
        frame.extend_from_slice(&route_identifier(keys, call.peer)?.to_be_bytes());
        frame.extend_from_slice(rtp);
        Ok(frame)
    }

    #[test]
    fn authenticates_the_interface_exchange_and_frames_media_for_only_the_selected_caller()
    -> Result<()> {
        let call = RelayCall {
            id: Uuid::from_u128(0x6159_b337_c2f2_4467_9e19_dfc6_8f4e_5659),
            local: 77,
            peer: 55,
        };
        let keys = CallRelayKeys {
            identity: Zeroizing::new(Vec::new()),
            tls_psk: Zeroizing::new([0; 32]),
            hop_keys: Zeroizing::new([0; 64]),
            session_keys: Zeroizing::new([7; 48]),
        };
        let mut route = OneToOnePath::new(call, &keys, 0x4008, 0x1234)?;
        assert_eq!(route.caller_route, 0xa6e8_2a92_e7e3_7545);
        // Independent Python HMAC and TLV fixture.
        assert_eq!(
            hex::encode(route.announce(false)?),
            concat!(
                "800000200006003e000000000000000000000000000000000015000e20011900123404b0000000000000",
                "000c00020001000700040002691900010002000100090014e826f9f18088595e45ad7d975918c3b981314613",
            )
        );
        let peer = forwarded_control(call, &keys, false)?;
        let ack = forwarded_control(call, &keys, true)?;
        let mut altered_peer = peer.clone();
        *altered_peer.last_mut().unwrap() ^= 1;
        assert!(route.accept_control(&altered_peer)?.is_none());
        altered_peer.copy_from_slice(&peer);
        altered_peer[4] ^= 1;
        assert!(route.accept_control(&altered_peer)?.is_none());
        assert!(!route.ready());
        let answer = route
            .accept_control(&peer)?
            .context("Missing peer interface acknowledgment")?;
        assert_eq!(
            u16::from_be_bytes(answer[4..6].try_into()?),
            INTERFACE | ACK
        );
        assert!(!route.ready());
        assert!(route.accept_control(&ack)?.is_none());
        assert!(route.ready());

        let rtp = hex::decode("80681388010203001234567854e21a48c03a70957c92d1001036471633")?;
        let send = route.wrap_media(&rtp)?;
        assert_eq!(send[..8], [0x40, 0x08, 0, 33, 0x20, 0x40, 0x12, 0x34]);
        assert_eq!(send[8..], rtp);
        let inbound = forwarded_media(call, &keys, &rtp)?;
        let payload = turn_payload(&inbound, 0x4008).context("Invalid TURN fixture")?;
        assert_eq!(route.open_media(payload), Some(rtp.as_slice()));
        assert!(turn_payload(&inbound, 0x4009).is_none());
        assert!(turn_payload(&inbound[..8], 0x4008).is_none());
        let mut other = inbound;
        other[6] ^= 1;
        assert!(
            route
                .open_media(turn_payload(&other, 0x4008).unwrap())
                .is_none()
        );
        Ok(())
    }
}
