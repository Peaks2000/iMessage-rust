use std::{process::Stdio, time::Instant};

use anyhow::{Context, Result, ensure};
use openssl::rand::rand_bytes;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    process::{Child, Command},
    sync::{mpsc, watch},
};
use zeroize::Zeroizing;

use crate::{CallMode, apple::CallRtpHeader};

use super::{
    AnsweredCall,
    aac::{self, Decoder, FRAME_SAMPLES, SAMPLE_RATE},
};

const AAC_ELD_PAYLOAD: u8 = 104;
const RED_PAYLOAD: u8 = 20;
const PCM_BYTES: usize = FRAME_SAMPLES * size_of::<i16>();
const MAX_ACCESS_UNITS: usize = 8;
const MAX_CONCEALED_PACKETS: u16 = 3;

impl AnsweredCall {
    /// Run an accepted audio call on the default Linux microphone and speakers.
    /// Dropping the future or receiving a hangup releases both devices.
    pub async fn run_audio(mut self, mut muted: watch::Receiver<bool>) -> Result<()> {
        ensure!(
            self.local_description.mode == Some(CallMode::Audio),
            "An audio-only session is required by this FaceTime device driver"
        );
        ensure!(
            self.local_description
                .audio
                .payload_types
                .contains(&AAC_ELD_PAYLOAD)
                && self
                    .remote_description
                    .audio
                    .payload_types
                    .contains(&AAC_ELD_PAYLOAD),
            "The call did not negotiate the supported FaceTime audio codec"
        );
        let mut ended = self.watch_end();
        if ended.has_changed().is_err() {
            return Ok(());
        }
        let (mut encoder, decoder) = aac::open()?;
        let mut capture_device = audio_device(true)?;
        let mut playback_device = audio_device(false)?;
        let mut input = Capture::new(
            capture_device
                .stdout
                .take()
                .context("Opening FaceTime microphone stream")?,
        );
        let output = playback_device
            .stdin
            .take()
            .context("Opening FaceTime speaker stream")?;
        let (packets, pending) = mpsc::channel(6);
        let mut rtp = AudioSender::new(self.local_description.audio.ssrc)?;
        let mut feedback = AudioFeedback::default();
        let mut discard_partial_frame = false;
        let incoming_ssrc = self.remote_description.audio.ssrc;
        let playback = play_audio(output, decoder, pending, incoming_ssrc);
        tokio::pin!(playback);

        let result = async {
            loop {
                tokio::select! {
                    _ = ended.changed() => return Ok(()),
                    result = &mut playback => return result,
                    frame = input.next_frame() => {
                        let mut frame = frame?;
                        let mute_changed = muted.has_changed().unwrap_or(false);
                        let suppress_frame = *muted.borrow_and_update()
                            || mute_changed
                            || discard_partial_frame;
                        discard_partial_frame = false;
                        if suppress_frame {
                            // Flush any buffered audio through the encoder while suppressing RTP.
                            frame.fill(0);
                        }
                        let encoded = encoder.encode(&mut frame)?;
                        let packet = rtp.frame(encoded, suppress_frame, &feedback);
                        if let Some(packet) = packet {
                            tokio::select! {
                                biased;
                                Ok(()) = muted.changed() => discard_partial_frame = true,
                                result = self.send_rtp(&packet) => result?,
                            }
                        }
                    }
                    packet = self.receive_rtp() => {
                        let packet = packet?;
                        if let Some(header) = CallRtpHeader::parse(&packet)
                            && header.ssrc == incoming_ssrc
                        {
                            feedback.observe(&header, &packet);
                            // A stalled sound device cannot block the authenticated relay.
                            let _ = packets.try_send(packet);
                        }
                    }
                }
            }
        }
        .await;

        drop(capture_device);
        drop(playback_device);
        if ended.has_changed().is_err() {
            Ok(())
        } else {
            result
        }
    }
}

fn audio_device(capture: bool) -> Result<Child> {
    let (executable, arguments, label) = if capture {
        (
            "parec",
            ["--record", "--stream-name=FaceTime microphone"],
            "microphone",
        )
    } else {
        (
            "pacat",
            ["--playback", "--stream-name=FaceTime speakers"],
            "speakers",
        )
    };
    let mut command = Command::new(executable);
    command
        .args(arguments)
        .args([
            "--raw",
            "--format=s16le",
            &format!("--rate={SAMPLE_RATE}"),
            "--channels=1",
            "--latency-msec=40",
            "--process-time-msec=20",
            "--client-name=iMessage",
        ])
        .stdin(if capture {
            Stdio::null()
        } else {
            Stdio::piped()
        })
        .stdout(if capture {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stderr(Stdio::null())
        .kill_on_drop(true);
    command
        .spawn()
        .with_context(|| format!("Opening the Linux {label} with {executable}"))
}

struct Capture<R> {
    input: R,
    bytes: Zeroizing<[u8; PCM_BYTES]>,
    filled: usize,
}

impl<R: AsyncRead + Unpin> Capture<R> {
    fn new(input: R) -> Self {
        Self {
            input,
            bytes: Zeroizing::new([0; PCM_BYTES]),
            filled: 0,
        }
    }

    async fn next_frame(&mut self) -> Result<Zeroizing<[i16; FRAME_SAMPLES]>> {
        // The fill offset is retained even if select drops this future mid-frame.
        while self.filled < self.bytes.len() {
            let count = self
                .input
                .read(&mut self.bytes[self.filled..])
                .await
                .context("Reading the FaceTime microphone")?;
            ensure!(count > 0, "The FaceTime microphone stopped");
            self.filled += count;
        }
        self.filled = 0;
        let mut samples = Zeroizing::new([0; FRAME_SAMPLES]);
        for (sample, pair) in samples.iter_mut().zip(self.bytes.as_chunks::<2>().0) {
            *sample = i16::from_le_bytes(*pair);
        }
        Ok(samples)
    }
}

struct AudioSender {
    ssrc: u32,
    sequence: u16,
    timestamp: u32,
    start: Instant,
    marker: bool,
}

impl AudioSender {
    fn new(ssrc: u32) -> Result<Self> {
        let mut random = [0u8; 6];
        rand_bytes(&mut random)?;
        let [a, b, c, d, e, f] = random;
        Ok(Self {
            ssrc,
            sequence: u16::from_be_bytes([a, b]),
            timestamp: u32::from_be_bytes([c, d, e, f]),
            start: Instant::now(),
            marker: true,
        })
    }

    fn frame(
        &mut self,
        access_unit: &[u8],
        muted: bool,
        feedback: &AudioFeedback,
    ) -> Option<Zeroizing<Vec<u8>>> {
        let timestamp = self.timestamp;
        self.timestamp = self.timestamp.wrapping_add(FRAME_SAMPLES as u32);
        if muted || access_unit.is_empty() {
            self.marker = true;
            return None;
        }
        let length = u8::try_from(access_unit.len()).ok()?;
        let mut packet = Zeroizing::new(Vec::with_capacity(29 + access_unit.len()));
        packet.extend_from_slice(&[0x90, (u8::from(self.marker) << 7) | AAC_ELD_PAYLOAD]);
        packet.extend_from_slice(&self.sequence.to_be_bytes());
        packet.extend_from_slice(&timestamp.to_be_bytes());
        packet.extend_from_slice(&self.ssrc.to_be_bytes());
        feedback.append_extension(&mut packet, self.start);
        packet.push(length);
        packet.extend_from_slice(access_unit);
        self.sequence = self.sequence.wrapping_add(1);
        self.marker = false;
        Some(packet)
    }
}

#[derive(Default)]
struct AudioFeedback {
    received_packets: u16,
    received_bytes: u64,
    last_peer_clock: Option<(u16, Instant)>,
}

impl AudioFeedback {
    fn observe(&mut self, header: &CallRtpHeader, packet: &[u8]) {
        self.received_packets = self.received_packets.wrapping_add(1);
        self.received_bytes = self.received_bytes.saturating_add(packet.len() as u64);
        if let Some((profile, data)) = header.extension(packet)
            && profile & 0xc100 == 0x8100
            && let Some(clock) = data.get(8..10)
        {
            self.last_peer_clock = Some((u16::from_be_bytes([clock[0], clock[1]]), Instant::now()));
        }
    }

    fn append_extension(&self, packet: &mut Vec<u8>, start: Instant) {
        // Viceroy audio feedback version 2, with the optional 1024 Hz timing fields.
        packet.extend_from_slice(&0x8100u16.to_be_bytes());
        packet.extend_from_slice(&3u16.to_be_bytes());
        let (peer_clock, delay) = self.last_peer_clock.map_or((0, 0), |(clock, received)| {
            let ticks = received.elapsed().as_millis() * 128 / 125;
            (clock, u16::try_from(ticks).unwrap_or(u16::MAX))
        });
        let sender_clock = (start.elapsed().as_micros() * 1024 / 1_000_000) as u16;
        for field in [
            peer_clock,
            (self.received_bytes / 1000) as u16,
            self.received_packets & 0x0fff,
            delay,
            sender_clock,
            0, // Estimated one-way delay is unavailable at startup.
        ] {
            packet.extend_from_slice(&field.to_be_bytes());
        }
    }
}

fn access_units(payload_type: u8, payload: &[u8]) -> Option<Vec<&[u8]>> {
    let (payload_type, mut payload) = if payload_type == RED_PAYLOAD {
        red_primary(payload)?
    } else {
        (payload_type, payload)
    };
    if payload_type != AAC_ELD_PAYLOAD || payload.is_empty() {
        return None;
    }
    let mut units = Vec::new();
    while let Some((&length, data)) = payload.split_first() {
        if length == 0 || units.len() == MAX_ACCESS_UNITS {
            return None;
        }
        let (unit, remaining) = data.split_at_checked(usize::from(length))?;
        units.push(unit);
        payload = remaining;
    }
    Some(units)
}

fn red_primary(mut payload: &[u8]) -> Option<(u8, &[u8])> {
    let mut redundant_bytes = 0;
    loop {
        let (&header, rest) = payload.split_first()?;
        if header & 0x80 == 0 {
            return Some((header, rest.get(redundant_bytes..)?));
        }
        let (block, next) = rest.split_at_checked(3)?;
        redundant_bytes += (usize::from(block[1] & 3) << 8) | usize::from(block[2]);
        payload = next;
    }
}

async fn play_audio(
    mut output: impl AsyncWrite + Unpin,
    mut decoder: Decoder,
    mut packets: mpsc::Receiver<Zeroizing<Vec<u8>>>,
    ssrc: u32,
) -> Result<()> {
    let mut samples = Zeroizing::new([0i16; FRAME_SAMPLES]);
    let mut bytes = Zeroizing::new([0u8; PCM_BYTES]);
    let mut previous: Option<u16> = None;
    while let Some(packet) = packets.recv().await {
        let Some(header) = CallRtpHeader::parse(&packet).filter(|header| header.ssrc == ssrc)
        else {
            continue;
        };
        let distance = previous.map_or(1, |sequence| header.sequence.wrapping_sub(sequence));
        if distance == 0 || distance >= 0x8000 {
            continue;
        }
        previous = Some(header.sequence);
        let Some(units) = header
            .payload(&packet)
            .and_then(|payload| access_units(header.payload_type, payload))
        else {
            continue;
        };
        let gaps = distance.saturating_sub(1).min(MAX_CONCEALED_PACKETS);
        for unit in std::iter::repeat_n(None, gaps.into()).chain(units.into_iter().map(Some)) {
            if decoder.decode(unit, &mut samples).is_err() {
                continue;
            }
            for (pair, sample) in bytes.as_chunks_mut::<2>().0.iter_mut().zip(samples.iter()) {
                *pair = sample.to_le_bytes();
            }
            output
                .write_all(bytes.as_slice())
                .await
                .context("Writing to the FaceTime speakers")?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io;

    #[tokio::test]
    async fn capture_retains_pcm_when_an_interleaved_relay_event_interrupts_a_read() -> Result<()> {
        let (mut writer, reader) = io::duplex(PCM_BYTES);
        let mut capture = Capture::new(reader);
        writer.write_all(&[0x05, 0x7f, 0xbd]).await?;
        let mut first = Box::pin(capture.next_frame());
        assert!(futures_util::poll!(&mut first).is_pending());
        drop(first);
        writer.write_all(&[0x94]).await?;
        writer.write_all(&[0; PCM_BYTES - 4]).await?;
        let samples = capture.next_frame().await?;
        assert_eq!(&samples[..3], &[0x7f05, -27_459, 0]);
        Ok(())
    }

    #[test]
    fn aac_and_redundancy_frames_are_bounded_and_muting_leaves_an_rtp_timestamp_gap() -> Result<()>
    {
        let mut sender = AudioSender::new(0xffab0011)?;
        let feedback = AudioFeedback::default();
        let first = sender.frame(&[9, 10], false, &feedback).unwrap();
        let header = CallRtpHeader::parse(&first).unwrap();
        assert_eq!(header.ssrc, 0xffab0011);
        assert_eq!(header.payload_type, AAC_ELD_PAYLOAD);
        assert_eq!(header.extension(&first).unwrap().0, 0x8100);
        assert_eq!(header.payload(&first), Some(&[2, 9, 10][..]));
        assert_eq!(first[1] >> 7, 1);
        assert!(sender.frame(&[11], true, &feedback).is_none());
        let resumed = sender.frame(&[12], false, &feedback).unwrap();
        let timestamp = |packet: &[u8]| u32::from_be_bytes(packet[4..8].try_into().unwrap());
        assert_eq!(timestamp(&resumed).wrapping_sub(timestamp(&first)), 960);
        assert_eq!(resumed[1] >> 7, 1);

        let red = [0x80 | 104, 0, 0, 2, 104, 0xfe, 0xfe, 2, 1, 3, 1, 5];
        assert_eq!(access_units(20, &red), Some(vec![&[1, 3][..], &[5][..]]));
        for malformed in [&red[..2], &red[..6], &[104, 2, 1][..], &[104, 0][..]] {
            assert!(access_units(20, malformed).is_none());
        }
        assert!(access_units(104, &[1, 0].repeat(9)).is_none());
        Ok(())
    }

    #[tokio::test]
    async fn linux_aac_eld_encodes_and_plays_synthetic_speech_band_audio() -> Result<()> {
        let (mut encoder, decoder) = aac::open()?;
        let frames = 24;
        let (send, receive) = mpsc::channel(frames);
        let mut sender = AudioSender::new(42)?;
        let feedback = AudioFeedback::default();
        for frame in 0..frames {
            let mut samples = Zeroizing::new(std::array::from_fn(|index| {
                let time = (frame * FRAME_SAMPLES + index) as f64 / f64::from(SAMPLE_RATE);
                (9000.0 * (440.0 * std::f64::consts::TAU * time).sin()) as i16
            }));
            let encoded = encoder.encode(&mut samples)?;
            if let Some(packet) = sender.frame(encoded, false, &feedback)
                && frame != 12
            {
                send.try_send(packet)?;
            }
        }
        drop(send);
        let (writer, mut reader) = io::duplex(frames * PCM_BYTES);
        play_audio(writer, decoder, receive, 42).await?;
        let mut pcm = Zeroizing::new(Vec::new());
        reader.read_to_end(&mut pcm).await?;
        assert!(pcm.len() >= (frames - 2) * PCM_BYTES);
        let decoded: Vec<_> = pcm[PCM_BYTES * 4..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| f64::from(i16::from_le_bytes(*pair)))
            .collect();
        // Codec delay can change phase, so measure both quadratures of the test tone.
        let (sin, cos) = decoded
            .iter()
            .enumerate()
            .fold((0.0, 0.0), |(sin, cos), (i, pcm)| {
                let phase = i as f64 * 440.0 * std::f64::consts::TAU / f64::from(SAMPLE_RATE);
                (sin + pcm * phase.sin(), cos + pcm * phase.cos())
            });
        let amplitude = 2.0 * sin.hypot(cos) / decoded.len() as f64;
        assert!(
            amplitude > 4000.0,
            "Decoded test tone amplitude was {amplitude}"
        );
        Ok(())
    }
}
