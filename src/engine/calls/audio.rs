use std::{
    future::pending,
    process::Stdio,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use openssl::rand::rand_bytes;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    process::{Child, ChildStdout, Command},
    sync::{mpsc, watch},
};
use zeroize::Zeroizing;

use crate::{
    CallMode,
    apple::{AAC_ELD_PT, AUDIO_RED_PT, CallRtpHeader},
};

use super::{
    AnsweredCall,
    aac::{self, Decoder, Encoder, FRAME_SAMPLES, SAMPLE_RATE},
    video::{VideoCallOptions, VideoSession},
};

const PCM_BYTES: usize = FRAME_SAMPLES * size_of::<i16>();
const MAX_ACCESS_UNITS: usize = 8;
const MAX_CONCEALED_PACKETS: u16 = 3;

impl AnsweredCall {
    /// Run an accepted audio call on the default Linux microphone and speakers.
    /// Dropping the future or receiving a hangup releases both devices.
    pub async fn run_audio(
        self,
        muted: watch::Receiver<bool>,
        audio_ready: impl FnOnce(),
    ) -> Result<()> {
        self.run_media(muted, None, audio_ready).await
    }

    /// Run an accepted audio and video call using local Linux media devices.
    pub async fn run_video(
        self,
        muted: watch::Receiver<bool>,
        video: VideoCallOptions,
        media_ready: impl FnOnce(),
    ) -> Result<()> {
        self.run_media(muted, Some(video), media_ready).await
    }

    async fn run_media(
        mut self,
        muted: watch::Receiver<bool>,
        video: Option<VideoCallOptions>,
        media_ready: impl FnOnce(),
    ) -> Result<()> {
        let mode = if video.is_some() {
            CallMode::Video
        } else {
            CallMode::Audio
        };
        ensure!(
            self.local_description.mode == Some(mode),
            "The media devices do not match the accepted FaceTime call"
        );
        ensure!(
            self.local_description
                .audio
                .payload_types
                .contains(&AAC_ELD_PT)
                && self
                    .remote_description
                    .audio
                    .payload_types
                    .contains(&AAC_ELD_PT),
            "The call did not negotiate the supported FaceTime audio codec"
        );
        let mut ended = self.watch_end();
        if ended.has_changed().is_err() {
            return Ok(());
        }
        let mut video = video
            .map(|options| {
                VideoSession::start(
                    self.local_description
                        .video
                        .as_ref()
                        .context("The call has no local camera stream")?,
                    self.remote_description
                        .video
                        .as_ref()
                        .context("The call has no remote camera stream")?,
                    options,
                )
            })
            .transpose()?;
        let (encoder, decoder) = aac::open()?;
        let mut microphone = Microphone::new(muted, encoder);
        let mut playback_device = audio_device(false)?;
        let output = playback_device
            .stdin
            .take()
            .context("Opening FaceTime speaker stream")?;
        let (packets, queued) = mpsc::channel(6);
        let mut rtp = AudioSender::new(self.local_description.audio.ssrc)?;
        let mut feedback = AudioFeedback::default();
        let incoming_ssrc = self.remote_description.audio.ssrc;
        let playback = play_audio(output, decoder, queued, incoming_ssrc);
        tokio::pin!(playback);
        media_ready();

        let result = async {
            loop {
                tokio::select! {
                    _ = ended.changed() => return Ok(()),
                    result = &mut playback => return result,
                    packet = async {
                        if let Some(video) = &mut video {
                            video.next_packet().await
                        } else {
                            pending::<Result<Zeroizing<Vec<u8>>>>().await
                        }
                    } => {
                        let packet = packet?;
                        if let Some(video) = &video {
                            let mut camera = video.camera_switch();
                            if *camera.borrow() && camera.has_changed().is_ok_and(|changed| !changed) {
                                let mut muted = microphone.muted.clone();
                                tokio::select! {
                                    biased;
                                    _ = camera.changed() => (),
                                    Ok(()) = muted.changed() => (),
                                    result = self.send_rtp(&packet) => result?,
                                }
                            }
                        }
                    },
                    packet = microphone.next_packet(&mut rtp, &feedback, Recording::start) => {
                        let packet = packet?;
                        let mut muted = microphone.muted.clone();
                        if !*muted.borrow() && muted.has_changed().is_ok_and(|changed| !changed) {
                            let camera_change = async {
                                if let Some(video) = &video {
                                    video.camera_switch().changed().await.ok()
                                } else {
                                    pending().await
                                }
                            };
                            tokio::select! {
                                biased;
                                _ = muted.changed() => (),
                                Some(()) = camera_change => (),
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
                        } else if let Some(video) = &mut video {
                            video.receive(&packet);
                        }
                    }
                }
            }
        }
        .await;

        drop(microphone);
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

struct Recording {
    _device: Child,
    input: Capture<ChildStdout>,
    encoder: Encoder,
}

impl Recording {
    fn start(encoder: Encoder) -> Result<Self> {
        Self::with_device(audio_device(true)?, encoder)
    }

    fn with_device(mut device: Child, encoder: Encoder) -> Result<Self> {
        let input = Capture::new(
            device
                .stdout
                .take()
                .context("Opening the FaceTime microphone stream")?,
        );
        Ok(Self {
            _device: device,
            input,
            encoder,
        })
    }
}

struct Microphone {
    muted: watch::Receiver<bool>,
    paused_at: Option<Instant>,
    first_encoder: Option<Encoder>,
    recording: Option<Recording>,
}

impl Microphone {
    fn new(muted: watch::Receiver<bool>, encoder: Encoder) -> Self {
        Self {
            muted,
            paused_at: None,
            first_encoder: Some(encoder),
            recording: None,
        }
    }

    fn stop(&mut self) {
        // Closing the capture process and codec also discards partial samples and codec history.
        self.recording = None;
        self.paused_at.get_or_insert_with(Instant::now);
    }

    async fn next_packet(
        &mut self,
        rtp: &mut AudioSender,
        feedback: &AudioFeedback,
        start: impl Fn(Encoder) -> Result<Recording>,
    ) -> Result<Zeroizing<Vec<u8>>> {
        loop {
            let control_open = self.muted.has_changed().is_ok();
            let (capture, switch_changed) = {
                let state = self.muted.borrow_and_update();
                (control_open && !*state, state.has_changed())
            };
            if !capture || switch_changed {
                self.stop();
            }
            if capture && self.recording.is_none() {
                let encoder = self.first_encoder.take().map_or_else(Encoder::open, Ok)?;
                self.recording = Some(start(encoder)?);
                if let Some(paused_at) = self.paused_at.take() {
                    rtp.advance_clock(paused_at.elapsed());
                }
            }
            let next = async {
                let Some(recording) = &mut self.recording else {
                    return pending().await;
                };
                let mut samples = recording.input.next_frame().await?;
                let encoded = recording.encoder.encode(&mut samples)?;
                anyhow::Ok(rtp.frame(encoded, feedback))
            };
            tokio::select! {
                biased;
                _ = self.muted.changed(), if control_open => self.stop(),
                frame = next => {
                    if let Some(packet) = frame? {
                        return Ok(packet);
                    }
                }
            }
        }
    }
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
        feedback: &AudioFeedback,
    ) -> Option<Zeroizing<Vec<u8>>> {
        let timestamp = self.timestamp;
        self.timestamp = self.timestamp.wrapping_add(FRAME_SAMPLES as u32);
        if access_unit.is_empty() {
            self.marker = true;
            return None;
        }
        let length = u8::try_from(access_unit.len()).ok()?;
        let mut packet = Zeroizing::new(Vec::with_capacity(29 + access_unit.len()));
        packet.extend_from_slice(&[0x90, (u8::from(self.marker) << 7) | AAC_ELD_PT]);
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

    fn advance_clock(&mut self, pause: Duration) {
        let paused_samples = pause.as_micros() * u128::from(SAMPLE_RATE) / 1_000_000;
        self.timestamp = self.timestamp.wrapping_add(paused_samples as u32);
        self.marker = true;
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
    let (payload_type, mut payload) = if payload_type == AUDIO_RED_PT {
        red_primary(payload)?
    } else {
        (payload_type, payload)
    };
    if payload_type != AAC_ELD_PT || payload.is_empty() {
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
    use std::{cell::RefCell, path::Path};
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

    #[tokio::test]
    async fn muting_closes_the_microphone_and_unmuting_uses_a_clean_encoder() -> Result<()> {
        let (mute, control) = watch::channel(true);
        let opened = RefCell::new(Vec::new());
        let start = |encoder| {
            let pattern = if opened.borrow().is_empty() { "F" } else { "Z" };
            let device = Command::new("yes")
                .arg(pattern)
                .stdout(Stdio::piped())
                .kill_on_drop(true)
                .spawn()?;
            opened.borrow_mut().push(device.id().unwrap());
            Recording::with_device(device, encoder)
        };
        let mut mic = Microphone::new(control, Encoder::open()?);
        let mut sender = AudioSender::new(7)?;
        let feedback = AudioFeedback::default();

        let mut waiting = Box::pin(mic.next_packet(&mut sender, &feedback, &start));
        assert!(futures_util::poll!(&mut waiting).is_pending());
        drop(waiting);
        assert!(opened.borrow().is_empty());

        mute.send_replace(false);
        let first = tokio::time::timeout(
            Duration::from_secs(2),
            mic.next_packet(&mut sender, &feedback, &start),
        )
        .await??;
        let pid = opened.borrow()[0];
        let old_process = format!("/proc/{pid}");
        assert!(Path::new(&old_process).exists());

        mute.send_replace(true);
        let mut waiting = Box::pin(mic.next_packet(&mut sender, &feedback, &start));
        assert!(futures_util::poll!(&mut waiting).is_pending());
        drop(waiting);
        assert!(mic.recording.is_none());
        tokio::time::timeout(Duration::from_secs(2), async {
            while Path::new(&old_process).exists() {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await?;

        mute.send_replace(false);
        let resumed = tokio::time::timeout(
            Duration::from_secs(2),
            mic.next_packet(&mut sender, &feedback, &start),
        )
        .await??;
        assert_eq!(opened.borrow().len(), 2);
        assert_eq!(resumed[1] >> 7, 1);
        let first_header = CallRtpHeader::parse(&first).unwrap();
        let resumed_header = CallRtpHeader::parse(&resumed).unwrap();
        assert_eq!(
            resumed_header.sequence,
            first_header.sequence.wrapping_add(1)
        );

        let mut fresh = Encoder::open()?;
        let mut pcm = Zeroizing::new([i16::from_le_bytes(*b"Z\n"); FRAME_SAMPLES]);
        let payload = resumed_header
            .payload(&resumed)
            .context("Missing audio payload")?;
        let expected = fresh.encode(&mut pcm)?;
        assert_eq!(access_units(AAC_ELD_PT, payload), Some(vec![expected]));

        mute.send_replace(true);
        mute.send_replace(false);
        tokio::time::timeout(
            Duration::from_secs(2),
            mic.next_packet(&mut sender, &feedback, &start),
        )
        .await??;
        assert_eq!(opened.borrow().len(), 3);
        Ok(())
    }

    #[test]
    fn aac_and_redundancy_frames_are_bounded_and_muting_leaves_an_rtp_timestamp_gap() -> Result<()>
    {
        let mut sender = AudioSender::new(0xffab0011)?;
        let feedback = AudioFeedback::default();
        let first = sender.frame(&[9, 10], &feedback).unwrap();
        let header = CallRtpHeader::parse(&first).unwrap();
        assert_eq!(header.ssrc, 0xffab0011);
        assert_eq!(header.payload_type, AAC_ELD_PT);
        assert_eq!(header.extension(&first).unwrap().0, 0x8100);
        assert_eq!(header.payload(&first), Some(&[2, 9, 10][..]));
        assert_eq!(first[1] >> 7, 1);
        sender.advance_clock(Duration::from_millis(20));
        let resumed = sender.frame(&[12], &feedback).unwrap();
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
            if let Some(packet) = sender.frame(encoded, &feedback)
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
