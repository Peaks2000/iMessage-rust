use std::{os::unix::fs::FileTypeExt, path::Path, process::Stdio};

use anyhow::{Context, Result, ensure};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::{Child, ChildStdin, ChildStdout, Command},
};
use zeroize::Zeroizing;

use super::{FRAME_RATE, MAX_FRAME};

pub const VIDEO_WIDTH: u16 = 640;
pub const VIDEO_HEIGHT: u16 = 360;
const RGBA_BYTES: usize = VIDEO_WIDTH as usize * VIDEO_HEIGHT as usize * 4;

/// A Linux V4L2 camera encoded by a local FFmpeg process. Dropping it closes the device.
pub struct HevcCamera {
    process: Child,
    stream: AccessUnits<ChildStdout>,
}

impl HevcCamera {
    pub fn start(device: &Path) -> Result<Self> {
        ensure!(
            device
                .metadata()
                .with_context(|| format!("Opening camera {}", device.display()))?
                .file_type()
                .is_char_device(),
            "The FaceTime camera must be a V4L2 device"
        );
        let mut source = ffmpeg();
        source.args(["-f", "v4l2", "-i"]).arg(device);
        Self::from_source(source)
    }

    fn from_source(mut source: Command) -> Result<Self> {
        source
            .args(["-map", "0:v:0", "-an", "-sn", "-dn", "-filter_threads", "1", "-vf"])
            .arg(format!("fps={FRAME_RATE},{}", scale()))
            .args([
                "-pix_fmt", "yuv420p", "-c:v", "libx265", "-preset", "ultrafast",
                "-tune", "zerolatency", "-maxrate", "700k", "-bufsize", "350k",
                "-x265-params",
                "aud=1:repeat-headers=1:scenecut=0:pools=none:frame-threads=1:keyint=15:min-keyint=15:log-level=error",
                "-flush_packets", "1", "-f", "hevc", "pipe:1",
            ]);
        let mut child = source
            .stdin(Stdio::null())
            .spawn()
            .context("Starting the Linux FaceTime HEVC camera encoder (FFmpeg and libx265)")?;
        let stdout = child
            .stdout
            .take()
            .context("Opening the HEVC camera pipe")?;
        Ok(Self {
            process: child,
            stream: AccessUnits::new(stdout),
        })
    }

    /// Read one complete camera frame. The parser retains partial data when canceled.
    pub async fn next_frame(&mut self) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let frame = self.stream.next().await?;
        if frame.is_none() {
            let status = self
                .process
                .wait()
                .await
                .context("Waiting for the HEVC camera process")?;
            ensure!(
                status.success(),
                "The FaceTime camera encoder stopped ({status})"
            );
        }
        Ok(frame)
    }
}

/// A fixed-size display frame from the separate codec process.
pub struct VideoFrame {
    pub width: u16,
    pub height: u16,
    pub rgba: Zeroizing<Vec<u8>>,
}

/// Decode authenticated HEVC into bounded RGBA display frames.
pub struct HevcDecoder {
    _child: Child,
    input: ChildStdin,
    output: DecodedFrames,
}

impl HevcDecoder {
    pub fn start() -> Result<Self> {
        let mut child = ffmpeg()
            .stdin(Stdio::piped())
            .args([
                "-protocol_whitelist",
                "pipe",
                "-f",
                "hevc",
                "-c:v",
                "hevc",
                "-max_pixels",
                "2088960",
                "-threads",
                "1",
                "-flags",
                "low_delay",
                "-probesize",
                "32",
                "-analyzeduration",
                "1",
                "-i",
                "pipe:0",
                "-map",
                "0:v:0",
                "-an",
                "-sn",
                "-dn",
                "-filter_threads",
                "1",
                "-vf",
            ])
            .arg(scale())
            .args([
                "-threads",
                "1",
                "-fps_mode",
                "passthrough",
                "-pix_fmt",
                "rgba",
                "-flush_packets",
                "1",
                "-f",
                "rawvideo",
                "pipe:1",
            ])
            .spawn()
            .context("Starting the Linux FaceTime HEVC decoder (FFmpeg)")?;
        let input = child
            .stdin
            .take()
            .context("Opening the HEVC decoder input")?;
        let output = child
            .stdout
            .take()
            .context("Opening the HEVC decoder output")?;
        Ok(Self {
            _child: child,
            input,
            output: DecodedFrames {
                output,
                frame: Zeroizing::new(vec![0; RGBA_BYTES]),
                filled: 0,
            },
        })
    }

    /// Both directions must be driven concurrently to avoid filling a process pipe.
    pub fn streams(&mut self) -> (&mut ChildStdin, &mut DecodedFrames) {
        (&mut self.input, &mut self.output)
    }
}

pub struct DecodedFrames {
    output: ChildStdout,
    frame: Zeroizing<Vec<u8>>,
    filled: usize,
}

impl DecodedFrames {
    pub async fn next_frame(&mut self) -> Result<Option<VideoFrame>> {
        while self.filled < RGBA_BYTES {
            let read = self
                .output
                .read(&mut self.frame[self.filled..])
                .await
                .context("Reading decoded FaceTime video")?;
            if read == 0 {
                ensure!(
                    self.filled == 0,
                    "The FaceTime video decoder returned a partial frame"
                );
                return Ok(None);
            }
            self.filled += read;
        }
        self.filled = 0;
        Ok(Some(VideoFrame {
            width: VIDEO_WIDTH,
            height: VIDEO_HEIGHT,
            rgba: std::mem::replace(&mut self.frame, Zeroizing::new(vec![0; RGBA_BYTES])),
        }))
    }
}

fn ffmpeg() -> Command {
    let mut command = Command::new("ffmpeg");
    command
        .args(["-hide_banner", "-loglevel", "error", "-nostdin"])
        .stderr(Stdio::null())
        .stdout(Stdio::piped())
        .kill_on_drop(true);
    command
}

fn scale() -> String {
    format!(
        "scale={VIDEO_WIDTH}:{VIDEO_HEIGHT}:force_original_aspect_ratio=decrease,pad={VIDEO_WIDTH}:{VIDEO_HEIGHT}:(ow-iw)/2:(oh-ih)/2,setsar=1"
    )
}

struct AccessUnits<R> {
    source: R,
    bytes: Zeroizing<Vec<u8>>,
    next_scan: usize,
    found_first_delimiter: bool,
}

impl<R: AsyncRead + Unpin> AccessUnits<R> {
    fn new(source: R) -> Self {
        Self {
            source,
            bytes: Zeroizing::new(Vec::new()),
            next_scan: 0,
            found_first_delimiter: false,
        }
    }

    async fn next(&mut self) -> Result<Option<Zeroizing<Vec<u8>>>> {
        loop {
            // Keep the four-byte overlap so a start code and NAL header can cross reads.
            if let Some(index) = self.bytes[self.next_scan..]
                .windows(5)
                .position(|head| head[..3] == [0, 0, 1] && super::nal_type(&head[3..]) == Some(35))
            {
                let start = self.next_scan + index;
                self.next_scan = start + 5;
                if self.found_first_delimiter {
                    ensure!(
                        start <= MAX_FRAME,
                        "FaceTime camera frame exceeds the encoded size limit"
                    );
                    let tail = Zeroizing::new(self.bytes[start..].to_vec());
                    self.bytes.truncate(start);
                    self.next_scan = 5;
                    return Ok(Some(std::mem::replace(&mut self.bytes, tail)));
                }
                self.found_first_delimiter = true;
                continue;
            }
            self.next_scan = self.next_scan.max(self.bytes.len().saturating_sub(4));
            ensure!(
                self.bytes.len() <= MAX_FRAME,
                "FaceTime camera frame exceeds the encoded size limit"
            );
            let mut chunk = Zeroizing::new([0u8; 8192]);
            let length = self
                .source
                .read(chunk.as_mut())
                .await
                .context("Reading encoded FaceTime camera video")?;
            if length == 0 {
                let frame = std::mem::take(&mut self.bytes);
                self.next_scan = 0;
                if frame.is_empty() {
                    return Ok(None);
                }
                ensure!(
                    self.found_first_delimiter,
                    "The camera returned an invalid HEVC stream"
                );
                return Ok(Some(frame));
            }
            self.bytes.extend_from_slice(&chunk[..length]);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::{io::AsyncWriteExt, time::timeout};

    use crate::engine::video::{HevcFeatures, HevcPacketizer, HevcReceiver};

    use super::*;

    #[tokio::test]
    async fn synthetic_camera_survives_hevc_packetization_and_decodes_before_eof() -> Result<()> {
        // The runtime camera backend requires a local FFmpeg build with libx265.
        let codecs = match Command::new("ffmpeg")
            .args(["-v", "error", "-encoders"])
            .output()
            .await
        {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            output => output?,
        };
        if !String::from_utf8_lossy(&codecs.stdout).contains("libx265") {
            return Ok(());
        }
        let mut source = ffmpeg();
        source.stderr(Stdio::inherit());
        source.args([
            "-f",
            "lavfi",
            "-i",
            "testsrc2=size=640x360:rate=15",
            "-frames:v",
            "18",
        ]);
        let mut camera = HevcCamera::from_source(source)?;
        let features = HevcFeatures::negotiate(HevcFeatures::SUPPORTED);
        let mut packetizer = HevcPacketizer::new(1204, VIDEO_WIDTH, VIDEO_HEIGHT, features)?;
        let mut receiver = HevcReceiver::new(1204, features);
        let mut decoder = HevcDecoder::start()?;
        let (input, output) = decoder.streams();
        let send = async {
            let mut first = true;
            let mut count = 0;
            let mut captured = 0;
            while let Some(frame) = camera.next_frame().await? {
                captured += 1;
                let mut packets = packetizer.packetize(&frame)?;
                if first {
                    assert!(packets.len() > 3);
                    // Simulate the last fragment arriving before the remaining slices.
                    packets.rotate_right(1);
                    first = false;
                }
                for packet in packets {
                    if let Some(annex_b) = receiver.receive(&packet) {
                        count += 1;
                        if count == 1 {
                            let expected = super::super::annex_b_nals(&frame)
                                .filter(|nal| matches!(super::super::nal_type(nal), Some(0..=34)))
                                .collect::<Vec<_>>();
                            let actual = super::super::annex_b_nals(&annex_b).collect::<Vec<_>>();
                            assert_eq!(
                                actual.iter().map(|nal| nal.len()).collect::<Vec<_>>(),
                                expected.iter().map(|nal| nal.len()).collect::<Vec<_>>()
                            );
                            assert!(
                                actual == expected,
                                "VCL and parameter sets changed in the RTP round trip"
                            );
                        }
                        input.write_all(&annex_b).await?;
                    }
                }
            }
            assert!(captured > 0, "The synthetic capture produced no AVC units");
            assert!(
                count > 5,
                "Too few HEVC frames reached the decoder: {count}"
            );
            std::future::pending::<Result<()>>().await // A live camera keeps stdin open.
        };
        let rgba = timeout(Duration::from_secs(10), async {
            tokio::select! {
                result = send => {
                    result?;
                    anyhow::bail!("Synthetic video feed stopped");
                }
                frame = output.next_frame() => frame?.context("No decoded FaceTime frame"),
            }
        })
        .await??;
        assert_eq!((rgba.width, rgba.height), (VIDEO_WIDTH, VIDEO_HEIGHT));
        assert_eq!(rgba.rgba.len(), RGBA_BYTES);
        assert!(rgba.rgba.as_chunks::<4>().0.iter().any(|pixel| {
            pixel[3] == 255
                && pixel[..3].iter().max().unwrap() - pixel[..3].iter().min().unwrap() > 80
        }));
        Ok(())
    }
}
