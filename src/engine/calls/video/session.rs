use std::{
    future::pending,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
    vec::IntoIter,
};

use anyhow::{Context, Result, ensure};
use tokio::{
    io::AsyncWriteExt,
    sync::{mpsc, watch},
    task::JoinSet,
    time::{Instant as TokioInstant, timeout_at},
};
use zeroize::Zeroizing;

use crate::apple::{CAMERA_HEIGHT, CAMERA_WIDTH, CallRtpDescription};

use super::{
    HEVC_PAYLOAD_TYPE, HevcCamera, HevcDecoder, HevcFeatures, HevcPacketizer, HevcReceiver,
    VideoFrame, linux::default_camera,
};

const CAMERA_FRAME_TIMEOUT: Duration = Duration::from_secs(6);

/// A local camera and the display stream for a negotiated one-to-one video call.
pub struct VideoCallOptions {
    /// Use the current default capture device when this is absent.
    pub camera: Option<PathBuf>,
    pub camera_enabled: watch::Receiver<bool>,
    pub frames: watch::Sender<Option<Arc<VideoFrame>>>,
    pub preview: watch::Sender<Option<Arc<VideoFrame>>>,
    pub status: watch::Sender<VideoStatus>,
}

#[derive(Clone, Debug, Default)]
pub struct VideoStatus {
    pub camera_error: Option<String>,
    pub playback_error: Option<String>,
}

struct Capture {
    encoder: HevcCamera,
    deadline: TokioInstant,
}

pub(in crate::engine::calls) struct VideoSession {
    camera_path: Option<PathBuf>,
    camera_enabled: watch::Receiver<bool>,
    camera: Option<Capture>,
    preview: watch::Sender<Option<Arc<VideoFrame>>>,
    status: watch::Sender<VideoStatus>,
    paused_at: Option<Instant>,
    packetizer: HevcPacketizer,
    outgoing: IntoIter<Zeroizing<Vec<u8>>>,
    receiver: HevcReceiver,
    decode: mpsc::Sender<Zeroizing<Vec<u8>>>,
    decoder: JoinSet<Result<()>>,
}

impl VideoSession {
    pub(in crate::engine::calls) fn start(
        local: &CallRtpDescription,
        peer: &CallRtpDescription,
        options: VideoCallOptions,
    ) -> Result<Self> {
        ensure!(
            local.payload_types.contains(&HEVC_PAYLOAD_TYPE)
                && peer.payload_types.contains(&HEVC_PAYLOAD_TYPE),
            "The call did not negotiate the supported FaceTime video codec"
        );
        let sending_features =
            HevcFeatures::negotiate(local.hevc_features.enabled & peer.hevc_features.supported);
        let receiving_features =
            HevcFeatures::negotiate(peer.hevc_features.enabled & local.hevc_features.supported);
        let packetizer =
            HevcPacketizer::new(local.ssrc, CAMERA_WIDTH, CAMERA_HEIGHT, sending_features)?;
        let receiver = HevcReceiver::new(peer.ssrc, receiving_features);
        let (decode, frames) = mpsc::channel(3);
        let mut decoder = JoinSet::new();
        match HevcDecoder::start() {
            Ok(player) => {
                decoder.spawn(play_video(player, frames, FramePublisher(options.frames)));
            }
            Err(error) => options.status.send_modify(|status| {
                status.playback_error = Some(error.to_string());
            }),
        }
        Ok(Self {
            camera_path: options.camera,
            camera_enabled: options.camera_enabled,
            camera: None,
            preview: options.preview,
            status: options.status,
            paused_at: None,
            packetizer,
            outgoing: Vec::new().into_iter(),
            receiver,
            decode,
            decoder,
        })
    }

    pub(in crate::engine::calls) fn camera_switch(&self) -> watch::Receiver<bool> {
        self.camera_enabled.clone()
    }

    fn stop_capture(&mut self) {
        if self.camera.take().is_some() {
            self.paused_at = Some(Instant::now());
        }
        self.outgoing = Vec::new().into_iter();
    }

    fn open_camera(&self) -> Result<HevcCamera> {
        let device = self.camera_path.clone().map_or_else(default_camera, Ok)?;
        HevcCamera::start(&device, self.preview.clone())
    }

    fn camera_failed(&mut self, error: anyhow::Error) {
        self.stop_capture();
        self.status
            .send_modify(|status| status.camera_error = Some(error.to_string()));
    }

    pub(in crate::engine::calls) async fn next_packet(&mut self) -> Zeroizing<Vec<u8>> {
        loop {
            let can_change = self.camera_enabled.has_changed().is_ok();
            let (enabled, changed) = {
                let state = self.camera_enabled.borrow_and_update();
                (can_change && *state, state.has_changed())
            };
            if !enabled || changed {
                self.stop_capture();
            }
            if changed {
                self.status
                    .send_if_modified(|status| status.camera_error.take().is_some());
            }
            if enabled && self.camera.is_none() && self.status.borrow().camera_error.is_none() {
                match self.open_camera() {
                    Ok(encoder) => {
                        self.camera = Some(Capture {
                            encoder,
                            deadline: TokioInstant::now() + CAMERA_FRAME_TIMEOUT,
                        });
                        if let Some(paused) = self.paused_at.take() {
                            self.packetizer.advance_clock(paused.elapsed());
                        }
                    }
                    Err(error) => self.camera_failed(error),
                }
            }
            let packet = async {
                let Some(camera) = &mut self.camera else {
                    return pending().await;
                };
                if let Some(packet) = self.outgoing.next() {
                    return Ok(packet);
                }
                let frame = timeout_at(camera.deadline, camera.encoder.next_frame())
                    .await
                    .context("The FaceTime camera stopped sending video")??
                    .context("The FaceTime camera stopped")?;
                camera.deadline = TokioInstant::now() + CAMERA_FRAME_TIMEOUT;
                self.outgoing = self.packetizer.packetize(&frame)?.into_iter();
                self.outgoing
                    .next()
                    .context("The FaceTime camera produced an empty frame")
            };
            tokio::select! {
                biased;
                _ = wait_for_camera_change(&self.camera_enabled, can_change) => (),
                Some(completed) = self.decoder.join_next() => {
                    let error = match completed {
                        Ok(Err(error)) => error.to_string(),
                        _ => "The FaceTime video decoder stopped".to_owned(),
                    };
                    self.status.send_modify(|status| status.playback_error = Some(error));
                }
                result = packet => match result {
                    Ok(packet) => return packet,
                    Err(error) => self.camera_failed(error),
                },
            }
        }
    }

    pub(in crate::engine::calls) fn receive(&mut self, authenticated_rtp: &[u8]) {
        if !self.decode.is_closed()
            && let Some(hevc) = self.receiver.receive(authenticated_rtp)
            && self.decode.try_send(hevc).is_err()
        {
            // Avoid sending dependent frames to a decoder that missed its reference picture.
            self.receiver.needs_keyframe = true;
        }
    }
}

async fn wait_for_camera_change(switch: &watch::Receiver<bool>, open: bool) {
    if open {
        // Preserve the original version until the loop observes it, including quick off/on toggles.
        let _ = switch.clone().changed().await;
    } else {
        pending().await
    }
}

struct FramePublisher(watch::Sender<Option<Arc<VideoFrame>>>);

impl Drop for FramePublisher {
    fn drop(&mut self) {
        self.0.send_replace(None);
    }
}

async fn play_video(
    mut decoder: HevcDecoder,
    mut frames: mpsc::Receiver<Zeroizing<Vec<u8>>>,
    publisher: FramePublisher,
) -> Result<()> {
    let (input, output) = decoder.streams();
    let feed = async {
        while let Some(frame) = frames.recv().await {
            input
                .write_all(&frame)
                .await
                .context("Feeding the FaceTime video decoder")?;
        }
        Ok(())
    };
    let render = async {
        while let Some(frame) = output.next_frame().await? {
            publisher.0.send_replace(Some(Arc::new(frame)));
        }
        anyhow::bail!("The FaceTime video decoder closed its output")
    };
    tokio::select! {
        result = feed => result,
        result = render => result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn camera_off_discards_queued_video_without_opening_a_device() -> Result<()> {
        let (camera, enabled) = watch::channel(true);
        let (status, mut report) = watch::channel(VideoStatus::default());
        let temporary = tempfile::tempdir()?;
        let spooled = Zeroizing::new(vec![0x90, HEVC_PAYLOAD_TYPE]);
        let (decode, _frames) = mpsc::channel(1);
        let mut decoder = JoinSet::new();
        decoder.spawn(pending::<Result<()>>());
        let mut session = VideoSession {
            camera_path: Some(temporary.path().join("removed-camera")),
            camera_enabled: enabled,
            camera: None,
            preview: watch::channel(None).0,
            status,
            paused_at: None,
            packetizer: HevcPacketizer::new(
                1,
                CAMERA_WIDTH,
                CAMERA_HEIGHT,
                HevcFeatures::default(),
            )?,
            outgoing: vec![spooled].into_iter(),
            receiver: HevcReceiver::new(2, HevcFeatures::default()),
            decode,
            decoder,
        };
        camera.send_replace(false);
        let mut next = Box::pin(session.next_packet());
        assert!(futures_util::poll!(&mut next).is_pending());
        drop(next);
        assert!(session.outgoing.as_slice().is_empty());
        assert!(session.camera.is_none());
        assert!(report.borrow().camera_error.is_none());

        // A failed capture leaves the media loop alive and retries on a new request.
        for _ in 0..2 {
            camera.send_replace(true);
            let mut next = Box::pin(session.next_packet());
            assert!(futures_util::poll!(&mut next).is_pending());
            assert!(report.has_changed()?);
            assert!(report.borrow_and_update().camera_error.is_some());
        }
        Ok(())
    }
}
