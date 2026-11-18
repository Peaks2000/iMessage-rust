use std::{future::pending, path::PathBuf, sync::Arc, time::Instant, vec::IntoIter};

use anyhow::{Context, Result, ensure};
use tokio::{
    io::AsyncWriteExt,
    sync::{mpsc, watch},
    task::JoinSet,
};
use zeroize::Zeroizing;

use crate::apple::{CAMERA_HEIGHT, CAMERA_WIDTH, CallRtpDescription};

use super::{
    HEVC_PAYLOAD_TYPE, HevcCamera, HevcDecoder, HevcFeatures, HevcPacketizer, HevcReceiver,
    VideoFrame,
};

/// A local camera and the display stream for a negotiated one-to-one video call.
pub struct VideoCallOptions {
    pub camera: PathBuf,
    pub camera_enabled: watch::Receiver<bool>,
    pub frames: watch::Sender<Option<Arc<VideoFrame>>>,
}

pub(in crate::engine::calls) struct VideoSession {
    camera_path: PathBuf,
    camera_enabled: watch::Receiver<bool>,
    camera: Option<HevcCamera>,
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
        let player = HevcDecoder::start()?;
        let sending_features =
            HevcFeatures::negotiate(local.hevc_features.enabled & peer.hevc_features.supported);
        let receiving_features =
            HevcFeatures::negotiate(peer.hevc_features.enabled & local.hevc_features.supported);
        let packetizer =
            HevcPacketizer::new(local.ssrc, CAMERA_WIDTH, CAMERA_HEIGHT, sending_features)?;
        let receiver = HevcReceiver::new(peer.ssrc, receiving_features);
        let (decode, frames) = mpsc::channel(3);
        let mut decoder = JoinSet::new();
        decoder.spawn(play_video(player, frames, FramePublisher(options.frames)));
        Ok(Self {
            camera_path: options.camera,
            camera_enabled: options.camera_enabled,
            camera: None,
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

    pub(in crate::engine::calls) async fn next_packet(&mut self) -> Result<Zeroizing<Vec<u8>>> {
        loop {
            let can_change = self.camera_enabled.has_changed().is_ok();
            let (enabled, changed) = {
                let state = self.camera_enabled.borrow_and_update();
                (can_change && *state, state.has_changed())
            };
            if !enabled || changed {
                self.stop_capture();
            }
            if enabled && self.camera.is_none() {
                self.camera = Some(HevcCamera::start(&self.camera_path)?);
                if let Some(paused) = self.paused_at.take() {
                    self.packetizer.advance_clock(paused.elapsed());
                }
            }
            let packet = async {
                let Some(camera) = &mut self.camera else {
                    return pending().await;
                };
                if let Some(packet) = self.outgoing.next() {
                    return Ok(packet);
                }
                let frame = camera
                    .next_frame()
                    .await?
                    .context("The FaceTime camera stopped")?;
                self.outgoing = self.packetizer.packetize(&frame)?.into_iter();
                self.outgoing
                    .next()
                    .context("The FaceTime camera produced an empty frame")
            };
            tokio::select! {
                biased;
                _ = self.camera_enabled.changed(), if can_change => self.stop_capture(),
                completed = self.decoder.join_next() => {
                    let status = completed
                        .context("The FaceTime video decoder stopped")?
                        .context("The FaceTime video decoder task stopped")?;
                    status?;
                    anyhow::bail!("The FaceTime video decoder stopped");
                }
                result = packet => return result,
            }
        }
    }

    pub(in crate::engine::calls) fn receive(&mut self, authenticated_rtp: &[u8]) {
        if let Some(hevc) = self.receiver.receive(authenticated_rtp)
            && self.decode.try_send(hevc).is_err()
        {
            // Avoid sending dependent frames to a decoder that missed its reference picture.
            self.receiver.needs_keyframe = true;
        }
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
        let spooled = Zeroizing::new(vec![0x90, HEVC_PAYLOAD_TYPE]);
        let (decode, _frames) = mpsc::channel(1);
        let mut decoder = JoinSet::new();
        decoder.spawn(pending::<Result<()>>());
        let mut session = VideoSession {
            camera_path: PathBuf::from("/dev/null"),
            camera_enabled: enabled,
            camera: None,
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
        Ok(())
    }
}
