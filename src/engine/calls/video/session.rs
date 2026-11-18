use std::{path::PathBuf, sync::Arc, vec::IntoIter};

use anyhow::{Context, Result, ensure};
use tokio::{
    io::AsyncWriteExt,
    sync::{mpsc, watch},
    task::JoinSet,
};
use zeroize::Zeroizing;

use crate::apple::CallRtpDescription;

use super::{
    HEVC_PAYLOAD_TYPE, HevcCamera, HevcDecoder, HevcFeatures, HevcPacketizer, HevcReceiver,
    VIDEO_HEIGHT, VIDEO_WIDTH, VideoFrame,
};

/// A local camera and the display stream for a negotiated one-to-one video call.
pub struct VideoCallOptions {
    pub camera: PathBuf,
    pub features: HevcFeatures,
    pub frames: watch::Sender<Option<Arc<VideoFrame>>>,
}

pub(in crate::engine::calls) struct VideoSession {
    camera: HevcCamera,
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
        let camera = HevcCamera::start(&options.camera)?;
        let player = HevcDecoder::start()?;
        let packetizer =
            HevcPacketizer::new(local.ssrc, VIDEO_WIDTH, VIDEO_HEIGHT, options.features)?;
        let receiver = HevcReceiver::new(peer.ssrc, options.features);
        let (decode, frames) = mpsc::channel(3);
        let mut decoder = JoinSet::new();
        decoder.spawn(play_video(player, frames, FramePublisher(options.frames)));
        Ok(Self {
            camera,
            packetizer,
            outgoing: Vec::new().into_iter(),
            receiver,
            decode,
            decoder,
        })
    }

    pub(in crate::engine::calls) async fn next_packet(&mut self) -> Result<Zeroizing<Vec<u8>>> {
        let packet = async {
            if let Some(packet) = self.outgoing.next() {
                return Ok(packet);
            }
            let frame = self
                .camera
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
            completed = self.decoder.join_next() => {
                let status = completed
                    .context("The FaceTime video decoder stopped")?
                    .context("The FaceTime video decoder task stopped")?;
                status?;
                anyhow::bail!("The FaceTime video decoder stopped");
            }
            result = packet => result,
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
