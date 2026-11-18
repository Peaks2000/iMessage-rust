use std::{
    ffi::{c_int, c_uint, c_void},
    marker::PhantomData,
    mem::MaybeUninit,
    ptr::{NonNull, null, null_mut},
};

use anyhow::{Context, Result, ensure};
use fdk_aac_sys as fdk;
use zeroize::Zeroizing;

pub(super) use crate::apple::AAC_ELD_SAMPLE_RATE as SAMPLE_RATE;
pub(super) const FRAME_SAMPLES: usize = 480;
const MAX_ACCESS_UNIT: usize = u8::MAX as usize;

struct BufferSlot<'a, T> {
    pointer: *mut c_void,
    identifier: c_int,
    size: c_int,
    element_size: c_int,
    _data: PhantomData<&'a mut [T]>,
}

impl<'a, T> BufferSlot<'a, T> {
    fn new(data: &'a mut [T], identifier: u32) -> Self {
        Self {
            pointer: data.as_mut_ptr().cast(),
            identifier: identifier as c_int,
            size: size_of_val(data) as c_int,
            element_size: size_of::<T>() as c_int,
            _data: PhantomData,
        }
    }

    fn describe(&mut self) -> fdk::AACENC_BufDesc {
        fdk::AACENC_BufDesc {
            numBufs: 1,
            bufs: &mut self.pointer,
            bufferIdentifiers: &mut self.identifier,
            bufSizes: &mut self.size,
            bufElSizes: &mut self.element_size,
        }
    }
}

pub(super) struct Encoder {
    handle: NonNull<fdk::AACENCODER>,
    output: Zeroizing<Vec<u8>>,
}

pub(super) struct Decoder(NonNull<fdk::AAC_DECODER_INSTANCE>);

// The FDK handles have no thread affinity. Each wrapper owns an independent
// handle, and encoding and decoding require exclusive access.
unsafe impl Send for Encoder {}
unsafe impl Send for Decoder {}

pub(super) fn open() -> Result<(Encoder, Decoder)> {
    let mut encoder = Encoder::new()?;
    let mut info = MaybeUninit::<fdk::AACENC_InfoStruct>::zeroed();
    status(
        unsafe { fdk::aacEncInfo(encoder.handle.as_ptr(), info.as_mut_ptr()) },
        "reading AAC-ELD configuration",
    )?;
    let mut info = unsafe { info.assume_init() };
    let length = info.confSize as usize;
    ensure!(
        (1..=info.confBuf.len()).contains(&length)
            && info.frameLength as usize == FRAME_SAMPLES
            && info.inputChannels == 1
            && (MAX_ACCESS_UNIT..=16 * 1024).contains(&(info.maxOutBufBytes as usize)),
        "FDK AAC returned an incompatible FaceTime audio configuration"
    );
    encoder.output.resize(info.maxOutBufBytes as usize, 0);
    let decoder = Decoder::new(&mut info.confBuf[..length])?;
    Ok((encoder, decoder))
}

impl Encoder {
    fn new() -> Result<Self> {
        let mut handle = null_mut();
        let open = unsafe { fdk::aacEncOpen(&mut handle, 0, 1) };
        let encoder = NonNull::new(handle).map(|handle| Self {
            handle,
            output: Zeroizing::new(Vec::new()),
        });
        status(open, "opening the AAC encoder")?;
        let encoder = encoder.context("FDK AAC did not create an encoder")?;
        for (parameter, value) in [
            (
                fdk::AACENC_PARAM_AACENC_AOT,
                fdk::AUDIO_OBJECT_TYPE_AOT_ER_AAC_ELD as u32,
            ),
            (fdk::AACENC_PARAM_AACENC_BITRATE, 48_000),
            (fdk::AACENC_PARAM_AACENC_SAMPLERATE, SAMPLE_RATE),
            (fdk::AACENC_PARAM_AACENC_SBR_MODE, 0),
            (
                fdk::AACENC_PARAM_AACENC_GRANULE_LENGTH,
                FRAME_SAMPLES as u32,
            ),
            (
                fdk::AACENC_PARAM_AACENC_CHANNELMODE,
                fdk::CHANNEL_MODE_MODE_1 as u32,
            ),
            (
                fdk::AACENC_PARAM_AACENC_TRANSMUX,
                fdk::TRANSPORT_TYPE_TT_MP4_RAW as u32,
            ),
        ] {
            status(
                unsafe { fdk::aacEncoder_SetParam(encoder.handle.as_ptr(), parameter, value) },
                "setting AAC-ELD parameters",
            )
            .with_context(|| format!("FDK AAC parameter 0x{parameter:04x} rejected {value}"))?;
        }
        status(
            unsafe {
                fdk::aacEncEncode(encoder.handle.as_ptr(), null(), null(), null(), null_mut())
            },
            "initializing AAC-ELD",
        )?;
        Ok(encoder)
    }

    pub(super) fn encode(&mut self, samples: &mut [i16; FRAME_SAMPLES]) -> Result<&[u8]> {
        let mut pcm = BufferSlot::new(samples, fdk::AACENC_BufferIdentifier_IN_AUDIO_DATA);
        let mut bitstream = BufferSlot::new(
            self.output.as_mut_slice(),
            fdk::AACENC_BufferIdentifier_OUT_BITSTREAM_DATA,
        );
        let input = pcm.describe();
        let output = bitstream.describe();
        let args = fdk::AACENC_InArgs {
            numInSamples: FRAME_SAMPLES as c_int,
            numAncBytes: 0,
        };
        let mut written = MaybeUninit::<fdk::AACENC_OutArgs>::zeroed();
        // Both descriptor slots and their buffer slices stay alive for the call.
        status(
            unsafe {
                fdk::aacEncEncode(
                    self.handle.as_ptr(),
                    &input,
                    &output,
                    &args,
                    written.as_mut_ptr(),
                )
            },
            "encoding FaceTime audio",
        )?;
        let written = unsafe { written.assume_init() };
        let length = usize::try_from(written.numOutBytes)?;
        ensure!(
            length <= MAX_ACCESS_UNIT && written.numInSamples == FRAME_SAMPLES as c_int,
            "FDK AAC returned an invalid FaceTime audio frame"
        );
        Ok(&self.output[..length])
    }
}

impl Drop for Encoder {
    fn drop(&mut self) {
        unsafe { fdk::aacEncClose(&mut self.handle.as_ptr()) };
    }
}

impl Decoder {
    fn new(config: &mut [u8]) -> Result<Self> {
        let handle =
            NonNull::new(unsafe { fdk::aacDecoder_Open(fdk::TRANSPORT_TYPE_TT_MP4_RAW, 1) })
                .context("FDK AAC did not create a decoder")?;
        let decoder = Self(handle);
        status(
            unsafe {
                fdk::aacDecoder_ConfigRaw(
                    handle.as_ptr(),
                    &mut config.as_mut_ptr(),
                    &(config.len() as c_uint),
                )
            },
            "configuring the AAC-ELD decoder",
        )?;
        Ok(decoder)
    }

    pub(super) fn decode(
        &mut self,
        packet: Option<&[u8]>,
        samples: &mut [i16; FRAME_SAMPLES],
    ) -> Result<()> {
        if let Some(packet) = packet {
            ensure!(
                (1..=MAX_ACCESS_UNIT).contains(&packet.len()),
                "Invalid FaceTime AAC-ELD access unit"
            );
            let mut input = Zeroizing::new([0u8; MAX_ACCESS_UNIT]);
            input[..packet.len()].copy_from_slice(packet);
            let size = packet.len() as c_uint;
            let mut available = size;
            status(
                unsafe {
                    fdk::aacDecoder_Fill(
                        self.0.as_ptr(),
                        &mut input.as_mut_ptr(),
                        &size,
                        &mut available,
                    )
                },
                "reading FaceTime AAC-ELD data",
            )?;
            ensure!(available == 0, "FDK AAC did not consume a full access unit");
        }
        let flags = if packet.is_none() {
            fdk::AACDEC_CONCEAL
        } else {
            0
        };
        status(
            unsafe {
                fdk::aacDecoder_DecodeFrame(
                    self.0.as_ptr(),
                    samples.as_mut_ptr(),
                    FRAME_SAMPLES as c_int,
                    flags,
                )
            },
            "decoding FaceTime audio",
        )
    }
}

impl Drop for Decoder {
    fn drop(&mut self) {
        unsafe { fdk::aacDecoder_Close(self.0.as_ptr()) };
    }
}

fn status(code: c_uint, action: &str) -> Result<()> {
    ensure!(code == 0, "FDK AAC failed while {action} (0x{code:04x})");
    Ok(())
}
