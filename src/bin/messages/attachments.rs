use std::{
    collections::HashMap,
    fs::File,
    io::{Cursor, Read, Write},
    path::Path,
    sync::mpsc::{self, Receiver},
    time::Instant,
};

use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use eframe::egui::{
    self, Align, Align2, ColorImage, FontId, Layout, Rect, RichText, Sense, TextureHandle, Ui,
    Vec2, vec2,
};
use image::{DynamicImage, ImageDecoder, ImageReader, Limits, RgbaImage};
use linux_imessage::{Attachment, FILE_LIMIT, MAX_ATTACHMENTS, Upload};
use uuid::Uuid;

use super::{
    chrome::{self, BUBBLE_GRAY, DANGER, INK, Icon, MUTED},
    connection::{Action, Connection},
    session_import::run_file_picker,
};

const MAX_PIXELS: u64 = 48_000_000;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) struct AttachmentId {
    pub message: Uuid,
    pub index: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Purpose {
    Thumbnail,
    Open,
}

impl AttachmentId {
    pub fn route(self) -> String {
        format!("/v1/attachments/{}/{}", self.message, self.index)
    }
}

pub(super) struct Contents {
    pub preview: Option<ColorImage>,
    pub original: Option<Bytes>,
}

impl Contents {
    pub fn load(original: Bytes, purpose: Purpose) -> Result<Self> {
        let preview = match purpose {
            Purpose::Thumbnail => Some(color_image(&decode(&original)?, 1024)),
            Purpose::Open => decode(&original)
                .ok()
                .map(|image| color_image(&image, 2560)),
        };
        Ok(Self {
            preview,
            original: (purpose == Purpose::Open).then_some(original),
        })
    }
}

#[derive(Clone)]
pub(super) struct Preview(TextureHandle);

impl Preview {
    pub fn new(ctx: &egui::Context, image: ColorImage) -> Self {
        Self(ctx.load_texture("iMessage attachment", image, egui::TextureOptions::LINEAR))
    }

    pub fn size(&self) -> Vec2 {
        self.0.size_vec2()
    }

    pub fn widget(&self, size: Vec2, radius: u8) -> egui::Image<'static> {
        egui::Image::new(egui::load::SizedTexture::new(self.0.id(), size))
            .fit_to_exact_size(size)
            .corner_radius(radius)
    }
}

pub(super) struct DraftFile {
    pub upload: Upload,
    pub preview: Option<Preview>,
}

pub(super) struct LoadedFile {
    pub upload: Upload,
    pub preview: Option<ColorImage>,
}

#[derive(Default)]
pub(super) struct TranscriptMedia {
    thumbnails: HashMap<AttachmentId, (Instant, Thumbnail)>,
    viewer: Option<Viewer>,
}

enum Thumbnail {
    Waiting,
    Ready(Preview),
    Failed,
}

struct Viewer {
    id: AttachmentId,
    name: String,
    data: Option<(Option<Preview>, Bytes)>,
    loading: bool,
    saving: Option<Receiver<Result<()>>>,
    error: Option<String>,
}

impl TranscriptMedia {
    pub fn is_open(&self) -> bool {
        self.viewer.is_some()
    }

    pub fn seed(&mut self, message: Uuid, files: &[DraftFile]) {
        for (index, file) in files.iter().enumerate() {
            if let Some(preview) = &file.preview {
                self.thumbnails.insert(
                    AttachmentId { message, index },
                    (Instant::now(), Thumbnail::Ready(preview.clone())),
                );
            }
        }
        self.trim();
    }

    pub fn size(&self, id: AttachmentId, info: &Attachment, width: f32) -> Vec2 {
        if info.is_image() {
            let limit = vec2(width.clamp(70., 352.), 275.);
            if let Some((_, Thumbnail::Ready(preview))) = self.thumbnails.get(&id) {
                return fit(preview.size(), limit);
            }
            if !matches!(self.thumbnails.get(&id), Some((_, Thumbnail::Failed))) {
                if info.width > 0 && info.height > 0 {
                    // Once the preview loads, the downsampled texture may differ by a pixel.
                    return fit(vec2(info.width as f32, info.height as f32), limit);
                }
                return vec2(limit.x.min(225.), 145.);
            }
        }
        vec2(width.clamp(70., 270.), 46.)
    }

    pub fn paint(
        &mut self,
        ui: &mut Ui,
        rect: Rect,
        id: AttachmentId,
        info: &Attachment,
        connection: Option<&Connection>,
    ) {
        if !ui.is_rect_visible(rect) {
            return;
        }
        let send = |purpose| {
            connection.is_some_and(|connection| {
                connection
                    .actions
                    .send(Action::Attachment { id, purpose })
                    .is_ok()
            })
        };
        if info.is_image()
            && !self.thumbnails.contains_key(&id)
            && self
                .thumbnails
                .values()
                .filter(|(_, state)| matches!(state, Thumbnail::Waiting))
                .count()
                < 2
            && send(Purpose::Thumbnail)
        {
            self.thumbnails
                .insert(id, (Instant::now(), Thumbnail::Waiting));
        }
        let response = ui.interact(rect, ui.id().with(id), Sense::click());
        response
            .widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, true, &info.name));
        if let Some((used, Thumbnail::Ready(preview))) = self.thumbnails.get_mut(&id) {
            *used = Instant::now();
            preview.widget(rect.size(), 14).paint_at(ui, rect);
        } else {
            ui.painter().rect_filled(rect, 13, BUBBLE_GRAY);
            let center = rect.left_center();
            chrome::icon(
                ui.painter(),
                center + vec2(19., 0.),
                if info.is_image() {
                    Icon::Photo
                } else {
                    Icon::File
                },
                MUTED,
            );
            let mut label = ui.new_child(
                egui::UiBuilder::new()
                    .max_rect(Rect::from_min_max(
                        rect.min + vec2(36., (rect.height() - 16.) * 0.5),
                        rect.max - vec2(8., 0.),
                    ))
                    .layout(Layout::top_down(Align::Min)),
            );
            label.add(egui::Label::new(RichText::new(&info.name).size(12.).color(INK)).truncate());
        }
        if response
            .on_hover_text(&info.name)
            .on_hover_cursor(egui::CursorIcon::PointingHand)
            .clicked()
        {
            let loading = send(Purpose::Open);
            self.viewer = Some(Viewer {
                id,
                name: info.name.clone(),
                data: None,
                loading,
                saving: None,
                error: (!loading).then(|| "Could not load the attachment".to_owned()),
            });
        }
    }

    pub fn received(
        &mut self,
        ctx: &egui::Context,
        id: AttachmentId,
        purpose: Purpose,
        result: Result<Contents>,
    ) {
        match purpose {
            Purpose::Thumbnail => {
                let thumbnail = result
                    .ok()
                    .and_then(|data| data.preview)
                    .map(|image| Thumbnail::Ready(Preview::new(ctx, image)))
                    .unwrap_or(Thumbnail::Failed);
                self.thumbnails.insert(id, (Instant::now(), thumbnail));
                self.trim();
            }
            Purpose::Open => {
                if let Some(viewer) = self.viewer.as_mut().filter(|viewer| viewer.id == id) {
                    viewer.loading = false;
                    match result {
                        Ok(contents) => {
                            let preview = contents.preview.map(|image| Preview::new(ctx, image));
                            if let Some(original) = contents.original {
                                viewer.data = Some((preview, original));
                            }
                        }
                        Err(error) => viewer.error = Some(format!("{error:#}")),
                    }
                }
            }
        }
    }

    fn trim(&mut self) {
        while self.thumbnails.len() > 48 {
            let oldest = self
                .thumbnails
                .iter()
                .filter(|(_, (_, state))| !matches!(state, Thumbnail::Waiting))
                .min_by_key(|(_, (used, _))| *used);
            let Some((&oldest, _)) = oldest else { break };
            self.thumbnails.remove(&oldest);
        }
    }

    pub fn show(&mut self, ctx: &egui::Context) {
        let Some(viewer) = &mut self.viewer else {
            return;
        };
        if let Some(result) = viewer.saving.as_ref().and_then(|save| save.try_recv().ok()) {
            viewer.saving = None;
            viewer.error = result.err().map(|error| format!("{error:#}"));
        }
        let panel = egui::Modal::new(egui::Id::new("attachment-viewer"))
            .frame(chrome::sheet())
            .show(ctx, |ui| {
                let room = (ctx.content_rect().size() - vec2(100., 124.)).max(vec2(240., 200.));
                let size = viewer
                    .data
                    .as_ref()
                    .and_then(|(image, _)| image.as_ref())
                    .map(|image| fit(image.size(), room));
                ui.set_width(size.map_or(290., |size| size.x.max(290.)));
                ui.add(egui::Label::new(chrome::bold(&viewer.name, 14.)).truncate());
                if viewer.loading {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label("Loading…");
                    });
                }
                if let Some((preview, _)) = &viewer.data {
                    if let (Some(preview), Some(size)) = (preview, size) {
                        ui.vertical_centered(|ui| {
                            ui.add(preview.widget(size, 9));
                        });
                    } else {
                        let (rect, _) =
                            ui.allocate_exact_size(vec2(ui.available_width(), 65.), Sense::hover());
                        chrome::icon(ui.painter(), rect.center(), Icon::File, MUTED);
                        ui.painter().text(
                            rect.center_bottom(),
                            Align2::CENTER_BOTTOM,
                            "Attachment",
                            FontId::proportional(11.),
                            MUTED,
                        );
                    }
                }
                if let Some(error) = &viewer.error {
                    ui.label(RichText::new(error).color(DANGER));
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let close = ui.button("Done").clicked();
                    if let Some((_, bytes)) = &viewer.data
                        && ui
                            .add_enabled(viewer.saving.is_none(), egui::Button::new("Save…"))
                            .clicked()
                    {
                        let name = viewer.name.clone();
                        let bytes = bytes.clone();
                        viewer.saving = Some(task(ctx, move || save(name, bytes)));
                    }
                    close
                })
                .inner
            });
        if panel.inner || panel.should_close() {
            self.viewer = None;
        }
    }
}

impl LoadedFile {
    fn read(path: &Path) -> Result<Self> {
        ensure!(path.metadata()?.is_file(), "Select a regular file");
        let mut bytes = Vec::new();
        File::open(path)?
            .take(FILE_LIMIT as u64 + 1)
            .read_to_end(&mut bytes)?;
        let name = path
            .file_name()
            .context("The file has no name")?
            .to_string_lossy();
        Self::from_bytes(&name, bytes.into())
    }

    fn from_bytes(name: &str, bytes: Bytes) -> Result<Self> {
        ensure!(
            (1..=FILE_LIMIT).contains(&bytes.len()),
            "Choose a file up to 32 MiB"
        );
        let mut name = name
            .chars()
            .map(|c| {
                if c.is_control() || matches!(c, '/' | '\\') {
                    '_'
                } else {
                    c
                }
            })
            .collect::<String>();
        if name.len() > 255 {
            let end = (252..=255)
                .rev()
                .find(|index| name.is_char_boundary(*index))
                .expect("UTF-8 characters are no longer than four bytes");
            name.truncate(end);
        }
        if name.trim().is_empty() {
            name = "Attachment".into();
        }
        let format = image::guess_format(&bytes).ok();
        let heic = is_heic(&bytes);
        let mime = match (format, heic) {
            (_, true) => "image/heic",
            (Some(format), _) => format.to_mime_type(),
            (None, _) if bytes.starts_with(b"%PDF-") => "application/pdf",
            _ => "application/octet-stream",
        };
        let image = (format.is_some() || heic)
            .then(|| decode(&bytes).ok())
            .flatten();
        let (width, height) = image
            .as_ref()
            .map_or((0, 0), |image| (image.width(), image.height()));
        let preview = image.as_ref().map(|image| color_image(image, 1024));
        Ok(Self {
            upload: Upload {
                info: Attachment {
                    name,
                    mime: mime.into(),
                    size: bytes.len(),
                    width,
                    height,
                },
                bytes,
            },
            preview,
        })
    }
}

pub(super) fn choose(photos: bool) -> Result<Vec<LoadedFile>> {
    let title = if photos {
        "Choose a Photo"
    } else {
        "Choose an Attachment"
    };
    let filter = "--file-filter=Images | *.bmp *.gif *.heic *.heif *.ico *.jpeg *.jpg *.png *.tif *.tiff *.webp *.HEIC *.HEIF *.PNG *.JPG *.JPEG";
    let options = if photos { &[filter][..] } else { &[] };
    let Some(path) = run_file_picker(title, options)? else {
        return Ok(Vec::new());
    };
    let file = LoadedFile::read(&path).context("Could not attach the selected file")?;
    ensure!(
        !photos || file.preview.is_some(),
        "Choose a supported photo"
    );
    Ok(vec![file])
}

pub(super) fn dropped(files: Vec<egui::DroppedFile>) -> Result<Vec<LoadedFile>> {
    ensure!(
        files.len() <= MAX_ATTACHMENTS,
        "A message can contain up to {MAX_ATTACHMENTS} attachments"
    );
    let mut size = 0;
    let mut loaded = Vec::with_capacity(files.len());
    for file in files {
        let file = match file.path {
            Some(path) => LoadedFile::read(&path)?,
            None => {
                let bytes = file.bytes.context("Could not read the dropped file")?;
                ensure!(bytes.len() <= FILE_LIMIT, "Choose a file up to 32 MiB");
                LoadedFile::from_bytes(&file.name, Bytes::copy_from_slice(&bytes))?
            }
        };
        size += file.upload.info.size;
        ensure!(
            size <= FILE_LIMIT,
            "A message can contain up to 32 MiB of attachments"
        );
        loaded.push(file);
    }
    Ok(loaded)
}

pub(super) fn save(name: String, bytes: Bytes) -> Result<()> {
    let filename = format!("--filename={name}");
    let Some(path) = run_file_picker(
        "Save Attachment",
        &["--save", "--confirm-overwrite", &filename],
    )?
    else {
        return Ok(());
    };
    let folder = path
        .parent()
        .filter(|folder| !folder.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut file =
        tempfile::NamedTempFile::new_in(folder).context("Could not open the destination folder")?;
    file.write_all(&bytes)
        .context("Could not write the attachment")?;
    file.persist(path)
        .context("Could not save the attachment")?;
    Ok(())
}

pub(super) fn task<T: Send + 'static>(
    ctx: &egui::Context,
    work: impl FnOnce() -> Result<T> + Send + 'static,
) -> Receiver<Result<T>> {
    let (tx, rx) = mpsc::channel();
    let ctx = ctx.clone();
    std::thread::spawn(move || {
        let _ = tx.send(work());
        ctx.request_repaint();
    });
    rx
}

fn is_heic(bytes: &[u8]) -> bool {
    bytes.get(4..8) == Some(b"ftyp") && heic_rs::ftyp::parse(bytes).is_ok()
}

fn decode(bytes: &[u8]) -> Result<DynamicImage> {
    if is_heic(bytes) {
        let options = heic_rs::DecodeOptions::default()
            .with_layout(heic_rs::PixelLayout::Rgba8)
            .with_max_pixels(Some(MAX_PIXELS));
        let decoded =
            heic_rs::decode(bytes, &options).context("Could not decode the HEIC photo")?;
        let pixels = RgbaImage::from_raw(decoded.width, decoded.height, decoded.data)
            .context("The HEIC photo returned invalid dimensions")?;
        return Ok(DynamicImage::from(pixels));
    }
    let mut reader = ImageReader::new(Cursor::new(bytes)).with_guessed_format()?;
    let mut limits = Limits::default();
    limits.max_image_width = Some(16_384);
    limits.max_image_height = Some(16_384);
    limits.max_alloc = Some(256 * 1024 * 1024);
    reader.limits(limits);
    let mut decoder = reader.into_decoder().context("Unsupported image format")?;
    let (width, height) = decoder.dimensions();
    ensure!(
        u64::from(width) * u64::from(height) <= MAX_PIXELS,
        "The image is too large to preview"
    );
    let orientation = decoder.orientation()?;
    let mut image = DynamicImage::from_decoder(decoder)?;
    image.apply_orientation(orientation);
    Ok(image)
}

fn color_image(image: &DynamicImage, max: u32) -> ColorImage {
    let pixels = if image.width() > max || image.height() > max {
        image
            .resize(max, max, image::imageops::FilterType::Triangle)
            .into_rgba8()
    } else {
        image.to_rgba8()
    };
    ColorImage::from_rgba_unmultiplied([pixels.width() as usize, pixels.height() as usize], &pixels)
}

pub(super) fn fit(pixels: Vec2, limit: Vec2) -> Vec2 {
    let scale = (limit.x / pixels.x).min(limit.y / pixels.y).min(1.);
    vec2((pixels.x * scale).max(1.), (pixels.y * scale).max(1.))
}
