use std::{ops::Range, sync::Arc};

use eframe::egui::{
    self, Color32, FontId, Rect, Response, Stroke, Ui, pos2,
    text::{Galley, LayoutJob, TextFormat},
};
use linkify::{LinkFinder, LinkKind};
use url::Url;

use super::chrome::{BLUE, INK};

pub(super) struct MessageText {
    pub galley: Arc<Galley>,
    links: Vec<(Range<usize>, Url)>,
}

impl MessageText {
    pub fn layout(ui: &Ui, body: &str, outgoing: bool, width: f32) -> Self {
        let color = if outgoing { Color32::WHITE } else { INK };
        let link_color = if outgoing { Color32::WHITE } else { BLUE };
        let normal = TextFormat::simple(FontId::proportional(13.), color);
        let mut link_style = TextFormat::simple(FontId::proportional(13.), link_color);
        link_style.underline = Stroke::new(0.8_f32, link_color);
        let mut job = LayoutJob::default();
        job.wrap.max_width = width;
        let mut links = Vec::new();
        let mut last_end = 0;
        let mut index = 0;
        let mut finder = LinkFinder::new();
        finder.kinds(&[LinkKind::Url]).url_must_have_scheme(false);
        for link in finder.links(body) {
            let Some(url) = web_url(link.as_str()) else {
                continue;
            };
            let prefix = &body[last_end..link.start()];
            job.append(prefix, 0., normal.clone());
            job.append(link.as_str(), 0., link_style.clone());
            index += prefix.chars().count();
            let end = index + link.as_str().chars().count();
            links.push((index..end, url));
            last_end = link.end();
            index = end;
        }
        job.append(&body[last_end..], 0., normal);
        Self {
            galley: ui.fonts_mut(|fonts| fonts.layout_job(job)),
            links,
        }
    }

    pub fn show(&self, ui: &mut Ui) -> Response {
        let response = ui.add(egui::Label::new(self.galley.clone()).selectable(true));
        if self.links.is_empty() {
            return response;
        }
        let link = self.pointer_link(ui, &response);
        let menu = response.id.with("link-menu");
        if response.secondary_clicked() {
            ui.ctx().data_mut(|data| {
                if let Some(url) = link {
                    data.insert_temp(menu, url.clone());
                } else {
                    data.remove::<Url>(menu);
                }
            });
        }
        if let Some(url) = ui.ctx().data_mut(|data| data.get_temp::<Url>(menu)) {
            response.context_menu(|ui| {
                if ui.button("Open Link").clicked() {
                    ui.ctx().open_url(egui::OpenUrl::new_tab(url.as_str()));
                    ui.close();
                }
                if ui.button("Copy Link").clicked() {
                    ui.ctx().copy_text(url.to_string());
                    ui.close();
                }
            });
        }
        if let Some(url) = link {
            if response.clicked() {
                ui.ctx().open_url(egui::OpenUrl::new_tab(url.as_str()));
            }
            return response
                .on_hover_cursor(egui::CursorIcon::PointingHand)
                .on_hover_text(url.as_str());
        }
        response
    }

    pub fn has_link_at_pointer(&self, ui: &Ui, response: &Response) -> bool {
        self.pointer_link(ui, response).is_some()
    }

    fn pointer_link(&self, ui: &Ui, response: &Response) -> Option<&Url> {
        let pointer = response
            .interact_pointer_pos()
            .or_else(|| ui.input(|input| input.pointer.hover_pos()))?;
        if !ui.clip_rect().contains(pointer) {
            return None;
        }
        let relative = pointer - response.rect.min;
        self.link_at(pos2(relative.x, relative.y))
    }

    fn link_at(&self, point: egui::Pos2) -> Option<&Url> {
        let mut offset = 0;
        for row in &self.galley.rows {
            if let Some((column, _)) = row.glyphs.iter().enumerate().find(|(_, glyph)| {
                Rect::from_min_max(
                    pos2(row.pos.x + glyph.pos.x, row.min_y()),
                    pos2(row.pos.x + glyph.pos.x + glyph.advance_width, row.max_y()),
                )
                .contains(point)
            }) {
                let index = offset + column;
                return self
                    .links
                    .iter()
                    .find(|(range, _)| range.contains(&index))
                    .map(|(_, url)| url);
            }
            offset += row.char_count_including_newline();
        }
        None
    }
}

fn web_url(text: &str) -> Option<Url> {
    let url = if text.contains("://") {
        Url::parse(text).ok()?
    } else {
        Url::parse(&format!("https://{text}")).ok()?
    };
    (matches!(url.scheme(), "http" | "https")
        && url.host().is_some()
        && url.username().is_empty()
        && url.password().is_none())
    .then_some(url)
}
