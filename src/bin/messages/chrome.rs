use eframe::egui::{
    self, Color32, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, Frame, Margin,
    Pos2, Rect, Response, RichText, Sense, Shape, Stroke, StrokeKind, Ui, Vec2, pos2, vec2,
};

pub(super) const INK: Color32 = Color32::from_rgb(31, 31, 31);
pub(super) const MUTED: Color32 = Color32::from_rgb(108, 108, 108);
pub(super) const SIDEBAR: Color32 = Color32::from_rgba_unmultiplied_const(232, 231, 229, 244);
pub(super) const TITLEBAR: Color32 = Color32::from_rgba_unmultiplied_const(247, 245, 245, 248);
pub(super) const COMPOSER: Color32 = Color32::from_rgba_unmultiplied_const(252, 252, 252, 249);
pub(super) const HAIRLINE: Color32 = Color32::from_rgb(209, 208, 205);
pub(super) const CANVAS: Color32 = Color32::from_rgb(255, 255, 255);
pub(super) const BLUE: Color32 = Color32::from_rgb(0, 122, 255);
pub(super) const BUBBLE_GRAY: Color32 = Color32::from_rgb(231, 231, 233);
pub(super) const DANGER: Color32 = Color32::from_rgb(193, 47, 50);
pub(super) const TOOLBAR_HEIGHT: f32 = 48.;

pub(super) fn theme(ctx: &egui::Context) {
    let mut fonts = FontDefinitions::default();
    fonts.font_data.insert(
        "Inter".into(),
        FontData::from_static(include_bytes!("../../../assets/Inter.ttf")).into(),
    );
    fonts.font_data.insert(
        "Inter Semibold".into(),
        FontData::from_static(include_bytes!("../../../assets/Inter-Semibold.ttf")).into(),
    );
    let proportional = fonts
        .families
        .get_mut(&FontFamily::Proportional)
        .expect("Default proportional font");
    proportional.insert(0, "Inter".into());
    let mut bold = proportional.clone();
    bold.insert(0, "Inter Semibold".into());
    fonts
        .families
        .insert(FontFamily::Name("Inter Semibold".into()), bold);
    ctx.set_fonts(fonts);

    let mut light = egui::Visuals::light();
    light.override_text_color = Some(INK);
    light.extreme_bg_color = Color32::WHITE;
    light.widgets.noninteractive.bg_stroke = Stroke::new(1.0_f32, HAIRLINE);
    light.widgets.inactive.bg_fill = Color32::WHITE;
    light.widgets.inactive.weak_bg_fill = Color32::WHITE;
    light.widgets.inactive.bg_stroke = Stroke::new(1.0_f32, HAIRLINE);
    light.widgets.hovered.bg_fill = Color32::from_gray(233);
    light.widgets.hovered.weak_bg_fill = Color32::from_gray(233);
    light.widgets.active.bg_fill = Color32::from_gray(223);
    for widgets in [
        &mut light.widgets.inactive,
        &mut light.widgets.hovered,
        &mut light.widgets.active,
        &mut light.widgets.open,
    ] {
        widgets.corner_radius = CornerRadius::ZERO;
    }
    light.selection.bg_fill = Color32::from_rgb(198, 223, 254);
    light.selection.stroke = Stroke::new(1.0_f32, BLUE);
    ctx.set_visuals(light);
    ctx.style_mut(|style| {
        style.spacing.item_spacing = vec2(7., 5.);
        style.spacing.button_padding = vec2(10., 5.);
        style.spacing.interact_size.y = 26.;
        style.animation_time = 0.16;
        style.spacing.scroll.bar_width = 7.;
    });
}

pub(super) fn bold_font(size: f32) -> FontId {
    FontId::new(size, FontFamily::Name("Inter Semibold".into()))
}

pub(super) fn bold(text: impl Into<String>, size: f32) -> RichText {
    RichText::new(text).font(bold_font(size))
}

pub(super) fn sheet() -> Frame {
    Frame::new()
        .fill(Color32::from_rgba_unmultiplied(248, 247, 247, 249))
        .corner_radius(13)
        .inner_margin(Margin::same(16))
        .stroke(Stroke::new(1.0_f32, HAIRLINE))
        .shadow(egui::epaint::Shadow {
            offset: [0, 5],
            blur: 18,
            spread: 0,
            color: Color32::from_black_alpha(42),
        })
}

pub(super) fn popover() -> Frame {
    sheet().inner_margin(Margin::same(6)).corner_radius(11)
}

pub(super) fn window_radius(ctx: &egui::Context) -> u8 {
    let squared = ctx.input(|input| {
        input.viewport().maximized.unwrap_or(false) || input.viewport().fullscreen.unwrap_or(false)
    });
    if squared { 0 } else { 8 }
}

pub(super) fn attachment_item(ui: &mut Ui, symbol: Icon, label: &str, tint: Color32) -> Response {
    let response = ui.add(egui::Button::new("").frame(false).min_size(vec2(146., 33.)));
    response.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, true, label));
    let hover = ui.ctx().animate_bool_with_time(
        response.id,
        response.hovered() || response.has_focus(),
        0.12,
    );
    ui.painter().rect_filled(
        response.rect,
        6,
        Color32::from_black_alpha((21. * hover) as u8),
    );
    let at = response.rect.left_center() + vec2(20., 0.);
    ui.painter()
        .rect_filled(Rect::from_center_size(at, Vec2::splat(25.)), 6, tint);
    icon(ui.painter(), at, symbol, Color32::WHITE);
    ui.painter().text(
        response.rect.left_center() + vec2(40., 0.),
        egui::Align2::LEFT_CENTER,
        label,
        FontId::proportional(13.),
        INK,
    );
    response
}

#[derive(Clone, Copy)]
pub(super) enum Icon {
    Compose,
    Search,
    Phone,
    Video,
    Microphone,
    EndCall,
    Info,
    Plus,
    Emoji,
    Send,
    Photo,
    File,
}

pub(super) fn icon(painter: &egui::Painter, at: Pos2, which: Icon, color: Color32) {
    let p = |x, y| at + vec2(x, y);
    let line = |a, b| {
        painter.line_segment([a, b], Stroke::new(1.35_f32, color));
    };
    let edge = Stroke::new(1.25_f32, color);
    match which {
        Icon::Compose => {
            painter.add(Shape::line(
                vec![
                    p(1.6, -6.4),
                    p(-6.4, -6.4),
                    p(-6.4, 6.4),
                    p(6.4, 6.4),
                    p(6.4, -1.5),
                ],
                edge,
            ));
            line(p(-1.8, 2.), p(7., -6.8));
            line(p(-1.8, 2.), p(-0.9, -0.7));
            line(p(-1.8, 2.), p(0.9, 1.1));
        }
        Icon::Search => {
            painter.circle_stroke(p(-1., -1.), 3.55, edge);
            line(p(1.7, 1.7), p(4.7, 4.7));
        }
        Icon::Phone => {
            painter.add(Shape::closed_line(
                vec![
                    p(-6.5, -5.3),
                    p(-3.5, -7.),
                    p(-1.1, -3.2),
                    p(-3., -1.2),
                    p(-1.2, 1.1),
                    p(1.3, 3.),
                    p(3.3, 1.1),
                    p(7., 3.6),
                    p(5.4, 6.6),
                    p(2.7, 6.5),
                    p(-1.8, 4.),
                    p(-4.1, 1.7),
                    p(-6.5, -2.8),
                ],
                edge,
            ));
        }
        Icon::Video => {
            painter.rect_stroke(
                Rect::from_center_size(p(-2.7, 0.), vec2(11., 9.)),
                1.7,
                edge,
                StrokeKind::Middle,
            );
            painter.add(Shape::line(
                vec![p(2.8, -1.4), p(8.5, -4.4), p(8.5, 4.4), p(2.8, 1.4)],
                edge,
            ));
        }
        Icon::Microphone => {
            painter.rect_stroke(
                Rect::from_center_size(p(0., -2.1), vec2(5.6, 10.)),
                3,
                edge,
                StrokeKind::Middle,
            );
            painter.add(Shape::line(
                vec![
                    p(-5.2, -1.2),
                    p(-5.2, 0.5),
                    p(-3.6, 3.5),
                    p(0., 4.8),
                    p(3.6, 3.5),
                    p(5.2, 0.5),
                    p(5.2, -1.2),
                ],
                edge,
            ));
            line(p(0., 4.8), p(0., 7.));
            line(p(-2.7, 7.), p(2.7, 7.));
        }
        Icon::EndCall => {
            painter.add(Shape::closed_line(
                vec![
                    p(-8.2, 1.8),
                    p(-7.7, -0.7),
                    p(-5.8, -2.2),
                    p(-2.8, -3.3),
                    p(2.8, -3.3),
                    p(5.8, -2.2),
                    p(7.7, -0.7),
                    p(8.2, 1.8),
                    p(6.9, 2.9),
                    p(3.5, 2.9),
                    p(3.1, 0.9),
                    p(-3.1, 0.9),
                    p(-3.5, 2.9),
                    p(-6.9, 2.9),
                ],
                edge,
            ));
        }
        Icon::Info => {
            painter.circle_stroke(at, 6.5, edge);
            painter.circle_filled(p(0., -2.8), 0.8, color);
            line(p(0., -0.6), p(0., 3.3));
        }
        Icon::Plus => {
            line(p(-4., 0.), p(4., 0.));
            line(p(0., -4.), p(0., 4.));
        }
        Icon::Emoji => {
            painter.circle_stroke(at, 7., edge);
            painter.circle_filled(p(-2.6, -1.7), 0.9, color);
            painter.circle_filled(p(2.6, -1.7), 0.9, color);
            painter.add(Shape::line(
                vec![p(-3.3, 1.4), p(-2., 3.), p(0., 3.7), p(2., 3.), p(3.3, 1.4)],
                edge,
            ));
        }
        Icon::Send => {
            line(p(0., -4.7), p(0., 5.));
            painter.add(Shape::line(
                vec![p(-3.8, -1.), p(0., -4.7), p(3.8, -1.)],
                Stroke::new(1.55_f32, color),
            ));
        }
        Icon::Photo => {
            painter.rect_stroke(
                Rect::from_center_size(at, vec2(14., 11.)),
                2,
                edge,
                StrokeKind::Middle,
            );
            painter.circle_filled(p(-3., -2.), 1.1, color);
            painter.add(Shape::line(
                vec![
                    p(-6., 4.),
                    p(-2.5, 0.8),
                    p(-0.2, 3.),
                    p(3.2, -0.6),
                    p(6.1, 2.4),
                ],
                edge,
            ));
        }
        Icon::File => {
            painter.add(Shape::closed_line(
                vec![p(-5., -7.), p(1.5, -7.), p(5., -3.6), p(5., 7.), p(-5., 7.)],
                edge,
            ));
            painter.add(Shape::line(
                vec![p(1.2, -6.8), p(1.2, -3.4), p(4.6, -3.4)],
                edge,
            ));
        }
    }
}

pub(super) fn icon_button(
    ui: &mut Ui,
    which: Icon,
    label: &str,
    circle: Option<Color32>,
) -> Response {
    let response = ui.add(egui::Button::new("").frame(false).min_size(vec2(26., 28.)));
    response.widget_info(|| {
        egui::WidgetInfo::labeled(egui::WidgetType::Button, ui.is_enabled(), label)
    });
    let hover = ui
        .ctx()
        .animate_bool_with_time(response.id, response.hovered(), 0.12);
    let center = response.rect.center();
    if hover > 0. {
        ui.painter().rect_filled(
            response.rect.expand2(vec2(0., -1.)),
            5,
            Color32::from_black_alpha((22. * hover) as u8),
        );
    }
    if response.has_focus() {
        ui.painter().rect_stroke(
            response.rect.shrink(1.),
            5,
            Stroke::new(1.0_f32, BLUE),
            StrokeKind::Inside,
        );
    }
    if let Some(fill) = circle {
        ui.painter().circle_filled(center, 10.4, fill);
    }
    let color = if matches!(which, Icon::Send) {
        Color32::WHITE
    } else {
        MUTED
    };
    icon(ui.painter(), center, which, color);
    response.on_hover_text(label)
}

pub(super) fn traffic_lights(ui: &mut Ui) -> bool {
    let size = vec2(56., 20.);
    let (rect, _) = ui.allocate_exact_size(size, Sense::hover());
    let controls = [
        (
            Color32::from_rgb(255, 95, 87),
            Color32::from_rgb(149, 33, 29),
            "Close Window",
        ),
        (
            Color32::from_rgb(254, 188, 46),
            Color32::from_rgb(151, 107, 25),
            "Minimize",
        ),
        (
            Color32::from_rgb(40, 200, 64),
            Color32::from_rgb(25, 118, 33),
            "Full Screen",
        ),
    ];
    let active = ui.input(|input| input.viewport().focused.unwrap_or(true));
    let hover = ui.ctx().animate_bool_with_time(
        ui.id().with("traffic-hover"),
        ui.rect_contains_pointer(rect.expand(2.0)),
        0.12,
    );
    let mut quit = false;
    for (index, (fill, glyph, label)) in controls.into_iter().enumerate() {
        let at = pos2(rect.left() + 7.5 + index as f32 * 18.5, rect.center().y);
        let button = ui.interact(
            Rect::from_center_size(at, Vec2::splat(17.)),
            ui.id().with(label),
            Sense::click(),
        );
        button.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, true, label));
        let color = if active || hover > 0. {
            fill
        } else {
            Color32::from_gray(190)
        };
        ui.painter().circle(
            at,
            5.6,
            color,
            Stroke::new(0.65_f32, glyph.gamma_multiply(0.32)),
        );
        if hover > 0. {
            let glyph = glyph.gamma_multiply(hover);
            let p = |x, y| at + vec2(x, y);
            let pen = Stroke::new(0.9_f32, glyph);
            match index {
                0 => {
                    ui.painter().line_segment([p(-2., -2.), p(2., 2.)], pen);
                    ui.painter().line_segment([p(-2., 2.), p(2., -2.)], pen);
                }
                1 => {
                    ui.painter().line_segment([p(-2.5, 0.), p(2.5, 0.)], pen);
                }
                _ => {
                    ui.painter().add(Shape::convex_polygon(
                        vec![p(-2.6, -2.6), p(1.4, -2.6), p(-2.6, 1.4)],
                        glyph,
                        Stroke::NONE,
                    ));
                    ui.painter().add(Shape::convex_polygon(
                        vec![p(2.6, 2.6), p(-1.4, 2.6), p(2.6, -1.4)],
                        glyph,
                        Stroke::NONE,
                    ));
                }
            }
        }
        if button.clicked() {
            let command = match index {
                0 => egui::ViewportCommand::Close,
                1 => egui::ViewportCommand::Minimized(true),
                _ => egui::ViewportCommand::Fullscreen(
                    !ui.input(|input| input.viewport().fullscreen.unwrap_or(false)),
                ),
            };
            ui.ctx().send_viewport_cmd(command);
        }
        if index == 0 {
            button.context_menu(|ui| {
                quit = ui
                    .add(egui::Button::new("Quit iMessage").shortcut_text("Ctrl+Q"))
                    .clicked();
                if quit {
                    ui.close();
                }
            });
        }
        button.on_hover_text(label);
    }
    quit
}

pub(super) fn drag_region(ui: &mut Ui, rect: Rect) {
    let response = ui.interact(rect, ui.id().with("drag-window"), Sense::click_and_drag());
    if response.drag_started() {
        ui.ctx().send_viewport_cmd(egui::ViewportCommand::StartDrag);
    }
    if response.double_clicked() {
        ui.ctx().send_viewport_cmd(egui::ViewportCommand::Maximized(
            !ui.input(|input| input.viewport().maximized.unwrap_or(false)),
        ));
    }
}

pub(super) fn avatar(ui: &Ui, center: Pos2, size: f32, name: &str, address: &str) {
    const COLORS: [[u8; 3]; 7] = [
        [152, 151, 185],
        [115, 164, 191],
        [165, 147, 171],
        [162, 171, 195],
        [105, 168, 154],
        [177, 151, 146],
        [129, 140, 170],
    ];
    let hash = address.bytes().fold(0u32, |state, byte| {
        state.wrapping_mul(31).wrapping_add(u32::from(byte))
    });
    let [r, g, b] = COLORS[hash as usize % COLORS.len()];
    let fill = Color32::from_rgb(r, g, b);
    let light = fill.lerp_to_gamma(Color32::WHITE, 0.29);
    let shadow = fill.lerp_to_gamma(Color32::BLACK, 0.20);
    let mut gradient = egui::Mesh::default();
    let pixels_per_point = ui.ctx().pixels_per_point();
    let segments = (std::f32::consts::PI * size * pixels_per_point / 2.5)
        .ceil()
        .clamp(32., 160.) as u32;
    let antialias = 0.6 / pixels_per_point;
    gradient.colored_vertex(center, fill);
    for index in 0..segments {
        let theta = index as f32 * std::f32::consts::TAU / segments as f32;
        let offset = vec2(theta.cos(), theta.sin());
        let color = light.lerp_to_gamma(shadow, (offset.y + 1.) * 0.5);
        gradient.colored_vertex(center + offset * (size / 2. - antialias), color);
        gradient.colored_vertex(
            center + offset * (size / 2. + antialias),
            Color32::TRANSPARENT,
        );
        let inner = 1 + index * 2;
        let next = 1 + ((index + 1) % segments) * 2;
        gradient.add_triangle(0, inner, next);
        gradient.add_triangle(inner, inner + 1, next);
        gradient.add_triangle(next, inner + 1, next + 1);
    }
    ui.painter().add(Shape::mesh(gradient));
    let initials = name
        .split_whitespace()
        .take(2)
        .filter_map(|word| word.chars().next())
        .flat_map(char::to_uppercase)
        .collect::<String>();
    ui.painter().text(
        center,
        egui::Align2::CENTER_CENTER,
        initials,
        bold_font(size * 0.31),
        Color32::WHITE,
    );
}

pub(super) fn line(ui: &Ui, rect: Rect, from_left: f32) {
    ui.painter().line_segment(
        [
            pos2(rect.left() + from_left, rect.bottom()),
            rect.right_bottom(),
        ],
        Stroke::new(0.8_f32, HAIRLINE),
    );
}

pub(super) fn bubble_shape(
    painter: &egui::Painter,
    rect: Rect,
    outgoing: bool,
    tail: bool,
    fill: Color32,
) {
    let radius = CornerRadius::same(13);
    painter.rect_filled(rect, radius, fill);
    if tail {
        let sign: f32 = if outgoing { 1. } else { -1. };
        let at = if outgoing {
            rect.right_bottom()
        } else {
            rect.left_bottom()
        };
        let p = |x, y| at + vec2(x * sign, y);
        let mut mesh = egui::Mesh::default();
        mesh.colored_vertex(p(-5.0, -5.0), fill);
        let outline = [
            (-7.0, -9.5),
            (-0.2, -10.0),
            (0.0, -6.0),
            (0.5, -3.4),
            (1.7, -1.6),
            (3.0, -0.65),
            (4.2, 0.05),
            (1.8, 0.3),
            (-0.9, -0.05),
            (-3.9, -0.9),
            (-7.0, -2.1),
        ];
        for (index, (x, y)) in outline.into_iter().enumerate() {
            mesh.colored_vertex(p(x, y), fill);
            mesh.add_triangle(
                0,
                index as u32 + 1,
                (index + 1) as u32 % outline.len() as u32 + 1,
            );
        }
        painter.add(Shape::mesh(mesh));
    }
}
