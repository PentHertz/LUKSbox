// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Centralised dark-theme styling for the egui app. Keeps colours and
//! spacing in one place so the views stay terse.

use egui::{Color32, CornerRadius, FontFamily, FontId, Stroke, TextStyle, Visuals};

pub const BG: Color32 = Color32::from_rgb(0x0e, 0x10, 0x14);
pub const PANEL: Color32 = Color32::from_rgb(0x16, 0x19, 0x22);
pub const PANEL2: Color32 = Color32::from_rgb(0x1d, 0x22, 0x30);
pub const BORDER: Color32 = Color32::from_rgb(0x26, 0x2b, 0x3a);
pub const TEXT: Color32 = Color32::from_rgb(0xe6, 0xe8, 0xee);
pub const DIM: Color32 = Color32::from_rgb(0x98, 0xa0, 0xb0);
pub const FAINT: Color32 = Color32::from_rgb(0x5b, 0x62, 0x75);
pub const ACCENT: Color32 = Color32::from_rgb(0x6a, 0xa3, 0xff);
pub const OK: Color32 = Color32::from_rgb(0x56, 0xd3, 0x97);
pub const WARN: Color32 = Color32::from_rgb(0xff, 0xb4, 0x54);
pub const DANGER: Color32 = Color32::from_rgb(0xff, 0x6f, 0x6f);

pub fn install(ctx: &egui::Context) {
    // Force LUKSbox to use the dark theme slot regardless of the OS
    // theme. egui's default `ThemePreference::System` reads the host
    // theme each frame and routes `set_visuals`/`set_global_style`
    // writes to whichever slot is "active" (dark_style or light_style).
    // On Windows in light mode that meant our custom-colored visuals
    // were being written into the LIGHT slot, while the framework still
    // asked Windows DWM for a light title bar + light scrollbars, which
    // mismatched our dark body. Locking to Dark here is what makes the
    // app look the same on every OS / system-theme combo.
    ctx.set_theme(egui::ThemePreference::Dark);
    // Push the same hint to the windowing system so Windows DWM paints
    // the title bar + caption buttons in dark mode and Linux/Wayland
    // window managers that honour preferred-color-scheme follow suit.
    // No-op on backends that don't expose a theme channel.
    ctx.send_viewport_cmd(egui::ViewportCommand::SetTheme(egui::SystemTheme::Dark));

    let mut v = Visuals::dark();
    v.window_fill = PANEL;
    v.panel_fill = BG;
    v.faint_bg_color = PANEL2;
    v.extreme_bg_color = BG;
    v.code_bg_color = PANEL2;
    v.override_text_color = Some(TEXT);
    v.hyperlink_color = ACCENT;
    v.selection.bg_fill = ACCENT.linear_multiply(0.35);
    v.selection.stroke = Stroke::new(1.0, ACCENT);
    v.widgets.noninteractive.bg_fill = PANEL;
    v.widgets.noninteractive.bg_stroke = Stroke::new(1.0, BORDER);
    v.widgets.noninteractive.fg_stroke = Stroke::new(1.0, DIM);
    v.widgets.inactive.bg_fill = PANEL2;
    v.widgets.inactive.bg_stroke = Stroke::new(1.0, BORDER);
    v.widgets.inactive.fg_stroke = Stroke::new(1.0, TEXT);
    v.widgets.inactive.weak_bg_fill = PANEL2;
    v.widgets.hovered.bg_fill = BORDER;
    v.widgets.hovered.bg_stroke = Stroke::new(1.0, DIM);
    v.widgets.hovered.fg_stroke = Stroke::new(1.0, TEXT);
    v.widgets.active.bg_fill = ACCENT.linear_multiply(0.30);
    v.widgets.active.bg_stroke = Stroke::new(1.0, ACCENT);
    v.widgets.active.fg_stroke = Stroke::new(1.0, TEXT);
    v.widgets.open.bg_fill = PANEL2;
    v.widgets.open.bg_stroke = Stroke::new(1.0, ACCENT);
    let r = CornerRadius::same(6);
    v.widgets.noninteractive.corner_radius = r;
    v.widgets.inactive.corner_radius = r;
    v.widgets.hovered.corner_radius = r;
    v.widgets.active.corner_radius = r;
    v.widgets.open.corner_radius = r;
    v.window_corner_radius = CornerRadius::same(10);
    v.menu_corner_radius = CornerRadius::same(8);
    ctx.set_visuals(v);

    let mut style = (*ctx.global_style()).clone();
    style.spacing.item_spacing = egui::vec2(8.0, 8.0);
    style.spacing.button_padding = egui::vec2(12.0, 6.0);
    style.spacing.interact_size = egui::vec2(40.0, 28.0);
    // Use SOLID scrollbars (own reserved column, outside the content
    // area) instead of egui's default `floating()` style. Floating
    // scrollbars overlay the rightmost ~bar_width pixels of the
    // content, every button / input / slider in that strip becomes
    // a dead zone where clicks go to the (invisible) scrollbar
    // instead of the widget. The widened-floating-bar version of this
    // theme made the dead zone painfully large.
    let mut scroll = egui::style::ScrollStyle::solid();
    scroll.bar_width = 10.0;
    scroll.handle_min_length = 32.0;
    // Bigger outer margin pushes the scrollbar further right so it
    // sits well clear of any content widget, eliminating the "right
    // edge of buttons / sliders is dead" symptom we saw at the
    // bottom of long ScrollArea-wrapped pages.
    scroll.bar_inner_margin = 8.0;
    scroll.bar_outer_margin = 6.0;
    style.spacing.scroll = scroll;
    style.text_styles.insert(
        TextStyle::Heading,
        FontId::new(22.0, FontFamily::Proportional),
    );
    style
        .text_styles
        .insert(TextStyle::Body, FontId::new(14.0, FontFamily::Proportional));
    style.text_styles.insert(
        TextStyle::Monospace,
        FontId::new(13.0, FontFamily::Monospace),
    );
    style.text_styles.insert(
        TextStyle::Button,
        FontId::new(13.0, FontFamily::Proportional),
    );
    style.text_styles.insert(
        TextStyle::Small,
        FontId::new(11.0, FontFamily::Proportional),
    );
    ctx.set_global_style(style);
}

pub fn pill(ui: &mut egui::Ui, text: impl Into<egui::WidgetText>, color: Color32) {
    let label = egui::Label::new(text.into().color(color));
    egui::Frame::new()
        .fill(color.linear_multiply(0.10))
        .stroke(Stroke::new(1.0, color))
        .corner_radius(CornerRadius::same(99))
        .inner_margin(egui::Margin::symmetric(8, 2))
        .show(ui, |ui| {
            ui.add(label);
        });
}
