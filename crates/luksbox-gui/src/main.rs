// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

// Pure-Rust GUI for LUKSbox. No webview, no JS, no HTML, only egui drawing
// commands and direct calls into the audited luksbox-* crates.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod clipboard_guard;
mod ops;
mod preferences;
mod recent;
mod theme;

use app::LuksboxApp;

/// PNGs embedded at compile time. Replace the files in
/// `crates/luksbox-gui/assets/` with your branding and rebuild.
const ICON_PNG: &[u8] = include_bytes!("../assets/icon.png");

fn main() -> eframe::Result<()> {
    // Process-wide hardening before we touch any keying material.
    luksbox_core::secret_mem::disable_core_dumps();
    let _ = luksbox_core::secret_mem::enable_memory_lock();

    // First positional arg = initial vault path. Set when the user
    // double-clicks a .lbx in Nautilus / Dolphin (Exec=luksbox-gui %f
    // in com.penthertz.luksbox.desktop) or runs `luksbox-gui foo.lbx`
    // from a shell. Anything that's not a real file is ignored.
    let initial_vault = std::env::args_os()
        .nth(1)
        .map(std::path::PathBuf::from)
        .filter(|p| p.is_file());

    let icon = decode_icon(ICON_PNG);

    let opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("LUKSbox")
            .with_inner_size([1180.0, 760.0])
            .with_min_inner_size([880.0, 540.0])
            .with_app_id("com.penthertz.luksbox")
            .with_icon(std::sync::Arc::new(icon)),
        ..Default::default()
    };
    eframe::run_native(
        "LUKSbox",
        opts,
        Box::new(|cc| {
            theme::install(&cc.egui_ctx);
            // egui_extras handles `Image::from_bytes(...)` decoding.
            egui_extras::install_image_loaders(&cc.egui_ctx);
            // Manual zoom override for fractional-DPI displays.
            //   LUKSBOX_GUI_ZOOM=1.5  -> render at 1.5x (e.g. for GPD-class
            //   handhelds where the OS reports 200% but the actual pixel
            //   density makes egui's hit-rect rounding drift on the
            //   right/bottom of long pages).
            // Without the env var we default to whatever eframe detected
            // from the OS. Users can also press Ctrl++/Ctrl+- in-app to
            // adjust live; the runtime handler is in `LuksboxApp::ui`.
            if let Some(z) = std::env::var("LUKSBOX_GUI_ZOOM")
                .ok()
                .and_then(|s| s.parse::<f32>().ok())
                .filter(|z| (0.5..=4.0).contains(z))
            {
                cc.egui_ctx.set_zoom_factor(z);
            }
            Ok(Box::new(LuksboxApp::new_with_vault(initial_vault)))
        }),
    )
}

/// Decode a PNG into the (raw RGBA, width, height) shape eframe wants.
/// Falls back to a 1x1 transparent icon if the PNG is malformed.
fn decode_icon(bytes: &[u8]) -> egui::IconData {
    match image::load_from_memory(bytes) {
        Ok(img) => {
            let img = img.into_rgba8();
            let (w, h) = img.dimensions();
            egui::IconData {
                rgba: img.into_raw(),
                width: w,
                height: h,
            }
        }
        Err(_) => egui::IconData {
            rgba: vec![0, 0, 0, 0],
            width: 1,
            height: 1,
        },
    }
}
