// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! CJK / wide-Unicode fallback fonts (issue #28, "additional issue").
//!
//! egui's bundled fonts cover Latin, Cyrillic, Greek, and emoji but no
//! CJK, so a vault or file name containing e.g. Chinese characters
//! rendered as empty boxes. We can't bundle a CJK font (the smallest
//! usable ones are ~15 MB and would triple the binary), but every
//! desktop OS ships one, so at startup we append the first system
//! fonts we can read to the END of egui's fallback chains: Latin
//! rendering is untouched, and glyphs egui's own fonts lack fall
//! through to the system font.
//!
//! Everything here is best-effort: a missing file, a locked-down
//! fonts directory, or an unparseable font must never stop the GUI
//! from starting - worst case the boxes stay.

use std::sync::Arc;

/// One candidate system font: a short stable egui font name, the file
/// to read, and which face of a .ttc collection to use.
struct Candidate {
    name: &'static str,
    path: std::path::PathBuf,
    index: u32,
}

/// Windows: Microsoft YaHei (simplified Chinese + kana + Latin,
/// ships since Vista - covers the report in issue #28) plus Malgun
/// Gothic (Korean hangul, which YaHei lacks). Traditional-Chinese and
/// Japanese text falls back to YaHei's unified-ideograph glyphs.
#[cfg(target_os = "windows")]
fn candidates() -> Vec<Candidate> {
    let fonts_dir = std::path::PathBuf::from(
        std::env::var_os("WINDIR").unwrap_or_else(|| "C:\\Windows".into()),
    )
    .join("Fonts");
    vec![
        Candidate {
            name: "sys-cjk",
            path: fonts_dir.join("msyh.ttc"),
            index: 0,
        },
        Candidate {
            name: "sys-hangul",
            path: fonts_dir.join("malgun.ttf"),
            index: 0,
        },
    ]
}

/// macOS: PingFang (Chinese ideographs) + Apple SD Gothic Neo
/// (hangul) + Hiragino Sans (kana). All /System/Library/Fonts paths
/// are stable across recent macOS releases; whichever are readable
/// get used.
#[cfg(target_os = "macos")]
fn candidates() -> Vec<Candidate> {
    let sys = std::path::Path::new("/System/Library/Fonts");
    vec![
        Candidate {
            name: "sys-cjk",
            path: sys.join("PingFang.ttc"),
            index: 0,
        },
        Candidate {
            name: "sys-kana",
            path: sys.join("ヒラギノ角ゴシック W3.ttc"),
            index: 0,
        },
        Candidate {
            name: "sys-hangul",
            path: sys.join("AppleSDGothicNeo.ttc"),
            index: 0,
        },
    ]
}

/// Linux/BSD: Noto Sans CJK under its common distro paths, then
/// WenQuanYi Zen Hei. Each Noto CJK face carries the full pan-CJK
/// repertoire (ideographs + kana + hangul; the faces differ only in
/// regional glyph variants), so face index 0 is fine and the first
/// hit is enough.
#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn candidates() -> Vec<Candidate> {
    [
        // Debian / Ubuntu
        "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
        // Arch
        "/usr/share/fonts/noto-cjk/NotoSansCJK-Regular.ttc",
        // Fedora (variable-font packaging)
        "/usr/share/fonts/google-noto-sans-cjk-vf-fonts/NotoSansCJK-VF.ttc",
        "/usr/share/fonts/google-noto-cjk/NotoSansCJK-Regular.ttc",
        // openSUSE
        "/usr/share/fonts/truetype/NotoSansCJK-Regular.ttc",
        // WenQuanYi (Debian/Ubuntu path)
        "/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc",
    ]
    .iter()
    .map(|p| Candidate {
        name: "sys-cjk",
        path: std::path::PathBuf::from(p),
        index: 0,
    })
    .collect()
}

/// True iff `bytes` starts with a plausible TTF/OTF/TTC magic. epaint
/// PANICS on an unparseable font file, so gate on the magic rather
/// than crashing the whole GUI over a truncated or exotic file.
fn looks_like_font(bytes: &[u8]) -> bool {
    matches!(
        bytes.get(..4),
        Some(b"\x00\x01\x00\x00") | Some(b"OTTO") | Some(b"ttcf") | Some(b"true")
    )
}

/// Append whichever candidate system fonts exist to egui's fallback
/// chains (proportional + monospace). Call once at startup, before the
/// first frame.
pub fn install_unicode_fallbacks(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    let mut installed = false;
    for cand in candidates() {
        // Two candidates may share a `name` (the Linux first-hit list);
        // keep only the first that loads.
        if fonts.font_data.contains_key(cand.name) {
            continue;
        }
        let Ok(bytes) = std::fs::read(&cand.path) else {
            continue;
        };
        if !looks_like_font(&bytes) {
            continue;
        }
        let mut data = egui::FontData::from_owned(bytes);
        data.index = cand.index;
        fonts.font_data.insert(cand.name.to_owned(), Arc::new(data));
        for family in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
            fonts
                .families
                .entry(family)
                .or_default()
                .push(cand.name.to_owned());
        }
        installed = true;
    }
    if installed {
        ctx.set_fonts(fonts);
    }
}
