// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! `rfd::FileDialog` wrapper that tells a cancelled dialog apart from
//! one that never opened (GitHub issue #35).
//!
//! On Linux rfd 0.15 asks the XDG desktop portal for the file chooser
//! (on GNOME `xdg-desktop-portal-gnome`, which uses Nautilus) and, if
//! that fails, falls back to `zenity`. When both fail it logs the
//! errors through the `log` crate and returns `None`, the same value as
//! a user pressing Cancel. The GUI used to treat every `None` as a
//! cancel, so a broken portal made Browse, Mount, Add file and the
//! extract / save actions silently do nothing.
//!
//! `install_logger` routes `log` records to stderr and remembers rfd's
//! errors; the `pick_*` / `save_file` helpers report
//! [`Picked::Unavailable`] when the dialog could not be shown at all,
//! so callers can explain the failure and offer a typed path instead.
//! `LUKSBOX_GUI_TYPED_PATHS=1` skips the system dialog entirely (for a
//! portal that hangs rather than fails).

use std::path::PathBuf;
use std::sync::Mutex;

/// Outcome of a file / folder dialog.
pub enum Picked {
    Path(PathBuf),
    /// The dialog was shown and the user dismissed it.
    Cancelled,
    /// No dialog could be shown; carries the reason for the user.
    Unavailable(String),
}

/// rfd error records logged since the last dialog started.
static DIALOG_ERRORS: Mutex<Vec<String>> = Mutex::new(Vec::new());

struct GuiLogger;

static LOGGER: GuiLogger = GuiLogger;

impl log::Log for GuiLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::Level::Warn
    }

    fn log(&self, record: &log::Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let msg = record.args().to_string();
        eprintln!("luksbox-gui: [{}] {}", record.target(), msg);
        if record.target().starts_with("rfd")
            && record.level() == log::Level::Error
            && let Ok(mut errors) = DIALOG_ERRORS.lock()
        {
            errors.push(msg);
        }
    }

    fn flush(&self) {}
}

/// Route `log` records (warnings and errors) to stderr and capture
/// rfd's dialog errors. Call once at startup.
pub fn install_logger() {
    if log::set_logger(&LOGGER).is_ok() {
        log::set_max_level(log::LevelFilter::Warn);
    }
}

fn typed_paths_forced() -> bool {
    std::env::var_os("LUKSBOX_GUI_TYPED_PATHS").is_some_and(|v| !v.is_empty() && v != "0")
}

/// Classify a dialog result from the rfd errors logged during the call.
/// rfd logs "Failed to <op>: <portal error>" and then tries zenity; it
/// only gives up (and logs "... with zenity: ...") when that fails too.
/// A portal error alone therefore means zenity was shown, so `None` is
/// a genuine cancel.
fn classify(result: Option<PathBuf>, errors: Vec<String>) -> Picked {
    match result {
        Some(p) => Picked::Path(p),
        None if errors.iter().any(|e| e.contains("with zenity")) => {
            Picked::Unavailable(errors.join("; "))
        }
        None => Picked::Cancelled,
    }
}

fn run(dialog: impl FnOnce() -> Option<PathBuf>) -> Picked {
    if typed_paths_forced() {
        return Picked::Unavailable(
            "the system file dialog is disabled by LUKSBOX_GUI_TYPED_PATHS".into(),
        );
    }
    let take = || {
        DIALOG_ERRORS
            .lock()
            .map(|mut e| std::mem::take(&mut *e))
            .unwrap_or_default()
    };
    take();
    let result = dialog();
    classify(result, take())
}

pub fn pick_file(dialog: rfd::FileDialog) -> Picked {
    run(|| dialog.pick_file())
}

pub fn pick_folder(dialog: rfd::FileDialog) -> Picked {
    run(|| dialog.pick_folder())
}

pub fn save_file(dialog: rfd::FileDialog) -> Picked {
    run(|| dialog.save_file())
}

/// User-facing explanation for [`Picked::Unavailable`].
pub fn unavailable_message(reason: &str) -> String {
    format!(
        "The system file dialog could not be opened ({reason}). Type the path instead. \
         On Linux the dialog comes from xdg-desktop-portal (GNOME: xdg-desktop-portal-gnome, \
         which uses Nautilus); installing `zenity` gives LUKSbox a fallback dialog."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picked_path_wins_over_logged_errors() {
        let r = classify(
            Some(PathBuf::from("/x")),
            vec!["Failed to pick file: portal".into()],
        );
        assert!(matches!(r, Picked::Path(p) if p == std::path::Path::new("/x")));
    }

    #[test]
    fn no_errors_is_a_cancel() {
        assert!(matches!(classify(None, vec![]), Picked::Cancelled));
    }

    /// Portal failed but zenity was shown and dismissed: still a cancel.
    #[test]
    fn portal_error_alone_is_a_cancel() {
        let r = classify(None, vec!["Failed to pick file: no portal".into()]);
        assert!(matches!(r, Picked::Cancelled));
    }

    /// Portal and zenity both failed: no dialog was ever shown.
    #[test]
    fn portal_and_zenity_errors_mean_unavailable() {
        let r = classify(
            None,
            vec![
                "Failed to pick folder: org.freedesktop.portal.Error.Failed".into(),
                "Failed to pick folder with zenity: No such file or directory".into(),
            ],
        );
        match r {
            Picked::Unavailable(reason) => {
                assert!(reason.contains("portal.Error.Failed") && reason.contains("zenity"))
            }
            _ => panic!("expected Unavailable"),
        }
    }
}
