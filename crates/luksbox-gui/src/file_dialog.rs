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
//!
//! On Linux the dialog runs in a helper process (see `helper`): the GUI
//! process is non-dumpable, which newer portals refuse to serve.

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

/// The options of a file dialog: the `rfd::FileDialog` options the GUI
/// uses, kept as plain data so a helper process can show the dialog.
#[derive(Clone, Default)]
pub struct Dialog {
    title: Option<String>,
    file_name: Option<String>,
    /// `(name, extensions)`; not passed to the helper process (a dialog
    /// with filters is shown in this process).
    filters: Vec<(String, Vec<String>)>,
}

impl Dialog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }

    pub fn set_file_name(mut self, name: impl Into<String>) -> Self {
        self.file_name = Some(name.into());
        self
    }

    pub fn add_filter(mut self, name: impl Into<String>, extensions: &[impl ToString]) -> Self {
        self.filters.push((
            name.into(),
            extensions.iter().map(|e| e.to_string()).collect(),
        ));
        self
    }

    fn to_rfd(&self) -> rfd::FileDialog {
        let mut d = rfd::FileDialog::new();
        if let Some(t) = &self.title {
            d = d.set_title(t);
        }
        if let Some(n) = &self.file_name {
            d = d.set_file_name(n);
        }
        for (name, extensions) in &self.filters {
            d = d.add_filter(name, extensions);
        }
        d
    }
}

#[derive(Clone, Copy)]
enum Op {
    PickFile,
    PickFolder,
    SaveFile,
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
impl Op {
    fn name(self) -> &'static str {
        match self {
            Op::PickFile => "pick-file",
            Op::PickFolder => "pick-folder",
            Op::SaveFile => "save-file",
        }
    }

    fn parse(name: &str) -> Option<Self> {
        [Op::PickFile, Op::PickFolder, Op::SaveFile]
            .into_iter()
            .find(|op| op.name() == name)
    }
}

/// Show the dialog in this process.
fn show_here(op: Op, dialog: &Dialog) -> Picked {
    let take = || {
        DIALOG_ERRORS
            .lock()
            .map(|mut e| std::mem::take(&mut *e))
            .unwrap_or_default()
    };
    take();
    let d = dialog.to_rfd();
    let result = match op {
        Op::PickFile => d.pick_file(),
        Op::PickFolder => d.pick_folder(),
        Op::SaveFile => d.save_file(),
    };
    classify(result, take())
}

fn show(op: Op, dialog: Dialog) -> Picked {
    if typed_paths_forced() {
        return Picked::Unavailable(
            "the system file dialog is disabled by LUKSBOX_GUI_TYPED_PATHS".into(),
        );
    }
    #[cfg(target_os = "linux")]
    if dialog.filters.is_empty()
        && let Some(picked) = helper::show(op, &dialog)
    {
        return picked;
    }
    show_here(op, &dialog)
}

pub fn pick_file(dialog: Dialog) -> Picked {
    show(Op::PickFile, dialog)
}

pub fn pick_folder(dialog: Dialog) -> Picked {
    show(Op::PickFolder, dialog)
}

pub fn save_file(dialog: Dialog) -> Picked {
    show(Op::SaveFile, dialog)
}

#[cfg(target_os = "linux")]
pub use helper::{HELPER_ARG, run_helper};

/// The dialog in a helper process (Linux).
///
/// The GUI makes itself non-dumpable at startup
/// (`secret_mem::disable_core_dumps`: no core dumps, and other processes
/// of the same user cannot read its memory). That also makes its
/// `/proc/<pid>/root` unreadable to them, and newer xdg-desktop-portal
/// versions open it to identify the calling app, so they refuse the
/// GUI ("Unable to open /proc/<pid>/root"). Each dialog therefore runs
/// in a new process of this binary, started with [`HELPER_ARG`]: a new
/// program is dumpable again, and this one holds no keys (`main` hands
/// it to [`run_helper`] before any hardening or vault code). It prints
/// the chosen path on stdout. If it cannot run, the dialog is shown in
/// this process as before (the portal refuses, rfd falls back to zenity).
#[cfg(target_os = "linux")]
mod helper {
    use std::ffi::OsString;
    use std::io::Write;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::process::CommandExt;
    use std::path::PathBuf;
    use std::process::{Command, Stdio};

    use super::{Dialog, Op, Picked, show_here};

    /// First argument that makes `luksbox-gui` a dialog helper:
    /// `--file-dialog-helper <op> <title> <file name>` (empty: not set).
    pub const HELPER_ARG: &str = "--file-dialog-helper";

    const PICKED: i32 = 0;
    const CANCELLED: i32 = 10;
    const UNAVAILABLE: i32 = 11;
    const USAGE: i32 = 64;

    /// `None` if the helper did not run or report (the caller then shows
    /// the dialog itself).
    pub(super) fn show(op: Op, dialog: &Dialog) -> Option<Picked> {
        // This very binary, even if the file was replaced since.
        let mut cmd = Command::new("/proc/self/exe");
        if let Some(argv0) = std::env::args_os().next() {
            cmd.arg0(argv0);
        }
        let out = cmd
            .arg(HELPER_ARG)
            .arg(op.name())
            .arg(dialog.title.as_deref().unwrap_or(""))
            .arg(dialog.file_name.as_deref().unwrap_or(""))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .output()
            .ok()?;
        parse_reply(out.status.code(), out.stdout)
    }

    fn parse_reply(code: Option<i32>, stdout: Vec<u8>) -> Option<Picked> {
        match code? {
            PICKED if stdout.is_empty() => Some(Picked::Cancelled),
            PICKED => Some(Picked::Path(PathBuf::from(OsString::from_vec(stdout)))),
            CANCELLED => Some(Picked::Cancelled),
            UNAVAILABLE => Some(Picked::Unavailable(
                String::from_utf8_lossy(&stdout).into_owned(),
            )),
            _ => None,
        }
    }

    /// The helper process: show the dialog described by `args` (what
    /// follows [`HELPER_ARG`]) and report it. Returns the exit code.
    pub fn run_helper(args: impl Iterator<Item = OsString>) -> i32 {
        let args: Vec<OsString> = args.collect();
        let [op, title, name] = args.as_slice() else {
            return USAGE;
        };
        let Some(op) = op.to_str().and_then(Op::parse) else {
            return USAGE;
        };
        let text = |s: &OsString| s.to_str().filter(|s| !s.is_empty()).map(str::to_owned);
        let dialog = Dialog {
            title: text(title),
            file_name: text(name),
            filters: Vec::new(),
        };
        let (code, reply) = match show_here(op, &dialog) {
            Picked::Path(p) => (PICKED, p.into_os_string().into_vec()),
            Picked::Cancelled => (CANCELLED, Vec::new()),
            Picked::Unavailable(reason) => (UNAVAILABLE, reason.into_bytes()),
        };
        let mut out = std::io::stdout().lock();
        match out.write_all(&reply).and_then(|()| out.flush()) {
            Ok(()) => code,
            Err(_) => 1,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn replies_are_read_back() {
            let path = |r| matches!(r, Some(Picked::Path(p)) if p == PathBuf::from("/a\nb"));
            assert!(path(parse_reply(Some(PICKED), b"/a\nb".to_vec())));
            assert!(matches!(
                parse_reply(Some(PICKED), Vec::new()),
                Some(Picked::Cancelled)
            ));
            assert!(matches!(
                parse_reply(Some(CANCELLED), Vec::new()),
                Some(Picked::Cancelled)
            ));
            assert!(matches!(
                parse_reply(Some(UNAVAILABLE), b"no portal".to_vec()),
                Some(Picked::Unavailable(r)) if r == "no portal"
            ));
            // Crashed, killed or usage error: show the dialog here.
            assert!(parse_reply(Some(101), Vec::new()).is_none());
            assert!(parse_reply(Some(USAGE), Vec::new()).is_none());
            assert!(parse_reply(None, Vec::new()).is_none());
        }

        #[test]
        fn malformed_requests_are_refused() {
            let run = |a: &[&str]| run_helper(a.iter().map(OsString::from));
            assert_eq!(run(&["pick-file", "t"]), USAGE);
            assert_eq!(run(&["pick-file", "t", "", "extra"]), USAGE);
            assert_eq!(run(&["format-disk", "t", ""]), USAGE);
        }
    }
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
