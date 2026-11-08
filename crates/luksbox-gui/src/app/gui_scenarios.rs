//! Headless GUI scenarios: the real `LuksboxApp` driven through its
//! widgets with egui_kittest (AccessKit), no display needed. Each step
//! clicks or types into a widget found by its label, waits for the
//! worker the app started, and checks the result on disk.
//!
//! Argon2id at the real presets is slow in a debug build; run with
//! `--config 'profile.dev.package.argon2.opt-level=3'` (TESTING.md).

use super::*;
use egui::accesskit::Role;
use egui_kittest::Harness;
use egui_kittest::kittest::{By, NodeT, Queryable};
use std::time::Instant;

struct Gui {
    h: Harness<'static, LuksboxApp>,
    /// Every toast shown so far, in order.
    log: Vec<String>,
}

impl Gui {
    fn new() -> Self {
        let mut frame = eframe::Frame::_new_kittest();
        let h = Harness::builder()
            .with_size(SCREEN)
            // One frame per queued event: at the default 1/4 s a
            // double-click spans 0.75 s, past egui's 0.3 s window.
            .with_step_dt(1.0 / 60.0)
            .build_ui_state(
                move |ui, app: &mut LuksboxApp| {
                    <LuksboxApp as eframe::App>::ui(app, ui, &mut frame);
                },
                LuksboxApp::new_with_vault(None),
            );
        let mut g = Gui { h, log: Vec::new() };
        g.frames(3);
        g
    }

    fn app(&self) -> &LuksboxApp {
        self.h.state()
    }

    fn frames(&mut self, n: usize) {
        for _ in 0..n {
            self.h.step();
            for t in &self.h.state().toasts {
                if self.log.last() != Some(&t.text) && !self.log.contains(&t.text) {
                    self.log.push(t.text.clone());
                }
            }
        }
    }

    /// Click a widget, scrolling it into view first when it is off
    /// screen, as a user would. (A scroll request is consumed by the
    /// next scroll area drawn, so it is only made when needed: on a
    /// visible button it scrolled the page that button opened.)
    fn click(&mut self, label: &str) {
        // A button can wait on background work (Unlock is enabled once
        // the vault's keyslots were read): give it time, as a user would.
        let start = Instant::now();
        while self.h.get_by_label(label).accesskit_node().is_disabled() {
            assert!(
                start.elapsed() < Duration::from_secs(60),
                "{label:?} stayed disabled\n{}",
                dump(&self.h)
            );
            self.frames(1);
            std::thread::sleep(Duration::from_millis(5));
        }
        if !on_screen(self.h.get_by_label(label).rect()) {
            self.h.get_by_label(label).scroll_to_me();
            self.settle(|h| h.get_by_label(label).rect());
        }
        self.h.get_by_label(label).click();
        self.frames(3);
    }

    fn click_contains(&mut self, label: &str) {
        if !on_screen(self.h.get_by_label_contains(label).rect()) {
            self.h.get_by_label_contains(label).scroll_to_me();
            self.settle(|h| h.get_by_label_contains(label).rect());
        }
        self.h.get_by_label_contains(label).click();
        self.frames(3);
    }

    /// Run frames until a widget stops moving (the scroll into view is
    /// animated).
    fn settle(&mut self, rect: impl Fn(&Harness<'static, LuksboxApp>) -> egui::Rect) {
        // The scroll starts a frame or two after the request: wait for
        // ten still frames, not one.
        let mut last = rect(&self.h);
        let mut still = 0;
        for _ in 0..600 {
            self.frames(1);
            let now = rect(&self.h);
            still = if now == last { still + 1 } else { 0 };
            if still >= 10 {
                return;
            }
            last = now;
        }
    }

    /// Type into the `index`-th widget of `role` (text or password input).
    fn type_nth(&mut self, role: Role, index: usize, text: &str) {
        let node = self
            .h
            .query_all_by_role(role)
            .nth(index)
            .unwrap_or_else(|| panic!("no {role:?} #{index}\n{}", dump(&self.h)));
        if !on_screen(node.rect()) {
            node.scroll_to_me();
            self.settle(|h| h.query_all_by_role(role).nth(index).unwrap().rect());
        }
        let node = self.h.query_all_by_role(role).nth(index).unwrap();
        node.focus();
        self.frames(1);
        self.h
            .query_all_by_role(role)
            .nth(index)
            .unwrap()
            .type_text(text);
        self.frames(2);
    }

    fn type_placeholder(&mut self, placeholder: &str, text: &str) {
        self.h
            .get_by(move |n| n.placeholder() == Some(placeholder))
            .focus();
        self.frames(1);
        self.h
            .get_by(move |n| n.placeholder() == Some(placeholder))
            .type_text(text);
        self.frames(2);
    }

    /// The typed-path prompt that replaces the file dialog
    /// (LUKSBOX_GUI_TYPED_PATHS): type the path, press OK.
    fn answer_path_prompt(&mut self, path: &Path) {
        assert!(
            self.app().path_prompt.is_some(),
            "no path prompt\n{}",
            dump(&self.h)
        );
        self.type_placeholder("/home/you/...", &path.display().to_string());
        self.click("OK");
    }

    fn saw(&self, needle: &str) -> bool {
        self.log.iter().any(|t| t.contains(needle))
    }

    fn assert_saw(&self, needle: &str) {
        assert!(
            self.saw(needle),
            "no toast containing {needle:?}; toasts: {:#?}",
            self.log
        );
    }

    fn assert_no_error(&self) {
        let errs: Vec<_> = self
            .h
            .state()
            .toasts
            .iter()
            .filter(|t| t.kind == ToastKind::Err)
            .map(|t| t.text.clone())
            .collect();
        assert!(errs.is_empty(), "error toasts: {errs:#?}");
    }
}

const SCREEN: egui::Vec2 = egui::vec2(1180.0, 760.0);

/// Comfortably visible: not under the bottom edge, where the page's
/// scroll area is clipped by the panel margins (a widget there is only
/// partly drawn and its centre does not take clicks).
fn on_screen(r: egui::Rect) -> bool {
    egui::Rect::from_min_max(egui::Pos2::ZERO, egui::pos2(SCREEN.x, SCREEN.y - 60.0))
        .contains_rect(r)
}

fn dump(h: &Harness<'_, LuksboxApp>) -> String {
    let mut out = String::new();
    for n in h.query_all(By::new()) {
        let a = n.accesskit_node();
        let label = a.label().unwrap_or_default();
        let value = a.value().unwrap_or_default();
        let ph = a.placeholder().unwrap_or_default();
        let role = a.role();
        if matches!(role, Role::TextRun) {
            continue;
        }
        if label.is_empty()
            && value.is_empty()
            && ph.is_empty()
            && !matches!(role, Role::TextInput | Role::PasswordInput)
        {
            continue;
        }
        if matches!(role, Role::Label) && value.len() > 60 {
            continue;
        }
        out.push_str(&format!(
            "{role:?}{} label={label:?} value={value:?} ph={ph:?}\n",
            if a.is_disabled() { " DISABLED" } else { "" }
        ));
    }
    out
}

fn isolate_env(dir: &Path) {
    // SAFETY: test-only; every test that sets these holds
    // `crate::test_env_lock()`.
    unsafe {
        std::env::set_var("HOME", dir);
        std::env::set_var("XDG_DATA_HOME", dir.join("data"));
        std::env::set_var("XDG_CONFIG_HOME", dir.join("config"));
        std::env::set_var("LUKSBOX_GUI_TYPED_PATHS", "1");
        std::env::set_var("LUKSBOX_SYNC_STATE_DIR", dir.join("sync-state"));
    }
}

const PASS: &str = "Gui-Scenario-Passphrase-Long-73";
const PASS2: &str = "Second-Gui-Keyslot-Passphrase-58";

impl Gui {
    /// Run frames until `done(app)` holds.
    fn wait_until(&mut self, what: &str, done: impl Fn(&LuksboxApp) -> bool) -> Duration {
        let start = Instant::now();
        while !done(self.app()) {
            self.frames(1);
            assert!(
                start.elapsed() < Duration::from_secs(300),
                "{what}: not done after 5 min; toasts {:#?}\n{}",
                self.log,
                dump(&self.h)
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        let took = start.elapsed();
        self.frames(3);
        took
    }

    fn click_last(&mut self, label: &str) {
        let n = self
            .h
            .query_all_by_label(label)
            .last()
            .unwrap_or_else(|| panic!("no {label:?}\n{}", dump(&self.h)));
        n.click();
        self.frames(3);
    }

    fn row_menu(&mut self, row: &str, item: &str) {
        self.h.get_by_value(row).click_secondary();
        self.frames(3);
        self.click(item);
    }

    fn vfs(&mut self) -> &mut luksbox_vfs::Vfs {
        &mut self
            .h
            .state_mut()
            .vault
            .as_mut()
            .expect("a vault is open")
            .vfs
    }

    fn read_vault(&mut self, path: &str) -> Vec<u8> {
        let vfs = self.vfs();
        let id = vfs
            .lookup_path(path)
            .unwrap_or_else(|e| panic!("{path}: {e}"));
        let size = vfs.stat(id).unwrap().size as usize;
        let mut out = vec![0u8; size];
        let mut off = 0;
        while off < size {
            let n = vfs.read(id, off as u64, &mut out[off..]).unwrap();
            assert!(n > 0, "short read of {path}");
            off += n;
        }
        out
    }

    fn exists(&mut self, path: &str) -> bool {
        self.vfs().lookup_path(path).is_ok()
    }

    /// Fill the create form's passphrase and confirmation, press
    /// Create, wait for the vault to open.
    fn finish_create(&mut self, what: &str) -> Duration {
        self.type_nth(Role::PasswordInput, 0, PASS);
        self.type_nth(Role::PasswordInput, 1, PASS);
        if self.h.query_by_label("Create sync bundle").is_some() {
            self.click("Create sync bundle");
        } else {
            self.click("Create vault");
        }
        let t = self.wait_until(what, |a| {
            a.pending.is_none() && a.creating_bundle.is_none() && a.vault.is_some()
        });
        self.assert_no_error();
        t
    }

    /// The unlock form of a vault: passphrase, Unlock, wait.
    fn unlock_with(&mut self, pass: &str, what: &str) {
        self.wait_until(&format!("{what}: unlock form"), |a| {
            matches!(a.view, View::Unlock)
        });
        self.type_nth(Role::PasswordInput, 0, pass);
        self.click("Unlock");
        self.wait_until(what, |a| a.pending.is_none() && a.vault.is_some());
        self.assert_no_error();
    }

    /// Lock; answer "Give back free space?" (asked after deletes) by
    /// giving it back.
    fn lock(&mut self) -> bool {
        let vault_len = |a: &LuksboxApp| {
            a.vault
                .as_ref()
                .and_then(|v| std::fs::metadata(&v.vault_path).ok())
                .map(|m| m.len())
        };
        let before = vault_len(self.app());
        self.click("Lock");
        self.wait_until("lock or its shrink question", |a| {
            a.shrink_prompt.is_some() || (a.vault.is_none() && a.pending.is_none())
        });
        let asked = self.app().shrink_prompt.is_some();
        if asked {
            let give_back = |n: &egui_kittest::kittest::AccessKitNode<'_>| {
                n.role() == Role::Button && n.label().is_some_and(|l| l.starts_with("Give back "))
            };
            self.h.get_by(give_back).click();
            self.frames(3);
        }
        self.wait_until("lock", |a| {
            a.vault.is_none()
                && a.pending.is_none()
                && a.shrink_prompt.is_none()
                && !crate::sync_gui::finishing()
        });
        if asked {
            eprintln!("lock: shrink asked, vault was {before:?} bytes");
        }
        asked
    }

    fn add_folder(&mut self, local: &Path) -> Duration {
        self.click("+ Add folder...");
        self.answer_path_prompt(local);
        let t = self.wait_until("add folder", |a| a.pending.is_none());
        self.assert_no_error();
        t
    }
}

/// A local tree: `n` small files, a subfolder with one `big_mib` file.
fn make_tree(root: &Path, n: usize, big_mib: usize) -> Vec<(String, Vec<u8>)> {
    let mut files = Vec::new();
    std::fs::create_dir_all(root.join("sub")).unwrap();
    for i in 0..n {
        let data: Vec<u8> = (0..(500 + i * 37)).map(|b| (b * 31 + i) as u8).collect();
        let rel = format!("f{i:04}.txt");
        std::fs::write(root.join(&rel), &data).unwrap();
        files.push((rel, data));
    }
    let big: Vec<u8> = (0..big_mib << 20).map(|b| (b % 251) as u8).collect();
    std::fs::write(root.join("sub/big.bin"), &big).unwrap();
    files.push(("sub/big.bin".into(), big));
    files
}

fn check_tree_in_vault(g: &mut Gui, inner: &str, files: &[(String, Vec<u8>)]) {
    for (rel, data) in files {
        let got = g.read_vault(&format!("{inner}/{rel}"));
        assert!(got == *data, "{inner}/{rel}: content differs");
    }
}

fn check_tree_on_disk(root: &Path, files: &[(String, Vec<u8>)]) {
    for (rel, data) in files {
        let got = std::fs::read(root.join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"));
        assert!(got == *data, "{rel}: extracted content differs");
    }
}

fn is_mounted(mp: &Path) -> bool {
    let m = std::fs::read_to_string("/proc/self/mounts").unwrap_or_default();
    let mp = mp.display().to_string();
    m.lines().any(|l| l.split(' ').nth(1) == Some(mp.as_str()))
}

fn mib_s(bytes: usize, t: Duration) -> String {
    format!("{:.1} MB/s", bytes as f64 / 1e6 / t.as_secs_f64())
}

/// Every GUI path a user takes with a vault file, a sync bundle and a
/// hardened vault (detached header, anchor, hidden sizes): create, the
/// browser's file actions, keyslots, lock and unlock, mount, bundle
/// conversion. Checks the vault contents and the extracted files.
/// Runs `gui_scenarios_end_to_end` in a process of its own (this test
/// binary, filtered to that one test): the GUI keeps process-wide state
/// (the open sync bundle session, HOME and XDG variables) that other
/// tests of this binary also touch when they run in parallel threads.
#[test]
fn gui_scenarios_end_to_end_in_its_own_process() {
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "app::gui_scenarios::gui_scenarios_end_to_end",
            "--exact",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    // The timings and the toasts, for the log.
    eprintln!("{text}");
    assert!(
        out.status.success() && text.contains("1 passed"),
        "GUI end-to-end scenario failed"
    );
}

#[test]
#[ignore = "run by gui_scenarios_end_to_end_in_its_own_process (process-wide \
            state); run it alone with --ignored, see TESTING.md"]
fn gui_scenarios_end_to_end() {
    let _env = crate::test_env_lock();
    let tmp = tempfile::tempdir().unwrap();
    let w = tmp.path();
    isolate_env(w);
    let tree_mib: usize = std::env::var("LUKSBOX_GUI_SCENARIO_MIB")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4);
    let tree = w.join("photos");
    let files = make_tree(&tree, 120, tree_mib);
    let tree_bytes: usize = files.iter().map(|(_, d)| d.len()).sum();
    let mut timings: Vec<(String, String)> = Vec::new();

    let mut g = Gui::new();

    // ---- 1. Vault file, passphrase ------------------------------------
    g.click("+ Create a new vault");
    let vault = w.join("gui.lbx");
    g.type_placeholder(
        &path_hints::home("secret.lbx"),
        &vault.display().to_string(),
    );
    let t = g.finish_create("create .lbx");
    timings.push(("create (.lbx, Interactive KDF)".into(), format!("{t:.2?}")));
    assert!(vault.is_file());
    g.assert_saw("vault created");
    assert!(g.app().recent_list.iter().any(|r| r.path == vault));

    // New folder: the name field has the focus, Enter creates it.
    g.click("+ Folder");
    g.h.event(egui::Event::Text("docs".into()));
    g.frames(1);
    g.h.key_press(egui::Key::Enter);
    g.frames(3);
    assert!(g.exists("/docs"), "toasts {:?}", g.log);

    // Add one file.
    let hello = w.join("hello.txt");
    std::fs::write(&hello, b"hello from the gui").unwrap();
    g.click("+ Add files...");
    g.answer_path_prompt(&hello);
    g.wait_until("add file", |a| a.pending.is_none());
    assert_eq!(g.read_vault("/hello.txt"), b"hello from the gui");

    // Add a folder tree.
    let t = g.add_folder(&tree);
    timings.push((
        ".lbx: + Add folder".into(),
        format!("{t:.2?} ({})", mib_s(tree_bytes, t)),
    ));
    check_tree_in_vault(&mut g, "/photos", &files);

    // Browse: double-click a folder, back to the parent.
    g.h.get_by_value("docs").click();
    g.h.get_by_value("docs").click();
    g.frames(3);
    assert_eq!(g.app().cwd, "/docs");
    // A folder made in a subfolder is reported with its full path.
    g.click("+ Folder");
    g.h.event(egui::Event::Text("inner".into()));
    g.frames(1);
    g.h.key_press(egui::Key::Enter);
    g.frames(3);
    assert!(g.exists("/docs/inner"));
    g.assert_saw("created /docs/inner");
    g.click_contains("parent dir");
    assert_eq!(g.app().cwd, "/");

    // Rename: select the row, F2, type, Enter.
    g.h.get_by_value("hello.txt").click();
    g.frames(2);
    g.h.key_press(egui::Key::F2);
    g.frames(3);
    g.h.key_press_modifiers(egui::Modifiers::COMMAND, egui::Key::A);
    g.frames(1);
    g.h.event(egui::Event::Text("renamed.txt".into()));
    g.frames(1);
    g.h.key_press(egui::Key::Enter);
    g.frames(3);
    assert!(
        g.exists("/renamed.txt") && !g.exists("/hello.txt"),
        "toasts {:?}",
        g.log
    );

    // Download a file (typed destination).
    let out_file = w.join("out.txt");
    g.row_menu("renamed.txt", "Download...");
    g.answer_path_prompt(&out_file);
    g.wait_until("download file", |a| a.pending.is_none());
    assert_eq!(std::fs::read(&out_file).unwrap(), b"hello from the gui");

    // Download a folder, recursively.
    let out_dir = w.join("extracted");
    std::fs::create_dir(&out_dir).unwrap();
    g.row_menu("photos", "Download (recursive)...");
    g.answer_path_prompt(&out_dir);
    let t = g.wait_until("download folder", |a| a.pending.is_none());
    g.assert_no_error();
    timings.push((
        ".lbx: Download (recursive)".into(),
        format!("{t:.2?} ({})", mib_s(tree_bytes, t)),
    ));
    check_tree_on_disk(&out_dir.join("photos"), &files);

    // Delete a file, then a folder with its content (confirmation).
    g.row_menu("renamed.txt", "Delete");
    g.click_last("Delete");
    assert!(!g.exists("/renamed.txt"), "toasts {:?}", g.log);
    g.row_menu("photos", "Delete");
    g.click_last("Delete");
    assert!(!g.exists("/photos"), "toasts {:?}", g.log);

    // Vault size dialog.
    g.click("Vault size");
    assert!(g.app().size_dialog.is_some());
    let size_screen = dump(&g.h);
    g.h.key_press(egui::Key::Escape);
    g.frames(3);
    if g.app().size_dialog.is_some() {
        g.click_last("Close");
    }
    assert!(g.app().size_dialog.is_none(), "{size_screen}");

    // Keyslots: add a second passphrase.
    g.click("Keyslots");
    g.click("+ Add passphrase keyslot");
    g.type_nth(Role::PasswordInput, 0, PASS2);
    if g.h.query_all_by_role(Role::PasswordInput).count() > 1 {
        g.type_nth(Role::PasswordInput, 1, PASS2);
    }
    g.click("Enroll");
    g.wait_until("enroll passphrase", |a| a.pending.is_none());
    g.assert_saw("enrolled passphrase in slot");
    g.assert_no_error();
    g.click("< Back");

    // Lock (after the deletes it offers to give the space back), then
    // unlock from Recent with the new passphrase.
    let len_before = std::fs::metadata(&vault).unwrap().len();
    assert!(
        g.lock(),
        "no 'give back free space' question after deleting 4 MB"
    );
    let len_after = std::fs::metadata(&vault).unwrap().len();
    assert!(
        len_after < len_before,
        "vault not shrunk: {len_before} -> {len_after}"
    );
    g.h.get_all_by_value("gui.lbx").next().unwrap().click();
    g.frames(3);
    g.unlock_with(PASS2, "unlock with the second keyslot");
    assert!(g.exists("/docs/inner"));

    // Mount, write through the mount, unmount, check in the vault.
    if Path::new("/dev/fuse").exists() && luksbox_mount::FUSE_BACKEND != "none" {
        let mp = w.join("mnt");
        std::fs::create_dir(&mp).unwrap();
        g.click("Mount as volume...");
        g.answer_path_prompt(&mp);
        g.wait_until("mount", |a| a.mount_status.is_some());
        let start = Instant::now();
        while !is_mounted(&mp) {
            g.frames(1);
            assert!(
                start.elapsed() < Duration::from_secs(30),
                "mount never appeared"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        std::fs::write(mp.join("via-mount.txt"), b"written through FUSE").unwrap();
        assert!(mp.join("docs/inner").is_dir());
        g.click("Unmount");
        g.wait_until("unmount", |a| a.mount_status.is_none());
        assert!(!is_mounted(&mp));
        g.h.get_all_by_value("gui.lbx").next().unwrap().click();
        g.frames(3);
        g.unlock_with(PASS, "unlock after the mount");
        assert_eq!(g.read_vault("/via-mount.txt"), b"written through FUSE");
    } else {
        eprintln!("no /dev/fuse: mount step skipped");
    }

    // Make a sync bundle out of the open vault (typed folder).
    let bundles = w.join("Dropbox");
    std::fs::create_dir(&bundles).unwrap();
    g.click("Make sync bundle...");
    g.answer_path_prompt(&bundles);
    g.wait_until("make sync bundle", |a| a.pending.is_none());
    g.assert_no_error();
    assert!(
        crate::sync_gui::is_bundle(&bundles.join("gui.lbxs")),
        "toasts {:?}",
        g.log
    );
    g.lock();

    // ---- 2. Sync bundle created from the form --------------------------
    g.click("+ New vault");
    g.click("Sync bundle (.lbxs folder), experimental");
    let bundle = bundles.join("shared.lbxs");
    g.type_placeholder(
        &path_hints::home("Dropbox/secret.lbxs"),
        &bundle.display().to_string(),
    );
    let t = g.finish_create("create bundle");
    timings.push(("create (sync bundle)".into(), format!("{t:.2?}")));
    assert!(crate::sync_gui::is_bundle(&bundle));
    let t = g.add_folder(&tree);
    timings.push((
        "bundle: + Add folder".into(),
        format!("{t:.2?} ({})", mib_s(tree_bytes, t)),
    ));
    check_tree_in_vault(&mut g, "/photos", &files);
    g.click("Versions");
    g.frames(10);
    g.wait_until("versions list", |a| {
        a.versions.as_ref().is_some_and(|v| v.list.is_some())
    });
    let versions = match &g.app().versions.as_ref().unwrap().list {
        Some(Ok(l)) => l.len(),
        other => panic!("versions: {:?}", other.as_ref().map(|r| r.as_ref().err())),
    };
    assert!(versions >= 1, "no version listed");
    g.click("< Back");
    let t0 = Instant::now();
    g.lock();
    timings.push((
        "bundle: Lock (publish)".into(),
        format!("{:.2?}", t0.elapsed()),
    ));
    // Reopen it from Recent: the change was published and is there.
    g.h.get_all_by_value("shared.lbxs").next().unwrap().click();
    g.frames(3);
    g.unlock_with(PASS, "reopen the bundle");
    check_tree_in_vault(&mut g, "/photos", &files);
    g.lock();

    // ---- 3. Detached header, anchor, hidden sizes ----------------------
    g.click("+ New vault");
    let hard = w.join("hard.lbx");
    let hdr = w.join("usb/hard.hdr");
    let anchor = w.join("usb/hard.anchor");
    std::fs::create_dir(w.join("usb")).unwrap();
    g.type_placeholder(&path_hints::home("secret.lbx"), &hard.display().to_string());
    g.click_contains("Use a detached header sidecar");
    g.type_placeholder(&path_hints::usb("secret.hdr"), &hdr.display().to_string());
    g.click_contains("Rollback-detection anchor");
    g.type_placeholder(
        &path_hints::usb("secret.anchor"),
        &anchor.display().to_string(),
    );
    g.click("Advanced size-hiding (paranoid)");
    g.click_contains("Hide exact sizes");
    // A small metadata region: cheaper saves on slow storage.
    g.click("On-disk format (advanced)");
    let combo = |n: &egui_kittest::kittest::AccessKitNode<'_>| {
        n.role() == Role::ComboBox && n.value().is_some_and(|v| v == "64 MiB")
    };
    g.h.get_by(combo).click();
    g.frames(3);
    g.click("4 MiB: about 80 000 files");
    assert_eq!(g.app().create.metadata_mib, 4);
    g.finish_create("create hardened vault");
    assert_eq!(g.vfs().container().header.metadata_size, 4 << 20);
    assert!(hard.is_file() && hdr.is_file() && anchor.is_file());
    let t = g.add_folder(&tree);
    timings.push((
        "detached+anchor+hidden sizes: + Add folder".into(),
        format!("{t:.2?} ({})", mib_s(tree_bytes, t)),
    ));
    g.lock();
    g.h.get_all_by_value("hard.lbx").next().unwrap().click();
    g.frames(3);
    g.unlock_with(PASS, "unlock the hardened vault");
    check_tree_in_vault(&mut g, "/photos", &files);
    g.lock();

    // ---- 4. Deniable vault: create, add a file, reopen by path ----------
    g.click("+ New vault");
    let den = w.join("den.dat");
    g.type_placeholder(&path_hints::home("secret.lbx"), &den.display().to_string());
    g.click_contains("Use a deniable header");
    g.finish_create("create deniable vault");
    assert!(g.vfs().container().is_deniable());
    let note = w.join("note.txt");
    std::fs::write(&note, b"deniable note").unwrap();
    g.click("+ Add files...");
    g.answer_path_prompt(&note);
    g.wait_until("add file (deniable)", |a| a.pending.is_none());
    // Rotation is not offered for a deniable vault, and the page says why.
    g.click("Keyslots");
    assert!(g.h.query_by_label("Rotate master key...").is_none());
    assert!(
        g.h.query_by_label_contains("deniable vault's master key cannot be rotated")
            .is_some()
            || g.h.query_all_by_role(Role::Label).any(|n| n
                .accesskit_node()
                .value()
                .is_some_and(|v| v.contains("deniable vault's master key cannot be rotated"))),
        "{}",
        dump(&g.h)
    );
    g.click("< Back");
    g.lock();
    // A deniable vault is never in Recent: open it by path.
    g.click("Type path manually...");
    g.type_placeholder(
        "path to .lbx (or any vault file)",
        &den.display().to_string(),
    );
    g.click_contains("This vault uses a deniable header");
    g.unlock_with(PASS, "unlock the rotated deniable vault");
    assert_eq!(g.read_vault("/note.txt"), b"deniable note");
    g.lock();

    eprintln!(
        "GUI scenario timings ({} files, {tree_bytes} bytes):",
        files.len()
    );
    for (k, v) in &timings {
        eprintln!("  {k:<45} {v}");
    }
    eprintln!("toasts: {:#?}", g.log);
}

/// A toast must not take the clicks meant for what is under it: its
/// area stretched to about 600 x 400 px in the lower right, so for the
/// five seconds after every operation the buttons there did nothing
/// (here "+ Add passphrase keyslot", right after "vault created").
#[test]
fn a_toast_does_not_block_clicks_under_it() {
    let _env = crate::test_env_lock();
    let tmp = tempfile::tempdir().unwrap();
    isolate_env(tmp.path());
    let mut g = Gui::new();
    g.click("+ Create a new vault");
    g.type_placeholder(
        &path_hints::home("secret.lbx"),
        &tmp.path().join("k.lbx").display().to_string(),
    );
    g.finish_create("create");
    g.click("Keyslots");
    assert!(
        !g.app().toasts.is_empty(),
        "the create toast is still shown"
    );
    let toast_area = g.h.ctx.memory(|m| {
        m.layer_ids()
            .filter(|l| l.order == egui::Order::Tooltip)
            .filter_map(|l| m.area_rect(l.id))
            .next()
    });
    let toast_area = toast_area.expect("a toast area");
    assert!(
        toast_area.width() < 400.0 && toast_area.height() < 120.0,
        "toast area {toast_area:?} covers the page"
    );
    g.click("+ Add passphrase keyslot");
    assert!(
        g.app().add_passphrase_modal.is_some(),
        "the click did not reach the button"
    );
}
