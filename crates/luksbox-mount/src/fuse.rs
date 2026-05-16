// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fuser::{
    AccessFlags, Config, Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags, Generation,
    INodeNo, MountOption, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty,
    ReplyEntry, ReplyOpen, ReplyWrite, Request, TimeOrNow,
};

use luksbox_vfs::{Error as VfsError, FileId, InodeKind, Vfs};

const TTL: Duration = Duration::from_secs(1);

pub fn mount(vfs: Vfs, mountpoint: &Path, daemonize: bool) -> std::io::Result<()> {
    // AutoUnmount intentionally NOT used: on Linux it implies allow_other,
    // which kernel rejects for non-root unless /etc/fuse.conf has
    // user_allow_other. Users unmount via `luksbox umount` /
    // `fusermount3 -u <path>`. SIGINT/SIGTERM trigger an equivalent clean
    // unmount through the handler installed in the daemon child.
    let mount_options = vec![
        MountOption::FSName("luksbox".to_string()),
        MountOption::Subtype("luksbox".to_string()),
        MountOption::DefaultPermissions,
        MountOption::NoSuid,
        MountOption::NoDev,
    ];
    let mut config = Config::default();
    config.mount_options = mount_options;

    // Pre-flight: best-effort mountpoint validation BEFORE forking, so the
    // user sees common errors (path missing, not a directory) in the
    // foreground process where stderr still goes to their terminal. Once
    // we daemonize, fuser's mount errors land in /dev/null.
    let meta = std::fs::metadata(mountpoint)?;
    if !meta.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotADirectory,
            format!("mountpoint {} is not a directory", mountpoint.display()),
        ));
    }

    let fs = LuksboxFs::new(vfs);

    if daemonize {
        run_daemonized(fs, mountpoint, config)
    } else {
        install_signal_handler(mountpoint);
        spawn_suspend_listener(mountpoint);
        // `mount2` does Session::new + run() in one call. Blocks until
        // the FS is unmounted (kernel signals EOF on /dev/fuse fd).
        fuser::mount2(fs, mountpoint, &config)
    }
}

/// Refuse to fork() if more than one thread is alive. Forking a
/// multithreaded process is a known POSIX footgun: only the calling
/// thread survives in the child, and the others' shared state (most
/// notably the libc allocator mutex) is left frozen. The first malloc
/// in the child can deadlock or corrupt heap.
///
/// - Linux: count entries in `/proc/self/task/`.
/// - macOS: enumerate threads via Mach `task_threads()`.
/// - Other unix: no portable thread enumeration without extra deps; the
///   check is skipped. The `daemonize=true` callers in this workspace
///   (`luksbox-cli`) are single-threaded at fork time, so the gap is
///   documented rather than load-bearing.
#[cfg(target_os = "linux")]
fn assert_single_threaded_for_fork() -> std::io::Result<()> {
    let mut count = 0usize;
    for entry in std::fs::read_dir("/proc/self/task")? {
        let _ = entry?;
        count += 1;
        if count > 1 {
            return Err(std::io::Error::other(MULTITHREADED_FORK_MESSAGE));
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
#[allow(deprecated)] // libc::mach_task_self -> mach2; not worth a new dep.
fn assert_single_threaded_for_fork() -> std::io::Result<()> {
    use libc::{
        kern_return_t, mach_msg_type_number_t, mach_port_t, mach_task_self, thread_act_array_t,
        vm_address_t, vm_deallocate, vm_size_t,
    };

    unsafe extern "C" {
        fn mach_port_deallocate(task: mach_port_t, name: mach_port_t) -> kern_return_t;
    }
    const KERN_SUCCESS: kern_return_t = 0;

    let task = unsafe { mach_task_self() };
    let mut threads: thread_act_array_t = std::ptr::null_mut();
    let mut count: mach_msg_type_number_t = 0;
    let kr = unsafe { libc::task_threads(task, &mut threads, &mut count) };
    if kr != KERN_SUCCESS {
        return Err(std::io::Error::other(format!(
            "luksbox-mount: task_threads() failed with kr={kr}; \
             cannot verify single-threadedness before fork()"
        )));
    }
    for i in 0..count {
        let t = unsafe { *threads.add(i as usize) };
        let _ = unsafe { mach_port_deallocate(task, t) };
    }
    let _ = unsafe {
        vm_deallocate(
            task,
            threads as vm_address_t,
            (count as vm_size_t) * std::mem::size_of::<mach_port_t>(),
        )
    };

    if count > 1 {
        return Err(std::io::Error::other(MULTITHREADED_FORK_MESSAGE));
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn assert_single_threaded_for_fork() -> std::io::Result<()> {
    Ok(())
}

const MULTITHREADED_FORK_MESSAGE: &str = "luksbox-mount: refusing to daemonize from a multithreaded process \
     (POSIX async-signal-safety would be violated). \
     Run with --foreground, or call mount(daemonize=true) before \
     spawning any background thread.";

/// Fork-and-detach the FUSE event loop. Unlike fuser 0.16 (where we
/// could call Session::new in the parent to set up the kernel mount
/// before forking), fuser 0.17 wraps mount + run inside a single
/// `mount2()` call whose Session is private. So the kernel mount
/// happens in the CHILD after fork. Trade-off: kernel-mount errors in
/// the daemonized path land in /dev/null after `detach_from_terminal`
///, users hitting those should re-run with `--foreground`.
fn run_daemonized(fs: LuksboxFs, mountpoint: &Path, config: Config) -> std::io::Result<()> {
    assert_single_threaded_for_fork()?;

    // SAFETY: thread count was verified above. fork() in a single-threaded
    // process duplicates the address space cleanly; both parent and child
    // resume at the next instruction with the same fd table and memory.
    let pid = unsafe { libc::fork() };
    match pid {
        -1 => Err(std::io::Error::last_os_error()),
        0 => {
            // Child: detach from controlling terminal, redirect stdio to
            // /dev/null, install the signal handler so SIGTERM (e.g. from
            // logout) triggers a clean unmount, then run the session.
            unsafe { detach_from_terminal()? };
            install_signal_handler(mountpoint);
            spawn_suspend_listener(mountpoint);
            let res = fuser::mount2(fs, mountpoint, &config);
            std::process::exit(if res.is_ok() { 0 } else { 1 });
        }
        n => {
            // Parent: announce success and exit. Note: the kernel mount
            // happens in the child *after* this announcement, so an
            // immediate post-fork failure (rare, pre-flight validated
            // the mountpoint above) won't be visible here. Users can
            // verify by running `mount | grep luksbox` or by listing
            // the mountpoint.
            eprintln!("✓ mounting {} (pid {n})", mountpoint.display());
            eprintln!("  unmount: luksbox umount {}", mountpoint.display());
            std::process::exit(0);
        }
    }
}

unsafe fn detach_from_terminal() -> std::io::Result<()> {
    if unsafe { libc::setsid() } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    let null = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDWR) };
    if null < 0 {
        return Err(std::io::Error::last_os_error());
    }
    for &target in &[0_i32, 1, 2] {
        if unsafe { libc::dup2(null, target) } == -1 {
            let err = std::io::Error::last_os_error();
            unsafe { libc::close(null) };
            return Err(err);
        }
    }
    if null > 2 {
        unsafe { libc::close(null) };
    }
    Ok(())
}

fn install_signal_handler(mountpoint: &Path) {
    let mp = mountpoint.to_path_buf();
    let r = ctrlc::set_handler(move || {
        eprintln!("\nreceived interrupt, unmounting cleanly...");
        match resolved_unmount_program() {
            Ok(prog) => {
                let _ = std::process::Command::new(&prog)
                    .args(unmount_args())
                    .arg(&mp)
                    .status();
            }
            Err(e) => {
                eprintln!("warning: cannot unmount on signal: {e}");
            }
        }
    });
    if let Err(e) = r {
        eprintln!("warning: could not install signal handler: {e}");
    }
}

/// Candidate absolute paths for the platform unmount helper. The
/// helper is invoked at `luksbox umount` / SIGINT / suspend handler
/// time. Resolving by absolute path (instead of `Command::new("name")`,
/// which does a `$PATH` lookup) closes the PATH-hijack class flagged
/// by CVE-2024-54187 against VeraCrypt 1.26.18.
///
/// Order matters: the canonical install location for the distro comes
/// first. We probe in order and return the first one that exists.
#[cfg(target_os = "linux")]
const UNMOUNT_CANDIDATES: &[&str] = &[
    "/usr/bin/fusermount3",
    "/bin/fusermount3",
    "/usr/local/bin/fusermount3",
];
#[cfg(target_os = "macos")]
const UNMOUNT_CANDIDATES: &[&str] = &["/sbin/umount", "/usr/sbin/umount"];

/// Resolve the unmount helper to an absolute path. Returns `Err` if
/// none of the candidate locations exist (in which case the caller
/// MUST refuse to invoke an unmount, NOT fall back to a `$PATH`
/// lookup that an attacker could have poisoned). The function does a
/// fresh probe each call rather than caching, so a path that becomes
/// available after startup is picked up automatically; the cost is a
/// few stat(2) calls.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn resolved_unmount_program() -> Result<PathBuf, std::io::Error> {
    for candidate in UNMOUNT_CANDIDATES {
        let p = Path::new(candidate);
        if p.is_file() {
            return Ok(p.to_path_buf());
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        format!(
            "could not find a trusted unmount helper at any of: {}. \
             Refusing to fall back to a $PATH lookup (PATH-hijack \
             class CVE-2024-54187). Install the helper at a standard \
             system location.",
            UNMOUNT_CANDIDATES.join(", ")
        ),
    ))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn resolved_unmount_program() -> Result<PathBuf, std::io::Error> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "unmount helper not implemented for this platform",
    ))
}

#[cfg(target_os = "linux")]
fn unmount_args() -> &'static [&'static str] {
    &["-u"]
}

#[cfg(target_os = "macos")]
fn unmount_args() -> &'static [&'static str] {
    &[]
}

#[cfg(target_os = "linux")]
fn spawn_suspend_listener(mountpoint: &Path) {
    let mp = mountpoint.to_path_buf();
    std::thread::spawn(move || {
        if let Err(e) = listen_for_suspend(&mp) {
            eprintln!("luksbox: suspend listener disabled: {e}");
        }
    });
}

#[cfg(not(target_os = "linux"))]
fn spawn_suspend_listener(_mountpoint: &Path) {}

#[cfg(target_os = "linux")]
fn listen_for_suspend(mp: &Path) -> Result<(), Box<dyn std::error::Error>> {
    use zbus::blocking::{Connection, Proxy};

    let conn = Connection::system()?;
    let proxy = Proxy::new(
        &conn,
        "org.freedesktop.login1",
        "/org/freedesktop/login1",
        "org.freedesktop.login1.Manager",
    )?;
    let signals = proxy.receive_signal("PrepareForSleep")?;
    for msg in signals {
        let about_to_sleep: bool = msg.body().deserialize()?;
        if about_to_sleep {
            eprintln!("luksbox: system suspending, unmounting cleanly...");
            match resolved_unmount_program() {
                Ok(prog) => {
                    let _ = std::process::Command::new(&prog)
                        .args(unmount_args())
                        .arg(mp)
                        .status();
                }
                Err(e) => {
                    eprintln!("luksbox: cannot unmount on suspend: {e}");
                }
            }
        }
    }
    Ok(())
}

pub fn unmount(mountpoint: &Path) -> std::io::Result<()> {
    let prog = resolved_unmount_program()?;
    let mut cmd = std::process::Command::new(&prog);
    cmd.args(unmount_args()).arg(mountpoint);
    let status = cmd.status()?;
    if !status.success() {
        return Err(std::io::Error::other(format!(
            "{} returned {}",
            prog.display(),
            status
        )));
    }
    Ok(())
}

/// fuser 0.17 takes `&self` on every Filesystem method (vs `&mut self`
/// in 0.16). Wrap the Vfs in a Mutex for interior mutability, fuser
/// runs the session loop on a single thread by default
/// (`Config::n_threads = None` -> 1), so contention on the mutex is
/// trivial.
struct LuksboxFs {
    vfs: Mutex<Vfs>,
    uid: u32,
    gid: u32,
    /// Directory containing the .lbx vault file, cached at construction
    /// time so `statfs` can probe the host filesystem for real free-space
    /// numbers without re-locking the Vfs on every request. `None` only
    /// if the vault path has no parent (root-level path, never the case
    /// in practice). Used exclusively by `statfs`.
    vault_parent: Option<PathBuf>,
}

impl LuksboxFs {
    fn new(vfs: Vfs) -> Self {
        // SAFETY: getuid/getgid are signal-safe and always succeed.
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        let vault_parent = vfs
            .container()
            .vault_path()
            .parent()
            .map(|p| p.to_path_buf());
        Self {
            vfs: Mutex::new(vfs),
            uid,
            gid,
            vault_parent,
        }
    }

    fn attr(&self, id: FileId) -> Option<FileAttr> {
        let stat = self.vfs.lock().ok()?.stat(id).ok()?;
        let kind = match stat.kind {
            InodeKind::Directory => FileType::Directory,
            InodeKind::File => FileType::RegularFile,
        };
        let perm: u16 = match stat.kind {
            InodeKind::Directory => 0o700,
            InodeKind::File => 0o600,
        };
        let mtime = if stat.mtime_ns == 0 {
            UNIX_EPOCH
        } else {
            UNIX_EPOCH + Duration::from_nanos(stat.mtime_ns)
        };
        Some(FileAttr {
            ino: INodeNo(id),
            size: stat.size,
            blocks: stat.size.div_ceil(512),
            atime: mtime,
            mtime,
            ctime: mtime,
            crtime: mtime,
            kind,
            perm,
            nlink: if stat.kind == InodeKind::Directory {
                2
            } else {
                1
            },
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: 4096,
            flags: 0,
        })
    }
}

fn errno(e: &VfsError) -> Errno {
    match e {
        VfsError::NotFound => Errno::ENOENT,
        VfsError::AlreadyExists => Errno::EEXIST,
        VfsError::NotADirectory => Errno::ENOTDIR,
        VfsError::IsADirectory => Errno::EISDIR,
        VfsError::NotAFile => Errno::EISDIR,
        VfsError::NotEmpty => Errno::ENOTEMPTY,
        VfsError::InvalidPath(_) => Errno::EINVAL,
        _ => Errno::EIO,
    }
}

fn name_str(name: &OsStr) -> Option<&str> {
    name.to_str()
}

impl Filesystem for LuksboxFs {
    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let Some(name) = name_str(name) else {
            reply.error(Errno::EINVAL);
            return;
        };
        let parent = parent.0;
        let target = match name {
            "." => Some(parent),
            ".." => self.vfs.lock().ok().and_then(|v| v.parent_of(parent).ok()),
            _ => self
                .vfs
                .lock()
                .ok()
                .and_then(|v| v.lookup(parent, name).ok()),
        };
        match target.and_then(|id| self.attr(id)) {
            Some(attr) => reply.entry(&TTL, &attr, Generation(0)),
            None => reply.error(Errno::ENOENT),
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        match self.attr(ino.0) {
            Some(attr) => reply.attr(&TTL, &attr),
            None => reply.error(Errno::ENOENT),
        }
    }

    fn setattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<TimeOrNow>,
        _mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<fuser::BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        let ino = ino.0;
        if let Some(new_size) = size {
            let mut vfs = match self.vfs.lock() {
                Ok(v) => v,
                Err(_) => {
                    reply.error(Errno::EIO);
                    return;
                }
            };
            if let Err(e) = vfs.truncate(ino, new_size) {
                reply.error(errno(&e));
                return;
            }
            let _ = vfs.flush();
        }
        match self.attr(ino) {
            Some(attr) => reply.attr(&TTL, &attr),
            None => reply.error(Errno::ENOENT),
        }
    }

    fn opendir(&self, _req: &Request, _ino: INodeNo, _flags: fuser::OpenFlags, reply: ReplyOpen) {
        reply.opened(FileHandle(0), FopenFlags::empty());
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let ino = ino.0;
        let (entries, parent_ino) = {
            let vfs = match self.vfs.lock() {
                Ok(v) => v,
                Err(_) => {
                    reply.error(Errno::EIO);
                    return;
                }
            };
            let entries = match vfs.readdir(ino) {
                Ok(e) => e,
                Err(e) => {
                    reply.error(errno(&e));
                    return;
                }
            };
            let parent = vfs.parent_of(ino).unwrap_or(ino);
            (entries, parent)
        };

        let mut all: Vec<(u64, FileType, String)> = Vec::with_capacity(entries.len() + 2);
        all.push((ino, FileType::Directory, ".".to_string()));
        all.push((parent_ino, FileType::Directory, "..".to_string()));
        for e in entries {
            let kind = match e.kind {
                InodeKind::Directory => FileType::Directory,
                InodeKind::File => FileType::RegularFile,
            };
            all.push((e.id, kind, e.name));
        }

        for (i, (id, kind, name)) in all.iter().enumerate().skip(offset as usize) {
            if reply.add(INodeNo(*id), (i + 1) as u64, *kind, name) {
                break;
            }
        }
        reply.ok();
    }

    fn open(&self, _req: &Request, _ino: INodeNo, _flags: fuser::OpenFlags, reply: ReplyOpen) {
        reply.opened(FileHandle(0), FopenFlags::empty());
    }

    fn read(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: fuser::OpenFlags,
        _lock: Option<fuser::LockOwner>,
        reply: ReplyData,
    ) {
        let mut buf = vec![0u8; size as usize];
        let r = match self.vfs.lock() {
            Ok(mut v) => v.read(ino.0, offset, &mut buf),
            Err(_) => {
                reply.error(Errno::EIO);
                return;
            }
        };
        match r {
            Ok(n) => reply.data(&buf[..n]),
            Err(e) => reply.error(errno(&e)),
        }
    }

    fn write(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        data: &[u8],
        _wflags: fuser::WriteFlags,
        _flags: fuser::OpenFlags,
        _lock: Option<fuser::LockOwner>,
        reply: ReplyWrite,
    ) {
        let r = match self.vfs.lock() {
            Ok(mut v) => v.write(ino.0, offset, data),
            Err(_) => {
                reply.error(Errno::EIO);
                return;
            }
        };
        match r {
            Ok(n) => reply.written(n as u32),
            Err(e) => reply.error(errno(&e)),
        }
    }

    fn create(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        let Some(name) = name_str(name) else {
            reply.error(Errno::EINVAL);
            return;
        };
        let id = {
            let mut vfs = match self.vfs.lock() {
                Ok(v) => v,
                Err(_) => {
                    reply.error(Errno::EIO);
                    return;
                }
            };
            match vfs.create(parent.0, name) {
                Ok(id) => {
                    let _ = vfs.flush();
                    id
                }
                Err(e) => {
                    reply.error(errno(&e));
                    return;
                }
            }
        };
        match self.attr(id) {
            Some(attr) => reply.created(
                &TTL,
                &attr,
                Generation(0),
                FileHandle(0),
                FopenFlags::empty(),
            ),
            None => reply.error(Errno::EIO),
        }
    }

    fn mkdir(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let Some(name) = name_str(name) else {
            reply.error(Errno::EINVAL);
            return;
        };
        let id = {
            let mut vfs = match self.vfs.lock() {
                Ok(v) => v,
                Err(_) => {
                    reply.error(Errno::EIO);
                    return;
                }
            };
            match vfs.mkdir(parent.0, name) {
                Ok(id) => {
                    // Flush immediately: empty dirs create no file, so
                    // no later release() callback would persist this
                    // metadata change.
                    let _ = vfs.flush();
                    id
                }
                Err(e) => {
                    reply.error(errno(&e));
                    return;
                }
            }
        };
        match self.attr(id) {
            Some(attr) => reply.entry(&TTL, &attr, Generation(0)),
            None => reply.error(Errno::EIO),
        }
    }

    fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let Some(name) = name_str(name) else {
            reply.error(Errno::EINVAL);
            return;
        };
        let r = match self.vfs.lock() {
            Ok(mut v) => v.unlink(parent.0, name).map(|_| {
                let _ = v.flush();
            }),
            Err(_) => {
                reply.error(Errno::EIO);
                return;
            }
        };
        match r {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(errno(&e)),
        }
    }

    fn rmdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let Some(name) = name_str(name) else {
            reply.error(Errno::EINVAL);
            return;
        };
        let r = match self.vfs.lock() {
            Ok(mut v) => v.rmdir(parent.0, name).map(|_| {
                let _ = v.flush();
            }),
            Err(_) => {
                reply.error(Errno::EIO);
                return;
            }
        };
        match r {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(errno(&e)),
        }
    }

    fn rename(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        _flags: fuser::RenameFlags,
        reply: ReplyEmpty,
    ) {
        let Some(name) = name_str(name) else {
            reply.error(Errno::EINVAL);
            return;
        };
        let Some(newname) = name_str(newname) else {
            reply.error(Errno::EINVAL);
            return;
        };
        if parent.0 != newparent.0 {
            // Cross-directory rename intentionally not in v1.
            reply.error(Errno::ENOSYS);
            return;
        }
        let r = match self.vfs.lock() {
            Ok(mut v) => v.rename(parent.0, name, newname).map(|_| {
                let _ = v.flush();
            }),
            Err(_) => {
                reply.error(Errno::EIO);
                return;
            }
        };
        match r {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(errno(&e)),
        }
    }

    fn flush(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _lock_owner: fuser::LockOwner,
        reply: ReplyEmpty,
    ) {
        match self.vfs.lock().ok().and_then(|mut v| v.flush().ok()) {
            Some(()) => reply.ok(),
            None => reply.error(Errno::EIO),
        }
    }

    fn fsync(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        match self.vfs.lock().ok().and_then(|mut v| v.flush().ok()) {
            Some(()) => reply.ok(),
            None => reply.error(Errno::EIO),
        }
    }

    fn fsyncdir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        match self.vfs.lock().ok().and_then(|mut v| v.flush().ok()) {
            Some(()) => reply.ok(),
            None => reply.error(Errno::EIO),
        }
    }

    fn release(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _flags: fuser::OpenFlags,
        _lock: Option<fuser::LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        if let Ok(mut v) = self.vfs.lock() {
            let _ = v.flush();
        }
        reply.ok();
    }

    fn releasedir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _flags: fuser::OpenFlags,
        reply: ReplyEmpty,
    ) {
        reply.ok();
    }

    fn destroy(&mut self) {
        if let Ok(mut v) = self.vfs.lock() {
            let _ = v.flush();
        }
    }

    fn access(&self, _req: &Request, _ino: INodeNo, _mask: AccessFlags, reply: ReplyEmpty) {
        // DefaultPermissions is on; the kernel does the access check
        // from attrs returned in getattr. Anything that reaches here
        // means the kernel wants explicit confirmation, accept.
        reply.ok();
    }

    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: fuser::ReplyStatfs) {
        // FUSE-T on macOS bridges through the kernel NFS client, which
        // refuses writes when the FS reports `f_bavail == 0` (returns
        // ENOSPC, and Finder shows a "low allocation size" warning that
        // blocks drag-and-drop into the mounted volume). Reporting zeros
        // worked on macFUSE / libfuse-on-Linux because their kernels
        // don't gate writes on statfs, but it breaks every Finder copy
        // under FUSE-T. Query the underlying host filesystem (where the
        // .lbx vault lives) and surface its real numbers so growth is
        // bounded by actual disk space and Finder lets the user write.
        let host = self.vault_parent.as_deref().and_then(host_fs_statvfs);
        let (blocks, bfree, bavail, files, ffree, bsize, frsize) = match host {
            Some(s) => (
                s.blocks, s.bfree, s.bavail, s.files, s.ffree, s.bsize, s.frsize,
            ),
            // Conservative fallback: present as a roomy 1 TiB filesystem
            // so writes are not rejected when statvfs is unavailable.
            // Matches the practice in fuser's own example FS.
            None => (
                256 * 1024 * 1024,
                256 * 1024 * 1024,
                256 * 1024 * 1024,
                1_000_000,
                1_000_000,
                4096,
                4096,
            ),
        };
        reply.statfs(blocks, bfree, bavail, files, ffree, bsize, 255, frsize);
    }

    fn symlink(
        &self,
        _req: &Request,
        _parent: INodeNo,
        _link_name: &OsStr,
        _target: &Path,
        reply: ReplyEntry,
    ) {
        reply.error(Errno::ENOSYS);
    }

    fn link(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _newparent: INodeNo,
        _newname: &OsStr,
        reply: ReplyEntry,
    ) {
        reply.error(Errno::EACCES);
    }
}

struct HostFsInfo {
    blocks: u64,
    bfree: u64,
    bavail: u64,
    files: u64,
    ffree: u64,
    bsize: u32,
    frsize: u32,
}

fn host_fs_statvfs(path: &Path) -> Option<HostFsInfo> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let c_path = CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: statvfs is signal-safe and the pointer is valid for the
    // call; the buffer is fully written by the syscall on success.
    let mut buf: libc::statvfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statvfs(c_path.as_ptr(), &mut buf) };
    if rc != 0 {
        return None;
    }
    // statvfs field widths differ across platforms (u64 on Linux, varies
    // on macOS); cast through u64 then clamp the block-size fields to
    // u32 for fuser's ReplyStatfs. The block counts (blocks/bfree/bavail)
    // are reported as u64 to fuser and can address the full host disk.
    Some(HostFsInfo {
        blocks: buf.f_blocks as u64,
        bfree: buf.f_bfree as u64,
        bavail: buf.f_bavail as u64,
        files: buf.f_files as u64,
        ffree: buf.f_ffree as u64,
        bsize: u32::try_from(buf.f_bsize as u64).unwrap_or(4096),
        frsize: u32::try_from(buf.f_frsize as u64).unwrap_or(4096),
    })
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::{UNMOUNT_CANDIDATES, assert_single_threaded_for_fork, resolved_unmount_program};

    /// On any Linux/macOS host that has FUSE installed (which is
    /// every CI runner that runs the FUSE integration tests), at
    /// least one of the canonical absolute paths must resolve.
    /// Skips with eprintln on hosts that lack the helper entirely.
    #[test]
    fn resolved_unmount_program_returns_existing_absolute_path() {
        match resolved_unmount_program() {
            Ok(p) => {
                assert!(p.is_absolute(), "must be absolute: {}", p.display());
                assert!(p.is_file(), "must exist: {}", p.display());
                // Belt-and-suspenders: must equal one of the canonical
                // candidates (i.e. came from our hard-coded allow-list,
                // not from somewhere on $PATH).
                let s = p.to_string_lossy().into_owned();
                assert!(
                    UNMOUNT_CANDIDATES.iter().any(|c| *c == s),
                    "resolved path {} not in UNMOUNT_CANDIDATES allow-list",
                    s
                );
            }
            Err(_) => {
                eprintln!(
                    "[skip] no unmount helper installed at any of: {}; \
                     test passes on hosts where the helper is present",
                    UNMOUNT_CANDIDATES.join(", ")
                );
            }
        }
    }

    #[test]
    fn assert_single_threaded_rejects_multithreaded_process() {
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let b = barrier.clone();
        let handle = std::thread::spawn(move || {
            b.wait();
            std::thread::sleep(std::time::Duration::from_millis(100));
        });
        barrier.wait();

        let r = assert_single_threaded_for_fork();

        handle.join().expect("worker thread panicked");

        let err = r.expect_err("should refuse to fork from multithreaded process");
        let msg = format!("{err}");
        assert!(
            msg.contains("multithreaded"),
            "error message should explain why: got {msg:?}"
        );
    }
}
