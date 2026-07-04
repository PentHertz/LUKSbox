// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! In-memory file backing for crash-impact tests.
//!
//! `SimFile` models a real file's two-tier durability:
//!
//! - `backing` -- the bytes the OS would show if you read the file right
//!   now. Receives writes immediately (like a kernel page cache).
//! - `durable` -- the bytes that would survive a sudden power loss. Only
//!   updated by an explicit `sync_all()` call. Same idea as fsync /
//!   FlushFileBuffers committing the page cache to platter.
//!
//! `crash()` reverts `backing` to `durable`, simulating "the box died
//! while these writes were still in the page cache." Pair with the
//! thread-local crash-injection hook in `container::set_crash_after_mirror_for_test`
//! to stop a `Vfs::flush` at the exact mirror-protocol fault window
//! (post-mirror-commit, pre-live-region-sync_all) and verify whether
//! the v0.2.2 durability fence saves the chunk-list-block writes.
//!
//! Production code never instantiates this type. The Container's
//! `file: Box<dyn LbxFile>` field accepts it via the test-only
//! `Container::swap_lbx_file_for_test` setter.

use std::io::{self, Read, Seek, SeekFrom, Write};

use crate::container::LbxFile;

/// In-memory file backing with crash-aware durability semantics.
#[derive(Debug, Clone)]
pub struct SimFile {
    /// What a normal read would return now. Mirrors a kernel page cache.
    pub backing: Vec<u8>,
    /// Last-fsync'd snapshot. What survives `crash()`.
    pub durable: Vec<u8>,
    /// Current seek position.
    pub pos: u64,
}

impl SimFile {
    /// Empty file: no bytes, nothing durable yet, pos at start.
    pub fn new() -> Self {
        Self {
            backing: Vec::new(),
            durable: Vec::new(),
            pos: 0,
        }
    }

    /// Initialise both `backing` and `durable` to `bytes`. Use this
    /// when handing a SimFile to a Container that's about to start
    /// reading an existing on-disk vault: the durable state mirrors
    /// what the test has already written to a real tempfile.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self {
            backing: bytes.clone(),
            durable: bytes,
            pos: 0,
        }
    }

    /// Discard every write that hasn't been `sync_all`'d. Simulates a
    /// hard crash mid-flight: page cache is gone, only what reached
    /// the platter survives.
    pub fn crash(&mut self) {
        self.backing = self.durable.clone();
        // Don't let the position dangle past the new (smaller) backing.
        if self.pos > self.backing.len() as u64 {
            self.pos = self.backing.len() as u64;
        }
    }

    /// Whether there are any in-cache writes that would be lost on
    /// `crash()`. Useful for test assertions.
    pub fn has_unflushed_writes(&self) -> bool {
        self.backing != self.durable
    }
}

impl Default for SimFile {
    fn default() -> Self {
        Self::new()
    }
}

impl Read for SimFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let p = self.pos as usize;
        if p >= self.backing.len() {
            return Ok(0);
        }
        let n = (self.backing.len() - p).min(buf.len());
        buf[..n].copy_from_slice(&self.backing[p..p + n]);
        self.pos += n as u64;
        Ok(n)
    }
}

impl Write for SimFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let p = self.pos as usize;
        if p + buf.len() > self.backing.len() {
            self.backing.resize(p + buf.len(), 0);
        }
        self.backing[p..p + buf.len()].copy_from_slice(buf);
        self.pos += buf.len() as u64;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        // No-op: `flush()` on a real File just kicks page-cache writeback
        // hints; durability is `sync_all`'s job.
        Ok(())
    }
}

impl Seek for SimFile {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(o) => o,
            SeekFrom::Current(o) => {
                let cur = self.pos as i64;
                let target = cur
                    .checked_add(o)
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seek overflow"))?;
                if target < 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "seek before start",
                    ));
                }
                target as u64
            }
            SeekFrom::End(o) => {
                let end = self.backing.len() as i64;
                let target = end
                    .checked_add(o)
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seek overflow"))?;
                if target < 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "seek before start",
                    ));
                }
                target as u64
            }
        };
        self.pos = new_pos;
        Ok(new_pos)
    }
}

impl LbxFile for SimFile {
    fn sync_all(&mut self) -> io::Result<()> {
        // Commit the page-cache view to the durable view, modeling fsync.
        self.durable = self.backing.clone();
        Ok(())
    }
    fn inode_pair(&self) -> io::Result<(u64, u64)> {
        // In-memory backend: no real inode. Never reached on the
        // real-filesystem rotation path; a stable sentinel is fine.
        Ok((0, 0))
    }
}

/// Shared handle over a `SimFile`. Lets the test keep a reference to
/// the underlying `SimFile` (for `crash()` and assertions) AFTER the
/// `Box<dyn LbxFile>` has been handed over to `Container`. Multiple
/// `SharedSimFile` clones over the same `Arc<Mutex<SimFile>>` see
/// each other's writes; the test wires one to the Container and keeps
/// one for itself.
#[derive(Debug, Clone)]
pub struct SharedSimFile {
    inner: std::sync::Arc<std::sync::Mutex<SimFile>>,
}

impl SharedSimFile {
    /// Wrap a `SimFile` in an Arc<Mutex<...>> so multiple handles
    /// can share it.
    pub fn new(sim: SimFile) -> Self {
        Self {
            inner: std::sync::Arc::new(std::sync::Mutex::new(sim)),
        }
    }

    /// A second handle over the same underlying `SimFile`. Wires
    /// one into the Container, keeps the original to call `crash()`
    /// or inspect state.
    pub fn handle(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }

    /// Discard every in-cache write. See `SimFile::crash`.
    pub fn crash(&self) {
        self.inner.lock().expect("SimFile mutex poisoned").crash();
    }

    /// Whether any in-cache writes would be lost on crash.
    pub fn has_unflushed_writes(&self) -> bool {
        self.inner
            .lock()
            .expect("SimFile mutex poisoned")
            .has_unflushed_writes()
    }

    /// Snapshot the current `backing` bytes. For test assertions.
    pub fn backing_snapshot(&self) -> Vec<u8> {
        self.inner
            .lock()
            .expect("SimFile mutex poisoned")
            .backing
            .clone()
    }

    /// Surgical post-crash corruption helper. Fills `[offset, offset+len)`
    /// with `0xCC` in BOTH `backing` and `durable` so the next read
    /// returns the modified bytes and a follow-up `crash()` won't
    /// restore the original. Models "this region was being overwritten
    /// when the crash hit and the resulting bytes are torn / fail AEAD."
    /// Used by the crash-impact test to force live-metadata AEAD
    /// failure so the mirror-recovery path is exercised.
    pub fn corrupt_range(&self, offset: u64, len: usize) {
        let mut sim = self.inner.lock().expect("SimFile mutex poisoned");
        let start = offset as usize;
        let end = start.saturating_add(len);
        if end <= sim.backing.len() {
            sim.backing[start..end].fill(0xCC);
        }
        if end <= sim.durable.len() {
            sim.durable[start..end].fill(0xCC);
        }
    }
}

impl Read for SharedSimFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner
            .lock()
            .map_err(|_| io::Error::other("SimFile mutex poisoned"))?
            .read(buf)
    }
}

impl Write for SharedSimFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner
            .lock()
            .map_err(|_| io::Error::other("SimFile mutex poisoned"))?
            .write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner
            .lock()
            .map_err(|_| io::Error::other("SimFile mutex poisoned"))?
            .flush()
    }
}

impl Seek for SharedSimFile {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.inner
            .lock()
            .map_err(|_| io::Error::other("SimFile mutex poisoned"))?
            .seek(pos)
    }
}

impl LbxFile for SharedSimFile {
    fn sync_all(&mut self) -> io::Result<()> {
        self.inner
            .lock()
            .map_err(|_| io::Error::other("SimFile mutex poisoned"))?
            .sync_all()
    }
    fn inode_pair(&self) -> io::Result<(u64, u64)> {
        Ok((0, 0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_then_read_round_trip() {
        let mut sim = SimFile::new();
        sim.write_all(b"hello").unwrap();
        sim.seek(SeekFrom::Start(0)).unwrap();
        let mut buf = [0u8; 5];
        sim.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"hello");
    }

    #[test]
    fn crash_reverts_unflushed_writes() {
        let mut sim = SimFile::new();
        sim.write_all(b"durable").unwrap();
        sim.sync_all().unwrap();
        sim.write_all(b"_lost").unwrap();
        assert!(sim.has_unflushed_writes());
        sim.crash();
        assert!(!sim.has_unflushed_writes());
        sim.seek(SeekFrom::Start(0)).unwrap();
        let mut buf = vec![0u8; 7];
        sim.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"durable");
    }

    #[test]
    fn sync_all_makes_writes_survive_crash() {
        let mut sim = SimFile::new();
        sim.write_all(b"committed").unwrap();
        sim.sync_all().unwrap();
        sim.crash();
        sim.seek(SeekFrom::Start(0)).unwrap();
        let mut buf = vec![0u8; 9];
        sim.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"committed");
    }

    #[test]
    fn from_bytes_initialises_durable() {
        let sim = SimFile::from_bytes(b"preload".to_vec());
        assert!(!sim.has_unflushed_writes());
        assert_eq!(&sim.durable, b"preload");
        assert_eq!(&sim.backing, b"preload");
    }
}
