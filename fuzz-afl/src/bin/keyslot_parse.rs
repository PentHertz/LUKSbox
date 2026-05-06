//! AFL++ harness: arbitrary 512 B buffers fed to `Keyslot::from_bytes`.

use luksbox_core::{Keyslot, SLOT_SIZE};

fn main() {
    afl::fuzz!(|data: &[u8]| {
        if data.len() < SLOT_SIZE {
            return;
        }
        let mut buf = [0u8; SLOT_SIZE];
        buf.copy_from_slice(&data[..SLOT_SIZE]);
        let _ = Keyslot::from_bytes(&buf);
    });
}
