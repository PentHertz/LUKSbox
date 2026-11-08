//! AFL++ harness for the sync-bundle object-name grammar. Mirrors
//! `fuzz/fuzz_targets/sync_name_grammar.rs`; shared corpus at
//! `fuzz/corpus/sync_name_grammar/`.

use luksbox_sync::names::{Area, HeaderName, Name, is_shard_name, is_tmp_name};

fn main() {
    afl::fuzz!(|data: &[u8]| {
        let Ok(s) = std::str::from_utf8(data) else {
            return;
        };
        for area in Area::ALL {
            if let Some(n) = Name::parse_in(area, s) {
                assert_eq!(n.leaf(), s, "a parsed name must print back unchanged");
            }
        }
        if let Some(h) = HeaderName::parse(s) {
            assert_eq!(h.to_name(), s);
        }
        let _ = is_tmp_name(s);
        let _ = is_shard_name(s);
    });
}
