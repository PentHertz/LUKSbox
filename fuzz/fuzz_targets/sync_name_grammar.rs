// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

#![no_main]

//! Object-name grammar of a sync bundle: names in the folder are
//! provider-controlled. A name either parses into exactly one object id
//! (and prints back as the same string: no aliases through case,
//! Unicode normalisation or padding) or is foreign.

use libfuzzer_sys::fuzz_target;
use luksbox_sync::names::{Area, HeaderName, Name, is_shard_name, is_tmp_name};

fuzz_target!(|data: &[u8]| {
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
