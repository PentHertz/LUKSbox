/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Penthertz <https://penthertz.com>
 *
 * bindgen entry point for luksbox-fuse-t.
 *
 * FUSE-T installs its libfuse 2.x-compatible header at one of:
 *   /usr/local/include/fuse_t/fuse.h    (Apple Silicon Homebrew)
 *   /usr/local/include/fuse.h           (legacy / non-Homebrew)
 *
 * We try the FUSE-T-namespaced path first so we don't accidentally
 * pick up a macFUSE `<fuse.h>` if both are installed (FUSE-T's path
 * is more specific). If only the bare include is present, fall back.
 *
 * FUSE_USE_VERSION pins us to libfuse 2.9. See build.rs for the
 * rationale and the Phase-2 note about libfuse 3.x / fuse_lowlevel.h.
 */
#define FUSE_USE_VERSION 29
#define _FILE_OFFSET_BITS 64

#if __has_include(<fuse_t/fuse.h>)
#  include <fuse_t/fuse.h>
#elif __has_include(<fuse.h>)
#  include <fuse.h>
#else
#  error "FUSE-T headers not found. Install with: brew install --cask fuse-t"
#endif
