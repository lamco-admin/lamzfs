//! `lamzfs` — a `no_std` + `alloc` **read-only** ZFS pool reader for UEFI
//! bootloaders.
//!
//! `lamzfs` reads kernels, initrds, and boot configuration directly from a ZFS
//! pool (the unencrypted `bpool` of an Ubuntu/Debian Root-on-ZFS install) without
//! the OpenZFS kernel module, without `std`, and without a GPL UEFI filesystem
//! driver. Scope is deliberately narrow (SPEC-LAMZFS §1): import a single /
//! mirror / raidz1 pool, walk to one dataset, read its files; reject everything
//! else with a typed error.
//!
//! **In development.** The on-disk **decoders** are vendored from `rzfs`
//! (`github.com/cybojanek/rzfs`, dual `GPL-2.0 OR MIT`; **MIT elected** — see
//! `NOTICE`); the **orchestration** (pool import, vdev routing, dataset walk,
//! path resolve, file read with decompression) is new `lamzfs` code.
//!
//! Read-only by construction: no write path, no `BlockWrite`, no mutating call
//! site.

#![cfg_attr(not(test), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]

extern crate alloc;

// ---------------------------------------------------------------------------
// Vendored rzfs decoders (MIT-elected; see NOTICE + docs/PORTING-NOTES.md).
//
// These are ported near-verbatim from rzfs `lib/` and are intentionally exempt
// from lamzfs's strict lint set: they predate the lamboot pedantic/doc/comment
// conventions and are validated against the on-disk ZFS format, not restyled.
// All SIMD-accelerated (and therefore `unsafe`) paths are `cfg`-gated off, so
// the crate-level `forbid(unsafe_code)` holds. New lamzfs orchestration code
// (below) carries the full lint set.
// ---------------------------------------------------------------------------
macro_rules! vendored {
    ($($m:ident),+ $(,)?) => {
        $(
            #[allow(
                clippy::all,
                clippy::pedantic,
                clippy::nursery,
                clippy::restriction,
                missing_docs,
                unused,
                unreachable_pub,
                elided_lifetimes_in_paths
            )]
            mod $m;
        )+
    };
}
vendored!(arch, checksum, compression, phys, util);
