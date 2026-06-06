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
// Orchestration is built milestone by milestone; intermediate modules expose
// items their consumers land in a later milestone. Lifted at M14 (release prep)
// once every module is wired — tracked in lamzfs-dev/docs/PORTING-NOTES.md.
#![allow(dead_code)]

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

// ---------------------------------------------------------------------------
// New lamzfs orchestration (MIT OR Apache-2.0) — full lint set applies.
// ---------------------------------------------------------------------------
mod block_read;
mod cksum;
mod compress;
mod error;
mod file;
mod path;
mod pool;
mod vdev;
mod walk;

use alloc::vec::Vec;

pub use block_read::{BlockRead, PoolMember};
pub use error::{Error, LabelReason, Location};
pub use path::Path;

/// An imported, read-only ZFS pool with one active dataset presented as a
/// single-rooted filesystem. Built by [`Zfs::import`].
pub struct Zfs<R: BlockRead> {
    members: Vec<PoolMember<R>>,
    pool: pool::ImportedPool,
}

impl<R: BlockRead> Zfs<R> {
    /// Import the pool from its member device(s): read the vdev label, build the
    /// topology (single / mirror), and select the active uberblock. Rejects an
    /// out-of-scope topology or a missing/corrupt label with a typed error.
    pub fn import(mut members: Vec<PoolMember<R>>) -> core::result::Result<Self, Error> {
        let pool = pool::import(&mut members)?;
        Ok(Self { members, pool })
    }

    /// The pool GUID (stable per pool) — surfaced as the volume `uuid()`.
    pub fn pool_guid(&self) -> u64 {
        self.pool.pool_guid
    }

    /// The pool name (e.g. `bpool`).
    pub fn pool_name(&self) -> &str {
        &self.pool.pool_name
    }

    /// The active uberblock's transaction group.
    pub fn txg(&self) -> u64 {
        self.pool.uberblock.txg
    }

    /// Member count (1 for a single disk, N for a mirror).
    pub fn member_count(&self) -> usize {
        self.members.len()
    }
}

/// Largest file [`Zfs::read_file`] will allocate up front. A hostile dnode can
/// declare a multi-GiB logical size while occupying almost no real blocks (a
/// holey file); this cap refuses the allocation rather than letting it abort the
/// boot (mirrors lamboot's `MAX_BOOT_FILE_BYTES`). The streaming `read_file_at`
/// path is unaffected. (SPEC-LAMZFS §2.5.)
pub const MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;
