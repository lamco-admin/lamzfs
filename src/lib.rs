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

// `no_std` unless the `std` feature is on (which adds `impl std::error::Error`)
// or we are building the test harness (the oracle tests use `std`).
#![cfg_attr(not(any(feature = "std", test)), no_std)]
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
                elided_lifetimes_in_paths,
                // The vendored subtree gates its SIMD paths behind feature names
                // (sha256-avx2, fletcher4-avx512f, …) that lamzfs does not
                // declare — those accelerators require `unsafe`, which the crate
                // forbids, so the gates are permanently-false and only the scalar
                // path compiles. Silence the resulting unknown-feature lint here.
                unexpected_cfgs
            )]
            mod $m;
        )+
    };
}
// NOTE: the rzfs `arch` module (x86 CPUID-based SIMD dispatch) is intentionally
// NOT compiled. Its only consumers are the SIMD checksum paths, which lamzfs
// gates off (scalar-only, see the features note in Cargo.toml). It also calls
// raw `__cpuid` intrinsics whose `unsafe`-ness varies by rustc version — leaving
// it out keeps `#![forbid(unsafe_code)]` robust across toolchains.
vendored!(checksum, compression, phys, util);

// ---------------------------------------------------------------------------
// New lamzfs orchestration (MIT OR Apache-2.0) — full lint set applies.
// ---------------------------------------------------------------------------
mod block_read;
mod cksum;
mod compress;
mod dataset;
mod error;
mod file;
mod pool;
mod vdev;
mod walk;

use alloc::{string::String, vec::Vec};

pub use block_read::{BlockRead, PoolMember};
pub use error::{Error, LabelReason, Location};

/// The kind of a directory entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    Regular,
    Directory,
    Symlink,
    Other,
}

/// A directory entry: a decoded name, its kind, and its object number within the
/// selected dataset.
#[derive(Debug, Clone)]
pub struct DirEntry {
    pub name: String,
    pub kind: EntryKind,
    pub object_id: u64,
}

/// ZPL packs the file type in the high bits of a directory-entry value and the
/// object number in the low 48 bits.
fn dirent_kind(value: u64) -> EntryKind {
    match value >> 60 {
        4 => EntryKind::Directory,
        8 => EntryKind::Regular,
        10 => EntryKind::Symlink,
        _ => EntryKind::Other,
    }
}
const DIRENT_OBJ_MASK: u64 = (1 << 48) - 1;

/// Metadata for a path within a dataset: its kind and, for a regular file, its
/// logical size in bytes (0 for non-files).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stat {
    pub kind: EntryKind,
    pub size: u64,
}

/// A pool's identity, read from a single member's label by [`peek_pool_id`]
/// without a full import — used to group members into pools before import.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolId {
    pub guid: u64,
    pub name: String,
}

/// Read one member device's pool identity (`guid`, `name`) from its vdev label,
/// without importing the pool. A host may carry members of several pools; group
/// them by [`PoolId::guid`] and pass each group to [`Zfs::import`].
pub fn peek_pool_id<R: BlockRead>(
    member: &mut PoolMember<R>,
) -> core::result::Result<PoolId, Error> {
    let (guid, name) = pool::peek_pool_id(member)?;
    Ok(PoolId { guid, name })
}

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

    /// The immediate child datasets under `parent` (the child-directory
    /// components selecting a dataset; empty = the pool root). Internal datasets
    /// (`$ORIGIN`, …) are omitted.
    pub fn child_datasets(&mut self, parent: &[&str]) -> core::result::Result<Vec<String>, Error> {
        dataset::child_dataset_names(
            &mut self.members,
            &self.pool.topology,
            &self.pool.mos_dnode,
            self.pool.order,
            parent,
        )
    }

    /// Every dataset in the pool, as its path components under the pool root
    /// (the root dataset is the empty path `[]`). Breadth-first, bounded by
    /// [`MAX_DATASETS`] and [`MAX_DATASET_DEPTH`] so a crafted DSL tree cannot
    /// drive unbounded work (SPEC-LAMZFS §2.5). A subtree whose enumeration
    /// errors is skipped rather than aborting the whole listing.
    pub fn datasets(&mut self) -> core::result::Result<Vec<Vec<String>>, Error> {
        let mut out: Vec<Vec<String>> = alloc::vec![Vec::new()];
        let mut queue: Vec<Vec<String>> = alloc::vec![Vec::new()];
        while let Some(parent) = queue.pop() {
            if out.len() >= MAX_DATASETS || parent.len() >= MAX_DATASET_DEPTH {
                continue;
            }
            let parent_ref: Vec<&str> = parent.iter().map(String::as_str).collect();
            let Ok(children) = self.child_datasets(&parent_ref) else {
                continue;
            };
            for child in children {
                if out.len() >= MAX_DATASETS {
                    break;
                }
                let mut path = parent.clone();
                path.push(child);
                out.push(path.clone());
                queue.push(path);
            }
        }
        Ok(out)
    }

    /// List a directory within a dataset. `dataset_path` is the child-directory
    /// components under the pool root selecting the dataset (e.g.
    /// `["BOOT", "ubuntu_x1"]`); `dir_path` is the directory within that
    /// dataset's ZPL filesystem (empty = the dataset's root directory).
    pub fn read_dir(
        &mut self,
        dataset_path: &[&str],
        dir_path: &[&str],
    ) -> core::result::Result<Vec<DirEntry>, Error> {
        let order = self.pool.order;
        let ds = self.open_dataset(dataset_path)?;
        let dir_obj = if dir_path.is_empty() {
            dataset::root_dir_obj(&mut self.members, &self.pool.topology, &ds, order)?
        } else {
            let (obj, value) = dataset::resolve_path(
                &mut self.members,
                &self.pool.topology,
                &ds,
                order,
                dir_path,
            )?;
            if dirent_kind(value) != EntryKind::Directory {
                return Err(Error::NotADirectory);
            }
            obj
        };
        let entries =
            dataset::list_dir(&mut self.members, &self.pool.topology, &ds, dir_obj, order)?;
        Ok(entries
            .into_iter()
            .map(|(name, value)| DirEntry {
                name,
                kind: dirent_kind(value),
                object_id: value & DIRENT_OBJ_MASK,
            })
            .collect())
    }

    /// Stat a path within a dataset (empty `path` = the dataset root, a
    /// directory). Returns the entry kind and, for a regular file, its size.
    pub fn stat(
        &mut self,
        dataset_path: &[&str],
        path: &[&str],
    ) -> core::result::Result<Stat, Error> {
        let order = self.pool.order;
        let ds = self.open_dataset(dataset_path)?;
        if path.is_empty() {
            return Ok(Stat {
                kind: EntryKind::Directory,
                size: 0,
            });
        }
        let (obj, value) =
            dataset::resolve_path(&mut self.members, &self.pool.topology, &ds, order, path)?;
        let kind = dirent_kind(value);
        let size = if kind == EntryKind::Regular {
            let dnode = walk::read_object_dnode(
                &mut self.members,
                &self.pool.topology,
                &ds.meta_dnode,
                obj,
                order,
            )?;
            dataset::sa_file_size(dnode.bonus_used(), order)?
        } else {
            0
        };
        Ok(Stat { kind, size })
    }

    /// Whether a path exists within a dataset. A genuine read error (corruption,
    /// I/O) still propagates; only "no such component" maps to `Ok(false)`.
    pub fn exists(
        &mut self,
        dataset_path: &[&str],
        path: &[&str],
    ) -> core::result::Result<bool, Error> {
        match self.stat(dataset_path, path) {
            Ok(_) => Ok(true),
            Err(Error::NotFound { .. }) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Read a regular file's full contents from `dataset_path` at `file_path`
    /// (components within that dataset). Caps the allocation at
    /// [`MAX_FILE_BYTES`]; a hole reads as zeros.
    pub fn read(
        &mut self,
        dataset_path: &[&str],
        file_path: &[&str],
    ) -> core::result::Result<Vec<u8>, Error> {
        let order = self.pool.order;
        let ds = self.open_dataset(dataset_path)?;
        let (dnode, size) = self.regular_file(&ds, file_path)?;
        if size > MAX_FILE_BYTES {
            return Err(Error::FileTooLarge {
                size,
                max: MAX_FILE_BYTES,
            });
        }
        let size = usize::try_from(size).map_err(|_| Error::FileTooLarge {
            size,
            max: MAX_FILE_BYTES,
        })?;
        file::read_dnode_range(
            &mut self.members,
            &self.pool.topology,
            &dnode,
            0,
            size,
            order,
        )
    }

    /// Read up to `len` bytes of a regular file starting at `offset` (the
    /// streaming path; a hole reads as zeros). The window is clamped to the file
    /// end, so a short read at EOF returns fewer than `len` bytes. A single
    /// window is itself bounded by [`MAX_FILE_BYTES`].
    pub fn read_at(
        &mut self,
        dataset_path: &[&str],
        file_path: &[&str],
        offset: u64,
        len: usize,
    ) -> core::result::Result<Vec<u8>, Error> {
        let order = self.pool.order;
        let ds = self.open_dataset(dataset_path)?;
        let (dnode, size) = self.regular_file(&ds, file_path)?;
        if offset >= size {
            return Ok(Vec::new());
        }
        let want = (len as u64).min(size - offset);
        if want > MAX_FILE_BYTES {
            return Err(Error::FileTooLarge {
                size: want,
                max: MAX_FILE_BYTES,
            });
        }
        let want = usize::try_from(want).map_err(|_| Error::FileTooLarge {
            size: want,
            max: MAX_FILE_BYTES,
        })?;
        file::read_dnode_range(
            &mut self.members,
            &self.pool.topology,
            &dnode,
            offset,
            want,
            order,
        )
    }

    /// Walk the MOS + DSL to the dataset named by `dataset_path` and open its
    /// object set.
    fn open_dataset(
        &mut self,
        dataset_path: &[&str],
    ) -> core::result::Result<dataset::Dataset, Error> {
        dataset::open_dataset(
            &mut self.members,
            &self.pool.topology,
            &self.pool.mos_dnode,
            self.pool.order,
            dataset_path,
        )
    }

    /// Resolve `file_path` within an opened dataset to its dnode and logical
    /// size, rejecting a non-regular target.
    fn regular_file(
        &mut self,
        ds: &dataset::Dataset,
        file_path: &[&str],
    ) -> core::result::Result<(crate::phys::Dnode, u64), Error> {
        let order = self.pool.order;
        let (obj, value) =
            dataset::resolve_path(&mut self.members, &self.pool.topology, ds, order, file_path)?;
        if dirent_kind(value) != EntryKind::Regular {
            return Err(Error::NotARegularFile);
        }
        let dnode = walk::read_object_dnode(
            &mut self.members,
            &self.pool.topology,
            &ds.meta_dnode,
            obj,
            order,
        )?;
        let size = dataset::sa_file_size(dnode.bonus_used(), order)?;
        Ok((dnode, size))
    }
}

/// Largest file [`Zfs::read`] will allocate up front. A hostile dnode can
/// declare a multi-GiB logical size while occupying almost no real blocks (a
/// holey file); this cap refuses the allocation rather than letting it abort the
/// boot (mirrors lamboot's `MAX_BOOT_FILE_BYTES`). (SPEC-LAMZFS §2.5.)
pub const MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;

/// Upper bound on datasets returned by [`Zfs::datasets`] — a crafted DSL tree
/// cannot drive an unbounded enumeration (SPEC-LAMZFS §2.5).
pub const MAX_DATASETS: usize = 256;

/// Upper bound on dataset nesting depth walked by [`Zfs::datasets`].
pub const MAX_DATASET_DEPTH: usize = 16;
