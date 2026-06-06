// SPDX-License-Identifier: MIT OR Apache-2.0
//! Typed error surface with stable `&'static str` tokens (SPEC-LAMZFS §2.3/§7).
//!
//! Every error carries a stable vocabulary token (see [`Error::token`]) so a
//! bootloader trust log can record *why* a read failed without string formatting
//! and without the token drifting across releases.

/// A ZFS pool read or import failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// An underlying [`BlockRead`](crate::BlockRead) call failed for a member.
    Io {
        /// Stable site token.
        token: &'static str,
        /// Leaf vdev GUID the read was routed to (0 if pre-topology).
        vdev: u64,
        /// Byte offset within that member.
        offset: u64,
    },
    /// A vdev label was missing, malformed, or failed its checksum.
    BadLabel(LabelReason),
    /// No uberblock in any label's array had a valid checksum.
    NoValidUberblock,
    /// A pool feature this reader does not implement is active / read-incompatible.
    UnsupportedFeature(&'static str),
    /// A vdev topology this reader does not support (raidz2/3, draid, stripe,
    /// alloc-class, …).
    UnsupportedTopology(&'static str),
    /// A construct that is out of scope (gang block, zvol-as-dataset, …).
    Unsupported(&'static str),
    /// A block-pointer / metadata checksum mismatch (Fletcher / SHA-256), on the
    /// last available copy.
    ChecksumMismatch {
        /// Leaf vdev GUID.
        vdev: u64,
        /// Byte offset of the failing read.
        offset: u64,
        /// Which checksum failed.
        what: &'static str,
    },
    /// A structural inconsistency found mid-walk (DVA out of range, bad dnode
    /// type, ZAP corruption, indirection-level mismatch, …).
    Inconsistent {
        /// Stable site token.
        token: &'static str,
        /// Where in the walk it surfaced.
        where_: Location,
    },
    /// A compression codec the build did not enable, or an unknown id.
    UnsupportedCompression {
        /// The on-disk `comp` id.
        comp: u8,
    },
    /// A decompressor rejected the block (corrupt compressed data, or a declared
    /// logical size that does not match the codec output).
    BadCompression {
        /// The on-disk `comp` id.
        comp: u8,
        /// Stable site token.
        token: &'static str,
    },
    /// Path resolution found no such component.
    NotFound {
        /// The missing component (or a short descriptor).
        component: &'static str,
    },
    /// The target exists but is not a regular file.
    NotARegularFile,
    /// A non-final path component (or a `read_dir` target) is not a directory.
    NotADirectory,
    /// The target exists but is not a symlink.
    NotASymlink,
    /// A metadata-reported size exceeded the read cap
    /// ([`MAX_FILE_BYTES`](crate::MAX_FILE_BYTES)) or did not fit `usize` — the
    /// denial-of-boot guard (SPEC-LAMZFS §2.5).
    FileTooLarge {
        /// The declared size.
        size: u64,
        /// The cap.
        max: u64,
    },
    /// An allocation failed at the named site. `lamzfs` never falls back.
    OutOfMemory {
        /// Stable site token.
        site: &'static str,
    },
}

/// Why a vdev label was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabelReason {
    /// The boot-block / nvlist magic was wrong.
    BadMagic,
    /// The label checksum did not verify.
    BadChecksum,
    /// No readable labels were found on any member.
    NoLabels,
    /// A member's label `pool_guid` did not match the pool being imported.
    PoolGuidMismatch,
    /// The device is not a ZFS member.
    NotAZfsMember,
}

/// Where in the read walk an [`Error::Inconsistent`] surfaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Location {
    /// While decoding a vdev's config.
    Vdev {
        /// Leaf vdev GUID.
        guid: u64,
    },
    /// While selecting / decoding the uberblock.
    Uberblock,
    /// While walking the Meta Object Set.
    Mos,
    /// While walking the DSL.
    Dsl {
        /// Object id.
        obj: u64,
    },
    /// While decoding a dnode.
    Dnode {
        /// Object id.
        obj: u64,
    },
    /// While walking an indirect block tree.
    Indirect {
        /// Object id.
        obj: u64,
        /// Indirection level.
        level: u8,
    },
    /// While decoding a ZAP.
    Zap {
        /// Object id.
        obj: u64,
    },
    /// While decoding a ZPL znode / SA.
    Zpl {
        /// Object id.
        obj: u64,
    },
}

impl Error {
    /// The stable vocabulary token for this error (trust-log friendly).
    pub fn token(&self) -> &'static str {
        match self {
            Error::Io { token, .. }
            | Error::Inconsistent { token, .. }
            | Error::BadCompression { token, .. } => token,
            Error::BadLabel(r) => r.token(),
            Error::NoValidUberblock => "no_valid_uberblock",
            Error::UnsupportedFeature(t)
            | Error::UnsupportedTopology(t)
            | Error::Unsupported(t) => t,
            Error::ChecksumMismatch { what, .. } => what,
            Error::UnsupportedCompression { .. } => "comp_unsupported",
            Error::NotFound { .. } => "not_found",
            Error::NotARegularFile => "not_a_regular_file",
            Error::NotADirectory => "not_a_directory",
            Error::NotASymlink => "not_a_symlink",
            Error::FileTooLarge { .. } => "file_too_large",
            Error::OutOfMemory { site } => site,
        }
    }
}

impl LabelReason {
    pub(crate) fn token(self) -> &'static str {
        match self {
            LabelReason::BadMagic => "label_bad_magic",
            LabelReason::BadChecksum => "label_bad_checksum",
            LabelReason::NoLabels => "label_none",
            LabelReason::PoolGuidMismatch => "label_pool_guid_mismatch",
            LabelReason::NotAZfsMember => "label_not_a_member",
        }
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "lamzfs: {}", self.token())
    }
}

#[cfg(feature = "std")]
extern crate std;
#[cfg(feature = "std")]
impl std::error::Error for Error {}

pub(crate) type Result<T> = core::result::Result<T, Error>;
