//! `lamzfs` — a `no_std` read-only ZFS reader for UEFI bootloaders.
//!
//! **Early development.** This crate establishes the build, license, CI, and the
//! public API contract; the filesystem implementation is in progress and the
//! crate is not yet functional.
//!
//! The planned surface is a read-only volume opened over a byte source, which a
//! bootloader traverses to locate a kernel and initramfs. Read-only by
//! construction.
#![cfg_attr(not(test), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]

extern crate alloc;
