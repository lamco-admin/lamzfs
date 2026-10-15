# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.4] - 2026-10-15

### Added

- **BLAKE3 checksums.** OpenZFS keys BLAKE3 with the pool's checksum salt (a
  32-byte value in the MOS object directory); lamzfs reads the salt at import
  and verifies BLAKE3 data and metadata blocks. It's behind the new default
  `blake3` feature, which uses the `blake3` crate in portable Rust. A dataset
  set to `checksum=blake3` was refused as `csum_unsupported` before.
- **Names over 255 bytes** (`longname`, OpenZFS 2.3) read like any other name;
  they live in fat ZAPs, which lamzfs already reads. The pool feature was
  refused before.

### Changed

- Skein and Edon-R blocks are refused as `csum_skein` and `csum_edonr`
  instead of `csum_unsupported`. Both are keyed with the pool's salt, and no
  permissive Rust implementation of either offers a keyed mode.
- A fat-ZAP value can be read as raw bytes, not only as one integer.

### Testing

- Three kernel-built fixtures: A pool checksummed with BLAKE3 throughout, a
  pool with a 300-byte file name and a 1,000-byte directory name, and Skein
  and Edon-R datasets beside a readable `/boot`. All three tests fail on
  0.1.3; the long-name pool replaces the old refusal fixture.

## [0.1.3] - 2026-10-15

### Fixed

- **A stale mirror member could win.** The active uberblock came from member
  0's first label only, so a mirror whose member 0 missed the last writes read
  as the older tree, with no error. It's now chosen from all four labels of
  every member, as ZFS does.
- **Pools with several top-level vdevs imported and read through member 0.**
  A stripe (Proxmox's RAID0) or a pool with log or special vdevs is now refused
  with `topo_multi_toplevel`, as the spec always said; a DVA naming any vdev
  but 0 is `dva_vdev`.
- **No pool feature gate.** Active read features are now checked twice: In the
  label before the MOS is read, and in the MOS `features_for_read` set after.
  Features lamzfs doesn't implement are refused by name (`raidz_expansion`,
  `longname`, `device_removal`, `draid`, `dynamic_gang_header`,
  `redacted_datasets`, `redaction_list_spill`) or as
  `feat_unknown_read_incompat`.
- **RAID-Z expansion.** An expanded RAID-Z keeps old blocks at their old
  width; such a pool is refused as `raidz_expansion`. Its label didn't decode
  at all before: The vendored nvlist decoder missed XDR's element count in
  front of every fixed-width array.
- **A native-encoded nvlist in a label panicked** (a `todo!()`); it's refused
  as an unknown encoding.
- **Uberblocks written during a RAID-Z expansion were skipped** (their
  `ub_raidz_reflow_info` wasn't decoded), which could select an older txg.
- **Gang blocks** are refused as `gang_block` instead of failing their
  checksum.

### Added

- **Large dnodes** (`dnodesize=auto` and up, Ubuntu's rpool): A file whose
  system-attribute bonus doesn't fit a 512-byte dnode used to fail with
  `dnode_decode`.
- **SHA-512 checksums** (OpenZFS's SHA-512/256), behind the new default
  `sha512` feature, which brings in `sha2` 0.11.
- Installer-shaped fixtures built by OpenZFS through the kernel module
  (`tests/fixtures/regen-installer.sh`): Proxmox VE's rpool, Ubuntu's rpool and
  bpool, a SHA-512 dataset, a stale mirror member, gang blocks, an encrypted
  sibling dataset, and the refused stripe, expanded RAID-Z and longname pools.
  Eight of the ten tests fail on 0.1.2.

### Changed

- `ruzstd` 0.8 to 0.9.1, which fixes RUSTSEC-2026-0344.
- CI runs weekly as well, and builds the library for `x86_64-unknown-uefi`.
- The README says the crate is MIT (the vendored rzfs decoders are MIT only),
  links the LamBoot site and docs, and LICENSE-APACHE carries the full license
  text.

## [0.1.2] - 2026-08-19

### Changed

- Bump `miniz_oxide` from 0.8 to 0.9 (the version carried in the Debian
  archive) and `sha2` (dev-dependency, oracle tests only) from 0.10 to 0.11.
  Both are dependency alignments with no functional change; the gzip oracle
  test still reads fixtures byte-exact.

## [0.1.1] - 2026-06-08

### Changed

- Bump the `lz4_flex` dependency from 0.11 to 0.13 (the version carried in the
  Debian archive); the `block::decompress_into` API is unchanged, so this is a
  dependency alignment with no functional change.

## [0.1.0] - 2026-06-06

First functional release: a `no_std` + `alloc`, read-only ZFS pool reader for
UEFI bootloaders. Read-only by construction — no write path, no `BlockWrite`.

### Added

- **Pool import**: vdev label parse, config nvlist (XDR) decode, uberblock-array
  scan with checksum selection, and the MOS-rooting block-pointer read.
- **Topologies**: single-disk, mirror (read any healthy child), and single-parity
  RAID-Z1 — including degraded-mode reads that reconstruct a missing or
  checksum-failing column from parity.
- **Dataset walk**: MOS object directory → DSL directory tree → a named dataset's
  object set → the ZPL master node and root directory.
- **Directory + path resolution**: micro and fat ZAP enumeration, ZPL directory
  listing, and recordsize-agnostic path resolution.
- **File read**: indirect block-pointer tree walk with hole (sparse) support and
  System-Attributes (SA) file-size decode.
- **Decompression**: `off`, `zle`, `lzjb`, `lz4`, `gzip`, and `zstd` (OpenZFS
  magicless frames), each behind a Cargo feature.
- **Checksums**: scalar Fletcher-2/4 and SHA-256 block verification.
- **Public API** over the `BlockRead` byte-source trait: `Zfs::import`,
  `pool_guid` / `pool_name` / `txg` / `member_count`, dataset enumeration
  (`datasets` / `child_datasets`), and dataset-scoped access — `read_dir` (any
  directory), `stat`, `exists`, `read` (full), and `read_at` (ranged).
- A `zfsdump` example and three `cargo-fuzz` harnesses (`import`, `walk`, `path`).

### Notes

- On-disk **decoders** are vendored from [rzfs](https://github.com/cybojanek/rzfs)
  (dual `GPL-2.0 OR MIT`; **MIT elected**); the orchestration is new lamzfs code.
  See [`NOTICE`](NOTICE).
- Scalar-only and `#![forbid(unsafe_code)]`. Out of scope for 0.1: encryption,
  RAID-Z2/3, dRAID, gang blocks, and any write path.
