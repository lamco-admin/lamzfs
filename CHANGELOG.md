# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
