# lamzfs

[![Crates.io](https://img.shields.io/crates/v/lamzfs.svg)](https://crates.io/crates/lamzfs)
[![Docs.rs](https://docs.rs/lamzfs/badge.svg)](https://docs.rs/lamzfs)
[![CI](https://github.com/lamco-admin/lamzfs/actions/workflows/ci.yml/badge.svg)](https://github.com/lamco-admin/lamzfs/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

A `no_std` read-only ZFS reader for UEFI bootloaders.

> **Early development.** This repository establishes the build, license, CI, and
> the public API contract. The filesystem implementation is in progress and the
> crate is **not yet functional** — do not depend on it for production use.

## Scope

`lamzfs` reads a single- or mirror-vdev ZFS boot pool (uberblock, block pointers, dnodes, DSL, ZAP, ZPL), unencrypted over a byte source, exposing a read-only volume a
bootloader can traverse to find a kernel and initramfs. Read-only by
construction. The motivating target is Ubuntu and Debian root-on-ZFS, which keep a simple `bpool` boot pool.

## Basis

It vendors the parsing core of [rzfs](https://github.com/awused/rzfs) (electing the MIT half of its GPL-2.0-OR-MIT dual license) (MIT) — a clean-room
reader, not GPL kernel/userspace source. See [`NOTICE`](NOTICE) for attribution.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option. Vendored upstream portions retain their own terms (see
[`NOTICE`](NOTICE)).

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you shall be dual licensed as above, without any
additional terms or conditions.
