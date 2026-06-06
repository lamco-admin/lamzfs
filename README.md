# lamzfs

[![Crates.io](https://img.shields.io/crates/v/lamzfs.svg)](https://crates.io/crates/lamzfs)
[![Docs.rs](https://docs.rs/lamzfs/badge.svg)](https://docs.rs/lamzfs)
[![CI](https://github.com/lamco-admin/lamzfs/actions/workflows/ci.yml/badge.svg)](https://github.com/lamco-admin/lamzfs/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

A `no_std` + `alloc`, **read-only** ZFS pool reader for UEFI bootloaders.

`lamzfs` imports a ZFS pool over a plain byte source, walks to one dataset, and
reads its files — enough for a bootloader to find a kernel and initramfs without
the OpenZFS kernel module, without `std`, and without a GPL UEFI driver. The
motivating target is Ubuntu / Debian root-on-ZFS, which keep a simple `bpool`
boot pool. **Read-only by construction**: there is no write path and no
`BlockWrite`.

## Scope (v0.1)

Supported:

- **Topologies**: single disk, mirror, and single-parity **RAID-Z1** (including
  degraded reads that reconstruct a missing/corrupt column from parity).
- **Compression**: `off`, `zle`, `lzjb`, `lz4`, `gzip`, `zstd` (each a feature).
- **Checksums**: Fletcher-2/4 and SHA-256 (scalar).
- The full read walk: vdev label → uberblock → MOS → DSL → dataset → ZPL →
  ZAP directories → indirect block-pointer tree (sparse-file aware).

Out of scope: any write path, encryption, RAID-Z2/3, dRAID, and gang blocks
(each rejected with a typed error).

## Usage

Implement `BlockRead` over your device, then import and read:

```rust
use lamzfs::{BlockRead, PoolMember, Zfs};

# struct Disk;
# impl BlockRead for Disk {
#     type Error = ();
#     fn read_at(&mut self, _off: u64, _buf: &mut [u8]) -> Result<(), ()> { Ok(()) }
# }
# fn members() -> Vec<PoolMember<Disk>> { Vec::new() }
let mut zfs = Zfs::import(members())?;          // one PoolMember per vdev member
println!("pool {} ({:#x})", zfs.pool_name(), zfs.pool_guid());

// Dataset path = child-directory components under the pool root; file path =
// components within that dataset's filesystem.
for entry in zfs.read_dir(&["BOOT", "default"])? {
    println!("{:?} {}", entry.kind, entry.name);
}
let kernel = zfs.read(&["BOOT", "default"], &["vmlinuz"])?;
# Ok::<(), lamzfs::Error>(())
```

See [`examples/zfsdump.rs`](examples/zfsdump.rs) for a runnable host tool.

## Basis

The on-disk **decoders** are vendored from
[rzfs](https://github.com/cybojanek/rzfs), electing the MIT half of its
`GPL-2.0 OR MIT` dual license — a clean-room reader, not GPL kernel/userspace
source. The orchestration (pool import, vdev routing, dataset walk, path
resolve, file read) is new `lamzfs` code. The crate is scalar-only and
`#![forbid(unsafe_code)]`. See [`NOTICE`](NOTICE) for attribution.

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
