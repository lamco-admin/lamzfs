# lamzfs

[![Crates.io](https://img.shields.io/crates/v/lamzfs.svg)](https://crates.io/crates/lamzfs)
[![Docs.rs](https://docs.rs/lamzfs/badge.svg)](https://docs.rs/lamzfs)
[![CI](https://github.com/lamco-admin/lamzfs/actions/workflows/ci.yml/badge.svg)](https://github.com/lamco-admin/lamzfs/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](#license)
[![Website](https://img.shields.io/badge/website-lamco.ai-blue.svg)](https://lamco.ai/products/lamboot/)

A `no_std` + `alloc`, **read-only** ZFS pool reader for UEFI bootloaders, from
Lamco Development LLC.

`lamzfs` imports a ZFS pool over a plain byte source, walks to one dataset, and
reads its files: Enough for a bootloader to find a kernel and initramfs without
the OpenZFS kernel module, without `std`, and without a GPL UEFI driver. The
motivating target is Ubuntu and Debian root-on-ZFS, which keep a simple `bpool`
boot pool. **Read-only by construction**: There is no write path and no
`BlockWrite`.

- **Website:** [LamBoot](https://lamco.ai/products/lamboot/), the bootloader lamzfs is maintained for
- **Documentation:** [docs.rs/lamzfs](https://docs.rs/lamzfs) and the [LamBoot docs](https://lamco.ai/products/lamboot/docs/)
- **Repository:** [github.com/lamco-admin/lamzfs](https://github.com/lamco-admin/lamzfs)
- **Company:** [Lamco Development LLC](https://lamco.ai/)

## What it reads

- **Topologies:** One top-level vdev: a single disk, a mirror, or a
  single-parity **RAID-Z1** (including degraded reads that rebuild a missing or
  corrupt column from parity). The active uberblock is chosen from all four
  labels of every member, so a mirror member that missed the last writes can't
  win.
- **Pools as installers create them:** Proxmox VE's (every feature enabled),
  Ubuntu's `bpool` and its `rpool` with `dnodesize=auto`, `xattr=sa`,
  `acltype=posixacl` and `normalization=formD`.
- **Compression:** `off`, `zle`, `lzjb`, `lz4`, `gzip` and `zstd` (each a
  feature).
- **Checksums:** Fletcher-2/4, SHA-256 and SHA-512 (OpenZFS's SHA-512/256).
- The full read walk: vdev label, uberblock, MOS, DSL, dataset, ZPL, ZAP
  directories (micro and fat), large dnodes, large blocks, and the indirect
  block-pointer tree (sparse-file aware).

## What it refuses

Everything else fails with a typed error and a stable token
([`Error::token`](https://docs.rs/lamzfs/latest/lamzfs/enum.Error.html#method.token)),
never a wrong read:

- **Active read features it doesn't implement**, checked in the label before
  the MOS is read and in the MOS `features_for_read` set after:
  `raidz_expansion`, `longname`, `device_removal`, `draid`,
  `dynamic_gang_header`, `redacted_datasets`, `redaction_list_spill`, and any
  feature it doesn't know (`feat_unknown_read_incompat`).
- **Several top-level vdevs** (`topo_multi_toplevel`): a stripe such as
  Proxmox's RAID0, or a pool with log or special vdevs.
- RAID-Z2/3 and dRAID, gang blocks (`gang_block`), and encrypted datasets
  (`encryption`; an unencrypted `/boot` beside them still reads).
- Skein, Edon-R and BLAKE3 checksums, block by block.

## Installation

```sh
cargo add lamzfs
```

or in `Cargo.toml`:

```toml
[dependencies]
lamzfs = "0.1"
```

### Features

| Feature | Default | What it adds |
|---|---|---|
| `lz4`, `zstd`, `gzip`, `lzjb` | yes | That compression algorithm |
| `mirror` | yes | Mirror topologies |
| `sha512` | yes | SHA-512/256 checksums (`sha2`) |
| `std` | no | `impl std::error::Error for Error` |

For `x86_64-unknown-uefi`, build in release mode: `sha2` 0.11's x86 backend
hits an LLVM error in unoptimized builds for that target. Release builds, and
every other target, are unaffected.

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

// Dataset path = child-directory components under the pool root; the second
// argument is the directory within that dataset (empty = its root).
for entry in zfs.read_dir(&["BOOT", "default"], &[])? {
    println!("{:?} {}", entry.kind, entry.name);
}
let kernel = zfs.read(&["BOOT", "default"], &["vmlinuz"])?;
# Ok::<(), lamzfs::Error>(())
```

See [`examples/zfsdump.rs`](examples/zfsdump.rs) for a runnable host tool.

## Testing

The fixtures are real pools that OpenZFS wrote through its kernel module, so the
kernel is the oracle: Every file must hash to what the kernel wrote, and every
refused layout must fail with its named token. `tests/fixtures/regen.sh` builds
the original `compatibility=grub2` pools and `tests/fixtures/regen-installer.sh`
the installer-shaped and refused ones (both need the ZFS kernel module and
sudo). Three fuzz targets live in `fuzz/`.

## Basis

The on-disk **decoders** are vendored from
[rzfs](https://github.com/cybojanek/rzfs), electing the MIT half of its
`GPL-2.0 OR MIT` dual license: a clean-room reader, not GPL kernel or userspace
source. The orchestration (pool import, vdev routing, feature gate, dataset
walk, path resolve, file read) is new `lamzfs` code. The crate is scalar-only
and `#![forbid(unsafe_code)]`. See [`NOTICE`](NOTICE) for attribution.

## Contributing

Issues and pull requests are welcome at
[github.com/lamco-admin/lamzfs](https://github.com/lamco-admin/lamzfs). A change
to the read path should come with a fixture built by one of the scripts in
`tests/fixtures/`.

## License

The crate as published is **MIT**
([LICENSE-MIT](LICENSE-MIT)). The vendored rzfs decoders are MIT only, by the
election recorded in [`NOTICE`](NOTICE). The code written for lamzfs is
additionally available under the Apache License, Version 2.0
([LICENSE-APACHE](LICENSE-APACHE)), as each of its files' SPDX headers says.

Copyright 2025-2026 Lamco Development LLC.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you shall be licensed as above, without any
additional terms or conditions.
