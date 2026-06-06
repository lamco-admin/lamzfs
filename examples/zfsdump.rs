// SPDX-License-Identifier: MIT OR Apache-2.0
//! Import a ZFS pool from one or more member images, print its identity, then
//! list a dataset's filesystem and read each small regular file. This is both a
//! worked example of the `lamzfs` public API and a host-side inspection tool.
//!
//! Usage:
//!   cargo run --example zfsdump -- <member.img> [<member2.img> ...] [-- <dir>...]
//!
//! Arguments before an optional `--` are raw member-device images; arguments
//! after it are the child-directory components of the dataset to open (e.g.
//! `BOOT test` selects `<pool>/BOOT/test`). With no dataset components, the
//! pool's root dataset is listed.
//!
//! The fixtures under `tests/fixtures/` are zstd-compressed; decompress one
//! first, e.g. `zstd -d single_lz4.img.zst -o /tmp/m.img`, then
//! `cargo run --example zfsdump -- /tmp/m.img -- BOOT test`.

use std::process::ExitCode;

use lamzfs::{BlockRead, DirEntry, EntryKind, PoolMember, Zfs};

/// A whole-image-in-memory block source. Adequate for a host demo; the UEFI
/// integration reads through a firmware Block-IO protocol instead of buffering
/// the device.
struct MemImage(Vec<u8>);

impl BlockRead for MemImage {
    type Error = ();
    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> Result<(), ()> {
        let off = usize::try_from(off).map_err(|_| ())?;
        let end = off.checked_add(buf.len()).ok_or(())?;
        buf.copy_from_slice(self.0.get(off..end).ok_or(())?);
        Ok(())
    }
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let sep = argv.iter().position(|a| a == "--");
    let (image_paths, ds_owned): (&[String], Vec<String>) = match sep {
        Some(i) => (&argv[..i], argv[i + 1..].to_vec()),
        None => (&argv[..], Vec::new()),
    };
    if image_paths.is_empty() {
        eprintln!("usage: zfsdump <member.img> [<member2.img> ...] [-- <dir>...]");
        return ExitCode::FAILURE;
    }

    let mut members = Vec::new();
    for p in image_paths {
        let bytes = match std::fs::read(p) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("read {p}: {e}");
                return ExitCode::FAILURE;
            }
        };
        let device_size_bytes = bytes.len() as u64;
        members.push(PoolMember {
            reader: MemImage(bytes),
            device_size_bytes,
        });
    }

    let mut zfs = match Zfs::import(members) {
        Ok(z) => z,
        Err(e) => {
            eprintln!("import failed: {e:?}");
            return ExitCode::FAILURE;
        }
    };

    println!(
        "pool    {} (guid {:#018x})",
        zfs.pool_name(),
        zfs.pool_guid()
    );
    println!("txg     {}", zfs.txg());
    println!("members {}", zfs.member_count());
    let ds: Vec<&str> = ds_owned.iter().map(String::as_str).collect();
    println!(
        "dataset {}",
        if ds.is_empty() {
            "<root>".into()
        } else {
            ds.join("/")
        }
    );
    println!();

    match zfs.read_dir(&ds) {
        Ok(entries) => print_listing(&mut zfs, &ds, &entries),
        Err(e) => {
            eprintln!("read_dir: {e:?}");
            return ExitCode::FAILURE;
        }
    }
    ExitCode::SUCCESS
}

/// Print a one-line summary per entry; for regular files, read the contents to
/// report the true byte length (exercising the file read + decompression path).
fn print_listing<R: BlockRead>(zfs: &mut Zfs<R>, ds: &[&str], entries: &[DirEntry]) {
    println!("/ ({} entries)", entries.len());
    for e in entries {
        let tag = match e.kind {
            EntryKind::Directory => "dir ",
            EntryKind::Regular => "file",
            EntryKind::Symlink => "link",
            EntryKind::Other => "??? ",
        };
        if e.kind == EntryKind::Regular {
            match zfs.read(ds, &[e.name.as_str()]) {
                Ok(data) => println!("  {tag} {:>10}  {}", data.len(), e.name),
                Err(err) => println!("  {tag} {:>10}  {}  (read error: {err:?})", "-", e.name),
            }
        } else {
            println!("  {tag} {:>10}  {}", "-", e.name);
        }
    }
}
