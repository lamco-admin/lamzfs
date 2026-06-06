// SPDX-License-Identifier: MIT OR Apache-2.0
//! Tree-walk fuzzing: import a single-member pool, list the root dataset's
//! filesystem, read every small regular file, and try each entry name as both a
//! nested dataset (the DSL walk) and a file path (the resolve + SA-size + block
//! read + decompression path). A global budget bounds the work so a malicious
//! ZAP or dnode tree cannot turn one input into unbounded effort.
//!
//! Seed from a real pool for depth (see `fuzz/README.md`).
#![no_main]

use libfuzzer_sys::fuzz_target;

use lamzfs::{BlockRead, EntryKind, PoolMember, Zfs};

struct Mem(Vec<u8>);

impl BlockRead for Mem {
    type Error = ();
    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> Result<(), ()> {
        let off = usize::try_from(off).map_err(|_| ())?;
        let end = off.checked_add(buf.len()).ok_or(())?;
        buf.copy_from_slice(self.0.get(off..end).ok_or(())?);
        Ok(())
    }
}

fuzz_target!(|data: &[u8]| {
    let device_size_bytes = data.len() as u64;
    let Ok(mut zfs) = Zfs::import(vec![PoolMember {
        reader: Mem(data.to_vec()),
        device_size_bytes,
    }]) else {
        return;
    };

    // Enumerate datasets (bounded DSL walk), then exercise a few.
    if let Ok(datasets) = zfs.datasets() {
        for ds in datasets.iter().take(8) {
            let ds_ref: Vec<&str> = ds.iter().map(String::as_str).collect();
            let _ = zfs.read_dir(&ds_ref, &[]);
        }
    }
    let _ = zfs.child_datasets(&[]);

    // The root dataset's ZPL root directory.
    let Ok(entries) = zfs.read_dir(&[], &[]) else {
        return;
    };

    let mut budget = 2048u32;
    for e in entries.iter().take(512) {
        if budget == 0 {
            break;
        }
        budget -= 1;
        let name = e.name.as_str();
        let _ = zfs.stat(&[], &[name]);
        let _ = zfs.exists(&[], &[name]);
        match e.kind {
            // Read the file: full and a window (resolve + size + block read +
            // decompress, plus the read_at offset/clamp arithmetic).
            EntryKind::Regular | EntryKind::Symlink | EntryKind::Other => {
                let _ = zfs.read(&[], &[name]);
                let _ = zfs.read_at(&[], &[name], 1, 64);
            }
            EntryKind::Directory => {
                // Nested listing within the root dataset (resolve + list_dir).
                let _ = zfs.read_dir(&[], &[name]);
                // The name is also a plausible child *dataset* — exercise the
                // DSL directory walk.
                let _ = zfs.read_dir(&[name], &[]);
            }
        }
    }
});
