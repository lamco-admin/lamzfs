// SPDX-License-Identifier: MIT OR Apache-2.0
//! Resolver fuzzing: an arbitrary multi-member image set plus hostile dataset
//! and file paths. The paths are adversarial by construction — empty, deeply
//! nested, non-UTF-8 bytes, names longer than any on disk — and every lookup
//! (the DSL directory walk, the ZAP scan, the ZPL path resolve, the SA bonus
//! decode) must terminate without panicking. Multiple members also reach
//! `build_topology`'s member-by-GUID matching and the raidz column path.
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use lamzfs::{BlockRead, PoolMember, Zfs};

#[derive(Arbitrary, Debug)]
struct Input {
    members: Vec<Vec<u8>>,
    dataset: Vec<Vec<u8>>,
    file: Vec<Vec<u8>>,
}

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

fuzz_target!(|inp: Input| {
    // Bound the member count; an empty set has nothing to import.
    if inp.members.is_empty() || inp.members.len() > 8 {
        return;
    }
    let members = inp
        .members
        .into_iter()
        .map(|b| {
            let device_size_bytes = b.len() as u64;
            PoolMember {
                reader: Mem(b),
                device_size_bytes,
            }
        })
        .collect();
    let Ok(mut zfs) = Zfs::import(members) else {
        return;
    };

    // Path components are arbitrary bytes; the API takes &str, so only the
    // valid-UTF-8 inputs reach the lookups — still a large hostile surface
    // (empty, separators, over-long, non-existent).
    let ds_owned: Vec<&str> = inp
        .dataset
        .iter()
        .filter_map(|b| core::str::from_utf8(b).ok())
        .collect();
    let fp_owned: Vec<&str> = inp
        .file
        .iter()
        .filter_map(|b| core::str::from_utf8(b).ok())
        .collect();

    let _ = zfs.read_dir(&ds_owned);
    let _ = zfs.read(&ds_owned, &fp_owned);
});
