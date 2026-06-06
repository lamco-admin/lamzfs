// SPDX-License-Identifier: MIT OR Apache-2.0
//! Import fuzzing: arbitrary bytes as a single member device through
//! `Zfs::import` — the vdev label parse, the config nvlist (XDR) decode, the
//! uberblock-array scan + checksum, and the MOS-rooting block-pointer read.
//! Import must reject or accept without ever panicking, over-reading, or
//! looping unboundedly.
//!
//! Seed from a real pool for depth (see `fuzz/README.md`): random bytes almost
//! never satisfy the label magic + nvlist + uberblock checksum, so the mutator
//! needs a valid base to reach the config and MOS decode.
#![no_main]

use libfuzzer_sys::fuzz_target;

use lamzfs::{BlockRead, PoolMember, Zfs};

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
    let members = vec![PoolMember {
        reader: Mem(data.to_vec()),
        device_size_bytes,
    }];
    let _ = Zfs::import(members);
});
