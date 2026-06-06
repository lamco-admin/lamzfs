// SPDX-License-Identifier: MIT OR Apache-2.0
//! Vdev topology + DVA routing, and the one primitive that reads, verifies, and
//! decompresses a single block pointer (SPEC-LAMZFS §3.2).
//!
//! A block pointer's Data Virtual Address `(vdev, offset, asize)` names a logical
//! location in the pool; this module maps it to physical reads on the member
//! devices. For a single leaf there is one copy; for a mirror every child holds
//! the same bytes, so a child that fails its checksum is retried against the next
//! (the read side of ZFS self-healing). RAIDZ1 reconstruction lands in a
//! follow-up increment; until then `Topology` models single + mirror, and import
//! rejects raidz with a typed error.

use alloc::{vec, vec::Vec};

use crate::{
    block_read::{read_exact, BlockRead, PoolMember},
    cksum::verify_block,
    compress::decompress,
    error::{Error, Location, Result},
    phys::BlockPointer,
};

/// Bytes reserved at the front of every leaf vdev before allocatable space:
/// the L0+L1 labels (2 × 256 KiB) plus the 3.5 MiB boot block = 4 MiB. A DVA
/// `offset` of 0 maps to this byte. (rzfs `BootBlock::BLOCK_DEVICE_OFFSET` +
/// `BootBlock::SIZE`.)
const LABEL_RESERVE: u64 = 4 * 1024 * 1024;

/// On-disk sector shift (512-byte sectors); DVA offsets and bp sizes are counted
/// in these.
const SECTOR_SHIFT: u32 = 9;

/// The pool's single top-level vdev, expressed as indices into the imported
/// member set. v0.1 supports a single leaf or a mirror.
pub(crate) enum Topology {
    /// One leaf device (member index).
    Single(usize),
    /// A mirror: every child holds the same data; read any healthy child.
    Mirror(Vec<usize>),
}

impl Topology {
    /// Member indices that physically hold a DVA's data, in read-try order.
    fn read_order(&self) -> &[usize] {
        match self {
            Topology::Single(idx) => core::slice::from_ref(idx),
            Topology::Mirror(children) => children,
        }
    }
}

/// Absolute byte offset on a leaf device for a DVA sector `offset`, or `None` if
/// the shift/add would overflow (a hostile offset).
fn dva_byte_offset(sector_offset: u64) -> Option<u64> {
    // checked_mul (not checked_shl, which only guards the shift amount) so a
    // hostile 63-bit offset is rejected rather than wrapped.
    sector_offset
        .checked_mul(1 << SECTOR_SHIFT)
        .and_then(|b| b.checked_add(LABEL_RESERVE))
}

/// Read, checksum-verify, and decompress one block pointer into its logical
/// bytes. Tries each DVA copy and, for a mirror, each child, returning the first
/// copy whose checksum verifies. An embedded pointer carries its data inline; an
/// encrypted pointer is out of scope.
pub(crate) fn read_block_pointer<R: BlockRead>(
    members: &mut [PoolMember<R>],
    topo: &Topology,
    bp: &BlockPointer,
) -> Result<Vec<u8>> {
    match bp {
        BlockPointer::Embedded(e) => {
            let src = e
                .payload
                .get(..e.physical_size)
                .ok_or(Error::Inconsistent {
                    token: "embedded_short",
                    where_: Location::Mos,
                })?;
            decompress(e.compression, src, e.logical_size)
        }
        BlockPointer::Encrypted(_) => Err(Error::UnsupportedFeature("encryption")),
        BlockPointer::Regular(r) => {
            let lsize = (r.logical_sectors as usize) << SECTOR_SHIFT;
            let psize = (r.physical_sectors as usize) << SECTOR_SHIFT;
            if psize == 0 || psize > crate::compress::MAX_BLOCK_LSIZE {
                return Err(Error::Inconsistent {
                    token: "bp_bad_psize",
                    where_: Location::Mos,
                });
            }
            let mut last = Error::Inconsistent {
                token: "bp_no_readable_copy",
                where_: Location::Mos,
            };
            for dva in r.dvas.iter().flatten() {
                let Some(byte) = dva_byte_offset(dva.offset) else {
                    last = Error::Inconsistent {
                        token: "dva_out_of_range",
                        where_: Location::Mos,
                    };
                    continue;
                };
                for &mi in topo.read_order() {
                    let Some(member) = members.get_mut(mi) else {
                        continue;
                    };
                    let mut raw = vec![0u8; psize];
                    if read_exact(
                        &mut member.reader,
                        byte,
                        &mut raw,
                        u64::from(dva.vdev),
                        "io_block",
                    )
                    .is_err()
                    {
                        last = Error::Io {
                            token: "io_block",
                            vdev: u64::from(dva.vdev),
                            offset: byte,
                        };
                        continue;
                    }
                    match verify_block(
                        r.checksum_type,
                        r.order,
                        &raw,
                        &r.checksum_value,
                        u64::from(dva.vdev),
                        dva.offset,
                    ) {
                        Ok(()) => return decompress(r.compression, &raw, lsize),
                        Err(e) => last = e,
                    }
                }
            }
            Err(last)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dva_offset_maps_past_the_label_reserve() {
        // Sector 0 -> the 4 MiB front reserve.
        assert_eq!(dva_byte_offset(0), Some(LABEL_RESERVE));
        // Sector 1 -> reserve + 512.
        assert_eq!(dva_byte_offset(1), Some(LABEL_RESERVE + 512));
        // A 63-bit offset overflows the << 9 and is refused, not wrapped.
        assert_eq!(dva_byte_offset(1 << 60), None);
    }

    #[test]
    fn read_order_single_and_mirror() {
        assert_eq!(Topology::Single(2).read_order(), &[2]);
        assert_eq!(Topology::Mirror(vec![1, 3, 5]).read_order(), &[1, 3, 5]);
    }
}
