// SPDX-License-Identifier: MIT OR Apache-2.0
//! The dnode block-pointer tree read (SPEC-LAMZFS §1.1, recordsize-agnostic):
//! resolve a logical byte range of any object (a file, a ZAP, the dnode array,
//! …) by walking the dnode's `levels` of indirection to each data block and
//! reading it through [`read_block_pointer`]. Holes read as zeros.

use alloc::{vec, vec::Vec};

use crate::{
    block_read::{BlockRead, PoolMember},
    error::{Error, Location, Result},
    phys::{
        BigEndianDecoder, BinaryDecoder, BlockPointer, Dnode, EndianOrder, LittleEndianDecoder,
    },
    vdev::{read_block_pointer, Topology},
};

/// Run `f` with a [`BinaryDecoder`] over `bytes` in the pool's byte `order`. The
/// concrete `Big`/`LittleEndianDecoder` implement `BinaryDecoder`; the combined
/// `BigLittleEndianDecoder` does not, so dispatch on the order here. The result
/// must be owned (or copied out) — the decoder borrows `bytes` only for `f`.
pub(crate) fn with_decoder<'b, T>(
    bytes: &'b [u8],
    order: EndianOrder,
    f: impl FnOnce(&mut dyn BinaryDecoder<'b>) -> T,
) -> T {
    match order {
        EndianOrder::Big => f(&mut BigEndianDecoder::from_bytes(bytes)),
        EndianOrder::Little => f(&mut LittleEndianDecoder::from_bytes(bytes)),
    }
}

/// On-disk block-pointer size (used as the indirect-block fan stride).
const BLKPTR_SIZE: usize = 128;

/// Hard ceiling on a dnode's indirection levels. ZFS never exceeds ~7
/// (`DN_MAX_LEVELS`); a larger value is corrupt or hostile. Capping it both
/// bounds the descent loop and keeps the shift exponents below 64 (a `u64`
/// shift `>= 64` panics in debug, wraps in release — neither is acceptable on
/// attacker-controlled metadata). SPEC-LAMZFS §2.5.
const DN_MAX_LEVELS: u8 = 16;

/// Read logical block `blkid` of `dnode`, descending its indirect tree. Returns
/// `None` for a hole (an absent pointer at any level), which the caller treats as
/// zeros. `order` is the pool's byte order (from the rooting block pointer).
pub(crate) fn read_dnode_block<R: BlockRead>(
    members: &mut [PoolMember<R>],
    topo: &Topology,
    dnode: &Dnode,
    blkid: u64,
    order: EndianOrder,
) -> Result<Option<Vec<u8>>> {
    let levels = dnode.levels;
    if levels == 0 {
        return Ok(None);
    }
    if levels > DN_MAX_LEVELS {
        return Err(Error::Inconsistent {
            token: "dnode_levels",
            where_: Location::Dnode { obj: 0 },
        });
    }
    let ptrs = dnode.pointers();
    // Entries per indirect block = 2^(indirect_block_shift - 7), since a block
    // pointer is 128 = 2^7 bytes.
    let epb_shift = u32::from(dnode.indirect_block_shift).saturating_sub(7);
    // Guard every shift below against a >= 64 exponent (panics in debug, wraps
    // in release): the top-level shift `epb_shift * (levels-1)` is the largest,
    // so if it and `epb_shift` (the mask) both fit, every per-level shift does.
    let top_exp = match epb_shift.checked_mul(u32::from(levels - 1)) {
        Some(t) if t < 64 && epb_shift < 64 => t,
        _ => {
            return Err(Error::Inconsistent {
                token: "dnode_indshift",
                where_: Location::Dnode { obj: 0 },
            })
        }
    };
    let mask = (1u64 << epb_shift) - 1;

    let top_idx = (blkid >> top_exp) as usize;
    let Some(Some(top)) = ptrs.get(top_idx) else {
        return Ok(None); // out of range or a hole at the top level
    };
    if levels == 1 {
        return Ok(Some(read_block_pointer(members, topo, top)?));
    }

    // Descend the indirect levels. `current` always holds the indirect block at
    // the level named by `l`; the entry it selects is one level lower.
    let mut current = read_block_pointer(members, topo, top)?;
    for l in (1..levels).rev() {
        let idx = ((blkid >> (epb_shift * u32::from(l - 1))) & mask) as usize;
        let start = idx * BLKPTR_SIZE;
        let slice = current
            .get(start..start + BLKPTR_SIZE)
            .ok_or(Error::Inconsistent {
                token: "indirect_oob",
                where_: Location::Indirect { obj: 0, level: l },
            })?;
        let child = with_decoder(slice, order, BlockPointer::from_decoder).map_err(|_| {
            Error::Inconsistent {
                token: "indirect_bp_decode",
                where_: Location::Indirect { obj: 0, level: l },
            }
        })?;
        let Some(child) = child else {
            return Ok(None); // hole at an indirect level
        };
        let block = read_block_pointer(members, topo, &child)?;
        if l == 1 {
            return Ok(Some(block)); // child was a data-block pointer
        }
        current = block;
    }
    // Unreachable: the `l == 1` arm returns for every levels >= 2.
    Err(Error::Inconsistent {
        token: "indirect_walk",
        where_: Location::Indirect { obj: 0, level: 0 },
    })
}

/// Read `len` logical bytes of `dnode` starting at `off`, spanning blocks and
/// zero-filling holes. The data block size comes from the dnode
/// (`data_block_size_sectors`), so this is recordsize-agnostic.
pub(crate) fn read_dnode_range<R: BlockRead>(
    members: &mut [PoolMember<R>],
    topo: &Topology,
    dnode: &Dnode,
    off: u64,
    len: usize,
    order: EndianOrder,
) -> Result<Vec<u8>> {
    let dbsz = (dnode.data_block_size_sectors as usize) << 9;
    if dbsz == 0 {
        return Err(Error::Inconsistent {
            token: "dnode_dbsz0",
            where_: Location::Dnode { obj: 0 },
        });
    }
    let mut out = vec![0u8; len];
    let mut filled = 0usize;
    while filled < len {
        let pos = off.checked_add(filled as u64).ok_or(Error::Inconsistent {
            token: "range_overflow",
            where_: Location::Dnode { obj: 0 },
        })?;
        let blkid = pos / dbsz as u64;
        let within = (pos % dbsz as u64) as usize;
        let want = core::cmp::min(dbsz - within, len - filled);
        if let Some(block) = read_dnode_block(members, topo, dnode, blkid, order)? {
            let src = block
                .get(within..within + want)
                .ok_or(Error::Inconsistent {
                    token: "block_short",
                    where_: Location::Dnode { obj: 0 },
                })?;
            out[filled..filled + want].copy_from_slice(src);
        }
        // else: hole — `out` is already zero.
        filled += want;
    }
    Ok(out)
}
