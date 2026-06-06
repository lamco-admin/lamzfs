// SPDX-License-Identifier: MIT OR Apache-2.0
//! Vdev topology + DVA routing, and the one primitive that reads, verifies, and
//! decompresses a single block pointer (SPEC-LAMZFS §3.2).
//!
//! A block pointer's Data Virtual Address `(vdev, offset, asize)` names a logical
//! location in the pool; this module maps it to physical reads on the member
//! devices. For a single leaf there is one copy; for a mirror every child holds
//! the same bytes, so a child that fails its checksum is retried against the next
//! (the read side of ZFS self-healing). RAIDZ1 stripes data across columns; the
//! healthy read concatenates the data columns (degraded-mode XOR reconstruction
//! is a follow-up). raidz2/3 and dRAID are rejected at import.

use alloc::{vec, vec::Vec};

use crate::{
    block_read::{read_exact, BlockRead, PoolMember},
    cksum::verify_block,
    compress::decompress,
    error::{Error, Location, Result},
    phys::{BlockPointer, BlockPointerRegular, Dva},
};

/// Bytes reserved at the front of every leaf vdev before allocatable space:
/// the L0+L1 labels (2 × 256 KiB) plus the 3.5 MiB boot block = 4 MiB. A DVA
/// `offset` of 0 maps to this byte. (rzfs `BootBlock::BLOCK_DEVICE_OFFSET` +
/// `BootBlock::SIZE`.)
const LABEL_RESERVE: u64 = 4 * 1024 * 1024;

/// On-disk sector shift (512-byte sectors); DVA offsets and bp sizes are counted
/// in these.
const SECTOR_SHIFT: u32 = 9;

/// Largest valid vdev `ashift` (ZFS `ASHIFT_MAX`, 16 → 64 KiB sectors). A config
/// claiming more is corrupt or hostile; rejecting it keeps the raidz geometry
/// shifts (`>> (ashift - 9)`, `>> ashift`) below the 64-bit overflow boundary.
const ASHIFT_MAX: u8 = 16;

/// The pool's single top-level vdev, expressed as indices into the imported
/// member set. v0.1 supports a single leaf or a mirror.
pub(crate) enum Topology {
    /// One leaf device (member index).
    Single(usize),
    /// A mirror: every child holds the same data; read any healthy child.
    Mirror(Vec<usize>),
    /// A single-parity RAID-Z: data is striped across `children` with one parity
    /// column per row; a missing or checksum-failing column is reconstructed by
    /// XOR against parity. A column is `None` when its member device was not
    /// provided (a degraded pool — raidz1 tolerates one).
    RaidZ1 {
        /// Member index per raidz column, in column order; `None` = absent.
        children: Vec<Option<usize>>,
        /// The vdev sector shift (raidz geometry is in `1 << ashift` sectors).
        ashift: u8,
    },
}

impl Topology {
    /// Member indices that physically hold a DVA's data, in read-try order
    /// (single + mirror only; raidz takes the dedicated column path).
    fn read_order(&self) -> &[usize] {
        match self {
            Topology::Single(idx) => core::slice::from_ref(idx),
            Topology::Mirror(children) => children,
            Topology::RaidZ1 { .. } => &[],
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
            // RAID-Z stripes data across columns — a dedicated assembly path.
            if let Topology::RaidZ1 { children, ashift } = topo {
                return raidz1_read(members, children, *ashift, r, psize, lsize);
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

/// One column of a RAID-Z row map.
struct RaidzCol {
    devidx: usize,
    offset: u64,
    size: usize,
    parity: bool,
}

/// Compute the RAID-Z column layout for a DVA (the `vdev_raidz_map_alloc`
/// geometry): which child holds each data/parity column, at what per-child byte
/// offset and size. `psize` is the *data* size; parity columns are added.
#[expect(
    clippy::many_single_char_names,
    reason = "b/s/f/o/q/r mirror the variable names in ZFS vdev_raidz_map_alloc"
)]
fn raidz_map(
    dva: &Dva,
    ashift: u8,
    dcols: u64,
    nparity: u64,
    psize: usize,
) -> Result<Vec<RaidzCol>> {
    let geom = || Error::Inconsistent {
        token: "raidz_geom",
        where_: Location::Vdev { guid: 0 },
    };
    // ashift is bounded to ZFS's valid range so `>> (ash - 9)` and `>> ash`
    // below cannot reach a >= 64 exponent (panic/wrap on a hostile config).
    if dcols <= nparity || !(9..=ASHIFT_MAX).contains(&ashift) {
        return Err(geom());
    }
    let ash = u32::from(ashift);
    let secsize = 1u64 << ash;
    // The DVA offset is in 512-byte sectors; convert to ashift-sized sectors.
    let b = dva.offset >> (ash - 9);
    // Data sectors, rounded UP: a sub-sector physical block (e.g. 512 B on an
    // ashift=12 vdev) still occupies one whole raidz data sector.
    let s = ((psize as u64) + secsize - 1) >> ash;
    if s == 0 {
        return Err(geom());
    }
    let f = b % dcols;
    let o = (b / dcols) << ash;
    let q = s / (dcols - nparity);
    let r = s - q * (dcols - nparity);
    let bc = if r == 0 { 0 } else { r + nparity };
    let acols = if q == 0 { bc } else { dcols };
    let mut cols = Vec::with_capacity(acols as usize);
    for c in 0..acols {
        let col = f + c;
        let (devidx, coff) = if col >= dcols {
            ((col - dcols) as usize, o + secsize)
        } else {
            (col as usize, o)
        };
        let size = if c < bc {
            (q + 1) * secsize
        } else {
            q * secsize
        };
        cols.push(RaidzCol {
            devidx,
            offset: coff,
            size: size as usize,
            parity: c < nparity,
        });
    }
    Ok(cols)
}

/// Read every raidz column into a per-column buffer; an absent member (`None`
/// index) or a failed read yields `None` for that column.
fn raidz1_read_columns<R: BlockRead>(
    members: &mut [PoolMember<R>],
    children: &[Option<usize>],
    cols: &[RaidzCol],
    vdev: u32,
) -> Vec<Option<Vec<u8>>> {
    cols.iter()
        .map(|col| {
            let mi = (*children.get(col.devidx)?)?;
            let byte = LABEL_RESERVE.checked_add(col.offset)?;
            let member = members.get_mut(mi)?;
            let mut buf = vec![0u8; col.size];
            read_exact(&mut member.reader, byte, &mut buf, u64::from(vdev), "io_raidz").ok()?;
            Some(buf)
        })
        .collect()
}

/// Concatenate the data columns into the physical block (truncated to `psize`),
/// substituting `replacement` for column `replace_idx` when given. `None` if a
/// needed data column is absent.
fn raidz1_assemble(
    cols: &[RaidzCol],
    colbufs: &[Option<Vec<u8>>],
    psize: usize,
    replace_idx: Option<usize>,
    replacement: Option<&[u8]>,
) -> Option<Vec<u8>> {
    let mut data = Vec::with_capacity(psize);
    for (i, col) in cols.iter().enumerate() {
        if col.parity {
            continue;
        }
        if Some(i) == replace_idx {
            data.extend_from_slice(replacement?);
        } else {
            data.extend_from_slice(colbufs.get(i)?.as_deref()?);
        }
    }
    if data.len() < psize {
        return None;
    }
    data.truncate(psize);
    Some(data)
}

/// Reconstruct raidz column `target` as parity XOR the other present columns
/// (raidz1: parity is column 0). `None` if parity or another needed column is
/// absent — more than the recoverable one is missing.
fn raidz1_reconstruct(cols: &[RaidzCol], colbufs: &[Option<Vec<u8>>], target: usize) -> Option<Vec<u8>> {
    let parity = colbufs.first()?.as_deref()?;
    let size = cols.get(target)?.size;
    let mut rebuilt = vec![0u8; size];
    let n = size.min(parity.len());
    rebuilt[..n].copy_from_slice(&parity[..n]);
    for (i, _col) in cols.iter().enumerate() {
        if i == 0 || i == target {
            continue; // skip parity (the seed) and the column being rebuilt
        }
        let other = colbufs.get(i)?.as_deref()?;
        for (k, b) in other.iter().enumerate().take(size) {
            rebuilt[k] ^= b;
        }
    }
    Some(rebuilt)
}

/// Read a RAID-Z1 block pointer. For each DVA copy: read all columns, try the
/// healthy assembly, and on a missing/checksum-failing column reconstruct each
/// data column from parity in turn until one verifies (raidz1 recovers one).
fn raidz1_read<R: BlockRead>(
    members: &mut [PoolMember<R>],
    children: &[Option<usize>],
    ashift: u8,
    r: &BlockPointerRegular,
    psize: usize,
    lsize: usize,
) -> Result<Vec<u8>> {
    let dcols = children.len() as u64;
    let mut last = Error::Inconsistent {
        token: "raidz_no_copy",
        where_: Location::Vdev { guid: 0 },
    };
    for dva in r.dvas.iter().flatten() {
        let cols = match raidz_map(dva, ashift, dcols, 1, psize) {
            Ok(c) => c,
            Err(e) => {
                last = e;
                continue;
            }
        };
        let colbufs = raidz1_read_columns(members, children, &cols, dva.vdev);
        let verify = |raw: &[u8]| {
            verify_block(
                r.checksum_type,
                r.order,
                raw,
                &r.checksum_value,
                u64::from(dva.vdev),
                dva.offset,
            )
            .is_ok()
        };
        // Healthy: every data column present and correct.
        if let Some(raw) = raidz1_assemble(&cols, &colbufs, psize, None, None) {
            if verify(&raw) {
                return decompress(r.compression, &raw, lsize);
            }
        }
        // Degraded: rebuild each data column from parity and re-verify.
        for (i, col) in cols.iter().enumerate() {
            if col.parity {
                continue;
            }
            let Some(rebuilt) = raidz1_reconstruct(&cols, &colbufs, i) else {
                continue;
            };
            if let Some(raw) = raidz1_assemble(&cols, &colbufs, psize, Some(i), Some(&rebuilt)) {
                if verify(&raw) {
                    return decompress(r.compression, &raw, lsize);
                }
            }
        }
        last = Error::ChecksumMismatch {
            vdev: u64::from(dva.vdev),
            offset: dva.offset,
            what: "raidz_unrecoverable",
        };
    }
    Err(last)
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

    #[test]
    fn raidz_map_rejects_hostile_geometry() {
        let dva = Dva {
            allocated: 8,
            offset: 1024,
            is_gang: false,
            vdev: 0,
        };
        // ashift past ASHIFT_MAX (would drive `>> (ash - 9)` toward a >= 64
        // exponent) is refused, not allowed to panic/wrap.
        assert!(raidz_map(&dva, 200, 3, 1, 4096).is_err());
        // Below the 9-bit sector floor.
        assert!(raidz_map(&dva, 8, 3, 1, 4096).is_err());
        // Degenerate width: data columns <= parity columns.
        assert!(raidz_map(&dva, 12, 1, 1, 4096).is_err());
        // A sane raidz1 width yields columns with exactly one parity column.
        let cols = raidz_map(&dva, 12, 3, 1, 4096).unwrap();
        assert_eq!(cols.iter().filter(|c| c.parity).count(), 1);
    }
}
