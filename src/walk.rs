// SPDX-License-Identifier: MIT OR Apache-2.0
//! Object-set and ZAP navigation built on the dnode read primitive
//! ([`crate::file`]): decode an object set, read an object's dnode out of the
//! dnode array, and look up names in a (micro) ZAP. These are the steps the MOS
//! and DSL walks compose.

use alloc::{string::String, vec::Vec};

use crate::{
    block_read::{BlockRead, PoolMember},
    error::{Error, Location, Result},
    file::{read_dnode_block, read_dnode_range, with_decoder},
    phys::{
        BlockPointer, Dnode, EndianOrder, ObjectSet, ZapLeafChunkData, ZapLeafChunkEntry,
        ZapLeafHeader, ZapMicroIterator,
    },
    vdev::{read_block_pointer, Topology},
};

/// ZAP block types (first `u64` of a block).
const ZAP_MICRO: u64 = 0x8000_0000_0000_0003;
const ZAP_FAT_HEADER: u64 = 0x8000_0000_0000_0001;
/// Fat-ZAP leaf layout: a 48-byte header, then a `1 << (block_shift - 5)`-entry
/// `u16` hash table, then 24-byte chunks.
const ZAP_LEAF_HEADER_SIZE: usize = 48;
const ZAP_LEAF_CHUNK_SIZE: usize = 24;
/// Upper bound on leaf blocks scanned in one fat ZAP (denial-of-boot guard).
const MAX_ZAP_LEAF_BLOCKS: u64 = 1 << 20;

/// On-disk dnode size; object `n`'s dnode lives at byte `n * 512` of the dnode
/// array (the object set's meta-dnode data).
const DNODE_SIZE: u64 = 512;

/// Read and decode the object set rooted at `bp` (the value is owned — the meta
/// dnode's pointers/bonus are copied out of the decode buffer).
pub(crate) fn read_objset<R: BlockRead>(
    members: &mut [PoolMember<R>],
    topo: &Topology,
    bp: &BlockPointer,
    order: EndianOrder,
) -> Result<ObjectSet> {
    let bytes = read_block_pointer(members, topo, bp)?;
    with_decoder(&bytes, order, ObjectSet::from_decoder).map_err(|_| Error::Inconsistent {
        token: "objset_decode",
        where_: Location::Mos,
    })
}

/// Read object `objnum`'s dnode out of `dnode_array` (an object set's meta-dnode).
pub(crate) fn read_object_dnode<R: BlockRead>(
    members: &mut [PoolMember<R>],
    topo: &Topology,
    dnode_array: &Dnode,
    objnum: u64,
    order: EndianOrder,
) -> Result<Dnode> {
    // `objnum` can be a raw ZAP value (a DSL object number), so guard the
    // byte-offset multiply against wrap on a hostile value.
    let byte_off = objnum.checked_mul(DNODE_SIZE).ok_or(Error::Inconsistent {
        token: "dnode_obj_overflow",
        where_: Location::Dnode { obj: objnum },
    })?;
    let buf = read_dnode_range(
        members,
        topo,
        dnode_array,
        byte_off,
        DNODE_SIZE as usize,
        order,
    )?;
    with_decoder(&buf, order, Dnode::from_decoder)
        .map_err(|_| Error::Inconsistent {
            token: "dnode_decode",
            where_: Location::Dnode { obj: objnum },
        })?
        .ok_or(Error::Inconsistent {
            token: "dnode_empty",
            where_: Location::Dnode { obj: objnum },
        })
}

/// Decode every entry of a micro-ZAP object into owned `(name, value)` pairs.
/// (Fat ZAPs — only for very large directories — are not yet handled; the boot
/// ZAPs this reader targets, the object directory / master node / small dirs,
/// are micro.)
pub(crate) fn zap_entries<R: BlockRead>(
    members: &mut [PoolMember<R>],
    topo: &Topology,
    zap_dnode: &Dnode,
    order: EndianOrder,
) -> Result<Vec<(String, u64)>> {
    let dbsz = (zap_dnode.data_block_size_sectors as usize) << 9;
    if dbsz == 0 {
        return Err(Error::Inconsistent {
            token: "zap_dbsz0",
            where_: Location::Zap { obj: 0 },
        });
    }
    // Read block 0 and dispatch on the ZAP block type.
    let block0 =
        read_dnode_block(members, topo, zap_dnode, 0, order)?.ok_or(Error::Inconsistent {
            token: "zap_empty",
            where_: Location::Zap { obj: 0 },
        })?;
    let bt = block_type(&block0, order);
    if bt == ZAP_MICRO {
        micro_entries(&block0, order)
    } else if bt == ZAP_FAT_HEADER {
        fat_entries(members, topo, zap_dnode, dbsz, order)
    } else {
        Err(Error::Inconsistent {
            token: "zap_bad_type",
            where_: Location::Zap { obj: 0 },
        })
    }
}

/// First `u64` of a block, in the pool byte order.
fn block_type(block: &[u8], order: EndianOrder) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&block[..8]);
    match order {
        EndianOrder::Big => u64::from_be_bytes(b),
        EndianOrder::Little => u64::from_le_bytes(b),
    }
}

/// Decode every entry of a single micro-ZAP block.
fn micro_entries(block: &[u8], order: EndianOrder) -> Result<Vec<(String, u64)>> {
    with_decoder(block, order, |dec| {
        let it = ZapMicroIterator::from_decoder(dec).map_err(|_| Error::Inconsistent {
            token: "zap_micro",
            where_: Location::Zap { obj: 0 },
        })?;
        let mut out = Vec::new();
        for entry in it {
            let entry = entry.map_err(|_| Error::Inconsistent {
                token: "zap_entry",
                where_: Location::Zap { obj: 0 },
            })?;
            out.push((String::from(entry.name), entry.value));
        }
        Ok(out)
    })
}

/// Decode every entry of a fat ZAP by scanning its leaf blocks (block 0 is the
/// header / pointer table; entries live in the leaf blocks that follow). Scanning
/// every leaf avoids needing the name-hash + pointer-table lookup for a full
/// listing.
fn fat_entries<R: BlockRead>(
    members: &mut [PoolMember<R>],
    topo: &Topology,
    zap_dnode: &Dnode,
    dbsz: usize,
    order: EndianOrder,
) -> Result<Vec<(String, u64)>> {
    let block_shift = dbsz.trailing_zeros();
    let hash_entries = 1usize << (block_shift - 5);
    let chunk_base = ZAP_LEAF_HEADER_SIZE + hash_entries * 2;
    if chunk_base >= dbsz {
        return Err(Error::Inconsistent {
            token: "zap_leaf_geom",
            where_: Location::Zap { obj: 0 },
        });
    }
    let nchunks = (dbsz - chunk_base) / ZAP_LEAF_CHUNK_SIZE;

    let mut out = Vec::new();
    let mut blkid = 1u64;
    while blkid < MAX_ZAP_LEAF_BLOCKS {
        let Some(block) = read_dnode_block(members, topo, zap_dnode, blkid, order)? else {
            break;
        };
        if block.len() >= 8 && block_type(&block, order) == ZapLeafHeader::BLOCK_TYPE {
            collect_leaf(&block, chunk_base, nchunks, order, &mut out)?;
        }
        blkid += 1;
    }
    Ok(out)
}

/// Reassemble every entry of one fat-ZAP leaf block into `out`.
fn collect_leaf(
    block: &[u8],
    chunk_base: usize,
    nchunks: usize,
    order: EndianOrder,
    out: &mut Vec<(String, u64)>,
) -> Result<()> {
    let bad = || Error::Inconsistent {
        token: "zap_leaf_chunk",
        where_: Location::Zap { obj: 0 },
    };
    for ci in 0..nchunks {
        let off = chunk_base + ci * ZAP_LEAF_CHUNK_SIZE;
        let chunk = block.get(off..off + ZAP_LEAF_CHUNK_SIZE).ok_or_else(bad)?;
        if chunk[0] != ZapLeafChunkEntry::CHUNK_TYPE {
            continue;
        }
        let entry =
            with_decoder(chunk, order, ZapLeafChunkEntry::from_decoder).map_err(|_| bad())?;
        let name_bytes = collect_chunks(
            block,
            chunk_base,
            nchunks,
            entry.name_chunk,
            entry.name_length as usize,
            order,
        )?;
        let name_end = name_bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(name_bytes.len());
        let name = alloc::string::String::from_utf8_lossy(&name_bytes[..name_end]).into_owned();

        let value_len = entry.value_int_size as usize * entry.value_length as usize;
        let value_bytes = collect_chunks(
            block,
            chunk_base,
            nchunks,
            entry.value_chunk,
            value_len,
            order,
        )?;
        // ZAP integer values are stored big-endian within the array; right-align
        // into a u64 (a directory entry is one 8-byte value).
        let mut v = [0u8; 8];
        let n = value_bytes.len().min(8);
        v[8 - n..].copy_from_slice(&value_bytes[value_bytes.len() - n..]);
        out.push((name, u64::from_be_bytes(v)));
    }
    Ok(())
}

/// Follow a fat-ZAP array-chunk chain from `start`, collecting `length` bytes.
fn collect_chunks(
    block: &[u8],
    chunk_base: usize,
    nchunks: usize,
    start: u16,
    length: usize,
    order: EndianOrder,
) -> Result<Vec<u8>> {
    let bad = || Error::Inconsistent {
        token: "zap_array_chunk",
        where_: Location::Zap { obj: 0 },
    };
    // `length` is attacker-influenced (value_int_size * value_length); the chunk
    // chain can yield at most `nchunks * data_per_chunk` bytes, so reserve the
    // smaller of the two rather than trust a declared multi-MiB length.
    let cap = length.min(nchunks.saturating_mul(ZapLeafChunkData::ZAP_LEAF_DATA_SIZE));
    let mut out = Vec::with_capacity(cap);
    let mut next = Some(start);
    let mut guard = 0usize;
    while out.len() < length {
        let Some(idx) = next else { break };
        let idx = idx as usize;
        if idx >= nchunks || guard > nchunks {
            return Err(bad());
        }
        guard += 1;
        let off = chunk_base + idx * ZAP_LEAF_CHUNK_SIZE;
        let chunk = block.get(off..off + ZAP_LEAF_CHUNK_SIZE).ok_or_else(bad)?;
        let data = with_decoder(chunk, order, ZapLeafChunkData::from_decoder).map_err(|_| bad())?;
        let take = (length - out.len()).min(ZapLeafChunkData::ZAP_LEAF_DATA_SIZE);
        out.extend_from_slice(&data.data[..take]);
        next = data.next;
    }
    Ok(out)
}

/// Look up one name in a micro-ZAP, returning its `u64` value (an object number).
pub(crate) fn zap_lookup<R: BlockRead>(
    members: &mut [PoolMember<R>],
    topo: &Topology,
    zap_dnode: &Dnode,
    name: &str,
    order: EndianOrder,
) -> Result<Option<u64>> {
    Ok(zap_entries(members, topo, zap_dnode, order)?
        .into_iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v))
}
