// SPDX-License-Identifier: MIT OR Apache-2.0
//! Pool import (SPEC-LAMZFS §3): read a member's vdev label, decode the config
//! nvlist, build the topology, and select the active uberblock (whose block
//! pointer roots the Meta Object Set).

use alloc::{string::String, vec, vec::Vec};

use crate::{
    block_read::{read_exact, BlockRead, PoolMember},
    checksum::{Sha256, Sha256Implementation},
    error::{Error, LabelReason, Location, Result},
    phys::{Dnode, EndianOrder, LabelNvPairs, NvList, UberBlock},
    vdev::Topology,
    walk::read_objset,
};

/// Byte offset of the L0 NvPairs region from the start of a leaf device:
/// blank (8 KiB) + boot header (8 KiB).
const L0_NVPAIRS_BYTE: u64 = 16 * 1024;
/// Same, in sectors — the label checksum (`label_verify`) takes a *sector*
/// offset and shifts it internally, so the verify calls pass sectors, not bytes.
const L0_NVPAIRS_SECTOR: u64 = L0_NVPAIRS_BYTE >> 9;
/// Byte offset of the L0 uberblock array (after blank + boot header + nvpairs).
const L0_UBERBLOCK_BYTE: u64 = 128 * 1024;
/// Same, in sectors (for the checksum offset).
const L0_UBERBLOCK_SECTOR: u64 = L0_UBERBLOCK_BYTE >> 9;
/// Total size of the uberblock array region in a label.
const UBERBLOCK_ARRAY_SIZE: usize = 128 * 1024;
/// `VDEV_UBERBLOCK_SHIFT` floor: an uberblock slot is at least 1 KiB.
const UBERBLOCK_SHIFT_MIN: u8 = 10;
/// `MAX_UBERBLOCK_SHIFT` ceiling: ZFS caps an uberblock slot at 8 KiB regardless
/// of `ashift`. The slot size is `clamp(ashift, MIN, MAX)` — keeping the ceiling
/// both matches ZFS's offsets for large-ashift pools and bounds `1 << shift`
/// against a hostile `ashift` (a `usize` shift `>= 64` panics).
const UBERBLOCK_SHIFT_MAX: u8 = 13;

/// An imported pool with its active uberblock and resolved topology. The
/// uberblock's `ptr` roots the MOS.
pub(crate) struct ImportedPool {
    pub pool_guid: u64,
    pub pool_name: String,
    pub topology: Topology,
    pub uberblock: UberBlock,
    /// The Meta Object Set's meta-dnode (the MOS dnode array), read from the
    /// active uberblock's block pointer. Roots the DSL walk.
    pub mos_dnode: Dnode,
    /// The pool's byte order (from the rooting block pointer), used for every
    /// subsequent objset/dnode/ZAP decode.
    pub order: EndianOrder,
}

/// Import the pool from its member device(s): decode member 0's config nvlist,
/// build the topology, and select the active uberblock.
pub(crate) fn import<R: BlockRead>(members: &mut [PoolMember<R>]) -> Result<ImportedPool> {
    if members.is_empty() {
        return Err(Error::BadLabel(LabelReason::NoLabels));
    }
    let mut sha = Sha256::new(Sha256Implementation::Generic).map_err(|_| Error::Inconsistent {
        token: "sha_init",
        where_: Location::Uberblock,
    })?;

    // Decode member 0's config nvlist into owned values (the borrow of the label
    // buffer ends with this block).
    let (pool_guid, pool_name, ashift, topology) = {
        let buf = read_nvpairs(&mut members[0], &mut sha)?;
        let nvp = LabelNvPairs::from_bytes(&buf, L0_NVPAIRS_SECTOR, &mut sha)
            .map_err(|_| Error::BadLabel(LabelReason::BadChecksum))?;
        let config =
            NvList::from_bytes(nvp.payload).map_err(|_| Error::BadLabel(LabelReason::BadMagic))?;

        let pool_guid = nv_u64(&config, "pool_guid")?;
        let pool_name = nv_str(&config, "name")?.into();
        let vtree = nv_nvlist(&config, "vdev_tree")?;
        let ashift = u8::try_from(nv_u64(&vtree, "ashift")?).unwrap_or(UBERBLOCK_SHIFT_MIN);
        let topology = build_topology(&vtree, members, &mut sha)?;
        (pool_guid, pool_name, ashift, topology)
    };

    let uberblock = select_uberblock(&mut members[0], ashift, &mut sha)?;

    // Read the MOS rooted at the active uberblock, in the pool's byte order.
    let order = uberblock.ptr.order();
    let mos = read_objset(members, &topology, &uberblock.ptr, order)?;

    Ok(ImportedPool {
        pool_guid,
        pool_name,
        topology,
        uberblock,
        mos_dnode: mos.dnode,
        order,
    })
}

/// Read member 0's L0 NvPairs region (112 KiB at [`L0_NVPAIRS_BYTE`]).
fn read_nvpairs<R: BlockRead>(member: &mut PoolMember<R>, _sha: &mut Sha256) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; LabelNvPairs::SIZE];
    read_exact(
        &mut member.reader,
        L0_NVPAIRS_BYTE,
        &mut buf,
        0,
        "io_nvpairs",
    )?;
    Ok(buf)
}

/// Build the topology from the config `vdev_tree`. v0.1: single leaf or mirror;
/// raidz is rejected until the raidz1 increment lands; everything else is out of
/// scope (SPEC-LAMZFS §1.2).
fn build_topology<R: BlockRead>(
    vtree: &NvList<'_>,
    members: &mut [PoolMember<R>],
    sha: &mut Sha256,
) -> Result<Topology> {
    let vtype = nv_str(vtree, "type")?;
    match vtype {
        "disk" | "file" => Ok(Topology::Single(0)),
        "mirror" => {
            let children = nv_child_guids(vtree)?;
            let mut idx = Vec::with_capacity(children.len());
            for guid in children {
                idx.push(find_member_by_guid(members, guid, sha)?);
            }
            Ok(Topology::Mirror(idx))
        }
        "raidz" => {
            let nparity = nv_u64(vtree, "nparity").unwrap_or(1);
            if nparity != 1 {
                return Err(Error::UnsupportedTopology("topo_raidz_multiparity"));
            }
            let ashift = u8::try_from(nv_u64(vtree, "ashift")?).unwrap_or(9);
            let children = nv_child_guids(vtree)?;
            let mut idx = Vec::with_capacity(children.len());
            let mut present = 0usize;
            for guid in children {
                let m = find_member_by_guid(members, guid, sha).ok();
                if m.is_some() {
                    present += 1;
                }
                idx.push(m);
            }
            // raidz1 needs all but at most one column present to read (parity
            // reconstructs the missing one).
            if present + 1 < idx.len() {
                return Err(Error::UnsupportedTopology("topo_raidz_degraded"));
            }
            Ok(Topology::RaidZ1 {
                children: idx,
                ashift,
            })
        }
        "draid" => Err(Error::UnsupportedTopology("topo_draid")),
        _ => Err(Error::UnsupportedTopology("topo_unknown")),
    }
}

/// Extract the `guid` of each child of a vdev `children` array.
fn nv_child_guids(vtree: &NvList<'_>) -> Result<Vec<u64>> {
    let pair = nv_find(vtree, "children")?;
    let array = pair.get_nv_list_array().map_err(|_| Error::Inconsistent {
        token: "nv_children",
        where_: Location::Vdev { guid: 0 },
    })?;
    let mut out = Vec::new();
    for child in array.iter() {
        let child = child.map_err(|_| Error::Inconsistent {
            token: "nv_child",
            where_: Location::Vdev { guid: 0 },
        })?;
        out.push(nv_u64(&child, "guid")?);
    }
    Ok(out)
}

/// Find the member whose label's top-level `guid` equals `guid`.
fn find_member_by_guid<R: BlockRead>(
    members: &mut [PoolMember<R>],
    guid: u64,
    sha: &mut Sha256,
) -> Result<usize> {
    for (i, member) in members.iter_mut().enumerate() {
        let buf = read_nvpairs(member, sha)?;
        let Ok(nvp) = LabelNvPairs::from_bytes(&buf, L0_NVPAIRS_SECTOR, sha) else {
            continue;
        };
        let Ok(config) = NvList::from_bytes(nvp.payload) else {
            continue;
        };
        if nv_u64(&config, "guid").is_ok_and(|g| g == guid) {
            return Ok(i);
        }
    }
    Err(Error::BadLabel(LabelReason::PoolGuidMismatch))
}

/// Select the active uberblock from member 0's L0 uberblock array: the highest
/// valid `(txg, timestamp)` with a verifying checksum.
fn select_uberblock<R: BlockRead>(
    member: &mut PoolMember<R>,
    ashift: u8,
    sha: &mut Sha256,
) -> Result<UberBlock> {
    let shift = ashift.clamp(UBERBLOCK_SHIFT_MIN, UBERBLOCK_SHIFT_MAX);
    let slot = 1usize << shift;
    let count = UBERBLOCK_ARRAY_SIZE / slot;
    let mut buf = vec![0u8; slot];
    let mut best: Option<UberBlock> = None;
    let slot_sectors = (slot >> 9) as u64;
    for i in 0..count {
        let byte_off = L0_UBERBLOCK_BYTE + (i * slot) as u64;
        let sector_off = L0_UBERBLOCK_SECTOR + i as u64 * slot_sectors;
        if read_exact(&mut member.reader, byte_off, &mut buf, 0, "io_uberblock").is_err() {
            continue;
        }
        if let Ok(Some(ub)) = UberBlock::from_bytes(&buf, sector_off, sha) {
            best = match best {
                Some(b) if !ub.is_newer_than(&b) => Some(b),
                _ => Some(ub),
            };
        }
    }
    best.ok_or(Error::NoValidUberblock)
}

// --- nvlist helpers (keys are always static literals) --------------------------

fn nv_find<'a>(list: &NvList<'a>, key: &'static str) -> Result<crate::phys::NvPair<'a, 'a>> {
    for pair in list {
        let pair = pair.map_err(|_| Error::Inconsistent {
            token: "nv_decode",
            where_: Location::Vdev { guid: 0 },
        })?;
        if pair.name == key {
            return Ok(pair);
        }
    }
    Err(Error::NotFound { component: key })
}

fn nv_u64(list: &NvList<'_>, key: &'static str) -> Result<u64> {
    nv_find(list, key)?
        .get_u64()
        .map_err(|_| Error::Inconsistent {
            token: "nv_u64",
            where_: Location::Vdev { guid: 0 },
        })
}

fn nv_str<'a>(list: &NvList<'a>, key: &'static str) -> Result<&'a str> {
    nv_find(list, key)?
        .get_str()
        .map_err(|_| Error::Inconsistent {
            token: "nv_str",
            where_: Location::Vdev { guid: 0 },
        })
}

fn nv_nvlist<'a>(list: &NvList<'a>, key: &'static str) -> Result<NvList<'a>> {
    nv_find(list, key)?
        .get_nv_list()
        .map_err(|_| Error::Inconsistent {
            token: "nv_nvlist",
            where_: Location::Vdev { guid: 0 },
        })
}
