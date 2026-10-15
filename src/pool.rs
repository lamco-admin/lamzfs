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
    vdev::{Layout, Topology},
    walk::{read_object_dnode, read_objset, zap_entries, zap_lookup, zap_lookup_bytes},
};

/// Byte offset of the L0 NvPairs region from the start of a leaf device:
/// blank (8 KiB) + boot header (8 KiB).
const L0_NVPAIRS_BYTE: u64 = 16 * 1024;
/// Same, in sectors — the label checksum (`label_verify`) takes a *sector*
/// offset and shifts it internally, so the verify calls pass sectors, not bytes.
const L0_NVPAIRS_SECTOR: u64 = L0_NVPAIRS_BYTE >> 9;
/// Size of one vdev label; a leaf carries four, two at each end.
const LABEL_SIZE: u64 = 256 * 1024;
/// Offset of the uberblock array within a label (after blank + boot header +
/// nvpairs).
const LABEL_UBERBLOCK_OFFSET: u64 = 128 * 1024;
/// Object 1 of the MOS: the object directory, which names `features_for_read`.
const MOS_OBJECT_DIRECTORY: u64 = 1;
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

/// Read one member's pool identity (`guid`, `name`) from its vdev label config
/// nvlist, without importing the pool — for grouping members into pools before
/// import (a host may carry members of several pools).
pub(crate) fn peek_pool_id<R: BlockRead>(member: &mut PoolMember<R>) -> Result<(u64, String)> {
    let mut sha = Sha256::new(Sha256Implementation::Generic).map_err(|_| Error::Inconsistent {
        token: "sha_init",
        where_: Location::Uberblock,
    })?;
    let buf = read_nvpairs(member, &mut sha)?;
    let nvp = LabelNvPairs::from_bytes(&buf, L0_NVPAIRS_SECTOR, &mut sha)
        .map_err(|_| Error::BadLabel(LabelReason::BadChecksum))?;
    let config =
        NvList::from_bytes(nvp.payload).map_err(|_| Error::BadLabel(LabelReason::BadMagic))?;
    let guid = nv_u64(&config, "pool_guid")?;
    let name = nv_str(&config, "name")?.into();
    Ok((guid, name))
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
    let (pool_guid, pool_name, ashift, mut topology) = {
        let buf = read_nvpairs(&mut members[0], &mut sha)?;
        let nvp = LabelNvPairs::from_bytes(&buf, L0_NVPAIRS_SECTOR, &mut sha)
            .map_err(|_| Error::BadLabel(LabelReason::BadChecksum))?;
        let config =
            NvList::from_bytes(nvp.payload).map_err(|_| Error::BadLabel(LabelReason::BadMagic))?;

        let pool_guid = nv_u64(&config, "pool_guid")?;
        let pool_name = nv_str(&config, "name")?.into();
        // The label lists the active features the MOS itself depends on, so
        // they're checked before any MOS block is read.
        if nv_has(&config, "features_for_read")? {
            let label_features = nv_nvlist(&config, "features_for_read")?;
            for pair in &label_features {
                let pair = pair.map_err(|_| Error::Inconsistent {
                    token: "nv_decode",
                    where_: Location::Vdev { guid: 0 },
                })?;
                check_read_feature(pair.name)?;
            }
        }
        // Each top-level vdev routes its own DVAs; this reader has one.
        if nv_has(&config, "vdev_children")? && nv_u64(&config, "vdev_children")? != 1 {
            return Err(Error::UnsupportedTopology("topo_multi_toplevel"));
        }
        let vtree = nv_nvlist(&config, "vdev_tree")?;
        let ashift = u8::try_from(nv_u64(&vtree, "ashift")?).unwrap_or(UBERBLOCK_SHIFT_MIN);
        let topology = Topology {
            layout: build_topology(&vtree, members, &mut sha)?,
            checksum_salt: None,
        };
        (pool_guid, pool_name, ashift, topology)
    };

    let uberblock = select_uberblock(members, &topology, ashift, &mut sha)?;
    // Non-zero while a RAID-Z expansion is moving data: Blocks then have two
    // geometries, which this reader doesn't model.
    if uberblock.raidz_reflow_info != 0 {
        return Err(Error::UnsupportedFeature("raidz_expansion"));
    }

    // Read the MOS rooted at the active uberblock, in the pool's byte order.
    let order = uberblock.ptr.order();
    let mos = read_objset(members, &topology, &uberblock.ptr, order)?;
    let objdir = read_object_dnode(members, &topology, &mos.dnode, MOS_OBJECT_DIRECTORY, order)?;
    check_mos_features(members, &topology, &mos.dnode, &objdir, order)?;
    topology.checksum_salt = checksum_salt(members, &topology, &objdir, order)?;

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
) -> Result<Layout> {
    let vtype = nv_str(vtree, "type")?;
    match vtype {
        "disk" | "file" => Ok(Layout::Single(0)),
        "mirror" => {
            let children = nv_child_guids(vtree)?;
            let mut idx = Vec::with_capacity(children.len());
            for guid in children {
                idx.push(find_member_by_guid(members, guid, sha)?);
            }
            Ok(Layout::Mirror(idx))
        }
        "raidz" => {
            let nparity = nv_u64(vtree, "nparity").unwrap_or(1);
            if nparity != 1 {
                return Err(Error::UnsupportedTopology("topo_raidz_multiparity"));
            }
            // An expanded RAID-Z keeps blocks written before each expansion
            // at their old width; the label records when it happened.
            if nv_has(vtree, "raidz_expand_txgs")? || nv_has(vtree, "raidz_expanding")? {
                return Err(Error::UnsupportedFeature("raidz_expansion"));
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
            Ok(Layout::RaidZ1 {
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

/// Select the active uberblock: the highest valid `(txg, timestamp)` with a
/// verifying checksum across all four labels of every member in the topology,
/// as ZFS does. A mirror member that missed the last writes still carries older
/// uberblocks, so reading only one member's labels can pick a stale tree.
fn select_uberblock<R: BlockRead>(
    members: &mut [PoolMember<R>],
    topology: &Topology,
    ashift: u8,
    sha: &mut Sha256,
) -> Result<UberBlock> {
    let shift = ashift.clamp(UBERBLOCK_SHIFT_MIN, UBERBLOCK_SHIFT_MAX);
    let slot = 1usize << shift;
    let count = UBERBLOCK_ARRAY_SIZE / slot;
    let mut buf = vec![0u8; slot];
    let mut best: Option<UberBlock> = None;
    for mi in topology.members() {
        let Some(member) = members.get_mut(mi) else {
            continue;
        };
        for label in label_offsets(member.device_size_bytes) {
            for i in 0..count {
                let byte_off = label + LABEL_UBERBLOCK_OFFSET + (i * slot) as u64;
                if read_exact(&mut member.reader, byte_off, &mut buf, 0, "io_uberblock").is_err() {
                    continue;
                }
                // The label checksum is seeded with the slot's device offset.
                if let Ok(Some(ub)) = UberBlock::from_bytes(&buf, byte_off >> 9, sha) {
                    best = match best {
                        Some(b) if !ub.is_newer_than(&b) => Some(b),
                        _ => Some(ub),
                    };
                }
            }
        }
    }
    best.ok_or(Error::NoValidUberblock)
}

/// Byte offsets of a leaf's four labels: L0 and L1 at the front, L2 and L3 in
/// the last 512 KiB of the device rounded down to a label boundary. Only the
/// front two when the device size is unknown or too small.
fn label_offsets(device_size: u64) -> Vec<u64> {
    let mut out = vec![0, LABEL_SIZE];
    let end = device_size - device_size % LABEL_SIZE;
    if end >= 4 * LABEL_SIZE {
        out.push(end - 2 * LABEL_SIZE);
        out.push(end - LABEL_SIZE);
    }
    out
}

/// Refuse an active read feature this reader doesn't understand. ZFS records
/// each enabled feature that a reader must understand once it's active in the
/// `features_for_read` set; features that only matter to writers live in
/// `features_for_write` and never block a read.
fn check_read_feature(guid: &str) -> Result<()> {
    if READ_FEATURES_UNDERSTOOD.contains(&guid) {
        return Ok(());
    }
    let short = guid.rsplit(':').next().unwrap_or(guid);
    Err(Error::UnsupportedFeature(
        REFUSED_FEATURE_TOKENS
            .iter()
            .find(|t| **t == short)
            .copied()
            .unwrap_or("feat_unknown_read_incompat"),
    ))
}

/// Read features this reader handles, or doesn't need to:
///
/// - Formats it reads: lz4 and zstd compression, embedded data, hole birth,
///   large blocks (up to 16 MiB), large dnodes and names over 255 bytes
///   (`longname`, held in fat ZAPs like any other name).
/// - Pool bookkeeping it never consults: extensible datasets, vdev ZAPs v2,
///   the head error log, bookmarks and crash dumps.
/// - Checksums: SHA-512 and BLAKE3 are verified. Skein and Edon-R are refused
///   block by block with a typed error, so a pool that uses them elsewhere still
///   opens.
/// - Encryption: Every block of an encrypted dataset is refused with the typed
///   `encryption` error, so an unencrypted `/boot` dataset beside encrypted ones
///   still reads.
const READ_FEATURES_UNDERSTOOD: &[&str] = &[
    "com.datto:encryption",
    "org.illumos:lz4_compress",
    "org.freebsd:zstd_compress",
    "com.delphix:embedded_data",
    "com.delphix:hole_birth",
    "org.open-zfs:large_blocks",
    "org.zfsonlinux:large_dnode",
    "com.delphix:extensible_dataset",
    "com.klarasystems:vdev_zaps_v2",
    "com.delphix:head_errlog",
    "com.delphix:bookmarks",
    "com.datto:bookmark_v2",
    "com.delphix:bookmark_written",
    "com.delphix:redaction_bookmarks",
    "com.joyent:multi_vdev_crash_dump",
    "org.zfsonlinux:longname",
    "org.illumos:sha512",
    "org.illumos:skein",
    "org.illumos:edonr",
    "org.openzfs:blake3",
];

/// Tokens for the refused read features this reader knows by name; any other
/// active read feature is `feat_unknown_read_incompat`.
const REFUSED_FEATURE_TOKENS: &[&str] = &[
    "raidz_expansion",
    "device_removal",
    "draid",
    "dynamic_gang_header",
    "redacted_datasets",
    "redaction_list_spill",
];

/// Check every active feature in the MOS `features_for_read` ZAP (feature guid
/// to reference count; a count of 0 means enabled but unused). A pool older
/// than feature flags (SPA version 28 and below) has no such ZAP.
fn check_mos_features<R: BlockRead>(
    members: &mut [PoolMember<R>],
    topology: &Topology,
    mos: &Dnode,
    objdir: &Dnode,
    order: EndianOrder,
) -> Result<()> {
    let Some(obj) = zap_lookup(members, topology, objdir, "features_for_read", order)? else {
        return Ok(());
    };
    let features = read_object_dnode(members, topology, mos, obj, order)?;
    for (guid, refcount) in zap_entries(members, topology, &features, order)? {
        if refcount != 0 {
            check_read_feature(&guid)?;
        }
    }
    Ok(())
}

/// The pool's checksum salt: 32 bytes ZFS creates with the pool, which key the
/// salted checksums (BLAKE3, Skein, Edon-R). Older pools may lack it.
fn checksum_salt<R: BlockRead>(
    members: &mut [PoolMember<R>],
    topology: &Topology,
    objdir: &Dnode,
    order: EndianOrder,
) -> Result<Option<[u8; 32]>> {
    let Some(bytes) = zap_lookup_bytes(
        members,
        topology,
        objdir,
        "org.illumos:checksum_salt",
        order,
    )?
    else {
        return Ok(None);
    };
    let salt = <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| Error::Inconsistent {
        token: "checksum_salt",
        where_: Location::Mos,
    })?;
    Ok(Some(salt))
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

/// Is `key` present in `list`?
fn nv_has(list: &NvList<'_>, key: &'static str) -> Result<bool> {
    match nv_find(list, key) {
        Ok(_) => Ok(true),
        Err(Error::NotFound { .. }) => Ok(false),
        Err(e) => Err(e),
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_features_installers_activate_are_understood() {
        for guid in [
            "org.illumos:lz4_compress",
            "com.delphix:hole_birth",
            "com.delphix:embedded_data",
            "com.klarasystems:vdev_zaps_v2",
            "com.delphix:head_errlog",
            "org.zfsonlinux:large_dnode",
            "com.datto:encryption",
            "org.zfsonlinux:longname",
            "org.openzfs:blake3",
        ] {
            assert_eq!(check_read_feature(guid), Ok(()), "{guid}");
        }
    }

    #[test]
    fn refused_read_features_carry_their_own_token() {
        let token = |guid| match check_read_feature(guid) {
            Err(Error::UnsupportedFeature(t)) => t,
            other => panic!("{guid}: {other:?}"),
        };
        assert_eq!(token("org.openzfs:raidz_expansion"), "raidz_expansion");
        assert_eq!(token("com.delphix:device_removal"), "device_removal");
        assert_eq!(token("org.openzfs:draid"), "draid");
        assert_eq!(
            token("org.openzfs:dynamic_gang_header"),
            "dynamic_gang_header"
        );
        assert_eq!(
            token("org.openzfs:draid_failure_domains"),
            "feat_unknown_read_incompat"
        );
        assert_eq!(token("com.example:future"), "feat_unknown_read_incompat");
    }

    #[test]
    fn labels_sit_at_both_ends_of_the_device() {
        let mib = 1024 * 1024;
        assert_eq!(
            label_offsets(128 * mib),
            [
                0,
                LABEL_SIZE,
                128 * mib - 2 * LABEL_SIZE,
                128 * mib - LABEL_SIZE
            ]
        );
        // The end labels align down to a label boundary.
        let odd = 128 * mib + 1000;
        assert_eq!(label_offsets(odd)[3], 128 * mib - LABEL_SIZE);
        // Unknown or tiny devices: The front two only.
        assert_eq!(label_offsets(0), [0, LABEL_SIZE]);
        assert_eq!(label_offsets(3 * LABEL_SIZE), [0, LABEL_SIZE]);
    }
}
