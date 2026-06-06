// SPDX-License-Identifier: MIT OR Apache-2.0
//! DSL traversal to a target dataset and its ZPL filesystem root (SPEC-LAMZFS
//! §3/§8.5): MOS object directory → root DSL directory → child directories by
//! name → the dataset's object set → the ZPL master node and root directory.

use alloc::{string::String, vec::Vec};

use crate::{
    block_read::{BlockRead, PoolMember},
    error::{Error, Location, Result},
    file::with_decoder,
    phys::{Dnode, DslDataSet, DslDirectory, EndianOrder},
    vdev::Topology,
    walk::{read_object_dnode, read_objset, zap_entries, zap_lookup},
};

/// Object 1 of the MOS — the object directory (a ZAP) mapping pool-level names.
const MOS_OBJECT_DIRECTORY: u64 = 1;
/// Object 1 of a filesystem object set — the ZPL master node (a ZAP).
const ZPL_MASTER_NODE: u64 = 1;

/// A mounted dataset: the meta-dnode of its object set (the dnode array for this
/// filesystem's objects).
pub(crate) struct Dataset {
    pub meta_dnode: Dnode,
}

/// Decode a DSL directory's `dsl_dir_phys` bonus from its dnode.
fn dsl_dir<R: BlockRead>(
    members: &mut [PoolMember<R>],
    topo: &Topology,
    mos: &Dnode,
    obj: u64,
    order: EndianOrder,
) -> Result<DslDirectory> {
    let dnode = read_object_dnode(members, topo, mos, obj, order)?;
    with_decoder(dnode.bonus_used(), order, DslDirectory::from_decoder).map_err(|_| {
        Error::Inconsistent {
            token: "dsl_dir",
            where_: Location::Dsl { obj },
        }
    })
}

/// Walk to the dataset named by `names` — child-directory components under the
/// root dataset (e.g. `["BOOT", "test"]`, the `DatasetSelector::Name` case) — and
/// open its object set.
pub(crate) fn open_dataset<R: BlockRead>(
    members: &mut [PoolMember<R>],
    topo: &Topology,
    mos: &Dnode,
    order: EndianOrder,
    names: &[&str],
) -> Result<Dataset> {
    let objdir = read_object_dnode(members, topo, mos, MOS_OBJECT_DIRECTORY, order)?;
    let mut dir_obj =
        zap_lookup(members, topo, &objdir, "root_dataset", order)?.ok_or(Error::NotFound {
            component: "root_dataset",
        })?;

    for name in names {
        let dir = dsl_dir(members, topo, mos, dir_obj, order)?;
        let child_zap = read_object_dnode(members, topo, mos, dir.child_directory_zap_obj, order)?;
        dir_obj = zap_lookup(members, topo, &child_zap, name, order)?.ok_or(Error::NotFound {
            component: "dataset",
        })?;
    }

    // The selected DSL directory → head dataset → dsl_dataset_phys → objset bp.
    let dir = dsl_dir(members, topo, mos, dir_obj, order)?;
    let ds_obj = dir.head_dataset_obj.ok_or(Error::NotFound {
        component: "head_dataset",
    })?;
    let ds_dnode = read_object_dnode(members, topo, mos, ds_obj, order)?;
    let ds =
        with_decoder(ds_dnode.bonus_used(), order, DslDataSet::from_decoder).map_err(|_| {
            Error::Inconsistent {
                token: "dsl_dataset",
                where_: Location::Dsl { obj: ds_obj },
            }
        })?;
    let bp = ds.block_pointer.ok_or(Error::Inconsistent {
        token: "dataset_no_bp",
        where_: Location::Dsl { obj: ds_obj },
    })?;
    let objset = read_objset(members, topo, &bp, order)?;
    Ok(Dataset {
        meta_dnode: objset.dnode,
    })
}

/// Names of the immediate child datasets under `parent` (the child-directory
/// components selecting a DSL directory; empty = the pool root dataset). Internal
/// datasets (`$ORIGIN`, `$MOS`, …) are filtered out. The child-directory ZAP maps
/// each child's name to its DSL directory object.
pub(crate) fn child_dataset_names<R: BlockRead>(
    members: &mut [PoolMember<R>],
    topo: &Topology,
    mos: &Dnode,
    order: EndianOrder,
    parent: &[&str],
) -> Result<Vec<String>> {
    let objdir = read_object_dnode(members, topo, mos, MOS_OBJECT_DIRECTORY, order)?;
    let mut dir_obj =
        zap_lookup(members, topo, &objdir, "root_dataset", order)?.ok_or(Error::NotFound {
            component: "root_dataset",
        })?;
    for name in parent {
        let dir = dsl_dir(members, topo, mos, dir_obj, order)?;
        let child_zap = read_object_dnode(members, topo, mos, dir.child_directory_zap_obj, order)?;
        dir_obj = zap_lookup(members, topo, &child_zap, name, order)?.ok_or(Error::NotFound {
            component: "dataset",
        })?;
    }
    let dir = dsl_dir(members, topo, mos, dir_obj, order)?;
    let child_zap = read_object_dnode(members, topo, mos, dir.child_directory_zap_obj, order)?;
    let names = zap_entries(members, topo, &child_zap, order)?
        .into_iter()
        .map(|(name, _obj)| name)
        .filter(|name| !name.starts_with('$'))
        .collect();
    Ok(names)
}

/// The dataset's ZPL root directory object number (from the master node's `ROOT`).
pub(crate) fn root_dir_obj<R: BlockRead>(
    members: &mut [PoolMember<R>],
    topo: &Topology,
    dataset: &Dataset,
    order: EndianOrder,
) -> Result<u64> {
    let master = read_object_dnode(members, topo, &dataset.meta_dnode, ZPL_MASTER_NODE, order)?;
    zap_lookup(members, topo, &master, "ROOT", order)?.ok_or(Error::NotFound { component: "ROOT" })
}

/// List a directory object's entries: `(name, value)` where the ZPL packs the
/// object number in the low 48 bits and the file type in the high bits.
pub(crate) fn list_dir<R: BlockRead>(
    members: &mut [PoolMember<R>],
    topo: &Topology,
    dataset: &Dataset,
    dir_obj: u64,
    order: EndianOrder,
) -> Result<Vec<(String, u64)>> {
    let dir = read_object_dnode(members, topo, &dataset.meta_dnode, dir_obj, order)?;
    zap_entries(members, topo, &dir, order)
}

/// ZPL packs the object number in the low 48 bits of a directory-entry value.
const DIRENT_OBJ_MASK: u64 = (1 << 48) - 1;

/// Resolve `components` from the dataset's ZPL root to the final entry, returning
/// `(object_number, dirent_value)` (the value carries the type in its high bits).
/// Each non-final component must be a directory.
pub(crate) fn resolve_path<R: BlockRead>(
    members: &mut [PoolMember<R>],
    topo: &Topology,
    dataset: &Dataset,
    order: EndianOrder,
    components: &[&str],
) -> Result<(u64, u64)> {
    let mut dir_obj = root_dir_obj(members, topo, dataset, order)?;
    let mut result = None;
    for (i, comp) in components.iter().enumerate() {
        let dir = read_object_dnode(members, topo, &dataset.meta_dnode, dir_obj, order)?;
        let value = zap_lookup(members, topo, &dir, comp, order)?
            .ok_or(Error::NotFound { component: "path" })?;
        let obj = value & DIRENT_OBJ_MASK;
        if i + 1 == components.len() {
            result = Some((obj, value));
        } else {
            dir_obj = obj; // descend (a non-final component must be a directory)
        }
    }
    result.ok_or(Error::NotFound {
        component: "empty_path",
    })
}

/// SA (System Attributes) bonus magic (`0x2F505A`).
const SA_MAGIC: u32 = 0x002F_505A;
/// Byte offset of `ZPL_SIZE` within the SA data. ZFS `zfs_mknode` writes znode
/// attributes in a fixed creation order whose first two are always `ZPL_MODE`
/// (8 bytes) then `ZPL_SIZE` — verified against the on-disk SA LAYOUTS (layout 2
/// = [MODE, SIZE, GEN, UID, GID, …]). So `SIZE` is at SA-data offset 8 for every
/// file/dir/symlink layout, regardless of the variable-length DACL that follows.
/// (A general SA_ATTRS layout walk is a later refinement; this fixed offset is
/// correct for any stock ZFS-created file.)
const SA_SIZE_OFFSET_STD: usize = 8;

/// Extract a regular file's logical size from its SA bonus buffer. v0.1 assumes
/// the standard ZPL attribute layout (the only one a stock `/boot` file uses);
/// parsing the SA_ATTRS registry for arbitrary layouts is a later refinement.
pub(crate) fn sa_file_size(bonus: &[u8], order: EndianOrder) -> Result<u64> {
    let unsupported = Error::UnsupportedFeature("sa_layout");
    let magic_bytes = bonus.get(0..4).ok_or(unsupported.clone())?;
    let magic = match order {
        EndianOrder::Big => u32::from_be_bytes(magic_bytes.try_into().unwrap()),
        EndianOrder::Little => u32::from_le_bytes(magic_bytes.try_into().unwrap()),
    };
    if magic != SA_MAGIC {
        return Err(unsupported);
    }
    let info_bytes = bonus.get(4..6).ok_or(unsupported.clone())?;
    let layout_info = match order {
        EndianOrder::Big => u16::from_be_bytes(info_bytes.try_into().unwrap()),
        EndianOrder::Little => u16::from_le_bytes(info_bytes.try_into().unwrap()),
    };
    // High 6 bits of layout_info hold the SA header size in 8-byte units.
    let hdrsz = usize::from((layout_info >> 10) & 0x3f) * 8;
    let off = hdrsz + SA_SIZE_OFFSET_STD;
    let size_bytes = bonus.get(off..off + 8).ok_or(unsupported)?;
    Ok(match order {
        EndianOrder::Big => u64::from_be_bytes(size_bytes.try_into().unwrap()),
        EndianOrder::Little => u64::from_le_bytes(size_bytes.try_into().unwrap()),
    })
}
