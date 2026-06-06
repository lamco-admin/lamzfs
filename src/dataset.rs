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
