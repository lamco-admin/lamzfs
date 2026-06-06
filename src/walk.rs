// SPDX-License-Identifier: MIT OR Apache-2.0
//! Object-set and ZAP navigation built on the dnode read primitive
//! ([`crate::file`]): decode an object set, read an object's dnode out of the
//! dnode array, and look up names in a (micro) ZAP. These are the steps the MOS
//! and DSL walks compose.

use alloc::{string::String, vec::Vec};

use crate::{
    block_read::{BlockRead, PoolMember},
    error::{Error, Location, Result},
    file::{read_dnode_range, with_decoder},
    phys::{BlockPointer, Dnode, EndianOrder, ObjectSet, ZapMicroIterator},
    vdev::{read_block_pointer, Topology},
};

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
    let buf = read_dnode_range(
        members,
        topo,
        dnode_array,
        objnum * DNODE_SIZE,
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
    let bytes = read_dnode_range(members, topo, zap_dnode, 0, dbsz, order)?;
    with_decoder(&bytes, order, |dec| {
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
