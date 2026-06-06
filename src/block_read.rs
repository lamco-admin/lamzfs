// SPDX-License-Identifier: MIT OR Apache-2.0
//! The `BlockRead` seam — how `lamzfs` reads one pool member (one leaf device /
//! partition) — and the `PoolMember` bundle handed to [`crate::Zfs::import`].

use crate::error::Error;

/// Block-level reads for ONE leaf device of a pool. Identical in shape to
/// `lambutter::BlockRead` / `lamxfs::BlockRead`, so a consumer that already
/// provides one needs only a one-line adapter.
///
/// A pool may span several members (a mirror, a raidz1 group); the caller hands
/// each as a separate `BlockRead` in a [`PoolMember`], and `lamzfs` reads each
/// member's label to assemble the topology — the caller does not need to know
/// vdev GUIDs in advance.
pub trait BlockRead {
    /// Error type surfaced by the underlying device.
    type Error: core::fmt::Debug;

    /// Fill `buf` entirely from this member starting at `offset_bytes`. A short
    /// read is an error — `lamzfs` always sizes `buf` to exactly the range it
    /// needs.
    fn read_at(&mut self, offset_bytes: u64, buf: &mut [u8]) -> Result<(), Self::Error>;
}

/// One pool member handed to [`crate::Zfs::import`]: a reader plus the byte
/// length of that partition (accepted for device-bounds parity / future checks).
pub struct PoolMember<R: BlockRead> {
    /// The block reader for this leaf device.
    pub reader: R,
    /// Byte length of the partition behind `reader`.
    pub device_size_bytes: u64,
}

/// Fill `buf` from `reader` at `offset`, mapping any device failure to a typed
/// [`Error::Io`] carrying the stable `token` and the leaf `vdev` GUID (0 before
/// the topology is known, e.g. during the initial label scan). The one place an
/// `R::Error` is dropped, at the `lamzfs` boundary.
pub(crate) fn read_exact<R: BlockRead>(
    reader: &mut R,
    offset: u64,
    buf: &mut [u8],
    vdev: u64,
    token: &'static str,
) -> crate::error::Result<()> {
    reader.read_at(offset, buf).map_err(|_| Error::Io {
        token,
        vdev,
        offset,
    })
}
