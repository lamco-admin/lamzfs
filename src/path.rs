// SPDX-License-Identifier: MIT OR Apache-2.0
//! Borrowed filesystem path newtype (within the selected dataset).

/// A path within the selected dataset, as raw bytes. Components are
/// `/`-separated; empty components and `.` are ignored by the resolver, so
/// `/boot//vmlinuz` and `/boot/vmlinuz` resolve identically. `lamzfs` does not
/// own paths.
#[derive(Copy, Clone, Debug)]
pub struct Path<'a>(&'a [u8]);

impl<'a> Path<'a> {
    /// Wrap a byte slice as a path.
    pub fn new(bytes: &'a [u8]) -> Self {
        Path(bytes)
    }

    /// The raw bytes.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.0
    }

    /// Iterate non-empty, non-`.` path components in order.
    pub(crate) fn components(&self) -> impl Iterator<Item = &'a [u8]> {
        self.0
            .split(|&b| b == b'/')
            .filter(|c| !c.is_empty() && *c != b".")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::vec::Vec;

    #[test]
    fn splits_and_filters() {
        let p = Path::new(b"/boot//BOOT/./vmlinuz");
        let comps: Vec<&[u8]> = p.components().collect();
        assert_eq!(comps, [&b"boot"[..], &b"BOOT"[..], &b"vmlinuz"[..]]);
    }

    #[test]
    fn root_has_no_components() {
        assert_eq!(Path::new(b"/").components().count(), 0);
        assert_eq!(Path::new(b"").components().count(), 0);
    }
}
