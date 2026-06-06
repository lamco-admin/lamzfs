// SPDX-License-Identifier: MIT OR Apache-2.0
//! Per-block decompression dispatch (SPEC-LAMZFS §1.3).
//!
//! A ZFS block pointer selects a decompressor by its `comp` field. This module
//! maps that to an implementation and decompresses one block's *physical* bytes
//! into its *logical* size, with a hard per-block size cap so a hostile block
//! pointer cannot drive an unbounded allocation. LZJB comes from the vendored
//! rzfs fork; LZ4 / gzip / zstd are thin adapters over permissive `no_std`
//! crates, each behind a Cargo feature.

use alloc::{vec, vec::Vec};

use crate::{
    error::{Error, Result},
    phys::CompressionType,
};

/// Largest logical block size we will materialize (`SPA_MAXBLOCKSIZE`, 16 MiB).
/// A block pointer's logical size cannot exceed this; a larger value is hostile
/// or corrupt and is refused before allocation.
pub(crate) const MAX_BLOCK_LSIZE: usize = 16 * 1024 * 1024;

/// Decompress one block's physical bytes (`src`, length = `psize`) into exactly
/// `lsize` logical bytes, dispatching on `comp`. The caller has already verified
/// `src`'s checksum.
pub(crate) fn decompress(comp: CompressionType, src: &[u8], lsize: usize) -> Result<Vec<u8>> {
    if lsize > MAX_BLOCK_LSIZE {
        return Err(Error::FileTooLarge {
            size: lsize as u64,
            max: MAX_BLOCK_LSIZE as u64,
        });
    }

    match comp {
        // Uncompressed: the physical bytes are the logical bytes. ZFS pads the
        // physical allocation up to a sector, so `src` may be >= lsize.
        CompressionType::Off => {
            let region = src.get(..lsize).ok_or(Error::BadCompression {
                comp: 2,
                token: "off_short",
            })?;
            Ok(region.to_vec())
        }
        // Zero-Length Encoding: alternating literal/zero runs (SPEC-LAMZFS §1.3).
        CompressionType::Zle => zle_decode(src, lsize),
        CompressionType::Lzjb => lzjb_decode(src, lsize),
        CompressionType::Lz4 => lz4_decode(src, lsize),
        CompressionType::Gzip1
        | CompressionType::Gzip2
        | CompressionType::Gzip3
        | CompressionType::Gzip4
        | CompressionType::Gzip5
        | CompressionType::Gzip6
        | CompressionType::Gzip7
        | CompressionType::Gzip8
        | CompressionType::Gzip9 => gzip_decode(src, lsize),
        CompressionType::Zstd => zstd_decode(src, lsize),
        // `Inherit`/`On`/`Empty` are dataset-property or sentinel values, never a
        // concrete on-disk block `comp`. Reaching here means a corrupt pointer.
        CompressionType::Inherit | CompressionType::On | CompressionType::Empty => {
            Err(Error::UnsupportedCompression { comp: comp as u8 })
        }
    }
}

/// LZJB via the vendored rzfs decoder (always available).
fn lzjb_decode(src: &[u8], lsize: usize) -> Result<Vec<u8>> {
    use crate::compression::{Decompression, LzjbDecoder};
    let mut dst = vec![0u8; lsize];
    LzjbDecoder {}
        .decompress(&mut dst, src, 0)
        .map_err(|_| Error::BadCompression {
            comp: 3,
            token: "lzjb_bad",
        })?;
    Ok(dst)
}

/// ZLE: a stream of `(control, data)` runs. A control byte `c < 0x40` introduces
/// `c + 1` literal bytes; `c >= 0x40` introduces `c - 0x40 + 1` zero bytes. (The
/// on-disk ZLE level is 64, the only one ZFS uses.)
fn zle_decode(src: &[u8], lsize: usize) -> Result<Vec<u8>> {
    let mut dst = vec![0u8; lsize];
    let mut s = 0usize;
    let mut d = 0usize;
    let bad = || Error::BadCompression {
        comp: 14,
        token: "zle_bad",
    };
    while d < lsize {
        let c = *src.get(s).ok_or_else(bad)?;
        s += 1;
        if c < 0x40 {
            let n = usize::from(c) + 1;
            let run = src.get(s..s + n).ok_or_else(bad)?;
            let out = dst.get_mut(d..d + n).ok_or_else(bad)?;
            out.copy_from_slice(run);
            s += n;
            d += n;
        } else {
            let n = usize::from(c) - 0x40 + 1;
            // dst is already zero-initialized; just advance, bounded.
            if d + n > lsize {
                return Err(bad());
            }
            d += n;
        }
    }
    Ok(dst)
}

/// ZFS LZ4: a 4-byte big-endian compressed-length prefix, then an LZ4 block.
#[cfg(feature = "lz4")]
fn lz4_decode(src: &[u8], lsize: usize) -> Result<Vec<u8>> {
    let bad = |token| Error::BadCompression { comp: 15, token };
    let len_bytes = src.get(..4).ok_or_else(|| bad("lz4_no_prefix"))?;
    let clen = u32::from_be_bytes(len_bytes.try_into().unwrap()) as usize;
    let block = src.get(4..4 + clen).ok_or_else(|| bad("lz4_short"))?;
    let mut dst = vec![0u8; lsize];
    let n = lz4_flex::block::decompress_into(block, &mut dst).map_err(|_| bad("lz4_decode"))?;
    if n != lsize {
        return Err(bad("lz4_len"));
    }
    Ok(dst)
}

#[cfg(not(feature = "lz4"))]
fn lz4_decode(_src: &[u8], _lsize: usize) -> Result<Vec<u8>> {
    Err(Error::UnsupportedCompression { comp: 15 })
}

/// ZFS gzip: a standard zlib stream (DEFLATE with a zlib header/trailer).
#[cfg(feature = "gzip")]
fn gzip_decode(src: &[u8], lsize: usize) -> Result<Vec<u8>> {
    let bad = |token| Error::BadCompression { comp: 5, token };
    let mut dst = vec![0u8; lsize];
    let n = miniz_oxide::inflate::decompress_slice_iter_to_slice(
        &mut dst,
        core::iter::once(src),
        true, // zlib header present
        true, // strict (whole input)
    )
    .map_err(|_| bad("gzip_decode"))?;
    if n != lsize {
        return Err(bad("gzip_len"));
    }
    Ok(dst)
}

#[cfg(not(feature = "gzip"))]
fn gzip_decode(_src: &[u8], _lsize: usize) -> Result<Vec<u8>> {
    Err(Error::UnsupportedCompression { comp: 5 })
}

/// ZFS zstd: an 8-byte `zfs_zstdhdr` (BE 32-bit compressed length, then a packed
/// version/level word), then a **magicless** zstd frame (OpenZFS omits the 4-byte
/// frame magic on disk — the version lives in the header). Prepend the magic so a
/// standard zstd decoder accepts it.
#[cfg(feature = "zstd")]
fn zstd_decode(src: &[u8], lsize: usize) -> Result<Vec<u8>> {
    use ruzstd::io::Read as _;
    const ZSTD_MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];
    let bad = |token| Error::BadCompression { comp: 16, token };
    let hdr = src.get(..8).ok_or_else(|| bad("zstd_no_hdr"))?;
    let clen = u32::from_be_bytes(hdr[..4].try_into().unwrap()) as usize;
    let frame = src.get(8..8 + clen).ok_or_else(|| bad("zstd_short"))?;
    let mut framed = Vec::with_capacity(4 + frame.len());
    framed.extend_from_slice(&ZSTD_MAGIC);
    framed.extend_from_slice(frame);
    let mut dec = ruzstd::decoding::StreamingDecoder::new(framed.as_slice())
        .map_err(|_| bad("zstd_frame"))?;
    let mut dst = vec![0u8; lsize];
    dec.read_exact(&mut dst).map_err(|_| bad("zstd_decode"))?;
    // A trailing byte would mean lsize was understated.
    let mut extra = [0u8; 1];
    if dec.read(&mut extra).is_ok_and(|n| n != 0) {
        return Err(bad("zstd_len"));
    }
    Ok(dst)
}

#[cfg(not(feature = "zstd"))]
fn zstd_decode(_src: &[u8], _lsize: usize) -> Result<Vec<u8>> {
    Err(Error::UnsupportedCompression { comp: 16 })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn off_copies_logical_prefix() {
        let src = b"hello world padding-past-lsize";
        let out = decompress(CompressionType::Off, src, 11).unwrap();
        assert_eq!(&out, b"hello world");
    }

    #[test]
    fn zle_literals_and_zero_runs() {
        // control 0x02 -> 3 literals "abc"; control 0x43 -> 4 zero bytes;
        // control 0x00 -> 1 literal "z".
        let src = [0x02, b'a', b'b', b'c', 0x43, 0x00, b'z'];
        let out = zle_decode(&src, 8).unwrap();
        assert_eq!(out, [b'a', b'b', b'c', 0, 0, 0, 0, b'z']);
    }

    #[test]
    fn oversize_lsize_refused() {
        let e = decompress(CompressionType::Off, b"x", MAX_BLOCK_LSIZE + 1).unwrap_err();
        assert!(matches!(e, Error::FileTooLarge { .. }));
    }

    #[test]
    fn off_short_source_errors() {
        let e = decompress(CompressionType::Off, b"hi", 8).unwrap_err();
        assert!(matches!(e, Error::BadCompression { .. }));
    }
}
