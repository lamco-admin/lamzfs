// SPDX-License-Identifier: MIT
// Adapted from rzfs @ea41cf0b5b29 (dual GPL-2.0 OR MIT; MIT elected); see NOTICE.

/*! LZJB compression.
 *
 * LZJB is based on LZRW and LZ77 compression algorithms.
 *
 * ### Byte layout.
 *
 * The byte layout of LZJB compressed data is a sequence of one byte MAP,
 * followed by up to eight blocks. There will fewer than eight blocks if it is
 * the end of the compressed data. Each block is one or two bytes.
 *
 * ```text
 * +-----+-------+-------+-----+-------+-----+-------+-----+
 * | MAP | BLK 0 | BLK 1 | ... | BLK 7 | MAP | BLK 0 | ... |
 * +-----+-------+-------+-----+-------+-----+-------+-----+
 * ```
 *
 * Each bit of MAP, in LSB, indicates how to decode the Nth block after the MAP.
 * If the bit is 0, then BLK is one byte of uncompressed data. If the bit is 1,
 * the block is a two byte big endian encoded [u16], where the most significant
 * 6 bits are a length, and the least significant 10 bits are an offset. To
 * decompress the data, take the current destinaton, subtract offset, and use
 * that as the source of the next length + 3 decompressed bytes.
 *
 * ```text
 *                0
 *  7 6 5 4 3 2 1 0
 * +---------------+
 * |h|g|f|e|d|c|b|a|
 * +---------------+
 *
 * a - 0 or 1 for BLK 0
 * b - 0 or 1 for BLK 1
 * c - ...
 * ```
 *
 * Bit layout of length and offset.
 *
 * ```text
 *            1                   0
 *  5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 * +-------------------------------+
 * | length (6)|    offset (10)    |
 * +-------------------------------+
 * ```
 */
use core::cmp;
use core::result::Result;

use crate::compression::{Compression, CompressionError, Decompression, DecompressionError};

////////////////////////////////////////////////////////////////////////////////

/// Number of bits for encoded length.
const LENGTH_BITS: u32 = 6;

/// Number of btis for encoded offset.
const OFFSET_BITS: u32 = 10;

////////////////////////////////////////////////////////////////////////////////

/// Encoded length is the top bits.
const LENGTH_SHIFT: u32 = OFFSET_BITS;

/// Encoded offset uses bottom bits.
const OFFSET_MASK: u16 = (1 << OFFSET_BITS) - 1;

////////////////////////////////////////////////////////////////////////////////

/** The minimum non-encoded length is three, in order to overcome the overhead
 * of using two bytes for length and offset.
 */
const LENGTH_MIN: usize = 3;

/** The maximum length is all six bits, plus the minimum length, because
 * [`LENGTH_MIN`] is subtracted from the length before it is encoded. This comes
 * out to 63 plus 3, which is 66.
 */
const LENGTH_MAX: usize = ((1 << LENGTH_BITS) - 1) + LENGTH_MIN;

////////////////////////////////////////////////////////////////////////////////

/// The value of copy mask, when getting the next copy map.
const COPY_MASK_NEXT: u8 = 0;

/** Length of hash table. Do not change in order to keep compression
 * deterministic, because deduplication happens after compression.
 */
const TABLE_LENGTH: usize = 1024;

////////////////////////////////////////////////////////////////////////////////

/// LZJB compression encoder.
pub struct LzjbEncoder {
    table: [u16; TABLE_LENGTH],
}

impl Default for LzjbEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl LzjbEncoder {
    /// Create a new LZJB compression encoder.
    pub fn new() -> LzjbEncoder {
        LzjbEncoder {
            table: [0; TABLE_LENGTH],
        }
    }

    /** Compress with LZJB parameters before ZFS version 21.
     *
     * When the deduplication feature was released in ZFS version 21, the
     * parameters for LZJB were altered. This function will compress using the
     * old parameters, and is included for testing LZJB re-compression for older
     * file systems.
     */
    pub fn compress_pre_v21(
        &mut self,
        dst: &mut [u8],
        src: &[u8],
        _level: u32,
    ) -> Result<usize, CompressionError> {
        // NOTE: Refer to [LzjbEncoder::compress] for documentation of common code.
        // NOTE: The table is smaller.
        self.table[0..256].fill(0);

        let mut src_idx: usize = 0;
        let mut dst_idx: usize = 0;

        let mut copy_mask: u8 = COPY_MASK_NEXT;
        let mut copy_map_idx = 0;

        while src_idx < src.len() {
            copy_mask <<= 1;

            if copy_mask == COPY_MASK_NEXT {
                copy_mask = 1;

                if dst.len() - dst_idx < 1 + (u8::BITS * 2) as usize {
                    return Err(CompressionError::NotCompressable {});
                }

                copy_map_idx = dst_idx;
                dst[copy_map_idx] = 0;
                dst_idx += 1;
            }

            if src.len() - src_idx < LENGTH_MAX {
                dst[dst_idx] = src[src_idx];
                dst_idx += 1;
                src_idx += 1;
                continue;
            }

            // NOTE: Hash computation is different, and table is limited to 256.
            let hash: u8 = src[src_idx].wrapping_add(13)
                ^ src[src_idx + 1].wrapping_sub(13)
                ^ src[src_idx + 2];

            let cpy_idx_modulo = &mut self.table[usize::from(hash)];

            let old_offset = (src_idx - (*cpy_idx_modulo as usize)) & usize::from(OFFSET_MASK);
            *cpy_idx_modulo = src_idx as u16;

            let cpy_idx = src_idx - old_offset;

            if cpy_idx != src_idx
                && src[src_idx] == src[cpy_idx]
                && src[src_idx + 1] == src[cpy_idx + 1]
                && src[src_idx + 2] == src[cpy_idx + 2]
            {
                dst[copy_map_idx] |= copy_mask;

                let mut length = LENGTH_MIN;
                while length < LENGTH_MAX {
                    if src[src_idx + length] == src[cpy_idx + length] {
                        length += 1;
                    } else {
                        break;
                    }
                }

                src_idx += length;

                let length_offset = (((length - LENGTH_MIN) << LENGTH_SHIFT) | old_offset) as u16;

                dst[dst_idx..dst_idx + 2].copy_from_slice(&u16::to_be_bytes(length_offset));
                dst_idx += 2;
            } else {
                dst[dst_idx] = src[src_idx];
                dst_idx += 1;
                src_idx += 1;
            }
        }

        Ok(dst_idx)
    }
}

impl Compression for LzjbEncoder {
    fn compress(
        &mut self,
        dst: &mut [u8],
        src: &[u8],
        _level: u32,
    ) -> Result<usize, CompressionError> {
        // Reset the state of the encoder.
        self.table.fill(0);

        // Source and destination indices.
        let mut src_idx: usize = 0;
        let mut dst_idx: usize = 0;

        // Set the copy mask to a value that will cause it to create the
        // copy_map on the first iteration of the loop.
        let mut copy_mask: u8 = COPY_MASK_NEXT;
        let mut copy_map_idx = 0;

        while src_idx < src.len() {
            // Shift copy mask to use next bit.
            copy_mask <<= 1;

            // If no bits are available, get the next copy map index.
            if copy_mask == COPY_MASK_NEXT {
                // Reset the mask to the first bit.
                copy_mask = 1;

                // Check that there is enough space for the map, and for
                // encoding the data for the map, which in the worst case is
                // length and offset (2 bytes) for each bit in the map (8).
                // This might not be the optimal choice, but it simplifies the
                // rest of the code, and conforms to the existing ZFS behavior.
                if dst.len() - dst_idx < 1 + (u8::BITS * 2) as usize {
                    return Err(CompressionError::NotCompressable {});
                }

                // Set the new copy map index.
                copy_map_idx = dst_idx;

                // Set the initial mask to zero.
                dst[copy_map_idx] = 0;

                // Increment destination.
                dst_idx += 1;
            }

            // If there are fewer than LENGTH_MAX bytes remaining, do not try
            // to compress them, just copy them uncompressed.
            if src.len() - src_idx < LENGTH_MAX {
                dst[dst_idx] = src[src_idx];
                dst_idx += 1;
                src_idx += 1;
                continue;
            }

            // Calculate the hash over the next 3 bytes.
            // The access to src is safe, because there must be at least
            // LENGTH_MAX bytes remaining.
            let mut hash = (u32::from(src[src_idx]) << 16)
                | (u32::from(src[src_idx + 1]) << 8)
                | u32::from(src[src_idx + 2]);
            // NOTE: The hash above will be at most 24 bits, and after the
            //       additions below, it will be at most 25 bits.
            hash += hash >> 9;
            hash += hash >> 5;

            // Now look it up in table.
            let cpy_idx_modulo = &mut self.table[(hash as usize) % self.table.len()];

            // The value in the table is index into src, modulo 16 bits.
            // To be more precise, this could be modulus OFFSET_BITS + 1,
            // but casting it down to a [u16] is cheaper.
            //
            // In theory, this could be src_idx, but that would require storing
            // a [usize], requiring either 4k or 8k or memory. Using a [u16],
            // consumes only 2k.
            //
            // As a simplified example, take the following table.
            // The first row is src_idx, the second row is src_idx modulo 65536.
            //
            //  +---+---+---+-----+-------+-------+-------+-------+-----+
            //  | 0 | 1 | 2 | ... | 65535 | 65536 | 65537 | 65538 | ... |
            //  +---+---+---+-----+-------+-------+-------+-------+-----+
            //  | 0 | 1 | 2 | ... | 65535 |     0 |     1 |     2 | ... |
            //  +---+---+---+-----+-------+-------+-------+-------+-----+
            //
            // Within the same modulo block:
            // - take sample src_idx 5
            // - take sample cpy_idx_modulo 2
            // - (5 - 2) % 65536 = 3 is the offset
            //
            // Within the same modulo block:
            // - take sample src_idx 65541
            // - take sample cpy_idx_modulo 2
            // - (65541 - 2) % 65536 = 3 is the offset
            //
            // Across two modulo blocks:
            // - take sample src_idx 65541
            // - take sample cpy_idx_modulo 65535
            // - (65541 - 65535) % 65536 = 6 is the offset
            //
            // Across two modulo blocks.
            // - take sample src_idx 131077
            // - take sample cpy_idx_modulo 65535
            // - (131077 - 65535) % 65536 = 6 is the offset
            //
            // The subtraction is safe, because the value of cpy_idx_modulo must
            // be <= src_idx, since the table starts off filled with zeros, and
            // is filled in by src_idx values below.
            let old_offset = (src_idx - (*cpy_idx_modulo as usize)) & usize::from(OFFSET_MASK);
            *cpy_idx_modulo = src_idx as u16;

            // Compute the copy index.
            let cpy_idx = src_idx - old_offset;

            // If the copy index is not the source itself, and three bytes
            // match, then compress the bytes.
            if cpy_idx != src_idx
                && src[src_idx] == src[cpy_idx]
                && src[src_idx + 1] == src[cpy_idx + 1]
                && src[src_idx + 2] == src[cpy_idx + 2]
            {
                // Set this block as compressed.
                dst[copy_map_idx] |= copy_mask;

                // Start the length.
                let mut length = LENGTH_MIN;
                while length < LENGTH_MAX {
                    // The access to src is safe, because
                    // src.len() - src_idx < LENGTH_MAX is checked above,
                    // and cpy_idx must be less than src_idx.
                    if src[src_idx + length] == src[cpy_idx + length] {
                        length += 1;
                    } else {
                        break;
                    }
                }

                // Advance source index.
                src_idx += length;

                // Subtract minimum length and shift into encoded spot,
                // and or with offset (no shift).
                let length_offset = (((length - LENGTH_MIN) << LENGTH_SHIFT) | old_offset) as u16;

                // Encode to big endian and add to output.
                dst[dst_idx..dst_idx + 2].copy_from_slice(&u16::to_be_bytes(length_offset));
                dst_idx += 2;
            } else {
                // Cannot compress these bytes, so copy the byte, and try with
                // the next ones.
                dst[dst_idx] = src[src_idx];
                dst_idx += 1;
                src_idx += 1;
            }
        }

        Ok(dst_idx)
    }
}

////////////////////////////////////////////////////////////////////////////////

/// LZJB decompression decoder.
pub struct LzjbDecoder {}

impl Decompression for LzjbDecoder {
    fn decompress(
        &mut self,
        dst: &mut [u8],
        src: &[u8],
        _level: u32,
    ) -> Result<(), DecompressionError> {
        // Source and destination indices.
        let mut src_idx: usize = 0;
        let mut dst_idx: usize = 0;

        // Set the copy mask to a value that will cause it to fetch the copy_map on
        // the first iteration of the loop.
        let mut copy_mask: u8 = COPY_MASK_NEXT;
        let mut copy_map: u8 = 0;

        while dst_idx < dst.len() {
            // Shift copy mask to use next bit.
            copy_mask <<= 1;

            // If all 8 bits are used, get the next copy map.
            if copy_mask == COPY_MASK_NEXT {
                // Reset the mask to the first bit.
                copy_mask = 1;

                // Safely get the next copy map.
                copy_map = match src.get(src_idx) {
                    Some(v) => *v,
                    None => {
                        return Err(DecompressionError::EndOfInput {
                            offset: src_idx,
                            capacity: src.len(),
                            count: 1,
                        })
                    }
                };

                // Increment the source.
                src_idx += 1;
            }

            if (copy_map & copy_mask) != 0 {
                // Check if there are two more bytes available from the source.
                if src.len() - src_idx < 2 {
                    return Err(DecompressionError::EndOfInput {
                        offset: src_idx,
                        capacity: src.len(),
                        count: 2,
                    });
                }

                // Decode the next two bytes as a 16 bit big endian number.
                let length_offset =
                    u16::from_be_bytes(src[src_idx..src_idx + 2].try_into().unwrap());

                // Increment the source.
                src_idx += 2;

                // Extract the length and offset.
                let length = usize::from(length_offset >> LENGTH_SHIFT) + LENGTH_MIN;
                let offset = usize::from(length_offset & OFFSET_MASK);

                // Safely compute the copy index.
                let mut cpy_idx = match dst_idx.checked_sub(offset) {
                    Some(v) => v,
                    None => {
                        return Err(DecompressionError::InvalidInput {
                            offset: src_idx - 2,
                        })
                    }
                };

                // Clamp the length to the number of bytes to output.
                let length = cmp::min(length, dst.len() - dst_idx);

                // Copy the bytes one byte at a time.
                // An alternative would be to use:
                // dst.copy_within(cpy_idx..cpy_idx+length, dst_idx);
                // dst_idx += length;
                // However, it is not clear in what order copy_within would copy
                // the bytes. If cpy_idx + length > dst_idx, then it may copy
                // bytes from dst_idx + 1 before copying them from
                // dst_idx + 1 - length.
                for _ in 0..length {
                    dst[dst_idx] = dst[cpy_idx];
                    dst_idx += 1;
                    cpy_idx += 1;
                }
            } else {
                // Copy source to destination.
                dst[dst_idx] = match src.get(src_idx) {
                    Some(v) => *v,
                    None => {
                        return Err(DecompressionError::EndOfInput {
                            offset: src_idx,
                            capacity: src.len(),
                            count: 1,
                        })
                    }
                };

                // Increment source and destination.
                dst_idx += 1;
                src_idx += 1;
            }
        }

        Ok(())
    }
}

////////////////////////////////////////////////////////////////////////////////

