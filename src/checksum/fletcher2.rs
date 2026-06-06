// SPDX-License-Identifier: MIT
// Adapted from rzfs @ea41cf0b5b29 (dual GPL-2.0 OR MIT; MIT elected); see NOTICE.

use crate::checksum::{Checksum, ChecksumError};
use crate::phys::{ChecksumType, EndianOrder};

use core::cmp;
use core::fmt;
use core::fmt::Display;

#[cfg(all(
    target_arch = "x86",
    any(
        feature = "fletcher2-sse2",
        feature = "fletcher2-ssse3",
        feature = "fletcher2-avx2",
        feature = "fletcher2-avx512f",
        feature = "fletcher2-avx512bw",
    ),
))]
use core::arch::x86 as arch;

#[cfg(all(
    target_arch = "x86_64",
    any(
        feature = "fletcher2-sse2",
        feature = "fletcher2-ssse3",
        feature = "fletcher2-avx2",
        feature = "fletcher2-avx512f",
        feature = "fletcher2-avx512bw",
    ),
))]
use core::arch::x86_64 as arch;

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64",),
    any(feature = "fletcher2-sse2", feature = "fletcher2-ssse3",),
))]
use crate::arch::x86_any::is_sse2_supported;

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64",),
    feature = "fletcher2-ssse3",
))]
use crate::arch::x86_any::is_ssse3_supported;

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64",),
    feature = "fletcher2-avx2",
))]
use crate::arch::x86_any::{is_avx2_supported, is_avx_supported};

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64",),
    any(feature = "fletcher2-avx512f", feature = "fletcher2-avx512bw"),
))]
use crate::arch::x86_any::is_avx512f_supported;

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64",),
    feature = "fletcher2-avx512bw",
))]
use crate::arch::x86_any::is_avx512bw_supported;

////////////////////////////////////////////////////////////////////////////////

/// Fletcher2 block size in bytes.
const FLETCHER_2_BLOCK_SIZE: usize = 16;

/// Fletcher2 in u64.
const FLETCHER_2_U64_COUNT: usize = 4;

/// Fletcher2 maximum SIMD width.
const FLETCHER_2_MAX_SIMD_WIDTH: usize = 4;

/// Fletcher2 implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fletcher2Implementation {
    /// Generic.
    Generic,

    /// Superscalar using two streams.
    SuperScalar2,

    /// Superscalar using four streams.
    SuperScalar4,

    /// SSE2 128 bit SIMD.
    SSE2,

    /// SSSE3 128 bit SIMD.
    SSSE3,

    /// AVX2 256 bit SIMD.
    AVX2,

    /// AVX512F 512 bit SIMD.
    AVX512F,

    /// AVX512BW 512 bit SIMD.
    AVX512BW,
}

const ALL_FLETCHER_2_IMPLEMENTATIONS: [Fletcher2Implementation; 8] = [
    Fletcher2Implementation::Generic,
    Fletcher2Implementation::SuperScalar2,
    Fletcher2Implementation::SuperScalar4,
    Fletcher2Implementation::SSE2,
    Fletcher2Implementation::SSSE3,
    Fletcher2Implementation::AVX2,
    Fletcher2Implementation::AVX512F,
    Fletcher2Implementation::AVX512BW,
];

impl Fletcher2Implementation {
    /** Get a slice with all of the [`Fletcher2Implementation`].
     *
     * Runtime support depends on CPU. Calling [`Fletcher2::new`] might still
     * fail with [`ChecksumError::Unsupported`].
     */
    pub fn all() -> &'static [Fletcher2Implementation] {
        &ALL_FLETCHER_2_IMPLEMENTATIONS
    }

    /// Get the string name of the implementation.
    pub fn to_str(&self) -> &'static str {
        match self {
            Fletcher2Implementation::Generic => "generic",
            Fletcher2Implementation::SuperScalar2 => "superscalar2",
            Fletcher2Implementation::SuperScalar4 => "superscalar4",
            Fletcher2Implementation::SSE2 => "sse2",
            Fletcher2Implementation::SSSE3 => "ssse3",
            Fletcher2Implementation::AVX2 => "avx2",
            Fletcher2Implementation::AVX512F => "avx512f",
            Fletcher2Implementation::AVX512BW => "avx512bw",
        }
    }

    /** Get implementation context.
     *
     * # Errors
     *
     * Returns [`ChecksumError`] if the implementation is not supported.
     */
    fn get_implementation_ctx(&self) -> Result<&'static Fletcher2ImplementationCtx, ChecksumError> {
        let ctx = match self {
            Fletcher2Implementation::Generic => &FLETCHER_2_IMPL_CTX_GENERIC,
            Fletcher2Implementation::SuperScalar2 => &FLETCHER_2_IMPL_CTX_SUPERSCALAR_2,
            Fletcher2Implementation::SuperScalar4 => &FLETCHER_2_IMPL_CTX_SUPERSCALAR_4,

            #[cfg(feature = "fletcher2-sse2")]
            Fletcher2Implementation::SSE2 => &FLETCHER_2_IMPL_CTX_SSE2,

            #[cfg(feature = "fletcher2-ssse3")]
            Fletcher2Implementation::SSSE3 => &FLETCHER_2_IMPL_CTX_SSSE3,

            #[cfg(feature = "fletcher2-avx2")]
            Fletcher2Implementation::AVX2 => &FLETCHER_2_IMPL_CTX_AVX2,

            #[cfg(feature = "fletcher2-avx512f")]
            Fletcher2Implementation::AVX512F => &FLETCHER_2_IMPL_CTX_AVX512F,

            #[cfg(feature = "fletcher2-avx512bw")]
            Fletcher2Implementation::AVX512BW => &FLETCHER_2_IMPL_CTX_AVX512BW,

            #[cfg(any(
                not(feature = "fletcher2-sse2"),
                not(feature = "fletcher2-ssse3"),
                not(feature = "fletcher2-avx2"),
                not(feature = "fletcher2-avx512f"),
                not(feature = "fletcher2-avx512bw"),
            ))]
            _ => {
                return Err(ChecksumError::Unsupported {
                    checksum: ChecksumType::Fletcher2,
                    implementation: self.to_str(),
                })
            }
        };

        Ok(ctx)
    }
}

impl Display for Fletcher2Implementation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

/// Update state. Data length is a multiple of the implementation's block size.
type Fletcher2UpdateBlock = fn(state: &mut [u64], data: &[u8]);

/// Compute the final hash from multiple streams.
type Fletcher2FinishBlocks = fn(state: &[u64]) -> [u64; FLETCHER_2_U64_COUNT];

/// Is the implementation supported by the CPU.
type Fletcher2IsSupported = fn() -> bool;

/// Fletcher2 implementation context.
struct Fletcher2ImplementationCtx {
    /// A multiple of [`FLETCHER_2_BLOCK_SIZE`].
    block_size: usize,

    /// Big endian implementation of [`Fletcher2UpdateBlock`].
    update_blocks_big: Fletcher2UpdateBlock,

    /// Little Endian implementation of [`Fletcher2UpdateBlock`].
    update_blocks_little: Fletcher2UpdateBlock,

    /// Implementation of [`Fletcher2FinishBlocks`].
    finish_blocks: Fletcher2FinishBlocks,

    /// Is the implementation supported by the CPU.
    is_supported: Fletcher2IsSupported,
}

const FLETCHER_2_IMPL_CTX_GENERIC: Fletcher2ImplementationCtx = Fletcher2ImplementationCtx {
    block_size: FLETCHER_2_BLOCK_SIZE,
    update_blocks_big: Fletcher2::update_blocks_generic_big,
    update_blocks_little: Fletcher2::update_blocks_generic_little,
    finish_blocks: Fletcher2::finish_blocks_single_stream,
    is_supported: || true,
};

const FLETCHER_2_IMPL_CTX_SUPERSCALAR_2: Fletcher2ImplementationCtx = Fletcher2ImplementationCtx {
    block_size: 2 * FLETCHER_2_BLOCK_SIZE,
    update_blocks_big: Fletcher2::update_blocks_superscalar2_big,
    update_blocks_little: Fletcher2::update_blocks_superscalar2_little,
    finish_blocks: Fletcher2::finish_blocks_dual_stream,
    is_supported: || true,
};

const FLETCHER_2_IMPL_CTX_SUPERSCALAR_4: Fletcher2ImplementationCtx = Fletcher2ImplementationCtx {
    block_size: 4 * FLETCHER_2_BLOCK_SIZE,
    update_blocks_big: Fletcher2::update_blocks_superscalar4_big,
    update_blocks_little: Fletcher2::update_blocks_superscalar4_little,
    finish_blocks: Fletcher2::finish_blocks_quad_stream,
    is_supported: || true,
};

#[cfg(feature = "fletcher2-sse2")]
const FLETCHER_2_IMPL_CTX_SSE2: Fletcher2ImplementationCtx = Fletcher2ImplementationCtx {
    block_size: FLETCHER_2_BLOCK_SIZE,
    #[cfg(target_endian = "big")]
    update_blocks_big: Fletcher2::update_blocks_sse2_native,
    #[cfg(target_endian = "big")]
    update_blocks_little: Fletcher2::update_blocks_sse2_byteswap,
    #[cfg(target_endian = "little")]
    update_blocks_big: Fletcher2::update_blocks_sse2_byteswap,
    #[cfg(target_endian = "little")]
    update_blocks_little: Fletcher2::update_blocks_sse2_native,
    finish_blocks: Fletcher2::finish_blocks_single_stream,
    is_supported: is_sse2_supported,
};

#[cfg(feature = "fletcher2-ssse3")]
const FLETCHER_2_IMPL_CTX_SSSE3: Fletcher2ImplementationCtx = Fletcher2ImplementationCtx {
    block_size: FLETCHER_2_BLOCK_SIZE,
    #[cfg(target_endian = "big")]
    update_blocks_big: Fletcher2::update_blocks_sse2_native,
    #[cfg(target_endian = "big")]
    update_blocks_little: Fletcher2::update_blocks_ssse3_byteswap,
    #[cfg(target_endian = "little")]
    update_blocks_big: Fletcher2::update_blocks_ssse3_byteswap,
    #[cfg(target_endian = "little")]
    update_blocks_little: Fletcher2::update_blocks_sse2_native,
    finish_blocks: Fletcher2::finish_blocks_single_stream,
    is_supported: || is_sse2_supported() && is_ssse3_supported(),
};

#[cfg(feature = "fletcher2-avx2")]
const FLETCHER_2_IMPL_CTX_AVX2: Fletcher2ImplementationCtx = Fletcher2ImplementationCtx {
    block_size: 2 * FLETCHER_2_BLOCK_SIZE,
    #[cfg(target_endian = "big")]
    update_blocks_big: Fletcher2::update_blocks_avx2_native,
    #[cfg(target_endian = "big")]
    update_blocks_little: Fletcher2::update_blocks_avx2_byteswap,
    #[cfg(target_endian = "little")]
    update_blocks_big: Fletcher2::update_blocks_avx2_byteswap,
    #[cfg(target_endian = "little")]
    update_blocks_little: Fletcher2::update_blocks_avx2_native,
    finish_blocks: Fletcher2::finish_blocks_dual_stream,
    is_supported: || is_avx_supported() && is_avx2_supported(),
};

#[cfg(feature = "fletcher2-avx512f")]
const FLETCHER_2_IMPL_CTX_AVX512F: Fletcher2ImplementationCtx = Fletcher2ImplementationCtx {
    block_size: 4 * FLETCHER_2_BLOCK_SIZE,
    #[cfg(target_endian = "big")]
    update_blocks_big: Fletcher2::update_blocks_avx512f_native,
    #[cfg(target_endian = "big")]
    update_blocks_little: Fletcher2::update_blocks_avx512f_byteswap,
    #[cfg(target_endian = "little")]
    update_blocks_big: Fletcher2::update_blocks_avx512f_byteswap,
    #[cfg(target_endian = "little")]
    update_blocks_little: Fletcher2::update_blocks_avx512f_native,
    finish_blocks: Fletcher2::finish_blocks_quad_stream,
    is_supported: is_avx512f_supported,
};

#[cfg(feature = "fletcher2-avx512bw")]
const FLETCHER_2_IMPL_CTX_AVX512BW: Fletcher2ImplementationCtx = Fletcher2ImplementationCtx {
    block_size: 4 * FLETCHER_2_BLOCK_SIZE,
    #[cfg(target_endian = "big")]
    update_blocks_big: Fletcher2::update_blocks_avx512f_native,
    #[cfg(target_endian = "big")]
    update_blocks_little: Fletcher2::update_blocks_avx512bw_byteswap,
    #[cfg(target_endian = "little")]
    update_blocks_big: Fletcher2::update_blocks_avx512bw_byteswap,
    #[cfg(target_endian = "little")]
    update_blocks_little: Fletcher2::update_blocks_avx512f_native,
    finish_blocks: Fletcher2::finish_blocks_quad_stream,
    is_supported: || is_avx512f_supported() && is_avx512bw_supported(),
};

/// [`crate::phys::ChecksumType::Fletcher2`] implementation.
pub struct Fletcher2 {
    /// Number of bytes used in [`Fletcher2::buffer`].
    buffer_fill: usize,

    /// Partial block buffer.
    buffer: [u8; FLETCHER_2_BLOCK_SIZE * FLETCHER_2_MAX_SIMD_WIDTH],

    /// Ongoing checksum.
    state: [u64; FLETCHER_2_U64_COUNT * FLETCHER_2_MAX_SIMD_WIDTH],

    /// Byte order of input data.
    order: EndianOrder,

    /// Implementation context.
    impl_ctx: &'static Fletcher2ImplementationCtx,

    /// Current update blocks from impl_ctx depending on order.
    update_blocks: Fletcher2UpdateBlock,
}

impl Fletcher2 {
    /** Create a new Fletcher2 instance.
     *
     * # Errors
     *
     * Returns [`ChecksumError`] if the implementation is not supported.
     */
    pub fn new(implementation: Fletcher2Implementation) -> Result<Fletcher2, ChecksumError> {
        let ctx = implementation.get_implementation_ctx()?;

        if !(ctx.is_supported)() {
            return Err(ChecksumError::Unsupported {
                checksum: ChecksumType::Fletcher2,
                implementation: implementation.to_str(),
            });
        }

        Ok(Fletcher2 {
            buffer_fill: 0,
            buffer: [0; FLETCHER_2_BLOCK_SIZE * FLETCHER_2_MAX_SIMD_WIDTH],
            state: Default::default(),
            order: EndianOrder::Little,
            impl_ctx: ctx,
            update_blocks: ctx.update_blocks_little,
        })
    }

    /** Finish a check that is one stream.
     *
     * For one stream, this is a NO-OP.
     */
    fn finish_blocks_single_stream(state: &[u64]) -> [u64; FLETCHER_2_U64_COUNT] {
        [state[0], state[1], state[2], state[3]]
    }

    /** Finish a checksum that is two streams wide.
     *
     * - `a` and `b` correspond to `a` of [`Fletcher4::finish_blocks_dual_stream`].
     * - `c` and `d` correspond to `b` of [`Fletcher4::finish_blocks_dual_stream`].
     */
    fn finish_blocks_dual_stream(state: &[u64]) -> [u64; FLETCHER_2_U64_COUNT] {
        // Load state.
        let a0 = state[0];
        let b0 = state[1];

        let a1 = state[2];
        let b1 = state[3];

        let c0 = state[4];
        let d0 = state[5];

        let c1 = state[6];
        let d1 = state[7];

        let ra = a0.wrapping_add(a1);
        let rb = b0.wrapping_add(b1);

        let rc = c0.wrapping_add(c1).wrapping_mul(2).wrapping_sub(a1);
        let rd = d0.wrapping_add(d1).wrapping_mul(2).wrapping_sub(b1);

        [ra, rb, rc, rd]
    }

    /** Finish a checksum that is four streams wide.
     *
     * - `a` and `b` correspond to `a` of [`Fletcher4::finish_blocks_quad_stream`].
     * - `c` and `d` correspond to `b` of [`Fletcher4::finish_blocks_quad_stream`].
     */
    fn finish_blocks_quad_stream(state: &[u64]) -> [u64; FLETCHER_2_U64_COUNT] {
        let a0 = state[0];
        let b0 = state[1];

        let a1 = state[2];
        let b1 = state[3];

        let a2 = state[4];
        let b2 = state[5];

        let a3 = state[6];
        let b3 = state[7];

        let c0 = state[8];
        let d0 = state[9];

        let c1 = state[10];
        let d1 = state[11];

        let c2 = state[12];
        let d2 = state[13];

        let c3 = state[14];
        let d3 = state[15];

        let ra = a0.wrapping_add(a1).wrapping_add(a2).wrapping_add(a3);
        let rb = b0.wrapping_add(b1).wrapping_add(b2).wrapping_add(b3);

        let rc = c0
            .wrapping_add(c1)
            .wrapping_add(c2)
            .wrapping_add(c3)
            .wrapping_mul(4)
            .wrapping_sub(
                a1.wrapping_add(a2.wrapping_mul(2))
                    .wrapping_add(a3.wrapping_mul(3)),
            );

        let rd = d0
            .wrapping_add(d1)
            .wrapping_add(d2)
            .wrapping_add(d3)
            .wrapping_mul(4)
            .wrapping_sub(
                b1.wrapping_add(b2.wrapping_mul(2))
                    .wrapping_add(b3.wrapping_mul(3)),
            );

        [ra, rb, rc, rd]
    }

    /// Update blocks, reading one big endian [`u32`] at a time.
    fn update_blocks_generic_big(state: &mut [u64], data: &[u8]) {
        // Load state to local variables.
        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];

        // Iterate one block at a time.
        let mut iter = data.chunks_exact(FLETCHER_2_BLOCK_SIZE);

        for block in iter.by_ref() {
            // Decode values.
            let v = u64::from_be_bytes(block[0..8].try_into().unwrap());
            let w = u64::from_be_bytes(block[8..16].try_into().unwrap());

            // Update running checksum.
            a = a.wrapping_add(v);
            b = b.wrapping_add(w);
            c = c.wrapping_add(a);
            d = d.wrapping_add(b);
        }

        // Save state.
        state[0] = a;
        state[1] = b;
        state[2] = c;
        state[3] = d;
    }

    /// Update blocks, reading one little endian [`u32`] at a time.
    fn update_blocks_generic_little(state: &mut [u64], data: &[u8]) {
        // Load state to local variables.
        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];

        // Iterate one block at a time.
        let mut iter = data.chunks_exact(FLETCHER_2_BLOCK_SIZE);

        for block in iter.by_ref() {
            // Decode values.
            let v = u64::from_le_bytes(block[0..8].try_into().unwrap());
            let w = u64::from_le_bytes(block[8..16].try_into().unwrap());

            // Update running checksum.
            a = a.wrapping_add(v);
            b = b.wrapping_add(w);
            c = c.wrapping_add(a);
            d = d.wrapping_add(b);
        }

        // Save state.
        state[0] = a;
        state[1] = b;
        state[2] = c;
        state[3] = d;
    }

    /// Update blocks, reading two big endian [`u32`] at a time.
    fn update_blocks_superscalar2_big(state: &mut [u64], data: &[u8]) {
        // Load state.
        let mut a0 = state[0];
        let mut b0 = state[1];

        let mut a1 = state[2];
        let mut b1 = state[3];

        let mut c0 = state[4];
        let mut d0 = state[5];

        let mut c1 = state[6];
        let mut d1 = state[7];

        // Iterate two blocks at a time.
        let mut iter = data.chunks_exact(2 * FLETCHER_2_BLOCK_SIZE);

        for block in iter.by_ref() {
            // Decode values.
            let v = u64::from_be_bytes(block[0..8].try_into().unwrap());
            let w = u64::from_be_bytes(block[8..16].try_into().unwrap());
            let x = u64::from_be_bytes(block[16..24].try_into().unwrap());
            let y = u64::from_be_bytes(block[24..32].try_into().unwrap());

            // Update running checksum.
            a0 = a0.wrapping_add(v);
            b0 = b0.wrapping_add(w);
            a1 = a1.wrapping_add(x);
            b1 = b1.wrapping_add(y);

            c0 = c0.wrapping_add(a0);
            d0 = d0.wrapping_add(b0);
            c1 = c1.wrapping_add(a1);
            d1 = d1.wrapping_add(b1);
        }

        // Save state.
        state[0] = a0;
        state[1] = b0;

        state[2] = a1;
        state[3] = b1;

        state[4] = c0;
        state[5] = d0;

        state[6] = c1;
        state[7] = d1;
    }

    /// Update blocks, reading two little endian [`u32`] at a time.
    fn update_blocks_superscalar2_little(state: &mut [u64], data: &[u8]) {
        // Load state.
        let mut a0 = state[0];
        let mut b0 = state[1];

        let mut a1 = state[2];
        let mut b1 = state[3];

        let mut c0 = state[4];
        let mut d0 = state[5];

        let mut c1 = state[6];
        let mut d1 = state[7];

        // Iterate two blocks at a time.
        let mut iter = data.chunks_exact(2 * FLETCHER_2_BLOCK_SIZE);

        for block in iter.by_ref() {
            // Decode values.
            let v = u64::from_le_bytes(block[0..8].try_into().unwrap());
            let w = u64::from_le_bytes(block[8..16].try_into().unwrap());
            let x = u64::from_le_bytes(block[16..24].try_into().unwrap());
            let y = u64::from_le_bytes(block[24..32].try_into().unwrap());

            // Update running checksum.
            a0 = a0.wrapping_add(v);
            b0 = b0.wrapping_add(w);
            a1 = a1.wrapping_add(x);
            b1 = b1.wrapping_add(y);

            c0 = c0.wrapping_add(a0);
            d0 = d0.wrapping_add(b0);
            c1 = c1.wrapping_add(a1);
            d1 = d1.wrapping_add(b1);
        }

        // Save state.
        state[0] = a0;
        state[1] = b0;

        state[2] = a1;
        state[3] = b1;

        state[4] = c0;
        state[5] = d0;

        state[6] = c1;
        state[7] = d1;
    }

    /// Update blocks, reading two big endian [`u32`] at a time.
    fn update_blocks_superscalar4_big(state: &mut [u64], data: &[u8]) {
        // Load state.
        let mut a0 = state[0];
        let mut b0 = state[1];

        let mut a1 = state[2];
        let mut b1 = state[3];

        let mut a2 = state[4];
        let mut b2 = state[5];

        let mut a3 = state[6];
        let mut b3 = state[7];

        let mut c0 = state[8];
        let mut d0 = state[9];

        let mut c1 = state[10];
        let mut d1 = state[11];

        let mut c2 = state[12];
        let mut d2 = state[13];

        let mut c3 = state[14];
        let mut d3 = state[15];

        // Iterate four blocks at a time.
        let mut iter = data.chunks_exact(4 * FLETCHER_2_BLOCK_SIZE);

        for block in iter.by_ref() {
            // Decode values.
            let v = u64::from_be_bytes(block[0..8].try_into().unwrap());
            let w = u64::from_be_bytes(block[8..16].try_into().unwrap());
            let x = u64::from_be_bytes(block[16..24].try_into().unwrap());
            let y = u64::from_be_bytes(block[24..32].try_into().unwrap());
            let vv = u64::from_be_bytes(block[32..40].try_into().unwrap());
            let ww = u64::from_be_bytes(block[40..48].try_into().unwrap());
            let xx = u64::from_be_bytes(block[48..56].try_into().unwrap());
            let yy = u64::from_be_bytes(block[56..64].try_into().unwrap());

            // Update running checksum.
            a0 = a0.wrapping_add(v);
            b0 = b0.wrapping_add(w);
            a1 = a1.wrapping_add(x);
            b1 = b1.wrapping_add(y);

            a2 = a2.wrapping_add(vv);
            b2 = b2.wrapping_add(ww);
            a3 = a3.wrapping_add(xx);
            b3 = b3.wrapping_add(yy);

            c0 = c0.wrapping_add(a0);
            d0 = d0.wrapping_add(b0);
            c1 = c1.wrapping_add(a1);
            d1 = d1.wrapping_add(b1);

            c2 = c2.wrapping_add(a2);
            d2 = d2.wrapping_add(b2);
            c3 = c3.wrapping_add(a3);
            d3 = d3.wrapping_add(b3);
        }

        // Save state.
        state[0] = a0;
        state[1] = b0;

        state[2] = a1;
        state[3] = b1;

        state[4] = a2;
        state[5] = b2;

        state[6] = a3;
        state[7] = b3;

        state[8] = c0;
        state[9] = d0;

        state[10] = c1;
        state[11] = d1;

        state[12] = c2;
        state[13] = d2;

        state[14] = c3;
        state[15] = d3;
    }

    /// Update blocks, reading two little endian [`u32`] at a time.
    fn update_blocks_superscalar4_little(state: &mut [u64], data: &[u8]) {
        // Load state.
        let mut a0 = state[0];
        let mut b0 = state[1];

        let mut a1 = state[2];
        let mut b1 = state[3];

        let mut a2 = state[4];
        let mut b2 = state[5];

        let mut a3 = state[6];
        let mut b3 = state[7];

        let mut c0 = state[8];
        let mut d0 = state[9];

        let mut c1 = state[10];
        let mut d1 = state[11];

        let mut c2 = state[12];
        let mut d2 = state[13];

        let mut c3 = state[14];
        let mut d3 = state[15];

        // Iterate four blocks at a time.
        let mut iter = data.chunks_exact(4 * FLETCHER_2_BLOCK_SIZE);

        for block in iter.by_ref() {
            // Decode values.
            let v = u64::from_le_bytes(block[0..8].try_into().unwrap());
            let w = u64::from_le_bytes(block[8..16].try_into().unwrap());
            let x = u64::from_le_bytes(block[16..24].try_into().unwrap());
            let y = u64::from_le_bytes(block[24..32].try_into().unwrap());
            let vv = u64::from_le_bytes(block[32..40].try_into().unwrap());
            let ww = u64::from_le_bytes(block[40..48].try_into().unwrap());
            let xx = u64::from_le_bytes(block[48..56].try_into().unwrap());
            let yy = u64::from_le_bytes(block[56..64].try_into().unwrap());

            // Update running checksum.
            a0 = a0.wrapping_add(v);
            b0 = b0.wrapping_add(w);
            a1 = a1.wrapping_add(x);
            b1 = b1.wrapping_add(y);

            a2 = a2.wrapping_add(vv);
            b2 = b2.wrapping_add(ww);
            a3 = a3.wrapping_add(xx);
            b3 = b3.wrapping_add(yy);

            c0 = c0.wrapping_add(a0);
            d0 = d0.wrapping_add(b0);
            c1 = c1.wrapping_add(a1);
            d1 = d1.wrapping_add(b1);

            c2 = c2.wrapping_add(a2);
            d2 = d2.wrapping_add(b2);
            c3 = c3.wrapping_add(a3);
            d3 = d3.wrapping_add(b3);
        }

        // Save state.
        state[0] = a0;
        state[1] = b0;

        state[2] = a1;
        state[3] = b1;

        state[4] = a2;
        state[5] = b2;

        state[6] = a3;
        state[7] = b3;

        state[8] = c0;
        state[9] = d0;

        state[10] = c1;
        state[11] = d1;

        state[12] = c2;
        state[13] = d2;

        state[14] = c3;
        state[15] = d3;
    }

    #[cfg(all(
        feature = "fletcher2-sse2",
        any(target_arch = "x86", target_arch = "x86_64")
    ))]
    fn update_blocks_sse2_byteswap(state: &mut [u64], data: &[u8]) {
        // Intrinsics used:
        // +--------------------+------+
        // | _mm_add_epi64      | SSE2 |
        // | _mm_loadu_si128    | SSE2 |
        // | _mm_storeu_si128   | SSE2 |
        // +--------------------+------+

        #[target_feature(enable = "sse2")]
        unsafe fn update_blocks_sse2_byteswap_impl(state: &mut [u64], data: &[u8]) {
            // Load value pairs into xmm registers.
            let state = state.as_ptr() as *mut arch::__m128i;
            let mut ab = arch::_mm_loadu_si128(state.add(0));
            let mut cd = arch::_mm_loadu_si128(state.add(1));

            // Iterate one block at a time.
            let mut iter = data.chunks_exact(FLETCHER_2_BLOCK_SIZE);

            for block in iter.by_ref() {
                // Decode values.
                let v = u64::from_ne_bytes(block[0..8].try_into().unwrap()).swap_bytes();
                let w = u64::from_ne_bytes(block[8..16].try_into().unwrap()).swap_bytes();

                // Load v and w into an xmm register.
                //
                // vw[0..64]   = f[n]
                // vw[64..128] = f[n+1]
                let block: &[u64; 2] = &[v, w];
                let vw = arch::_mm_loadu_si128(block.as_ptr() as *const _);

                // Add the values to the lanes.
                // a, b += f[n], f[n+1]
                // ...
                ab = arch::_mm_add_epi64(ab, vw);
                cd = arch::_mm_add_epi64(cd, ab);
            }

            // Save state.
            arch::_mm_storeu_si128(state.add(0), ab);
            arch::_mm_storeu_si128(state.add(1), cd);
        }

        unsafe { update_blocks_sse2_byteswap_impl(state, data) }
    }

    #[cfg(all(
        any(feature = "fletcher2-sse2", feature = "fletcher2-ssse3"),
        any(target_arch = "x86", target_arch = "x86_64")
    ))]
    fn update_blocks_sse2_native(state: &mut [u64], data: &[u8]) {
        // Intrinsics used:
        // +--------------------+------+
        // | _mm_add_epi64      | SSE2 |
        // | _mm_loadu_si128    | SSE2 |
        // | _mm_storeu_si128   | SSE2 |
        // +--------------------+------+

        #[target_feature(enable = "sse2")]
        unsafe fn update_blocks_sse2_native_impl(state: &mut [u64], data: &[u8]) {
            // Load value pairs into xmm registers.
            let state = state.as_ptr() as *mut arch::__m128i;
            let mut ab = arch::_mm_loadu_si128(state.add(0));
            let mut cd = arch::_mm_loadu_si128(state.add(1));

            // Iterate one block at a time.
            let mut iter = data.chunks_exact(FLETCHER_2_BLOCK_SIZE);

            for block in iter.by_ref() {
                // Load v and w into an xmm register.
                //
                // vw[0..64]   = f[n]
                // vw[64..128] = f[n+1]
                let vw = arch::_mm_loadu_si128(block.as_ptr() as *const _);

                // Add the values to the lanes.
                // a, b += f[n], f[n+1]
                // ...
                ab = arch::_mm_add_epi64(ab, vw);
                cd = arch::_mm_add_epi64(cd, ab);
            }

            // Save state.
            arch::_mm_storeu_si128(state.add(0), ab);
            arch::_mm_storeu_si128(state.add(1), cd);
        }

        unsafe { update_blocks_sse2_native_impl(state, data) }
    }

    #[cfg(all(
        feature = "fletcher2-ssse3",
        any(target_arch = "x86", target_arch = "x86_64")
    ))]
    fn update_blocks_ssse3_byteswap(state: &mut [u64], data: &[u8]) {
        // Intrinsics used:
        // +--------------------+-------+
        // | _mm_add_epi64      | SSE2  |
        // | _mm_loadu_si128    | SSE2  |
        // | _mm_shuffle_epi8   | SSSE3 |
        // | _mm_storeu_si128   | SSE2  |
        // +--------------------+-------+

        #[target_feature(enable = "sse2,ssse3")]
        unsafe fn update_blocks_ssse3_byteswap_impl(state: &mut [u64], data: &[u8]) {
            // Load value pairs into xmm registers.
            let state = state.as_ptr() as *mut arch::__m128i;
            let mut ab = arch::_mm_loadu_si128(state.add(0));
            let mut cd = arch::_mm_loadu_si128(state.add(1));

            // Set the shuffle value.
            let shuffle = arch::_mm_set_epi8(
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, // f1
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // f0
            );

            // Iterate one block at a time.
            let mut iter = data.chunks_exact(FLETCHER_2_BLOCK_SIZE);

            for block in iter.by_ref() {
                // Load block into an xmm register.
                let vw = arch::_mm_loadu_si128(block.as_ptr() as *const _);

                // Swap the order of each 8-byte part of vw.
                // Each byte of shuffle indicates the byte index of vw.
                //
                // index = shuffle[0..8]
                // vw[0..8] = vw[index * 8..(index + 1) * 8]
                // vw[0..8] = vw[56..64]
                //
                // index = shuffle[8..16]
                // vw[8..16] = vw[index * 8..(index + 1) * 8]
                // vw[8..16] = vw[48..56]
                // ...
                let vw = arch::_mm_shuffle_epi8(vw, shuffle);

                // Add the values to the lanes.
                // a, b += f[n], f[n+1]
                // ...
                ab = arch::_mm_add_epi64(ab, vw);
                cd = arch::_mm_add_epi64(cd, ab);
            }

            // Save state.
            arch::_mm_storeu_si128(state.add(0), ab);
            arch::_mm_storeu_si128(state.add(1), cd);
        }

        unsafe { update_blocks_ssse3_byteswap_impl(state, data) }
    }

    #[cfg(all(
        feature = "fletcher2-avx2",
        any(target_arch = "x86", target_arch = "x86_64")
    ))]
    fn update_blocks_avx2_byteswap(state: &mut [u64], data: &[u8]) {
        // Intrinsics used:
        // +-----------------------+-------+
        // | _mm256_add_epi64      | AVX2  |
        // | _mm256_lddqu_si256    | AVX   |
        // | _mm256_shuffle_epi8   | AVX2  |
        // | _mm256_storeu_si256   | AVX   |
        // +-----------------------+-------+

        #[target_feature(enable = "avx,avx2")]
        unsafe fn update_blocks_avx2_byteswap_impl(state: &mut [u64], data: &[u8]) {
            // Set the shuffle value.
            let shuffle = arch::_mm256_set_epi8(
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, // f3
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // f2
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, // f1
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // f0
            );

            // Load each dual stream into a ymm register.
            let state = state.as_ptr() as *mut arch::__m256i;
            let mut ab = arch::_mm256_lddqu_si256(state.add(0));
            let mut cd = arch::_mm256_lddqu_si256(state.add(1));

            // Iterate two blocks at a time.
            let mut iter = data.chunks_exact(2 * FLETCHER_2_BLOCK_SIZE);

            for block in iter.by_ref() {
                // Load 256 bits into a ymm register.
                let vwxy = arch::_mm256_lddqu_si256(block.as_ptr() as *const _);

                // Swap the order of the each 8-byte part of vwxy.
                // Each byte of shuffle indicates the byte index of vwxy.
                // The shuffle is done on each 128 bit lane, so the indices
                // repeat for f0,f1 and f2,f3.
                //
                // index = shuffle[0..8]
                // vwxy[0..8] = vwxy[index * 8..(index + 1) * 8]
                // vwxy[0..8] = vwxy[56..64]
                //
                // index = shuffle[8..16]
                // vwxy[8..16] = vwxy[index * 8..(index + 1) * 8]
                // vwxy[8..16] = vwxy[48..56]
                // ...
                let vwxy = arch::_mm256_shuffle_epi8(vwxy, shuffle);

                // a[0], b[0], a[1], b[1] += f[n], f[n+1], f[n+2], f[n+3]
                // ...
                ab = arch::_mm256_add_epi64(ab, vwxy);
                cd = arch::_mm256_add_epi64(cd, ab);
            }

            // Save state.
            arch::_mm256_storeu_si256(state.add(0), ab);
            arch::_mm256_storeu_si256(state.add(1), cd);
        }

        unsafe { update_blocks_avx2_byteswap_impl(state, data) }
    }

    #[cfg(all(
        feature = "fletcher2-avx2",
        any(target_arch = "x86", target_arch = "x86_64")
    ))]
    fn update_blocks_avx2_native(state: &mut [u64], data: &[u8]) {
        // Intrinsics used:
        // +-----------------------+------+
        // | _mm256_add_epi64      | AVX2 |
        // | _mm256_lddqu_si256    | AVX  |
        // | _mm256_storeu_si256   | AVX  |
        // +-----------------------+------+

        #[target_feature(enable = "avx,avx2")]
        unsafe fn update_blocks_avx2_native_impl(state: &mut [u64], data: &[u8]) {
            // Load each dual stream into a ymm register.
            let state = state.as_ptr() as *mut arch::__m256i;
            let mut ab = arch::_mm256_lddqu_si256(state.add(0));
            let mut cd = arch::_mm256_lddqu_si256(state.add(1));

            // Iterate two blocks at a time.
            let mut iter = data.chunks_exact(2 * FLETCHER_2_BLOCK_SIZE);

            for block in iter.by_ref() {
                // Load 256 bits into a ymm register.
                let vwxy = arch::_mm256_lddqu_si256(block.as_ptr() as *const _);

                // a[0], b[0], a[1], b[1] += f[n], f[n+1], f[n+2], f[n+3]
                // ...
                ab = arch::_mm256_add_epi64(ab, vwxy);
                cd = arch::_mm256_add_epi64(cd, ab);
            }

            // Save state.
            arch::_mm256_storeu_si256(state.add(0), ab);
            arch::_mm256_storeu_si256(state.add(1), cd);
        }

        unsafe { update_blocks_avx2_native_impl(state, data) }
    }

    #[cfg(all(
        any(target_arch = "x86", target_arch = "x86_64",),
        feature = "fletcher2-avx512f",
    ))]
    fn update_blocks_avx512f_byteswap(state: &mut [u64], data: &[u8]) {
        // Intrinsics used:
        // +-----------------------+---------+
        // | *_mm256_lddqu_si256   | AVX     |
        // | _mm512_add_epi64      | AVX512F |
        // | _mm512_cvtepu32_epi64 | AVX512F |
        // | _mm512_loadu_si512    | AVX512F |
        // | _mm512_storeu_si512   | AVX512F |
        // +-----------------------+---------+

        #[target_feature(enable = "avx512f")]
        unsafe fn update_blocks_avx512f_byteswap_impl(state: &mut [u64], data: &[u8]) {
            // TODO(cybojanek): Check this ONLY uses avx512f.
            //                  At the time of this writing, the compiler
            //                  optimizes this code, and uses vpshufb, which is
            //                  an AVX512BW instruction.
            // Load each octo stream into a zmm register.
            let state = state.as_ptr() as *mut arch::__m512i;
            let mut ab = arch::_mm512_loadu_si512(state.add(0));
            let mut cd = arch::_mm512_loadu_si512(state.add(16));

            // Iterate four blocks at a time.
            let mut iter = data.chunks_exact(4 * FLETCHER_2_BLOCK_SIZE);

            // Use broadcast for the first, and then shift for remaining,
            // because shift is only one latency and one CPI.
            // 8xu64 [0x00000000000000ff, ... ]
            // 8xu64 [0x000000000000ff00, ... ]
            // ...
            let mask0 = arch::_mm512_maskz_set1_epi64(0xff, 0xff);
            let mask1 = arch::_mm512_slli_epi64(mask0, 8);
            let mask2 = arch::_mm512_slli_epi64(mask0, 16);
            let mask3 = arch::_mm512_slli_epi64(mask0, 24);
            let mask4 = arch::_mm512_slli_epi64(mask0, 32);
            let mask5 = arch::_mm512_slli_epi64(mask0, 40);
            let mask6 = arch::_mm512_slli_epi64(mask0, 48);
            let mask7 = arch::_mm512_slli_epi64(mask0, 56);

            for block in iter.by_ref() {
                // Load 512 bits into a zmm register.
                let values = arch::_mm512_loadu_si512(block.as_ptr() as *const _);

                // Select one byte of each u64 value.
                let s0 = arch::_mm512_and_epi64(values, mask0);
                let s1 = arch::_mm512_and_epi64(values, mask1);
                let s2 = arch::_mm512_and_epi64(values, mask2);
                let s3 = arch::_mm512_and_epi64(values, mask3);
                let s4 = arch::_mm512_and_epi64(values, mask4);
                let s5 = arch::_mm512_and_epi64(values, mask5);
                let s6 = arch::_mm512_and_epi64(values, mask6);
                let s7 = arch::_mm512_and_epi64(values, mask7);

                // Shift the selected byte of each u64, to its swapped place.
                let s0 = arch::_mm512_slli_epi64(s0, 56);
                let s1 = arch::_mm512_slli_epi64(s1, 40);
                let s2 = arch::_mm512_slli_epi64(s2, 24);
                let s3 = arch::_mm512_slli_epi64(s3, 8);

                let s4 = arch::_mm512_srli_epi64(s4, 8);
                let s5 = arch::_mm512_srli_epi64(s5, 24);
                let s6 = arch::_mm512_srli_epi64(s6, 40);
                let s7 = arch::_mm512_srli_epi64(s7, 56);

                // Or the values to get the swapped u64 values.
                let s01 = arch::_mm512_or_epi64(s0, s1);
                let s23 = arch::_mm512_or_epi64(s2, s3);

                let s45 = arch::_mm512_or_epi64(s4, s5);
                let s67 = arch::_mm512_or_epi64(s6, s7);

                let s03 = arch::_mm512_or_epi64(s01, s23);
                let s47 = arch::_mm512_or_epi64(s45, s67);

                let values = arch::_mm512_or_epi64(s03, s47);

                // a[0], b[0], ..., a[3], b[3] += f[n], f[n+1], ... , f[n+7]
                // ...
                ab = arch::_mm512_add_epi64(ab, values);
                cd = arch::_mm512_add_epi64(cd, ab);
            }

            // Save state.
            arch::_mm512_storeu_si512(state.add(0), ab);
            arch::_mm512_storeu_si512(state.add(1), cd);
        }

        unsafe { update_blocks_avx512f_byteswap_impl(state, data) }
    }

    #[cfg(all(
        any(target_arch = "x86", target_arch = "x86_64",),
        any(feature = "fletcher2-avx512f", feature = "fletcher2-avx512bw"),
    ))]
    fn update_blocks_avx512f_native(state: &mut [u64], data: &[u8]) {
        // Intrinsics used:
        // +---------------------+---------+
        // | _mm512_add_epi64    | AVX512F |
        // | _mm512_loadu_si512  | AVX512F |
        // | _mm512_storeu_si512 | AVX512F |
        // +---------------------+---------+

        #[target_feature(enable = "avx512f")]
        unsafe fn update_blocks_avx512f_native_impl(state: &mut [u64], data: &[u8]) {
            // Load each octo stream into a zmm register.
            let state = state.as_ptr() as *mut arch::__m512i;
            let mut ab = arch::_mm512_loadu_si512(state.add(0));
            let mut cd = arch::_mm512_loadu_si512(state.add(16));

            // Iterate four blocks at a time.
            let mut iter = data.chunks_exact(4 * FLETCHER_2_BLOCK_SIZE);

            for block in iter.by_ref() {
                // Load 512 bits into a zmm register.
                let values = arch::_mm512_loadu_si512(block.as_ptr() as *const _);

                // a[0], b[0], ..., a[3], b[3] += f[n], f[n+1], ... , f[n+7]
                // ...
                ab = arch::_mm512_add_epi64(ab, values);
                cd = arch::_mm512_add_epi64(cd, ab);
            }

            // Save state.
            arch::_mm512_storeu_si512(state.add(0), ab);
            arch::_mm512_storeu_si512(state.add(1), cd);
        }

        unsafe { update_blocks_avx512f_native_impl(state, data) }
    }

    #[cfg(all(
        any(target_arch = "x86", target_arch = "x86_64",),
        feature = "fletcher2-avx512bw",
    ))]
    fn update_blocks_avx512bw_byteswap(state: &mut [u64], data: &[u8]) {
        // Intrinsics used:
        // +---------------------+----------+
        // | _mm512_add_epi64    | AVX512F  |
        // | _mm512_loadu_si512  | AVX512F  |
        // | _mm512_shuffle_epi8 | AVX512BW |
        // | _mm512_storeu_si512 | AVX512F  |
        // +---------------------+----------+

        #[target_feature(enable = "avx512f,avx512bw")]
        unsafe fn update_blocks_avx512bw_byteswap_impl(state: &mut [u64], data: &[u8]) {
            // Set the shuffle value.
            let shuffle = arch::_mm512_set_epi8(
                0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, // f7
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, // f6
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, // f5
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // f4
                0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, // f3
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, // f2
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, // f1
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // f0
            );

            // Load each octo stream into a zmm register.
            let state = state.as_ptr() as *mut arch::__m512i;
            let mut ab = arch::_mm512_loadu_si512(state.add(0));
            let mut cd = arch::_mm512_loadu_si512(state.add(16));

            // Iterate four blocks at a time.
            let mut iter = data.chunks_exact(4 * FLETCHER_2_BLOCK_SIZE);

            for block in iter.by_ref() {
                // Load 512 bits into a zmm register.
                let values = arch::_mm512_loadu_si512(block.as_ptr() as *const _);

                // Swap the order of the 8-byte parts of values.
                // Each byte of shuffle indicates the byte index of values.
                // The shuffle is done on each 256 bit lane, so the indices
                // repeat for f0, f1, f2, f3 and f4, f5, f6, f7.
                //
                // index = shuffle[0..8]
                // values[0..8] = values[index * 8..(index + 1) * 8]
                // values[0..8] = values[56..64]
                //
                // index = shuffle[8..16]
                // values[8..16] = values[index * 8..(index + 1) * 8]
                // values[8..16] = values[48..56]
                // ...
                let values = arch::_mm512_shuffle_epi8(values, shuffle);

                // a[0], b[0], ..., a[3], b[3] += f[n], f[n+1], ... , f[n+7]
                // ...
                ab = arch::_mm512_add_epi64(ab, values);
                cd = arch::_mm512_add_epi64(cd, ab);
            }

            // Save state.
            arch::_mm512_storeu_si512(state.add(0), ab);
            arch::_mm512_storeu_si512(state.add(1), cd);
        }

        unsafe { update_blocks_avx512bw_byteswap_impl(state, data) }
    }
}

impl Checksum for Fletcher2 {
    fn reset(&mut self, order: EndianOrder) -> Result<(), ChecksumError> {
        self.buffer_fill = 0;
        self.buffer = [0; FLETCHER_2_BLOCK_SIZE * FLETCHER_2_MAX_SIMD_WIDTH];
        self.state = Default::default();

        self.order = order;
        self.update_blocks = match self.order {
            EndianOrder::Big => self.impl_ctx.update_blocks_big,
            EndianOrder::Little => self.impl_ctx.update_blocks_little,
        };

        Ok(())
    }

    fn update(&mut self, data: &[u8]) -> Result<(), ChecksumError> {
        // Make data pointer mutable, in case of self.buffer_fill.
        let mut data = data;

        // If block has some data, fill that up first.
        if self.buffer_fill > 0 {
            // Todo is minimum of block fill needed, and input data.
            let todo = cmp::min(self.impl_ctx.block_size - self.buffer_fill, data.len());

            // Copy to block.
            self.buffer[self.buffer_fill..self.buffer_fill + todo].copy_from_slice(&data[0..todo]);
            self.buffer_fill += todo;

            // Update data to skip copied block.
            data = &data[todo..];

            // If block is full, consume it.
            if self.buffer_fill == self.impl_ctx.block_size {
                let full_blocks_data = &self.buffer[0..self.buffer_fill];
                (self.update_blocks)(&mut self.state, full_blocks_data);
                self.buffer_fill = 0;
            }
        }

        // Calculate remainder.
        let remainder = data.len() % self.impl_ctx.block_size;

        // Update full blocks.
        let full_blocks_data = &data[0..data.len() - remainder];
        (self.update_blocks)(&mut self.state, full_blocks_data);

        // Check if remainder exists, to prevent clobbering fill with 0.
        if remainder > 0 {
            self.buffer[0..remainder].copy_from_slice(&data[data.len() - remainder..]);
            self.buffer_fill = remainder;
        }

        // Success.
        Ok(())
    }

    fn finalize(&mut self) -> Result<[u64; 4], ChecksumError> {
        // Finish the state for parallel streams.
        let mut result = (self.impl_ctx.finish_blocks)(&self.state);

        // Calculate remainder and full blocks.
        let remainder = self.buffer_fill % FLETCHER_2_BLOCK_SIZE;
        let full_block_bytes = self.buffer_fill - remainder;

        // Update full blocks.
        if full_block_bytes > 0 {
            let generic = match self.order {
                EndianOrder::Big => Fletcher2::update_blocks_generic_big,
                EndianOrder::Little => Fletcher2::update_blocks_generic_little,
            };

            (generic)(&mut result, &self.buffer[0..full_block_bytes]);
            result = Fletcher2::finish_blocks_single_stream(&result);
        }

        // Ignore remainder bytes, because they are not included in checksum.

        Ok(result)
    }

    fn hash(&mut self, data: &[u8], order: EndianOrder) -> Result<[u64; 4], ChecksumError> {
        self.reset(order)?;
        self.update(data)?;
        self.finalize()
    }
}

