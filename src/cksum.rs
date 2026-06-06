// SPDX-License-Identifier: MIT OR Apache-2.0
//! Block-pointer checksum verification (SPEC-LAMZFS §1.1 "Checksums").
//!
//! A regular block pointer stores the checksum of its *physical* (on-disk,
//! possibly compressed) bytes in `bp.cksum`. After reading those bytes,
//! [`verify_block`] recomputes the checksum with the algorithm the pointer names
//! and compares — a mismatch is corruption (and, for a mirror, the trigger to
//! try another child). Scalar Fletcher-2/4 + SHA-256 only (no SIMD), per §5.1.

use crate::{
    checksum::{
        Checksum, Fletcher2, Fletcher2Implementation, Fletcher4, Fletcher4Implementation, Sha256,
        Sha256Implementation,
    },
    error::{Error, Result},
    phys::{ChecksumType, ChecksumValue, EndianOrder},
};

/// Stable token for a checksum algorithm (trust log + error `what`).
pub(crate) fn checksum_name(kind: ChecksumType) -> &'static str {
    match kind {
        ChecksumType::Fletcher2 => "csum_fletcher2",
        ChecksumType::Fletcher4 => "csum_fletcher4",
        ChecksumType::Sha256 | ChecksumType::Label => "csum_sha256",
        _ => "csum_unsupported",
    }
}

/// Verify `data`'s checksum against `expected`, using algorithm `kind` in byte
/// order `order`. `vdev`/`offset` are carried into a [`Error::ChecksumMismatch`]
/// for the trust log. `Off` skips (no integrity stored); algorithms outside the
/// scalar set are rejected as an unsupported feature.
pub(crate) fn verify_block(
    kind: ChecksumType,
    order: EndianOrder,
    data: &[u8],
    expected: &ChecksumValue,
    vdev: u64,
    offset: u64,
) -> Result<()> {
    let init = |_| Error::ChecksumMismatch {
        vdev,
        offset,
        what: "csum_init",
    };
    let computed: [u64; 4] = match kind {
        // No integrity stored — nothing to verify.
        ChecksumType::Off => return Ok(()),
        ChecksumType::Fletcher2 => Fletcher2::new(Fletcher2Implementation::Generic)
            .map_err(init)?
            .hash(data, order)
            .map_err(init)?,
        ChecksumType::Fletcher4 => Fletcher4::new(Fletcher4Implementation::Generic)
            .map_err(init)?
            .hash(data, order)
            .map_err(init)?,
        ChecksumType::Sha256 | ChecksumType::Label => Sha256::new(Sha256Implementation::Generic)
            .map_err(init)?
            .hash(data, order)
            .map_err(init)?,
        other => return Err(Error::UnsupportedFeature(checksum_name(other))),
    };
    if computed == expected.words {
        Ok(())
    } else {
        Err(Error::ChecksumMismatch {
            vdev,
            offset,
            what: checksum_name(kind),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cv(words: [u64; 4]) -> ChecksumValue {
        ChecksumValue { words }
    }

    #[test]
    fn fletcher4_roundtrip_then_detect_corruption() {
        let data = b"the quick brown fox jumps over the lazy dog 0123456789abcdef!!";
        // Self-consistent: compute, then verify the same bytes against it.
        let good = Fletcher4::new(Fletcher4Implementation::Generic)
            .unwrap()
            .hash(data, EndianOrder::Little)
            .unwrap();
        assert!(verify_block(
            ChecksumType::Fletcher4,
            EndianOrder::Little,
            data,
            &cv(good),
            0,
            0
        )
        .is_ok());
        // A flipped expected word is a mismatch.
        let mut bad = good;
        bad[0] ^= 1;
        let e = verify_block(
            ChecksumType::Fletcher4,
            EndianOrder::Little,
            data,
            &cv(bad),
            7,
            99,
        )
        .unwrap_err();
        assert!(matches!(
            e,
            Error::ChecksumMismatch {
                vdev: 7,
                offset: 99,
                ..
            }
        ));
    }

    #[test]
    fn sha256_roundtrip() {
        let data = b"boot pool block";
        let good = Sha256::new(Sha256Implementation::Generic)
            .unwrap()
            .hash(data, EndianOrder::Little)
            .unwrap();
        assert!(verify_block(
            ChecksumType::Sha256,
            EndianOrder::Little,
            data,
            &cv(good),
            0,
            0
        )
        .is_ok());
    }

    #[test]
    fn off_skips_verification() {
        assert!(verify_block(
            ChecksumType::Off,
            EndianOrder::Little,
            b"x",
            &cv([0; 4]),
            0,
            0
        )
        .is_ok());
    }

    #[test]
    fn unsupported_algorithm_rejected() {
        let e = verify_block(
            ChecksumType::Skein,
            EndianOrder::Little,
            b"x",
            &cv([0; 4]),
            0,
            0,
        )
        .unwrap_err();
        assert!(matches!(e, Error::UnsupportedFeature(_)));
    }
}
