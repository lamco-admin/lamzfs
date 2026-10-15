// SPDX-License-Identifier: MIT OR Apache-2.0
//! Block-pointer checksum verification (SPEC-LAMZFS §1.1 "Checksums").
//!
//! A regular block pointer stores the checksum of its *physical* (on-disk,
//! possibly compressed) bytes in `bp.cksum`. After reading those bytes,
//! [`verify_block`] recomputes the checksum with the algorithm the pointer names
//! and compares — a mismatch is corruption (and, for a mirror, the trigger to
//! try another child). Scalar Fletcher-2/4, SHA-256 and, with their features,
//! SHA-512/256 and BLAKE3, per §5.1. Skein and Edon-R are refused per block.

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
        ChecksumType::Sha512_256 => "csum_sha512",
        ChecksumType::Skein => "csum_skein",
        ChecksumType::Edonr => "csum_edonr",
        ChecksumType::Blake3 => "csum_blake3",
        _ => "csum_unsupported",
    }
}

/// OpenZFS copies the SHA-512/256 and BLAKE3 digests straight into the
/// checksum words (unlike SHA-256, which it stores as big-endian words), so the
/// words read in the byte order the block pointer was written in.
#[cfg(any(feature = "sha512", feature = "blake3"))]
fn digest_words(digest: &[u8], order: EndianOrder) -> [u64; 4] {
    let mut words = [0u64; 4];
    for (word, chunk) in words.iter_mut().zip(digest.chunks_exact(8)) {
        let bytes: [u8; 8] = chunk.try_into().unwrap_or([0; 8]);
        *word = match order {
            EndianOrder::Big => u64::from_be_bytes(bytes),
            EndianOrder::Little => u64::from_le_bytes(bytes),
        };
    }
    words
}

/// OpenZFS's `sha512` is SHA-512/256.
#[cfg(feature = "sha512")]
fn sha512_256_words(data: &[u8], order: EndianOrder) -> [u64; 4] {
    use sha2::{Digest as _, Sha512_256};
    digest_words(&Sha512_256::digest(data), order)
}

/// BLAKE3 in OpenZFS is a salted checksum: keyed with the pool's checksum salt.
#[cfg(feature = "blake3")]
fn blake3_words(data: &[u8], salt: &[u8; 32], order: EndianOrder) -> [u64; 4] {
    digest_words(blake3::keyed_hash(salt, data).as_bytes(), order)
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
    salt: Option<&[u8; 32]>,
    vdev: u64,
    offset: u64,
) -> Result<()> {
    // Only the salted checksums read the salt.
    #[cfg(not(feature = "blake3"))]
    let _ = salt;
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
        #[cfg(feature = "sha512")]
        ChecksumType::Sha512_256 => sha512_256_words(data, order),
        // A salted checksum needs the pool's salt, which the MOS holds.
        #[cfg(feature = "blake3")]
        ChecksumType::Blake3 => match salt {
            Some(salt) => blake3_words(data, salt, order),
            None => return Err(Error::UnsupportedFeature("csum_blake3_no_salt")),
        },
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
            None,
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
            None,
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
            None,
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
            None,
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
            None,
            0,
            0,
        )
        .unwrap_err();
        assert!(matches!(e, Error::UnsupportedFeature(_)));
    }

    /// BLAKE3 is keyed with the pool's checksum salt; without one it can't be
    /// verified, and the block is refused rather than trusted.
    #[cfg(feature = "blake3")]
    #[test]
    fn blake3_without_a_salt_is_refused() {
        let e = verify_block(
            ChecksumType::Blake3,
            EndianOrder::Little,
            b"x",
            &cv([0; 4]),
            None,
            0,
            0,
        )
        .unwrap_err();
        assert_eq!(e, Error::UnsupportedFeature("csum_blake3_no_salt"));
    }

    /// The keyed digest's bytes become the words in the block pointer's order.
    #[cfg(feature = "blake3")]
    #[test]
    fn blake3_words_follow_the_byte_order() {
        let salt = [7u8; 32];
        let digest = blake3::keyed_hash(&salt, b"lamzfs");
        let bytes = digest.as_bytes();
        let le = blake3_words(b"lamzfs", &salt, EndianOrder::Little);
        let be = blake3_words(b"lamzfs", &salt, EndianOrder::Big);
        assert_eq!(le[0], u64::from_le_bytes(bytes[..8].try_into().unwrap()));
        assert_eq!(be[0], u64::from_be_bytes(bytes[..8].try_into().unwrap()));
        assert!(verify_block(
            ChecksumType::Blake3,
            EndianOrder::Little,
            b"lamzfs",
            &cv(le),
            Some(&salt),
            0,
            0,
        )
        .is_ok());
    }
}
