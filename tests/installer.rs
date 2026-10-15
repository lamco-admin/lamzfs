// SPDX-License-Identifier: MIT OR Apache-2.0
//! Pools shaped the way installers create them, and layouts lamzfs must refuse
//! rather than misread, built by OpenZFS through the kernel module
//! (`tests/fixtures/regen-installer.sh`). Each readable fixture's files must hash
//! to what the kernel wrote; each refused fixture must fail with its named token.

use std::io::Read as _;

use lamzfs::{BlockRead, EntryKind, Error, PoolMember, Zfs};
use serde_json::Value;
use sha2::{Digest, Sha256};

struct Mem(Vec<u8>);

impl BlockRead for Mem {
    type Error = ();
    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> Result<(), ()> {
        let off = usize::try_from(off).map_err(|_| ())?;
        let end = off.checked_add(buf.len()).ok_or(())?;
        buf.copy_from_slice(self.0.get(off..end).ok_or(())?);
        Ok(())
    }
}

fn fixtures_dir() -> String {
    format!("{}/tests/fixtures", env!("CARGO_MANIFEST_DIR"))
}

fn fixture(name: &str) -> Value {
    let s = std::fs::read_to_string(format!("{}/INSTALLER-MANIFEST.json", fixtures_dir()))
        .expect("INSTALLER-MANIFEST.json");
    let all: Value = serde_json::from_str(&s).expect("parse manifest");
    all["fixtures"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["name"] == name)
        .unwrap_or_else(|| panic!("fixture {name} in manifest"))
        .clone()
}

fn image(name: &str) -> Vec<u8> {
    let raw = std::fs::read(format!("{}/{}", fixtures_dir(), name)).expect("fixture image");
    let mut dec = ruzstd::decoding::StreamingDecoder::new(raw.as_slice()).expect("zstd");
    let mut out = Vec::new();
    dec.read_to_end(&mut out).expect("decompress");
    out
}

fn members(fx: &Value) -> Vec<PoolMember<Mem>> {
    fx["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| {
            let img = image(m.as_str().unwrap());
            let device_size_bytes = img.len() as u64;
            PoolMember {
                reader: Mem(img),
                device_size_bytes,
            }
        })
        .collect()
}

fn import(name: &str) -> (Zfs<Mem>, Value) {
    let fx = fixture(name);
    let zfs = Zfs::import(members(&fx)).unwrap_or_else(|e| panic!("import {name}: {e:?}"));
    (zfs, fx)
}

fn components(path: &str) -> Vec<&str> {
    path.split('/').filter(|c| !c.is_empty()).collect()
}

fn hex(data: &[u8]) -> String {
    use std::fmt::Write as _;
    Sha256::digest(data).iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Every file the kernel hashed reads back with the same SHA-256.
fn read_every_file(name: &str) -> Zfs<Mem> {
    let (mut zfs, fx) = import(name);
    assert_eq!(
        zfs.pool_guid(),
        fx["guid"].as_str().unwrap().parse::<u64>().unwrap()
    );
    let dataset = fx["dataset"].as_str().unwrap().to_string();
    let ds = components(&dataset);
    let files = fx["files"].as_array().unwrap();
    assert!(!files.is_empty(), "{name}: no files recorded");
    for f in files {
        let path = f["path"].as_str().unwrap();
        let data = zfs
            .read(&ds, &components(path))
            .unwrap_or_else(|e| panic!("{name}: read {path}: {e:?}"));
        assert_eq!(
            hex(&data),
            f["sha256"].as_str().unwrap(),
            "{name}: {path} differs from what the kernel wrote"
        );
    }
    zfs
}

fn refusal(name: &str) -> Error {
    let fx = fixture(name);
    let want = fx["expect"]
        .as_str()
        .unwrap()
        .strip_prefix("refuse:")
        .unwrap()
        .to_string();
    let err = match Zfs::import(members(&fx)) {
        Err(e) => e,
        Ok(mut zfs) => {
            // Still refused if the pool imports but its dataset can't be read.
            let ds = fx["dataset"].as_str().unwrap().to_string();
            match zfs.read_dir(&components(&ds), &[]) {
                Err(e) => e,
                Ok(entries) => panic!("{name}: imported and listed {} entries", entries.len()),
            }
        }
    };
    assert_eq!(err.token(), want, "{name}: refused with {err:?}");
    err
}

/// Proxmox VE: every feature enabled, so head_errlog, vdev_zaps_v2 and friends
/// are active, and a 1 MiB recordsize makes large_blocks active.
#[test]
fn proxmox_rpool_reads() {
    read_every_file("proxmox_rpool");
}

/// Ubuntu's rpool: dnodesize=auto puts these files in 1 KiB dnodes, and the
/// ACL'd files carry SA bonuses larger than a 512-byte dnode holds. bigdir is a
/// fat ZAP; the dataset normalizes names to formD.
#[test]
fn ubuntu_rpool_reads_large_dnodes() {
    let mut zfs = read_every_file("ubuntu_rpool");
    let fx = fixture("ubuntu_rpool");
    let ds = components(fx["dataset"].as_str().unwrap());
    let bigdir = zfs.read_dir(&ds, &["boot", "bigdir"]).unwrap();
    assert_eq!(bigdir.len(), 2000);
    assert!(bigdir.iter().all(|e| e.kind == EntryKind::Regular));
    let st = zfs.stat(&ds, &["boot", "acl2.conf"]).unwrap();
    assert_eq!((st.kind, st.size), (EntryKind::Regular, 11));
}

/// Ubuntu's bpool: default features off and only the eleven subiquity enables.
#[test]
fn ubuntu_bpool_reads() {
    read_every_file("ubuntu_bpool");
}

/// A dataset checksummed with SHA-512 (OpenZFS's SHA-512/256).
#[test]
fn sha512_checksums_verify() {
    read_every_file("sha512_boot");
}

/// Member 0 of a mirror missed the last writes. The newest uberblock is only on
/// member 1, so reading member 0's labels alone gives an older tree without the
/// late files.
#[test]
fn stale_mirror_member_does_not_win() {
    read_every_file("mirror_stale");
}

/// Gang blocks are refused with their own token; the rest of the dataset reads.
#[test]
fn gang_blocks_are_refused() {
    let mut zfs = read_every_file("gang_blocks");
    let fx = fixture("gang_blocks");
    let ds = components(fx["dataset"].as_str().unwrap());
    let err = zfs.read(&ds, &["ganged.bin"]).unwrap_err();
    assert_eq!(err.token(), "gang_block", "{err:?}");
}

#[test]
fn two_top_level_vdevs_are_refused() {
    refusal("refuse_stripe");
}

#[test]
fn raidz_expansion_is_refused() {
    refusal("refuse_raidz_expanded");
}

#[test]
fn longname_is_refused() {
    refusal("refuse_longname");
}

/// An unencrypted `/boot` beside an encrypted dataset reads; the encrypted
/// dataset itself is refused.
#[test]
fn encrypted_dataset_is_refused_and_its_sibling_reads() {
    let mut zfs = read_every_file("encrypted_sibling");
    let err = zfs.read_dir(&["secret"], &[]).unwrap_err();
    assert_eq!(err.token(), "encryption", "{err:?}");
}
