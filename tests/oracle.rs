// SPDX-License-Identifier: MIT OR Apache-2.0
//! Oracle tests: import the committed real-OpenZFS fixtures and check the reader
//! reproduces what the kernel wrote (SPEC-LAMZFS §6.2). The fixtures and their
//! `MANIFEST.json` are produced by `tests/fixtures/regen.sh`.

use std::io::Read as _;

use lamzfs::{BlockRead, EntryKind, PoolMember, Zfs};
use serde_json::Value;

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

fn manifest() -> Value {
    let s = std::fs::read_to_string(format!("{}/MANIFEST.json", fixtures_dir())).expect("MANIFEST");
    serde_json::from_str(&s).expect("parse MANIFEST")
}

fn decompress(name: &str) -> Vec<u8> {
    let raw = std::fs::read(format!("{}/{}", fixtures_dir(), name)).expect("fixture");
    let mut dec = ruzstd::decoding::StreamingDecoder::new(raw.as_slice()).expect("zstd");
    let mut out = Vec::new();
    dec.read_to_end(&mut out).expect("decompress");
    out
}

fn fixture(name: &str) -> Value {
    manifest()["fixtures"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["name"] == name)
        .unwrap_or_else(|| panic!("fixture {name} in MANIFEST"))
        .clone()
}

fn import(name: &str) -> (Zfs<Mem>, Value) {
    let fx = fixture(name);
    let members: Vec<PoolMember<Mem>> = fx["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| {
            let img = decompress(m.as_str().unwrap());
            let device_size_bytes = img.len() as u64;
            PoolMember {
                reader: Mem(img),
                device_size_bytes,
            }
        })
        .collect();
    let zfs = Zfs::import(members).unwrap_or_else(|e| panic!("import {name}: {e:?}"));
    (zfs, fx)
}

fn guid_of(fx: &Value) -> u64 {
    fx["guid"].as_str().unwrap().parse().unwrap()
}

#[test]
fn single_lz4_imports_with_matching_identity() {
    let (zfs, fx) = import("single_lz4");
    assert_eq!(zfs.pool_guid(), guid_of(&fx), "pool guid");
    assert_eq!(zfs.pool_name(), fx["pool"].as_str().unwrap(), "pool name");
    assert!(zfs.txg() > 0, "active uberblock has a txg");
    assert_eq!(zfs.member_count(), 1);
}

#[test]
fn mirror_imports_all_members() {
    let (zfs, fx) = import("mirror_lz4");
    assert_eq!(zfs.pool_guid(), guid_of(&fx));
    assert_eq!(zfs.member_count(), 2);
}

/// The child-directory components of the dataset name under the pool root, e.g.
/// `lamzt_single_lz4/BOOT/test` becomes `[BOOT, test]`.
fn dataset_path(fx: &Value) -> Vec<String> {
    let full = fx["dataset"].as_str().unwrap();
    let (_pool, rest) = full.split_once('/').unwrap();
    rest.split('/').map(String::from).collect()
}

#[test]
fn single_lz4_read_dir_lists_catalog() {
    let (mut zfs, fx) = import("single_lz4");
    let owned = dataset_path(&fx);
    let path: Vec<&str> = owned.iter().map(String::as_str).collect();
    let entries = zfs.read_dir(&path).unwrap();
    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    for expected in [
        "vmlinuz-6.1.0-test",
        "initrd.img-6.1.0-test",
        "os-release",
        "big.bin",
        "loader",
        "EFI",
    ] {
        assert!(names.contains(&expected), "missing {expected} in {names:?}");
    }
    let by = |n: &str| entries.iter().find(|e| e.name == n).unwrap().clone();
    assert_eq!(by("loader").kind, EntryKind::Directory);
    assert_eq!(by("big.bin").kind, EntryKind::Regular);
    assert_eq!(by("vmlinuz").kind, EntryKind::Symlink);
}
