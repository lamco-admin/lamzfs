// SPDX-License-Identifier: MIT OR Apache-2.0
//! Oracle tests: import the committed real-OpenZFS fixtures and check the reader
//! reproduces what the kernel wrote (SPEC-LAMZFS §6.2). The fixtures and their
//! `MANIFEST.json` are produced by `tests/fixtures/regen.sh`.

use std::io::Read as _;

use lamzfs::{BlockRead, EntryKind, PoolMember, Zfs};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn sha256_hex(data: &[u8]) -> String {
    use std::fmt::Write as _;
    Sha256::digest(data).iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

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
    let entries = zfs.read_dir(&path, &[]).unwrap();
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

    // Nested read_dir: list the `loader/entries` subdirectory within the dataset.
    let nested = zfs.read_dir(&path, &["loader", "entries"]).unwrap();
    assert!(
        nested.iter().any(|e| e.name == "test.conf"),
        "loader/entries should contain test.conf, got {:?}",
        nested.iter().map(|e| e.name.as_str()).collect::<Vec<_>>()
    );

    // stat: a regular file reports its size; a directory reports kind only.
    let st = zfs.stat(&path, &["os-release"]).unwrap();
    assert_eq!(st.kind, EntryKind::Regular);
    assert!(st.size > 0 && st.size < 4096);
    assert_eq!(
        zfs.stat(&path, &["loader"]).unwrap().kind,
        EntryKind::Directory
    );
    assert!(zfs.exists(&path, &["big.bin"]).unwrap());
    assert!(!zfs.exists(&path, &["no-such-file"]).unwrap());

    // read_at: a window in the middle of big.bin matches the full read.
    let full = zfs.read(&path, &["big.bin"]).unwrap();
    let window = zfs.read_at(&path, &["big.bin"], 4096, 256).unwrap();
    assert_eq!(window, &full[4096..4096 + 256]);
    // A read past EOF clamps to empty.
    assert!(zfs
        .read_at(&path, &["big.bin"], full.len() as u64 + 10, 16)
        .unwrap()
        .is_empty());
}

#[test]
fn peek_pool_id_groups_members() {
    // Every member of the mirror reports the same pool identity, without import.
    let fx = fixture("mirror_lz4");
    let want_guid = guid_of(&fx);
    let want_name = fx["pool"].as_str().unwrap();
    for m in fx["members"].as_array().unwrap() {
        let img = decompress(m.as_str().unwrap());
        let device_size_bytes = img.len() as u64;
        let mut member = PoolMember {
            reader: Mem(img),
            device_size_bytes,
        };
        let id = lamzfs::peek_pool_id(&mut member).expect("peek pool id");
        assert_eq!(id.guid, want_guid);
        assert_eq!(id.name, want_name);
    }
}

#[test]
fn single_lz4_enumerates_datasets() {
    let (mut zfs, _fx) = import("single_lz4");
    // Pool layout: lamzt_single_lz4 (root) / BOOT / BOOT/test.
    let all = zfs.datasets().unwrap();
    assert!(all.contains(&Vec::<String>::new()), "root dataset present");
    assert!(
        all.iter().any(|d| d == &["BOOT"]),
        "BOOT dataset present, got {all:?}"
    );
    assert!(
        all.iter().any(|d| d == &["BOOT", "test"]),
        "BOOT/test dataset present, got {all:?}"
    );
    // No internal ($ORIGIN/$MOS) datasets leak through.
    assert!(
        all.iter().all(|d| d.iter().all(|c| !c.starts_with('$'))),
        "no internal datasets, got {all:?}"
    );
    // Immediate children of the root include BOOT (and only real datasets).
    let kids = zfs.child_datasets(&[]).unwrap();
    assert!(
        kids.contains(&"BOOT".to_string()),
        "root child BOOT, got {kids:?}"
    );
}

/// Every file in the MANIFEST reads back byte-for-byte against its kernel-
/// produced SHA-256 — the headline oracle: contiguous, multi-block (big.bin),
/// nested (loader/entries/test.conf), and holey (sparse) files.
fn assert_files_byte_exact(name: &str) {
    let (mut zfs, fx) = import(name);
    let owned = dataset_path(&fx);
    let ds: Vec<&str> = owned.iter().map(String::as_str).collect();
    let mut checked = 0;
    for f in fx["files"].as_array().unwrap() {
        let path = f["path"].as_str().unwrap();
        let want = f["sha256"].as_str().unwrap();
        let comps: Vec<&str> = path.trim_start_matches('/').split('/').collect();
        let data = zfs
            .read(&ds, &comps)
            .unwrap_or_else(|e| panic!("read {path}: {e:?}"));
        assert_eq!(sha256_hex(&data), want, "content mismatch for {path}");
        checked += 1;
    }
    assert!(checked >= 5, "expected >= 5 files, checked {checked}");
}

#[test]
fn single_lz4_files_read_byte_exact() {
    assert_files_byte_exact("single_lz4");
}

#[test]
fn single_off_files_read_byte_exact() {
    assert_files_byte_exact("single_off");
}

#[test]
fn single_gzip_files_read_byte_exact() {
    assert_files_byte_exact("single_gzip");
}

#[test]
fn single_lzjb_files_read_byte_exact() {
    assert_files_byte_exact("single_lzjb");
}

#[test]
fn single_zstd_files_read_byte_exact() {
    assert_files_byte_exact("single_zstd");
}

#[test]
fn mirror_lz4_files_read_byte_exact() {
    assert_files_byte_exact("mirror_lz4");
}

#[test]
fn raidz1_imports_all_members() {
    let (zfs, fx) = import("raidz1_lz4");
    assert_eq!(zfs.pool_guid(), guid_of(&fx));
    assert_eq!(zfs.member_count(), 3);
}

#[test]
fn raidz1_lz4_files_read_byte_exact() {
    assert_files_byte_exact("raidz1_lz4");
}

/// Drop one of the three raidz1 members (a failed disk) and confirm every file
/// still reads back byte-exact — parity reconstructs the missing column.
#[test]
fn raidz1_degraded_reconstructs() {
    let fx = fixture("raidz1_lz4");
    let members: Vec<PoolMember<Mem>> = fx["members"]
        .as_array()
        .unwrap()
        .iter()
        .take(2) // only 2 of 3 columns provided
        .map(|m| {
            let img = decompress(m.as_str().unwrap());
            let device_size_bytes = img.len() as u64;
            PoolMember {
                reader: Mem(img),
                device_size_bytes,
            }
        })
        .collect();
    let mut zfs = Zfs::import(members).expect("import degraded raidz1");
    assert_eq!(zfs.member_count(), 2);
    let owned = dataset_path(&fx);
    let ds: Vec<&str> = owned.iter().map(String::as_str).collect();
    for f in fx["files"].as_array().unwrap() {
        let path = f["path"].as_str().unwrap();
        let want = f["sha256"].as_str().unwrap();
        let comps: Vec<&str> = path.trim_start_matches('/').split('/').collect();
        let data = zfs
            .read(&ds, &comps)
            .unwrap_or_else(|e| panic!("degraded read {path}: {e:?}"));
        assert_eq!(
            sha256_hex(&data),
            want,
            "degraded reconstruct mismatch for {path}"
        );
    }
}
