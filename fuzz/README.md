# lamzfs fuzz targets

Coverage-guided fuzzing of the read path with [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz)
(libFuzzer). Every target asserts the denial-of-boot contract (SPEC-LAMZFS §2.5):
arbitrary or hostile bytes must produce a typed error, never a panic, an
out-of-bounds read, an unbounded allocation, or an unbounded loop.

## Targets

| target   | surface |
|----------|---------|
| `import` | vdev label, config nvlist (XDR), uberblock scan + checksum, MOS root |
| `walk`   | dnode indirect tree, ZAP (micro + fat), DSL walk, file read + decompress |
| `path`   | multi-member import + topology match, hostile dataset/file path resolve |

## Running

```bash
cargo +nightly fuzz run import
cargo +nightly fuzz run walk
cargo +nightly fuzz run path
```

## Seeding (important)

Random bytes almost never satisfy the label magic + nvlist + uberblock checksum,
so `import`/`walk` need a valid pool image as a seed to reach the interesting
decode and read code. Decompress a committed fixture into the corpus:

```bash
mkdir -p fuzz/corpus/import fuzz/corpus/walk
for z in tests/fixtures/single_*.0 tests/fixtures/single_*.0.img; do :; done   # (members are zstd-compressed)
# Example: seed from the single_lz4 member listed in tests/fixtures/MANIFEST.json
zstd -d -f tests/fixtures/<member-file> -o fuzz/corpus/import/single_lz4.img
cp fuzz/corpus/import/single_lz4.img fuzz/corpus/walk/
```

(The exact member filenames are in `tests/fixtures/MANIFEST.json` under each
fixture's `members` array.) The `path` target takes an `Arbitrary`-derived
struct, so it does not use raw image seeds.

## Artifacts

Crashes are written to `fuzz/artifacts/<target>/`. Reproduce with:

```bash
cargo +nightly fuzz run <target> fuzz/artifacts/<target>/<crash-file>
```
