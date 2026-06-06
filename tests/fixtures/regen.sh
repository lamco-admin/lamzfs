#!/usr/bin/env bash
# Regenerate the lamzfs oracle fixtures (SPEC-LAMZFS §6.2).
#
# Builds real ZFS pools with OpenZFS `zpool`/`zfs` (the kernel is the oracle),
# populates a fixed catalog, exports, and captures each member device image as
# a zstd-compressed blob plus a MANIFEST.json recording per-file SHA-256 and the
# pool/dataset/topology. The host reader must reproduce every hash byte-for-byte.
#
# Requires: OpenZFS (zpool/zfs), sudo, zstd, sha256sum, python3, jq-free.
# Usage:    sudo ./regen.sh    (run from tests/fixtures/)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
ALTROOT="$WORK/mnt"
mkdir -p "$ALTROOT"
trap 'cd /; for p in $(zpool list -H -o name 2>/dev/null | grep "^lamzt_"); do zpool destroy -f "$p" 2>/dev/null || true; done; rm -rf "$WORK"' EXIT

MANIFEST="$HERE/MANIFEST.json"
echo '{ "fixtures": [' > "$MANIFEST"
FIRST=1

# Populate a fixed catalog into the dataset mounted at $1; echo "path\tsha256"
# lines for each regular file into $2.
populate() {
  local root="$1" hashfile="$2"
  mkdir -p "$root/loader/entries" "$root/EFI" "$root/empty.d"
  # a small "kernel", a >1-block compressible initramfs, os-release, a BLS entry,
  # a multi-block binary (indirect blocks), a symlink, and a holey file.
  head -c 4096 /dev/urandom > "$root/vmlinuz-6.1.0-test"
  python3 -c "import sys;sys.stdout.buffer.write(b'INITRAMFS-COMPRESSIBLE-PADDING-0123456789 '*6242)" > "$root/initrd.img-6.1.0-test"
  printf 'NAME="lamzfs-fixture"\nVERSION_ID="1"\n' > "$root/os-release"
  printf 'title Test\nlinux /vmlinuz-6.1.0-test\ninitrd /initrd.img-6.1.0-test\n' > "$root/loader/entries/test.conf"
  head -c 262144 /dev/urandom > "$root/big.bin"
  ln -s vmlinuz-6.1.0-test "$root/vmlinuz"
  # holey file: 64 KiB hole then a tail.
  truncate -s 65536 "$root/holey"
  printf 'TAIL' >> "$root/holey"
  sync
  : > "$hashfile"
  ( cd "$root" && for f in vmlinuz-6.1.0-test initrd.img-6.1.0-test os-release loader/entries/test.conf big.bin holey; do
      printf '%s\t%s\n' "$f" "$(sha256sum "$f" | cut -d" " -f1)" >> "$hashfile"
    done )
}

# build_fixture <name> <compression> <vdev-spec...>
# vdev-spec is passed to `zpool create` (e.g. "single img0" / "mirror img0 img1"
# / "raidz1 img0 img1 img2"). Captures every member image listed after the type.
build_fixture() {
  local name="$1" comp="$2" topo="$3"; shift 3
  local imgs=("$@") pool="lamzt_${name}"
  local paths=()
  for i in "${imgs[@]}"; do
    truncate -s 256M "$WORK/$i.img"
    paths+=("$WORK/$i.img")
  done

  local createspec="$topo"
  [ "$topo" = "single" ] && createspec=""
  # grub2 compat models a real bpool; zstd_compress is outside it, so the zstd
  # codec-coverage fixture omits the restriction (COMPAT=none).
  local compatarg=""
  [ "${COMPAT:-grub2}" != "none" ] && compatarg="-o compatibility=${COMPAT:-grub2}"
  # shellcheck disable=SC2086
  sudo zpool create -f -o ashift=12 $compatarg \
      -O mountpoint=none -O compression="$comp" -R "$ALTROOT" \
      "$pool" $createspec "${paths[@]}"
  sudo zfs create -o mountpoint=none "$pool/BOOT"
  sudo zfs create -o mountpoint=/boot "$pool/BOOT/test"
  local ds_mnt="$ALTROOT/boot"
  sudo chmod 0777 "$ds_mnt"
  populate "$ds_mnt" "$WORK/$name.hashes"
  local guid; guid="$(sudo zpool get -H -o value guid "$pool")"
  sudo zpool export "$pool"

  # Capture each member image, zstd-compressed.
  local members_json=""
  local idx=0
  for i in "${imgs[@]}"; do
    zstd -q -19 -f "$WORK/$i.img" -o "$HERE/${name}.${idx}.img.zst"
    [ -n "$members_json" ] && members_json+=","
    members_json+="\"${name}.${idx}.img.zst\""
    idx=$((idx+1))
  done

  # Emit MANIFEST entry.
  local files_json=""
  while IFS=$'\t' read -r path sha; do
    [ -n "$files_json" ] && files_json+=","
    files_json+="{\"path\":\"/$path\",\"sha256\":\"$sha\"}"
  done < "$WORK/$name.hashes"
  [ "$FIRST" -eq 1 ] || echo "," >> "$MANIFEST"
  FIRST=0
  printf '{"name":"%s","pool":"%s","guid":"%s","dataset":"%s/BOOT/test","topology":"%s","compression":"%s","members":[%s],"files":[%s]}' \
    "$name" "$pool" "$guid" "$pool" "$topo" "$comp" "$members_json" "$files_json" >> "$MANIFEST"
  echo "built fixture: $name ($topo, $comp) guid=$guid"
}

build_fixture single_lz4   lz4   single img0
build_fixture single_off   off   single img0
build_fixture single_gzip  gzip  single img0
build_fixture single_lzjb  lzjb  single img0
COMPAT=none build_fixture single_zstd zstd single img0
build_fixture mirror_lz4   lz4   mirror img0 img1
build_fixture raidz1_lz4   lz4   raidz1 img0 img1 img2

echo ']}' >> "$MANIFEST"
echo "MANIFEST written: $MANIFEST"
ls -la "$HERE"/*.img.zst
