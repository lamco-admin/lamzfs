#!/usr/bin/env bash
# Regenerate the installer-shaped lamzfs fixtures (tests/installer.rs).
#
# regen.sh builds the original seven pools, all with compatibility=grub2. These
# are shaped like the pools installers actually create, plus the layouts lamzfs
# must refuse rather than misread. OpenZFS writes every pool through the kernel
# module, so the kernel is the oracle: Each readable fixture records the SHA-256
# of every file as the kernel wrote it, and each refused one names the token
# lamzfs must return.
#
# Requires: OpenZFS with the kernel module loaded (zpool/zfs/zdb), sudo, zstd,
# sha256sum, python3 and setfacl. Usage: ./regen-installer.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d /var/tmp/lamzfs-installer.XXXXXX)"
ALTROOT="$WORK/mnt"
mkdir -p "$ALTROOT"
GANG=/sys/module/zfs/parameters/metaslab_force_ganging
GANG_PCT=/sys/module/zfs/parameters/metaslab_force_ganging_pct
GANG_OLD="$(cat "$GANG")"
GANG_PCT_OLD="$(cat "$GANG_PCT")"
cleanup() {
  cd /
  echo "$GANG_OLD" | sudo tee "$GANG" >/dev/null
  echo "$GANG_PCT_OLD" | sudo tee "$GANG_PCT" >/dev/null
  for p in $(sudo zpool list -H -o name 2>/dev/null | grep '^lamzi_'); do
    sudo zpool destroy -f "$p" 2>/dev/null || true
  done
  sudo rm -rf "$WORK"
}
trap cleanup EXIT

MANIFEST="$HERE/INSTALLER-MANIFEST.json"
ENTRIES=()

# The catalog every fixture carries, written under the mounted dataset $1.
# The files whose hashes are recorded are listed in $WORK/$2.list.
populate() {
  local root="$1" name="$2"
  sudo mkdir -p "$root/loader/entries" "$root/grub"
  sudo chmod -R 0777 "$root"
  head -c 9000 /dev/urandom > "$root/vmlinuz-6.12.0-test"
  python3 -c "import sys;sys.stdout.buffer.write(b'INITRAMFS-COMPRESSIBLE-PADDING-0123456789 '*6242)" > "$root/initrd.img-6.12.0-test"
  printf 'title Test\nlinux /vmlinuz-6.12.0-test\ninitrd /initrd.img-6.12.0-test\n' > "$root/loader/entries/test.conf"
  head -c 393216 /dev/urandom > "$root/big.bin"
  ln -s vmlinuz-6.12.0-test "$root/vmlinuz"
  truncate -s 65536 "$root/holey"
  printf 'TAIL' >> "$root/holey"
  printf 'set default=0\n' > "$root/grub/grub.cfg"
  printf '%s\n' vmlinuz-6.12.0-test initrd.img-6.12.0-test loader/entries/test.conf big.bin holey grub/grub.cfg > "$WORK/$name.list"
}

add_file() { echo "$2" >> "$WORK/$1.list"; }

# filler <bytes> <file>: one random 128 KiB chunk repeated. lz4's 64 KiB
# window can't compress it, so ZFS writes full-size blocks, while zstd -19
# shrinks the stored image to a fraction.
filler() {
  python3 -c "import os,sys; c=os.urandom(131072); n=int(sys.argv[1]); sys.stdout.buffer.write((c*(n//131072+1))[:n])" "$1" > "$2"
}

# hash_files <root> <name> [prefix]: the manifest path is the dataset path,
# so files under a subdirectory of the dataset carry it as a prefix.
hash_files() {
  local root="$1" name="$2" prefix="${3:-}" f
  sync
  : > "$WORK/$name.hashes"
  while IFS= read -r f; do
    printf '%s\t%s\n' "$prefix$f" "$(sha256sum "$root/$f" | cut -d' ' -f1)" >> "$WORK/$name.hashes"
  done < "$WORK/$name.list"
}

# make_images <n> <size>: create n sparse member images and print their paths.
make_images() {
  local n="$1" size="$2" i
  for i in $(seq 0 $((n - 1))); do
    rm -f "$WORK/m$i.img"
    truncate -s "$size" "$WORK/m$i.img"
    echo "$WORK/m$i.img"
  done
}

# record <name> <pool> <dataset> <expect> <image...>: store each exported
# member image zstd-compressed and add the manifest entry. The caller has
# exported the pool and noted its guid in $GUID.
record() {
  local name="$1" pool="$2" dataset="$3" expect="$4"; shift 4
  local members="" idx=0 img
  for img in "$@"; do
    zstd -q -19 -f "$img" -o "$HERE/${name}.${idx}.img.zst"
    [ -n "$members" ] && members+=","
    members+="\"${name}.${idx}.img.zst\""
    idx=$((idx + 1))
  done
  local files=""
  if [ -f "$WORK/$name.hashes" ]; then
    while IFS=$'\t' read -r path sha; do
      [ -n "$files" ] && files+=","
      files+="{\"path\":\"/$path\",\"sha256\":\"$sha\"}"
    done < "$WORK/$name.hashes"
  fi
  ENTRIES+=("$(printf '{"name":"%s","pool":"%s","guid":"%s","dataset":"%s","expect":"%s","members":[%s],"files":[%s]}' \
    "$name" "$pool" "$GUID" "$dataset" "$expect" "$members" "$files")")
  echo "built $name: expect=$expect guid=$GUID"
}

export_and_record() {
  local name="$1" pool="$2"
  GUID="$(sudo zpool get -H -o value guid "$pool")"
  sudo zpool export "$pool"
  record "$@"
}

# Proxmox VE's installer: zpool create with no compatibility property (every
# feature enabled), compression=on (lz4), acltype=posix on the root dataset,
# legacy dnodes. A 1 MiB recordsize on /boot makes large_blocks active too.
build_proxmox() {
  local name=proxmox_rpool pool=lamzi_pve
  mapfile -t imgs < <(make_images 1 192M)
  sudo zpool create -f -o cachefile=none -o ashift=12 -R "$ALTROOT" -O mountpoint=none "$pool" "${imgs[@]}"
  sudo zfs set compression=on "$pool"
  sudo zfs create -o mountpoint=none "$pool/ROOT"
  sudo zfs create -o mountpoint=/ -o acltype=posix "$pool/ROOT/pve-1"
  sudo zfs create -o mountpoint=/boot -o recordsize=1M "$pool/ROOT/pve-1/boot"
  local root="$ALTROOT/boot"
  populate "$root" "$name"
  filler 3145728 "$root/large-record.bin"
  add_file "$name" large-record.bin
  hash_files "$root" "$name"
  export_and_record "$name" "$pool" "ROOT/pve-1/boot" read "${imgs[@]}"
}

# Ubuntu's installer (subiquity): rpool with every default feature plus
# dnodesize=auto, xattr=sa, acltype=posixacl and normalization=formD. Files
# with POSIX ACLs and user xattrs carry SA bonuses too big for a 512-byte
# dnode, so they live in large dnodes; bigdir is a fat ZAP.
build_ubuntu_rpool() {
  local name=ubuntu_rpool pool=lamzi_rpool
  mapfile -t imgs < <(make_images 1 192M)
  sudo zpool create -f -o cachefile=none -o ashift=12 -o autotrim=on -R "$ALTROOT" \
    -O acltype=posixacl -O xattr=sa -O dnodesize=auto -O normalization=formD \
    -O relatime=on -O compression=lz4 -O canmount=off -O mountpoint=/ "$pool" "${imgs[@]}"
  sudo zfs create -o canmount=off -o mountpoint=none "$pool/ROOT"
  sudo zfs create -o mountpoint=/ "$pool/ROOT/ubuntu"
  local root="$ALTROOT/boot"
  sudo mkdir -p "$root"
  populate "$root" "$name"
  local i u acl
  for i in 1 2 3; do
    printf 'acl file %s\n' "$i" > "$root/acl$i.conf"
    acl="u:1001:rwx"
    for u in $(seq 1002 1012); do acl+=",u:$u:r-x"; done
    sudo setfacl -m "$acl" "$root/acl$i.conf"
    python3 -c "import os,sys; os.setxattr(sys.argv[1], 'user.lamzfs', b'x' * 240)" "$root/acl$i.conf"
    add_file "$name" "acl$i.conf"
  done
  printf 'accented name\n' > "$root/café.conf"
  add_file "$name" "café.conf"
  mkdir -p "$root/bigdir"
  for i in $(seq 1 2000); do printf '%s\n' "$i" > "$root/bigdir/entry-$i"; done
  add_file "$name" bigdir/entry-1777
  hash_files "$root" "$name" boot/
  export_and_record "$name" "$pool" "ROOT/ubuntu" read "${imgs[@]}"
  echo "ubuntu_rpool objects by dnode size (zdb -dd, column 6):"
  sudo /usr/sbin/zdb -e -p "$WORK" -dd "$pool/ROOT/ubuntu" 2>&1 | awk '$1 ~ /^[0-9]+$/ && NF >= 8 {print $6}' | sort | uniq -c
}

# Ubuntu's bpool: default features off and exactly the eleven subiquity
# enables, legacy dnodes, the rpool's dataset properties.
build_ubuntu_bpool() {
  local name=ubuntu_bpool pool=lamzi_bpool
  mapfile -t imgs < <(make_images 1 128M)
  local feats=() f
  for f in async_destroy bookmarks embedded_data empty_bpobj enabled_txg extensible_dataset \
           filesystem_limits hole_birth large_blocks lz4_compress spacemap_histogram; do
    feats+=(-o "feature@$f=enabled")
  done
  sudo zpool create -f -o cachefile=none -o ashift=12 -o autotrim=on -d "${feats[@]}" -R "$ALTROOT" \
    -O acltype=posixacl -O xattr=sa -O normalization=formD -O relatime=on -O compression=lz4 \
    -O devices=off -O canmount=off -O mountpoint=/boot "$pool" "${imgs[@]}"
  sudo zfs create -o canmount=off -o mountpoint=none "$pool/BOOT"
  sudo zfs create -o mountpoint=/boot "$pool/BOOT/ubuntu"
  local root="$ALTROOT/boot"
  populate "$root" "$name"
  hash_files "$root" "$name"
  export_and_record "$name" "$pool" "BOOT/ubuntu" read "${imgs[@]}"
}

# A dataset that checksums with SHA-512 (the sha512 feature becomes active).
build_sha512() {
  local name=sha512_boot pool=lamzi_sha512
  mapfile -t imgs < <(make_images 1 128M)
  sudo zpool create -f -o cachefile=none -o ashift=12 -R "$ALTROOT" -O mountpoint=none "$pool" "${imgs[@]}"
  sudo zfs create -o mountpoint=/boot -o checksum=sha512 -o compression=lz4 "$pool/boot"
  local root="$ALTROOT/boot"
  populate "$root" "$name"
  hash_files "$root" "$name"
  export_and_record "$name" "$pool" boot read "${imgs[@]}"
}

# A mirror whose member 0 missed the last writes. Member 0's image is set
# aside after the first export, the pool is imported from member 1 alone and
# written to, and then both images are recorded. The newest uberblock is only
# on member 1.
build_mirror_stale() {
  local name=mirror_stale pool=lamzi_mstale
  mapfile -t imgs < <(make_images 2 128M)
  sudo zpool create -f -o cachefile=none -o ashift=12 -R "$ALTROOT" -O mountpoint=none "$pool" mirror "${imgs[@]}"
  sudo zfs create -o mountpoint=/boot -o compression=lz4 "$pool/boot"
  local root="$ALTROOT/boot"
  populate "$root" "$name"
  sync
  sudo zpool export "$pool"
  mv "${imgs[0]}" "$WORK/hold0.img"
  mkdir -p "$WORK/only1"
  ln -s "${imgs[1]}" "$WORK/only1/m1.img"
  sudo zpool import -o cachefile=none -R "$ALTROOT" -d "$WORK/only1" "$pool"
  printf 'written after member 0 went stale\n' > "$root/late.conf"
  head -c 200000 /dev/urandom > "$root/late.bin"
  add_file "$name" late.conf
  add_file "$name" late.bin
  hash_files "$root" "$name"
  GUID="$(sudo zpool get -H -o value guid "$pool")"
  sudo zpool export "$pool"
  mv "$WORK/hold0.img" "${imgs[0]}"
  record "$name" "$pool" boot read "${imgs[@]}"
}

# Gang blocks: The kernel is told to gang every block of 256 KiB or more, and
# a 1 MiB-record file is written. Import works; reading that file refuses.
build_gang() {
  local name=gang_blocks pool=lamzi_gang
  mapfile -t imgs < <(make_images 1 128M)
  sudo zpool create -f -o cachefile=none -o ashift=12 -R "$ALTROOT" -O mountpoint=none "$pool" "${imgs[@]}"
  sudo zfs create -o mountpoint=/boot -o compression=off -o recordsize=1M "$pool/boot"
  local root="$ALTROOT/boot"
  populate "$root" "$name"
  hash_files "$root" "$name"
  sudo zpool sync "$pool"
  echo 262144 | sudo tee "$GANG" >/dev/null
  echo 100 | sudo tee "$GANG_PCT" >/dev/null
  filler 2097152 "$root/ganged.bin"
  sync
  sudo zpool sync "$pool"
  echo "$GANG_OLD" | sudo tee "$GANG" >/dev/null
  echo "$GANG_PCT_OLD" | sudo tee "$GANG_PCT" >/dev/null
  export_and_record "$name" "$pool" boot read "${imgs[@]}"
  echo "gang_blocks: zdb -ddddd lines mentioning gang:"
  sudo /usr/sbin/zdb -e -p "$WORK" -ddddd "$pool/boot" 2>&1 | grep -ci gang || true
}

# Two top-level vdevs (a stripe, Proxmox's RAID0): DVAs name vdev 0 or 1.
build_stripe() {
  local name=refuse_stripe pool=lamzi_stripe
  mapfile -t imgs < <(make_images 2 128M)
  sudo zpool create -f -o cachefile=none -o ashift=12 -R "$ALTROOT" -O mountpoint=none "$pool" "${imgs[@]}"
  sudo zfs create -o mountpoint=/boot "$pool/boot"
  populate "$ALTROOT/boot" "$name"
  filler 8388608 "$ALTROOT/boot/spread.bin"
  export_and_record "$name" "$pool" boot "refuse:topo_multi_toplevel" "${imgs[@]}"
}

# A raidz1 expanded from three disks to four (raidz_expansion active).
build_raidz_expanded() {
  local name=refuse_raidz_expanded pool=lamzi_rzx
  mapfile -t imgs < <(make_images 4 128M)
  sudo zpool create -f -o cachefile=none -o ashift=12 -R "$ALTROOT" -O mountpoint=none "$pool" raidz1 "${imgs[@]:0:3}"
  sudo zfs create -o mountpoint=/boot "$pool/boot"
  populate "$ALTROOT/boot" "$name"
  sync
  sudo zpool attach "$pool" raidz1-0 "${imgs[3]}"
  sudo zpool wait -t raidz_expand "$pool"
  sudo zpool status "$pool" | grep -iE "expan|raidz" || true
  export_and_record "$name" "$pool" boot "refuse:raidz_expansion" "${imgs[@]}"
}

# A name longer than 255 bytes (longname active).
build_longname() {
  local name=refuse_longname pool=lamzi_long
  mapfile -t imgs < <(make_images 1 128M)
  sudo zpool create -f -o cachefile=none -o ashift=12 -R "$ALTROOT" -O mountpoint=none "$pool" "${imgs[@]}"
  sudo zfs create -o mountpoint=/boot -o longname=on "$pool/boot"
  populate "$ALTROOT/boot" "$name"
  touch "$ALTROOT/boot/$(python3 -c "print('n'*300)")"
  export_and_record "$name" "$pool" boot "refuse:longname" "${imgs[@]}"
}

# An unencrypted /boot dataset beside an encrypted one (encryption active).
# /boot reads; the encrypted dataset is refused block by block.
build_encrypted() {
  local name=encrypted_sibling pool=lamzi_enc
  mapfile -t imgs < <(make_images 1 128M)
  printf 'lamzfs-fixture-passphrase\n' > "$WORK/key"
  sudo zpool create -f -o cachefile=none -o ashift=12 -R "$ALTROOT" -O mountpoint=none "$pool" "${imgs[@]}"
  sudo zfs create -o mountpoint=/boot "$pool/boot"
  populate "$ALTROOT/boot" "$name"
  hash_files "$ALTROOT/boot" "$name"
  sudo zfs create -o mountpoint=/secret -o encryption=on -o keyformat=passphrase \
    -o keylocation="file://$WORK/key" "$pool/secret"
  echo secret | sudo tee "$ALTROOT/secret/s.txt" >/dev/null
  export_and_record "$name" "$pool" boot read "${imgs[@]}"
}

for b in ${ONLY:-proxmox ubuntu_rpool ubuntu_bpool sha512 mirror_stale gang stripe raidz_expanded longname encrypted}; do
  "build_$b"
done

# With ONLY set, the other fixtures' entries already in the manifest stay.
printf '%s\n' "${ENTRIES[@]}" | python3 -c '
import json, os, sys
path = sys.argv[1]
new = [json.loads(line) for line in sys.stdin if line.strip()]
names = {f["name"] for f in new}
old = []
if os.environ.get("ONLY") and os.path.exists(path):
    old = [f for f in json.load(open(path))["fixtures"] if f["name"] not in names]
with open(path, "w") as out:
    out.write("{ \"fixtures\": [\n")
    out.write(",\n".join(json.dumps(f, separators=(",", ":"), ensure_ascii=False) for f in old + new))
    out.write("\n]}\n")
' "$MANIFEST"
echo "MANIFEST written: $MANIFEST"
