#!/usr/bin/env bash
# Regenerates tests/fixtures: small, real images from mke2fs and mkfs.btrfs, kept in the
# repository so the corruption tests run on any platform. $1 is the output directory.
set -euo pipefail
out=$1
mkdir -p "$out"
src=$(mktemp -d)
mkdir -p "$src/docs/nested" "$src/wide"
echo "hello from linux" > "$src/hello.txt"
head -c 200000 /dev/zero | tr '\0' 'x' > "$src/docs/nested/large.txt"
for i in $(seq 1 300); do echo "$i" > "$src/wide/file-$i"; done
ln -s hello.txt "$src/link"

ext() {
  local name=$1
  shift
  truncate -s 16M "$out/$name.img"
  mke2fs -q -F -d "$src" "$@" "$out/$name.img"
  gzip -9f "$out/$name.img"
}
ext ext4-default -t ext4 -J size=4
ext ext4-1k-nocsum -t ext4 -b 1024 -O '^metadata_csum,^64bit,uninit_bg' -J size=1
ext ext4-inline -t ext4 -O inline_data -J size=4
ext ext3-1k -t ext3 -b 1024 -J size=1
ext ext2-2k -t ext2 -b 2048

truncate -s 128M "$out/btrfs-default.img"
mkfs.btrfs -q -f --rootdir "$src" "$out/btrfs-default.img"
gzip -9f "$out/btrfs-default.img"
ls -la "$out"
