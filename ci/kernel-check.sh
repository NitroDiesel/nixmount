#!/usr/bin/env bash
# Has the Linux kernel read back what the engines wrote, then produces a genuinely dirty
# journal for the replay test. $1 is the oracle output directory.
set -euo pipefail
out=$1
mnt=$(mktemp -d)

for expected in "$out"/*.expected; do
  tag=$(basename "$expected" .expected)
  img="$out/$tag.img"
  fstype=ext4
  [[ $tag == btrfs* ]] && fstype=btrfs
  sudo mount -o loop,ro -t "$fstype" "$img" "$mnt"
  # The kernel's view must match the model exactly.
  sudo diff -r --no-dereference --exclude=lost+found "$mnt" "$expected"
  sudo umount "$mnt"
  echo "kernel agrees: $tag"
done

# A snapshot of a mounted, synced ext4 has committed but unchecked-pointed transactions.
img="$out/dirty-src.img"
truncate -s 96M "$img"
mke2fs -q -F -t ext4 -J size=8 "$img"
sudo mount -o loop,commit=1 "$img" "$mnt"
sudo mkdir "$mnt/journaled"
for i in $(seq 1 200); do sudo sh -c "echo file-$i > '$mnt/journaled/f$i'"; done
sync
sudo cp "$img" "$out/dirty.img"
sudo umount "$mnt"
sudo chown "$(id -u)" "$out/dirty.img"
