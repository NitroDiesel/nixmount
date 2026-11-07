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

# Compressed extents written by the kernel, in every codec.
for codec in zlib lzo zstd; do
  img="$out/kernel-$codec.image"
  src="$out/kernel-$codec.src"
  truncate -s 512M "$img"
  mkfs.btrfs -q -f "$img"
  mkdir -p "$src/sub"
  head -c 3000000 < <(yes "the quick brown fox jumps over the lazy dog") > "$src/text.txt"
  head -c 2000000 /dev/urandom > "$src/random.bin"
  { head -c 200000 /dev/urandom; head -c 200000 < <(yes abcdefgh); } > "$src/sub/mixed.bin"
  echo tiny > "$src/tiny.txt"
  sudo mount -o "loop,compress-force=$codec" "$img" "$mnt"
  sudo cp -r "$src/." "$mnt/"
  sync
  sudo umount "$mnt"
done

# Snapshots with real shared trees, deep enough that interior nodes are shared.
img="$out/kernel-snap.image"
src="$out/kernel-snap.src"
truncate -s 1G "$img"
mkfs.btrfs -q -f "$img"
mkdir -p "$src"
for i in $(seq 0 3999); do printf -v n 'f%04d' "$i"; echo "content $i" > "$src/$n"; done
sudo mount -o loop "$img" "$mnt"
sudo cp -r "$src/." "$mnt/"
sudo btrfs subvolume snapshot "$mnt" "$mnt/snap" > /dev/null
sudo btrfs subvolume snapshot -r "$mnt" "$mnt/frozen" > /dev/null
sync
sudo umount "$mnt"
sudo chown "$(id -u)" "$out"/kernel-*.image

# RAID5: the engine reads it, and must also read it with any one device missing.
src="$out/kernel-raid5.src"
imgs=()
for i in 0 1 2; do imgs+=("$out/kernel-raid5.$i.image"); truncate -s 512M "${imgs[$i]}"; done
mkfs.btrfs -q -f -d raid5 -m raid1 "${imgs[@]}"
mkdir -p "$src"
head -c 5000000 /dev/urandom > "$src/random.bin"
for i in $(seq 1 200); do echo "file $i" > "$src/f$i"; done
sudo btrfs device scan "${imgs[@]}" 2>/dev/null || true
loops=()
for f in "${imgs[@]}"; do loops+=("$(sudo losetup -f --show "$f")"); done
sudo btrfs device scan "${loops[@]}" > /dev/null
sudo mount "${loops[0]}" "$mnt"
sudo cp -r "$src/." "$mnt/"
sync
sudo umount "$mnt"
sudo losetup -d "${loops[@]}"
sudo chown "$(id -u)" "$out"/kernel-*.image
