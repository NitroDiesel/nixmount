#!/usr/bin/env bash
# LUKS against the real thing. `make` builds encrypted volumes with cryptsetup and fills them
# through the kernel; the luks crate's test then unlocks, reads and edits them; `verify` has
# Linux decrypt them again and judge what the engines wrote. Usage: luks-check.sh make|verify DIR
set -euo pipefail
mode=$1
dir=$2
mnt=$(mktemp -d)

unlock() { printf '%s\n' "$2" | sudo cryptsetup open "$dir/$1.img" "nm-$1"; }

if [[ $mode == make ]]; then
  rm -rf "$dir"
  mkdir -p "$dir/src/deep/a/b" "$dir/src/wide"
  echo "hello from linux" > "$dir/src/hello.txt"
  head -c 3000000 < <(yes "text that compresses well") > "$dir/src/text.txt"
  head -c 1000000 /dev/urandom > "$dir/src/deep/a/b/random.bin"
  for i in $(seq 1 150); do echo "file $i" > "$dir/src/wide/f$i"; done
  ln -s hello.txt "$dir/src/link"
  : > "$dir/volumes.txt"

  # volume NAME SIZE FS PASSPHRASE [luksFormat options...]
  volume() {
    local name=$1 size=$2 fs=$3 pass=$4
    shift 4
    truncate -s "$size" "$dir/$name.img"
    printf '%s' "$pass" | sudo cryptsetup luksFormat --batch-mode --key-file=- "$@" "$dir/$name.img"
    unlock "$name" "$pass"
    local dev=/dev/mapper/nm-$name opts=defaults
    if [[ $fs == ext4 ]]; then
      sudo mkfs.ext4 -q "$dev"
    else
      sudo mkfs.btrfs -q -f "$dev"
      opts=compress=zstd
    fi
    sudo mount -o "$opts" "$dev" "$mnt"
    sudo cp -r "$dir/src/." "$mnt/"
    sudo umount "$mnt"
    sudo cryptsetup close "nm-$name"
    echo "$name $fs $pass" >> "$dir/volumes.txt"
  }
  # add_key NAME PASSPHRASE NEW [luksAddKey options...]
  add_key() {
    local name=$1 pass=$2 new=$3
    shift 3
    printf '%s' "$new" > "$dir/newkey"
    printf '%s' "$pass" | sudo cryptsetup luksAddKey --batch-mode --key-file=- "$@" "$dir/$name.img" "$dir/newkey"
    rm "$dir/newkey"
    sed -i "/^$name /s/\$/ $new/" "$dir/volumes.txt"
  }

  # What installers did before LUKS2, and a second passphrase in another slot.
  volume luks1-ext4 64M ext4 first-pass --type luks1 --hash sha256 --pbkdf-force-iterations 1000
  add_key luks1-ext4 first-pass second-pass --pbkdf-force-iterations 1000
  # The defaults until 2013: CBC with ESSIV, and SHA-1.
  volume luks1-cbc-ext4 64M ext4 old-defaults --type luks1 --cipher aes-cbc-essiv:sha256 --key-size 256 \
    --hash sha1 --pbkdf-force-iterations 1000
  # Today's default layout with Btrfs and compression; small Argon2 costs keep CI quick.
  volume luks2-btrfs 256M btrfs open-sesame --type luks2 --label nixmount --pbkdf argon2id \
    --pbkdf-memory 65536 --pbkdf-parallel 2 --pbkdf-force-iterations 4
  add_key luks2-btrfs open-sesame other-slot --pbkdf argon2i --pbkdf-memory 32768 --pbkdf-force-iterations 4
  # 4096-byte encryption sectors, AES-128, PBKDF2 with SHA-512.
  volume luks2-4k-ext4 64M ext4 big-sectors --type luks2 --sector-size 4096 --key-size 256 --pbkdf pbkdf2 \
    --hash sha512 --pbkdf-force-iterations 1000
  # Nothing chosen: cryptsetup's own defaults, with key derivation tuned to this machine.
  volume luks2-default-ext4 64M ext4 just-defaults --type luks2
  sudo chown -R "$(id -u)" "$dir"
  cat "$dir/volumes.txt"
  exit 0
fi

while read -r name fs pass _; do
  unlock "$name" "$pass"
  dev=/dev/mapper/nm-$name
  if [[ $fs == ext4 ]]; then
    sudo e2fsck -fn "$dev"
  else
    sudo btrfs check --readonly --check-data-csum "$dev"
  fi
  sudo mount -o ro "$dev" "$mnt"
  sudo diff -r --no-dereference --exclude=lost+found "$mnt" "$dir/$name.expected"
  sudo umount "$mnt"
  sudo cryptsetup close "nm-$name"
  echo "Linux agrees: $name"
done < "$dir/volumes.txt"
