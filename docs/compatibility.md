# Compatibility

The rule behind these tables: a volume is writable only if every feature it uses is fully
supported. Otherwise it mounts read-only and says why. Causeway never ignores a feature to get
write access.

## ext2, ext3, ext4

| Feature | Read | Write |
|---|---|---|
| Extents, indirect block maps | Yes | Yes |
| `64bit`, `flex_bg`, `meta_bg`, `sparse_super`, `huge_file`, `large_file` | Yes | Yes |
| `metadata_csum`, `metadata_csum_seed`, `uninit_bg` | Yes | Yes |
| `dir_index` hashed directories, `large_dir` | Yes | Yes |
| Internal journal (`has_journal`), all checksum versions | Yes, with replay | Yes, every change is journaled |
| `orphan_file` | Yes | Yes, when empty |
| Hard links, symbolic links | Yes | Yes (hard links from Linux; see below) |
| Extended attributes | Stored values are kept | Not settable from Windows |
| `inline_data` | Yes | Read-only |
| `bigalloc` | Yes | Read-only |
| `ea_inode` | Yes | Read-only |
| `casefold` | Yes | Read-only |
| `quota`, `project` | Yes | Read-only: accounting would go stale |
| `verity`, `shared_blocks`, `sparse_super2`, `fast_commit` | Yes | Read-only |
| `mmp` | Yes | Read-only |
| `encrypt` | Listing only: file contents stay encrypted | Read-only |
| External journal | Yes, if already clean | Read-only |

Ext4Fsd could not mount `inline_data`, `ea_inode`, `casefold`, `encrypt`, `mmp` or `large_dir`
volumes at all, and did not journal its writes.

## Btrfs

| Feature | Read | Write |
|---|---|---|
| Single, DUP, RAID0, RAID1, RAID10, RAID1C3, RAID1C4 | Yes | Yes |
| RAID5, RAID6 | Yes, including with a device missing | Read-only |
| CRC32C, xxHash, SHA-256, BLAKE2 checksums | Verified on every read | Yes |
| zlib, LZO, Zstandard compression | Yes | New data is stored uncompressed |
| Subvolumes, snapshots | Yes | Create, snapshot, delete |
| Free space tree, block group tree, `no_holes`, `skinny_metadata` | Yes | Yes |
| Older layouts: v1 space cache, explicit holes | Yes | Yes |
| Multi-device filesystems | Yes | Yes |
| Degraded (a device missing) | Yes | Read-only |
| Pending tree log after a crash | The log is ignored | Read-only until Linux replays it |
| Quotas | Yes | Read-only: accounting would go stale |
| `mixed_groups`, simple quotas, verity | Yes | Read-only |
| Zoned, `extent_tree_v2`, RAID stripe tree | Not mountable | |

Deleting a subvolume unlinks it at once. Its blocks are freed the next time Linux mounts the
volume read-write.

## What changed from the original programs

Replaced by something better:

| Original | Causeway |
|---|---|
| Kernel drivers | User-mode engines on WinFsp |
| 54,000 lines of code page tables | One call into Windows for `--codepage` |
| `Ext2Mgr`, `Ext2Srv`, `shellbtrfs.dll`, `mkbtrfs.exe` and two drivers | One executable |
| Registry-based mount settings | Saved per volume by UUID |
| Dead drive letter cleanup | Not needed: letters are removed with the mount |
| Tray icon and manager autostart | Not needed: the service does this |

Removed on purpose:

- **Change partition type** (Ext2Mgr). It could destroy access to a volume and isn't needed to
  mount one.
- **Force writing on ext3** (Ext4Fsd). Writing past a safety check is how volumes get damaged.

Not implemented yet. For these, use Linux or the original tools:

- Formatting (`mkbtrfs`), resizing, balance, adding and removing devices
- Btrfs send and receive, reflink copy, defragmentation
- Writing compressed Btrfs data, and writing to RAID5 and RAID6
- Creating hard links from Windows: WinFsp has no operation for this. Hard links made on Linux
  work normally, including deleting and renaming them.
- Extended attributes as NTFS alternate data streams, per-file ACLs, and uid-to-SID mapping
- WSL (LXSS) metadata, booting Windows from Btrfs, and the Explorer shell extension
- Mounting at a folder instead of a drive letter
