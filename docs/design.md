# Design

## Why user mode

Ext4Fsd and WinBtrfs are kernel drivers. That design has three costs that no amount of care
removes:

- A parser bug on a hostile or damaged disk is a kernel bug: a blue screen at best.
- New drivers need Microsoft's attestation signing to load under Secure Boot.
- Nothing about a kernel driver can be tested without a machine to crash.

NixMount keeps all filesystem logic in an ordinary process and uses [WinFsp], an existing signed
driver, to forward Windows file requests to it. The price is a process hop per request. In
exchange a panic fails one request, the engines contain no `unsafe`, and they run unchanged on
Linux, where they can be judged by real tools.

WinFsp is the only way to get this that gives a real filesystem. A driver of NixMount's own would
need attestation signing and bring back everything above. Serving a loopback WebDAV or SMB share
has no real file semantics, and WebDAV caps files at about 4 GB. ProjFS and Cloud Files don't give
a drive letter. So WinFsp's signed, unmodified installer ships inside the executable.

## Setup

`nixmount.exe` is its own installer: `install.rs` handles install, upgrade and uninstall, with the
WinFsp MSI embedded through `include_bytes!`. The MSI stays on disk in the executable and is only
paged in during setup, so it costs no memory while running. A copy kept in the program folder
marks that NixMount installed WinFsp, which is how uninstalling knows whether to remove it.

To update WinFsp, replace `app/res/winfsp-*.msi` with a new release, checking its signature, and
change the path in `install.rs`.

## Layout

```
crates/fscore   Block device trait, partition and signature detection, the Filesystem trait
crates/ext4     ext2/3/4 engine            #![forbid(unsafe_code)]
crates/btrfs    Btrfs engine               #![forbid(unsafe_code)]
app             The Windows executable:
                  winfsp.rs   Serves a Filesystem through WinFsp
                  service.rs  Owns the mounts, as a Windows service
                  ipc.rs      Named-pipe protocol between the interface and the service
                  disk.rs     Raw partition access and enumeration
                  gui.rs      The interface     canvas.rs  Its software renderer
                  cli.rs      The command line
```

`unsafe` exists only in `app`, at the Win32 and WinFsp boundaries.

Engines know nothing about Windows. They see a `BlockDev` (read, write, flush) and expose a
`Filesystem` keyed by inode. Everything else is built on those two traits, including the crash
simulator and the corruption tests.

## ext4: transactions through the real journal

All metadata changes accumulate in a transaction in memory. A commit then does this:

1. Flush file data, so nothing committed can point at unwritten blocks (ordered mode).
2. Write descriptor blocks and metadata to the jbd2 log, then flush.
3. Write the commit block, then flush. The transaction is now durable.
4. Write the metadata to its real location, then flush.
5. Mark the log empty.

Checkpointing each commit at once leaves the log empty between transactions, which removes
revoke records and log wrapping from the write path. Replay at mount still handles everything
Linux can leave behind, including revokes, wrapping and all checksum versions.

Blocks freed in a transaction stay allocated until it commits, so a crash can never find a block
reused while the old metadata still points at it.

Each operation is a savepoint within the transaction. If one fails partway, for example on a full
disk, its changes roll back and earlier work in the transaction survives.

Read-only mounts of a dirty volume replay the log into an in-memory overlay. The device handle
has no write access, so this is enforced by Windows as well as by the code.

## Btrfs: copy-on-write

Nothing reachable from the last committed superblock is ever overwritten. Tree blocks are copied
on first change and edited in place only while they belong to the running transaction. A commit:

1. Applies queued reference changes to the extent tree. Doing that needs new blocks, which queue
   more changes, so this repeats along with free-space and root-item updates until it settles.
2. Writes all new blocks to every copy, then flushes.
3. Writes superblock copies, then the primary, flushing between them.

A crash before step 3 finishes leaves the previous transaction intact, with no recovery needed.

Reference counting follows the kernel's scheme, including full backrefs for blocks shared with
snapshots: when a shared block is copied, its children gain a reference for the new parent. A
snapshot is taken between two commits, so nothing in the source can change in place while it is
being shared.

Operations validate before they change anything. Anything worse than an invalid request aborts
the whole transaction, which costs nothing on a copy-on-write filesystem: the volume stays at
the last commit and goes read-only. Space is reserved up front for the same reason, so that
running out of room can't strike halfway through an operation.

Free space comes from the committed extent tree, not the on-disk caches: it is the source of
truth, and it can't be stale. The free space tree is updated incrementally, and a v1 cache is
invalidated, which Linux rebuilds.

## Interface

The window is plain Win32. Shapes are rasterized into a DIB by `canvas.rs` and text is drawn by
GDI, with no GPU context or toolkit. It repaints only when state changes: nothing animates, and
with nothing mounted there are no timers at all. Slow work runs on threads that post results back.

The custom drawing has a cost: screen readers can't see the window. Everything it does is
available from the command line, which they can.

## Verification

Testing a filesystem against its own idea of correct proves little, so the tests are built around
independent judges. Each runs in CI on every push.

| Judge | What it proves |
|---|---|
| `e2fsck -fn` and `btrfs check --check-data-csum` | After thousands of random operations, on 8 ext and 11 Btrfs layouts, the tools that define correctness find nothing wrong |
| The Linux kernel | `diff -r` between a kernel mount of each written image and the expected tree |
| Images written by the kernel | Compressed extents in all three codecs, journals left dirty, snapshots with shared trees, and RAID5 with any one device missing |
| The kernel's subvolume cleaner | Dropping a deleted snapshot walks every reference, auditing snapshot accounting |
| Power-cut simulator | Replays the write log to sampled points, losing a random part of what wasn't flushed. Recovery must land exactly on a commit boundary. On ext4, read-only recovery must also match a real replay without writing a byte |
| Reference model | Every random operation is mirrored in memory and compared with what the engine returns |
| Corrupted images | Random damage must give errors, never a panic or hang. On Btrfs the damage is re-signed with valid checksums, as an attacker would |
| Full volumes | Filling a volume must fail cleanly, and still pass `e2fsck` or `btrfs check` afterwards |
| Windows end to end | The real service, WinFsp, drive letters and raw partitions on a Windows runner, with the resulting images then checked by `e2fsck` and `btrfs check` on Linux |

Run the portable subset with `cargo test`. Tests needing the Linux tools skip themselves when
they aren't installed. `ci/kernel-check.sh` and `ci/windows-e2e.ps1` are the two end-to-end
stages, and `ci/make-fixtures.sh` regenerates the images in `tests/fixtures`.

[WinFsp]: https://winfsp.dev/rel/
