# Causeway

Mount ext2, ext3, ext4 and Btrfs volumes on Windows, with drive letters, in one small program.

![Causeway showing a mounted Btrfs volume](docs/images/mounted-dark.png)

Causeway is a Rust reimplementation of two long-running projects, [Ext4Fsd] and [WinBtrfs],
combined into a single application. Both are kernel drivers written in C. Causeway does the
same job in memory-safe user-mode code, so a bug or a corrupted disk can fail one request but
can't crash Windows.

| | Ext4Fsd + WinBtrfs | Causeway |
|---|---|---|
| Runs as | Two kernel drivers | One 2 MB program, on the Microsoft-signed [WinFsp] driver |
| Bad data on disk | Can crash the machine | An error on that request |
| ext4 writes | Not journaled | Journaled through the real jbd2 log |
| Mounting read-only | May replay the journal to disk | Never writes: recovery happens in memory |
| Secure Boot | Workarounds or a paid signature | Nothing to sign |
| Source | About 220,000 lines of C and C++, with bundled libraries | About 15,000 lines of Rust |
| Memory | Kernel pool | 5 MB for the interface, 2 MB for the idle service |

## Getting started

1. Install [WinFsp].
2. Run `causeway.exe` and choose **Install service**.
3. Pick a volume and choose **Mount**.

Volumes mount read-only until you turn on **Allow writing**. To look through a volume or copy
files out without installing anything, use **Browse files**.

## How far to trust it

This is a young project, and a filesystem is the last place to take that lightly. Its engines
are tested hard (see [Verification](docs/design.md#verification)), but they have not yet had
years of daily use. Keep backups of anything you write to, and try it on an image or a spare
disk first.

## Documentation

- [User guide](docs/guide.md): mounting, writing, snapshots, the command line, troubleshooting
- [Compatibility](docs/compatibility.md): which filesystem features work, and what changed from the originals
- [Design](docs/design.md): how it works and how it is verified
- [Security](docs/security.md): the threat model and what the design does about it

## License

GPL-2.0-only. See [NOTICE](NOTICE) for how this relates to the original projects.

WinFsp - Windows File System Proxy, Copyright (C) Bill Zissimopoulos,
<https://github.com/winfsp/winfsp>

[Ext4Fsd]: https://github.com/bobranten/Ext4Fsd
[WinBtrfs]: https://github.com/maharmstone/btrfs
[WinFsp]: https://winfsp.dev/rel/
