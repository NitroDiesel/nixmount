# Security

## Threat model

The main threat is a **hostile disk**: a USB drive or image crafted to attack whoever plugs it in.
Filesystem parsers are a classic target, because the data is complex, attacker-controlled, and
traditionally parsed in the kernel.

The second threat is **an unprivileged local user** trying to use NixMount's privileged service
to gain access they shouldn't have.

NixMount doesn't defend against an administrator, or against someone with physical access to a
disk: volumes aren't encrypted, and Linux permissions aren't enforced on Windows.

## Hostile disks

- **No kernel code.** A parser bug can't compromise the kernel, because no parser runs there.
- **Memory safety.** The engines are `#![forbid(unsafe_code)]`. Out-of-bounds reads return zero
  or an error, and offsets and sizes from the disk are range-checked before use.
- **Bounded work.** Tree walks, directory walks, journal scans, partition chains and decompression
  all have limits, so a crafted loop or decompression bomb ends in an error.
- **Contained failure.** A panic is caught at the WinFsp boundary and fails that one request.
- **Checksums first.** Btrfs tree blocks are verified and structurally validated before any field
  is used.
- **Symlinks stay inside.** Link targets are resolved against the volume root, as in a chroot.
  A link can't point at `C:\` or climb out of the volume with `..`.
- **Names can't become paths.** `:`, `\`, `/` and other path syntax in names are remapped, so a
  file can't address an NTFS stream or another directory. Export also skips `.` and `..`, renames
  Windows device names such as `NUL`, limits folder depth and doesn't follow symlinks, so a volume
  can't write outside the folder you chose.

## The service

The service runs as SYSTEM, so its boundaries matter:

- Its named pipe admits only SYSTEM and Administrators, and rejects remote clients. Claiming the
  first pipe instance stops another process from squatting on the name.
- Messages are size-limited and decoded with a schema, not parsed by hand.
- It runs from `Program Files`, not from wherever it was downloaded, and its path is quoted. A
  service binary in a user-writable folder would be a privilege-escalation hole.
- `%ProgramData%\NixMount` decides what the service mounts, so installing resets it to SYSTEM and
  Administrators only. Any user can create folders there, so it may already exist with a hostile
  owner or ACL, and the install stops if those can't be replaced.
- WinFsp's DLL is loaded by absolute path from the registry, which keeps DLL search-order attacks
  out of the process.

## Setup

Setup runs elevated from wherever it was downloaded to, usually a folder others can write to, which
makes installers a classic target:

- The executable is linked so that its imported DLLs load from `System32` only, never from next to
  the file. Tools it runs are found through the Windows system directory, not the search path.
- The bundled WinFsp installer is unpacked into the admin-only program folder, never a temporary
  one, so it can't be swapped between being written and being run.
- That installer is the official signed release, unmodified, and CI checks it against a pinned hash.

## Data safety

- Volumes mount read-only by default, and read-only mounts open the device without write access.
- A write mount locks the partition so nothing else can write to it at the same time.
- Unknown features are never ignored: an unknown incompatible feature refuses the mount, and an
  unknown read-only feature refuses writing.
- An I/O error during a commit switches the volume to read-only instead of guessing.

## Compared with the originals

| Problem in the original | NixMount |
|---|---|
| `Ext2Srv` asked for a pipe DACL granting full control to Guests and Anonymous | Pipe limited to SYSTEM and Administrators |
| Parsing untrusted disks in kernel mode | Safe user-mode code |
| A setting forced writing past safety checks (Ext3ForceWriting) | No override exists |
| Read-only mounts could replay a journal to disk | Recovery happens in memory |
| Secure Boot workarounds suggested in the documentation | Nothing to work around |

## Limits to be aware of

- Volume-level permissions: every signed-in user can read a mounted volume. See the
  [guide](guide.md#permissions).
- WinFsp is part of the trusted base, as a kernel driver maintained by its own project.
- `NixMount-Setup.exe` isn't code-signed, so Windows can't vouch for it. Check it against the
  published SHA-256 hash, or build it from source.
- Automount trusts a volume's UUID, which a crafted disk can copy. A disk with a remembered UUID
  gets mounted with the remembered options, including writing. It is still parsed with all the
  protections above.

## Reporting

Please report vulnerabilities through a private GitHub security advisory on this repository.
