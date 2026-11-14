# User guide

## Install

Run `NixMount-Setup.exe` and approve the administrator prompt, which is needed because only
administrators can read raw disks. Then select **Install**, or run `nixmount install`.

Everything comes in that one file. Setup copies the program to `C:\Program Files\NixMount`, adds
it to the Start menu, installs the WinFsp driver it carries, and starts a small background
service. Mounts belong to the service, so they stay up after you close the window, are visible
to every user on the PC, and are closed cleanly at shutdown.

Running a newer `NixMount-Setup.exe` upgrades in place. Mounted volumes are closed cleanly first.

Without installing, the same file can still **Browse files** and export them.

To remove NixMount, use **Installed apps** in Windows Settings, or run `nixmount uninstall`. This
removes everything setup added, including the driver. If WinFsp was already on the PC before
NixMount, it stays, since something else may need it.

## Mount a volume

Linux volumes appear in the list automatically. Pick one, choose a drive letter if you want a
particular one, and select **Mount**. A green dot marks mounted volumes. **Open** shows the
volume in Explorer.

**Unmount** before unplugging a disk or booting Linux. It commits everything and marks the
volume clean. If a mounted disk is unplugged anyway, its drive letter goes away by itself, and
Linux recovers the volume from its journal next time.

To mount a disk image, select **Add image**. Images with a partition table work too.

**Mount automatically** remembers the volume by its UUID, and mounts it at startup and whenever
it is plugged in. If you unmount it yourself, it stays unmounted until you unplug it or restart
Windows.

## Encrypted volumes

Volumes encrypted with LUKS, which Linux installers use for full-disk encryption, show a lock in
the list. Select one, type the passphrase you use when Linux starts, and select **Unlock**. It
then mounts and browses like any other volume. **Lock** forgets the key, and so does closing the
window. A mounted volume keeps its key until it is unmounted.

Unlocking takes a few seconds: LUKS makes each passphrase guess deliberately slow. Select
**Cancel** or press Escape to stop waiting and do something else. The
passphrase is only used to unlock and is never saved, which is also why encrypted volumes can't
mount automatically. Type the same characters you type at Linux's prompt. If Linux uses a
different keyboard layout, a key may produce another character on Windows.

From the command line, commands that open an encrypted volume ask for its passphrase in a small
window of their own, or read the first line of piped input.

## Write to a volume

Volumes mount read-only unless **Allow writing** is on. A read-only mount can't change the disk
in any way, even if the volume was not shut down cleanly: journal recovery then happens in
memory, and Linux redoes it for real next time.

Before writing:

- Shut Linux down fully. **Never write to a volume from a hibernated Linux.** Hibernation keeps
  a picture of the filesystem in memory, and Linux restores that picture on resume, destroying
  what you wrote. This can't be detected reliably.
- Keep backups of anything you can't lose.

If a volume uses a feature NixMount can't safely write, **Allow writing** is off and the window
says why. See [Compatibility](compatibility.md).

Changes reach the disk within five seconds, or at once when a program flushes a file. If a
write fails, the volume switches to read-only and says so rather than continuing.

## Browse and export

**Browse files** opens the volume read-only inside the window. Select a file or folder and use
**Export** to copy it to a Windows folder. Nothing is mounted and nothing on the volume changes.

## Verify a volume

**Verify checksums** checks a mounted volume. On Btrfs it reads every copy of all metadata and
data, and repairs bad copies from good ones when the volume is writable and has redundancy. On
ext4 it checks metadata, since ext4 has no checksums for file contents.

## Snapshots

On a mounted Btrfs volume, **Snapshot** makes a read-only snapshot at the top of the volume.
Mounted volumes list their snapshots and subvolumes. Click one to delete it. The space comes
back the next time Linux mounts the volume read-write.

## File names

Linux allows characters in names that Windows forbids, such as `:` and `?`, and names ending in
a dot. They appear in Windows as lookalike private-use characters and map back exactly, so the
real name on the volume is never altered. Names on these volumes are case-sensitive, so
`Notes.txt` and `notes.txt` can sit side by side. Some Windows programs handle that poorly.

Dotfiles are marked hidden. Use `--show-dotfiles` to turn that off.

Names are read as UTF-8. For an old volume with another encoding, pass its Windows code page,
for example `--codepage 1251`.

## Permissions

Linux user IDs mean nothing on Windows, so permissions apply per volume: signed-in users can
read a read-only mount, and read and change a writable one. New files take the owner of their
parent folder unless you pass `--uid` and `--gid`. Windows ACLs aren't stored on these volumes:
programs that set them succeed, but the ACL isn't kept.

Symbolic links work, but always stay inside the volume. An absolute Linux link such as
`/etc/hosts` resolves from the top of the volume, not from `C:\`.

## Command line

`nixmount help` lists every command. A few common ones:

```
nixmount list                        Show Linux volumes
nixmount info 1:3                    Details, and whether writing is available
nixmount mount 1:3 L: --rw           Mount disk 1, partition 3 as L:, writable
nixmount mount backup.img            Mount an image on the next free letter
nixmount unmount L:
nixmount ls 1:3 /home                List a folder without mounting
nixmount export 1:3 /home/me D:\me   Copy out without mounting
nixmount scrub L:                    Verify checksums
nixmount snapshot L: before-upgrade --read-only
nixmount subvolume delete L: before-upgrade
```

`nixmount list` shows the disk and partition numbers. Run from an elevated prompt. NixMount is a
windowed program, so a PowerShell script should end commands with `| Out-Host` to wait for them.

## Troubleshooting

**No volumes are listed.** Reading disks needs administrator rights. In Disk Management, check
that Windows sees the disk.

**Windows offers to format the disk.** Decline. Windows doesn't recognize Linux partitions and
formatting erases them.

**"The partition is in use by another program."** Writing needs exclusive access. Close anything
using the disk, such as a disk tool, a virtual machine or WSL. An image file gives the same
message if something else has it open for writing, including NixMount itself under another
drive letter.

**A volume mounted read-only although I asked for writing.** It uses a feature that isn't
writable, was not shut down cleanly in a way that can't be recovered here, or has recorded
errors. The window lists the reason. Most clear after mounting it once in Linux or running
`e2fsck`.

**An encrypted volume won't unlock with the right passphrase.** If Linux unlocks it with a TPM
or security key alone, it may have no passphrase at all. Add one in Linux with
`cryptsetup luksAddKey`. See [Compatibility](compatibility.md#luks-encryption) for what else
can stand in the way.

**The service won't start.** Run setup again to repair it, or run
`nixmount service debug` from an elevated prompt to watch it run.
