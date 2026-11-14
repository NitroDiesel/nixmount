//! Partition tables and filesystem signatures. Detection only ever reads.
use crate::dev::BlockDev;
use crate::vfs::Result;
use crate::Le;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FsKind {
    Ext(u8),
    Btrfs,
    Xfs,
    Lvm,
    MdRaid,
    Swap,
    Ntfs,
    Fat,
    ExFat,
    Bsd,
    Luks,
    Unknown,
}

impl FsKind {
    pub fn name(&self) -> String {
        match self {
            FsKind::Ext(v) => format!("ext{v}"),
            FsKind::Btrfs => "btrfs".into(),
            FsKind::Xfs => "XFS".into(),
            FsKind::Lvm => "LVM".into(),
            FsKind::MdRaid => "Linux RAID".into(),
            FsKind::Swap => "swap".into(),
            FsKind::Ntfs => "NTFS".into(),
            FsKind::Fat => "FAT".into(),
            FsKind::ExFat => "exFAT".into(),
            FsKind::Bsd => "BSD".into(),
            FsKind::Luks => "LUKS".into(),
            FsKind::Unknown => "unknown".into(),
        }
    }
    /// True for filesystems this project can mount.
    pub fn mountable(&self) -> bool {
        matches!(self, FsKind::Ext(_) | FsKind::Btrfs)
    }
}

#[derive(Clone, Debug)]
pub struct Partition {
    pub index: u32,
    pub start: u64,
    pub len: u64,
    pub name: String,
}

/// Reads `n` bytes at `off`, or returns None if the device is too small.
fn peek(dev: &dyn BlockDev, off: u64, n: usize) -> Option<Vec<u8>> {
    if off.checked_add(n as u64)? > dev.len() {
        return None;
    }
    let mut b = vec![0; n];
    dev.read_at(off, &mut b).ok()?;
    Some(b)
}

/// Identifies what occupies `dev` from its signatures.
pub fn probe(dev: &dyn BlockDev) -> FsKind {
    if let Some(sb) = peek(dev, 1024, 1024) {
        if sb.u16_at(0x38) == 0xEF53 {
            let (compat, incompat) = (sb.u32_at(0x5C), sb.u32_at(0x60));
            // extents | 64bit | flex_bg imply ext4; a journal without them is ext3.
            let v4 = incompat & (0x40 | 0x80 | 0x200) != 0;
            return FsKind::Ext(if v4 {
                4
            } else if compat & 0x4 != 0 {
                3
            } else {
                2
            });
        }
    }
    if peek(dev, 0x10040, 8).is_some_and(|m| m == b"_BHRfS_M") {
        return FsKind::Btrfs;
    }
    let Some(h) = peek(dev, 0, 4096) else { return FsKind::Unknown };
    if &h[0..4] == b"XFSB" {
        return FsKind::Xfs;
    }
    if h[0..6] == *b"LUKS\xba\xbe" {
        return FsKind::Luks;
    }
    if &h[3..11] == b"NTFS    " {
        return FsKind::Ntfs;
    }
    if &h[3..11] == b"EXFAT   " {
        return FsKind::ExFat;
    }
    if &h[0x36..0x39] == b"FAT" || &h[0x52..0x55] == b"FAT" {
        return FsKind::Fat;
    }
    if h[512..520] == *b"LABELONE" {
        return FsKind::Lvm;
    }
    if &h[4086..4096] == b"SWAPSPACE2" || &h[4086..4096] == b"SWAP-SPACE" {
        return FsKind::Swap;
    }
    if peek(dev, 4096, 4).is_some_and(|m| m.u32_at(0) == 0xA92B4EFC) || h.u32_at(0) == 0xA92B4EFC {
        return FsKind::MdRaid;
    }
    if peek(dev, 65536 + 1372, 4).is_some_and(|m| m.u32_at(0) == 0x19540119) {
        return FsKind::Bsd;
    }
    FsKind::Unknown
}

/// Parses GPT or MBR. A device with neither has no partitions, and the caller then
/// treats it as a bare filesystem.
pub fn partitions(dev: &dyn BlockDev, sector: u64) -> Result<Vec<Partition>> {
    let Some(mbr) = peek(dev, 0, 512) else { return Ok(vec![]) };
    if mbr.u16_at(510) != 0xAA55 {
        return Ok(vec![]);
    }
    if (0..4).any(|i| mbr.u8_at(446 + i * 16 + 4) == 0xEE) {
        if let Some(p) = gpt(dev, sector) {
            return Ok(p);
        }
    }
    let mut out = vec![];
    for i in 0..4usize {
        let e = 446 + i * 16;
        let (ty, lba, n) = (mbr.u8_at(e + 4), mbr.u32_at(e + 8) as u64, mbr.u32_at(e + 12) as u64);
        if ty == 0 || n == 0 {
            continue;
        }
        if matches!(ty, 0x05 | 0x0F | 0x85) {
            extended(dev, lba, sector, &mut out);
            continue;
        }
        out.push(Partition { index: i as u32 + 1, start: lba * sector, len: n * sector, name: String::new() });
    }
    Ok(out)
}

/// Follows the linked list of logical partitions, bounded against loops in hostile tables.
fn extended(dev: &dyn BlockDev, base: u64, sector: u64, out: &mut Vec<Partition>) {
    let mut ebr = base;
    let mut index = 5;
    for _ in 0..128 {
        let Some(b) = peek(dev, ebr * sector, 512) else { return };
        if b.u16_at(510) != 0xAA55 {
            return;
        }
        let (lba, n) = (b.u32_at(446 + 8) as u64, b.u32_at(446 + 12) as u64);
        if n != 0 {
            out.push(Partition { index, start: (ebr + lba) * sector, len: n * sector, name: String::new() });
            index += 1;
        }
        let next = b.u32_at(462 + 8) as u64;
        if next == 0 {
            return;
        }
        ebr = base + next;
    }
}

fn gpt(dev: &dyn BlockDev, sector: u64) -> Option<Vec<Partition>> {
    let h = peek(dev, sector, 512)?;
    if &h[0..8] != b"EFI PART" {
        return None;
    }
    let (lba, count, size) = (h.u64_at(72), h.u32_at(80).min(4096), h.u32_at(84) as u64);
    if !(128..=4096).contains(&size) {
        return None;
    }
    let table = peek(dev, lba.checked_mul(sector)?, (count as u64 * size) as usize)?;
    let mut out = vec![];
    for i in 0..count as usize {
        let e = &table[i * size as usize..(i + 1) * size as usize];
        if e[0..16].iter().all(|b| *b == 0) {
            continue;
        }
        let (first, last) = (e.u64_at(32), e.u64_at(40));
        if last < first {
            continue;
        }
        let name: Vec<u16> =
            e[56..128].as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).take_while(|c| *c != 0).collect();
        out.push(Partition {
            index: i as u32 + 1,
            start: first.checked_mul(sector)?,
            len: (last - first + 1).checked_mul(sector)?,
            name: String::from_utf16_lossy(&name),
        });
    }
    Some(out)
}
