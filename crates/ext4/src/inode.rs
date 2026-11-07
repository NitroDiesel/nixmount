//! Inodes are kept as raw on-disk bytes, so fields this code doesn't know about survive
//! every rewrite untouched.
use crate::{corrupt, Fs, Result};
use fscore::{crc32c_raw, FileKind, Ino, Le, LeMut, Stat, Time};

pub const F_INDEX: u32 = 0x1000;
pub const F_HUGE: u32 = 0x4_0000;
pub const F_EXTENTS: u32 = 0x8_0000;
pub const F_INLINE: u32 = 0x1000_0000;
pub const F_CASEFOLD: u32 = 0x4000_0000;
pub const F_ENCRYPT: u32 = 0x800;

pub const S_IFMT: u16 = 0xF000;
pub const S_IFDIR: u16 = 0x4000;
pub const S_IFREG: u16 = 0x8000;
pub const S_IFLNK: u16 = 0xA000;

pub const I_BLOCK: usize = 0x28;

/// Accessors over raw inode bytes.
pub trait Inode {
    fn mode(&self) -> u16;
    fn flags(&self) -> u32;
    fn links(&self) -> u16;
    fn size(&self) -> u64;
    fn file_acl(&self) -> u64;
    fn kind(&self) -> FileKind;
    fn generation(&self) -> u32;
    fn extra_isize(&self) -> usize;
    fn is_dir(&self) -> bool {
        self.mode() & S_IFMT == S_IFDIR
    }
}

impl Inode for [u8] {
    fn mode(&self) -> u16 {
        self.u16_at(0)
    }
    fn flags(&self) -> u32 {
        self.u32_at(0x20)
    }
    fn links(&self) -> u16 {
        self.u16_at(0x1A)
    }
    fn size(&self) -> u64 {
        self.u32_at(4) as u64 | (self.u32_at(0x6C) as u64) << 32
    }
    fn file_acl(&self) -> u64 {
        self.u32_at(0x68) as u64 | (self.u16_at(0x76) as u64) << 32
    }
    fn generation(&self) -> u32 {
        self.u32_at(0x64)
    }
    fn extra_isize(&self) -> usize {
        if self.len() > 128 {
            self.u16_at(0x80) as usize
        } else {
            0
        }
    }
    fn kind(&self) -> FileKind {
        match self.mode() & S_IFMT {
            S_IFREG => FileKind::File,
            S_IFDIR => FileKind::Dir,
            S_IFLNK => FileKind::Symlink,
            0x2000 => FileKind::CharDev,
            0x6000 => FileKind::BlockDev,
            0x1000 => FileKind::Fifo,
            0xC000 => FileKind::Socket,
            _ => FileKind::Unknown,
        }
    }
}

pub fn set_size(raw: &mut [u8], size: u64) {
    raw.put_u32(4, size as u32);
    raw.put_u32(0x6C, (size >> 32) as u32);
}

/// Decodes a timestamp: 32 signed seconds plus an optional extra word holding two
/// epoch bits and the nanoseconds.
fn time_at(raw: &[u8], lo: usize, extra: usize) -> Time {
    let mut sec = raw.u32_at(lo) as i32 as i64;
    let mut nsec = 0;
    if raw.len() > 128 && raw.extra_isize() + 128 >= extra + 4 {
        let e = raw.u32_at(extra);
        sec += ((e & 3) as i64) << 32;
        nsec = (e >> 2).min(999_999_999);
    }
    Time { sec, nsec }
}

fn put_time(raw: &mut [u8], lo: usize, extra: usize, t: Time) {
    raw.put_u32(lo, t.sec as u32);
    if raw.len() > 128 && raw.extra_isize() + 128 >= extra + 4 {
        let epoch = (((t.sec - (t.sec as i32 as i64)) >> 32) & 3) as u32;
        raw.put_u32(extra, t.nsec << 2 | epoch);
    }
}

pub fn set_atime(r: &mut [u8], t: Time) {
    put_time(r, 0x08, 0x8C, t)
}
pub fn set_ctime(r: &mut [u8], t: Time) {
    put_time(r, 0x0C, 0x84, t)
}
pub fn set_mtime(r: &mut [u8], t: Time) {
    put_time(r, 0x10, 0x88, t)
}
pub fn set_crtime(r: &mut [u8], t: Time) {
    put_time(r, 0x90, 0x94, t)
}

pub fn uid(r: &[u8]) -> u32 {
    r.u16_at(2) as u32 | (r.u16_at(0x78) as u32) << 16
}
pub fn gid(r: &[u8]) -> u32 {
    r.u16_at(0x18) as u32 | (r.u16_at(0x7A) as u32) << 16
}
pub fn set_uid(r: &mut [u8], v: u32) {
    r.put_u16(2, v as u16);
    r.put_u16(0x78, (v >> 16) as u16);
}
pub fn set_gid(r: &mut [u8], v: u32) {
    r.put_u16(0x18, v as u16);
    r.put_u16(0x7A, (v >> 16) as u16);
}

impl Fs {
    /// Number of 512-byte units in the inode's block count.
    pub fn i_blocks(&self, r: &[u8]) -> u64 {
        let n = r.u32_at(0x1C) as u64 | (r.u16_at(0x74) as u64) << 32;
        if self.g.huge_file && r.flags() & F_HUGE != 0 {
            n * (self.g.bs as u64 / 512)
        } else {
            n
        }
    }

    /// Adds or subtracts whole filesystem blocks from the inode's count.
    pub fn add_i_blocks(&self, r: &mut [u8], blocks: i64) {
        let unit = self.g.bs as i64 / 512;
        let raw = r.u32_at(0x1C) as i64 | (r.u16_at(0x74) as i64) << 32;
        let delta = if self.g.huge_file && r.flags() & F_HUGE != 0 { blocks } else { blocks * unit };
        let n = (raw + delta).max(0) as u64;
        r.put_u32(0x1C, n as u32);
        if self.g.huge_file {
            r.put_u16(0x74, (n >> 32) as u16);
        }
    }

    pub fn inode_loc(&self, ino: u32) -> Result<(u64, usize)> {
        if ino == 0 || ino > self.g.inodes {
            return corrupt(format!("inode {ino} is out of range"));
        }
        let g = (ino - 1) / self.g.ipg;
        let idx = ((ino - 1) % self.g.ipg) as u64 * self.g.isize as u64;
        let block = self.inode_table(g) + idx / self.g.bs as u64;
        Ok((block, (idx % self.g.bs as u64) as usize))
    }

    pub fn inode(&self, ino: u32) -> Result<Vec<u8>> {
        let (b, o) = self.inode_loc(ino)?;
        let blk = self.block(b)?;
        let raw = blk
            .get(o..o + self.g.isize)
            .map(<[u8]>::to_vec)
            .ok_or_else(|| fscore::FsError::Corrupt("inode crosses block".into()))?;
        if self.g.metadata_csum && !raw.iter().all(|b| *b == 0) && self.inode_csum(ino, &raw).1 != stored_csum(&raw, self.g.isize) {
            return corrupt(format!("inode {ino} failed its checksum"));
        }
        Ok(raw)
    }

    /// Per-inode checksum seed, also used for directory and extent blocks.
    pub fn inode_seed(&self, ino: u32, generation: u32) -> u32 {
        let s = crc32c_raw(self.g.csum_seed, &ino.to_le_bytes());
        crc32c_raw(s, &generation.to_le_bytes())
    }

    /// Returns the full checksum and its stored-width form.
    fn inode_csum(&self, ino: u32, raw: &[u8]) -> (u32, u32) {
        let seed = self.inode_seed(ino, raw.generation());
        let mut b = raw.to_vec();
        b.put_u16(0x7C, 0);
        let hi = self.has_csum_hi(raw);
        if hi {
            b.put_u16(0x82, 0);
        }
        let c = crc32c_raw(seed, &b);
        (c, if hi { c } else { c & 0xFFFF })
    }

    fn has_csum_hi(&self, raw: &[u8]) -> bool {
        self.g.isize > 128 && raw.extra_isize() >= 4
    }

    /// Stores an inode, stamping its checksum.
    pub fn put_inode(&mut self, ino: u32, raw: &mut [u8]) -> Result<()> {
        if self.g.metadata_csum {
            let (c, _) = self.inode_csum(ino, raw);
            raw.put_u16(0x7C, c as u16);
            if self.has_csum_hi(raw) {
                raw.put_u16(0x82, (c >> 16) as u16);
            }
        }
        let (b, o) = self.inode_loc(ino)?;
        let n = self.g.isize;
        self.modify(b)?[o..o + n].copy_from_slice(&raw[..n]);
        Ok(())
    }

    pub fn stat_of(&self, ino: u32, r: &[u8]) -> Stat {
        Stat {
            ino: Ino { tree: 0, id: ino as u64 },
            kind: r.kind(),
            mode: (r.mode() & 0o7777) as u32,
            uid: uid(r),
            gid: gid(r),
            nlink: r.links() as u32,
            size: r.size(),
            alloc: self.i_blocks(r) * 512,
            atime: time_at(r, 0x08, 0x8C),
            mtime: time_at(r, 0x10, 0x88),
            ctime: time_at(r, 0x0C, 0x84),
            crtime: if r.len() > 128 { time_at(r, 0x90, 0x94) } else { Time::default() },
        }
    }
}

fn stored_csum(raw: &[u8], isize: usize) -> u32 {
    let lo = raw.u16_at(0x7C) as u32;
    if isize > 128 && raw.extra_isize() >= 4 {
        lo | (raw.u16_at(0x82) as u32) << 16
    } else {
        lo
    }
}
