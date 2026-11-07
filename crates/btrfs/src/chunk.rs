//! Logical-to-physical mapping across devices, with mirror fallback and RAID5/6 rebuild.
use crate::{bad, Fs};
use fscore::{FsError, Le, Result};

pub const T_DATA: u64 = 1;
pub const T_SYSTEM: u64 = 2;
pub const T_METADATA: u64 = 4;
pub const RAID0: u64 = 8;
pub const RAID1: u64 = 0x10;
pub const DUP: u64 = 0x20;
pub const RAID10: u64 = 0x40;
pub const RAID5: u64 = 0x80;
pub const RAID6: u64 = 0x100;
pub const RAID1C3: u64 = 0x200;
pub const RAID1C4: u64 = 0x400;
pub const PROFILE_MASK: u64 = RAID0 | RAID1 | DUP | RAID10 | RAID5 | RAID6 | RAID1C3 | RAID1C4;

#[derive(Clone, Debug)]
pub struct Stripe {
    pub devid: u64,
    pub offset: u64,
    pub uuid: [u8; 16],
}

#[derive(Clone, Debug)]
pub struct Chunk {
    pub start: u64,
    pub len: u64,
    pub ty: u64,
    pub stripe_len: u64,
    pub sub_stripes: u64,
    pub stripes: Vec<Stripe>,
}

/// Decodes a chunk item, rejecting geometry that would break the address arithmetic.
pub fn parse_chunk(start: u64, b: &[u8]) -> Result<Chunk> {
    let n = b.u16_at(44) as usize;
    let (len, stripe_len, ty) = (b.u64_at(0), b.u64_at(16), b.u64_at(24));
    let sub = b.u16_at(46) as u64;
    if n == 0 || b.len() < 48 + n * 32 || len == 0 || !stripe_len.is_power_of_two() || stripe_len < 4096 {
        return bad(format!("invalid chunk at {start:#x}"));
    }
    if start.checked_add(len).is_none() || (ty & RAID10 != 0 && (sub == 0 || n as u64 % sub != 0)) {
        return bad(format!("invalid chunk at {start:#x}"));
    }
    if ty & RAID5 != 0 && n < 2 || ty & RAID6 != 0 && n < 3 {
        return bad(format!("invalid parity chunk at {start:#x}"));
    }
    let stripes = (0..n)
        .map(|i| {
            let o = 48 + i * 32;
            let mut uuid = [0; 16];
            uuid.copy_from_slice(&b[o + 16..o + 32]);
            Stripe { devid: b.u64_at(o), offset: b.u64_at(o + 8), uuid }
        })
        .collect();
    Ok(Chunk { start, len, ty, stripe_len, sub_stripes: sub.max(1), stripes })
}

impl Chunk {
    pub fn parity_stripes(&self) -> usize {
        if self.ty & RAID5 != 0 {
            1
        } else if self.ty & RAID6 != 0 {
            2
        } else {
            0
        }
    }

    pub fn is_parity(&self) -> bool {
        self.parity_stripes() > 0
    }

    /// Bytes each device holds for this chunk.
    pub fn stripe_size(&self) -> u64 {
        let n = self.stripes.len() as u64;
        match self.ty & PROFILE_MASK {
            RAID0 => self.len / n,
            RAID10 => self.len / (n / self.sub_stripes),
            RAID5 | RAID6 => self.len / (n - self.parity_stripes() as u64),
            _ => self.len,
        }
    }

    /// Independent copies of any byte, counting parity rebuild as one more.
    pub fn mirrors(&self) -> usize {
        match self.ty & PROFILE_MASK {
            RAID1 | DUP | RAID1C3 | RAID1C4 => self.stripes.len(),
            RAID10 => self.sub_stripes as usize,
            RAID5 | RAID6 => 2,
            _ => 1,
        }
    }

    /// Where the byte at chunk offset `off` lives, and how many bytes follow contiguously.
    /// Returns one (stripe index, physical offset) per copy.
    pub fn locate(&self, off: u64) -> (Vec<(usize, u64)>, u64) {
        let sl = self.stripe_len;
        let n = self.stripes.len() as u64;
        let (nr, inside) = (off / sl, off % sl);
        let to_edge = sl - inside;
        let at = |i: u64, row: u64| (i as usize, self.stripes[i as usize].offset + row * sl + inside);
        match self.ty & PROFILE_MASK {
            RAID0 => (vec![at(nr % n, nr / n)], to_edge),
            RAID10 => {
                let groups = n / self.sub_stripes;
                let first = (nr % groups) * self.sub_stripes;
                ((first..first + self.sub_stripes).map(|i| at(i, nr / groups)).collect(), to_edge)
            }
            RAID5 | RAID6 => {
                let data = n - self.parity_stripes() as u64;
                let (row, i) = (nr / data, nr % data);
                (vec![at((i + row) % n, row)], to_edge)
            }
            0 => (vec![(0, self.stripes[0].offset + off)], self.len - off),
            _ => {
                let v = (0..n as usize).map(|i| (i, self.stripes[i].offset + off)).collect();
                (v, self.len - off)
            }
        }
    }

    /// Logical addresses whose physical location is `phys` on `devid`, used to keep
    /// superblock copies out of allocation.
    pub fn logical_of(&self, devid: u64, phys: u64) -> Vec<u64> {
        let (sl, n) = (self.stripe_len, self.stripes.len() as u64);
        let size = self.stripe_size();
        let mut out = vec![];
        for (i, s) in self.stripes.iter().enumerate() {
            if s.devid != devid || phys < s.offset || phys >= s.offset + size {
                continue;
            }
            let (i, off) = (i as u64, phys - s.offset);
            let (row, inside) = (off / sl, off % sl);
            let nr = match self.ty & PROFILE_MASK {
                RAID0 => row * n + i,
                RAID10 => row * (n / self.sub_stripes) + i / self.sub_stripes,
                RAID5 | RAID6 => {
                    let data = n - self.parity_stripes() as u64;
                    let idx = (i + n - row % n) % n;
                    if idx >= data {
                        continue;
                    }
                    row * data + idx
                }
                _ => {
                    out.push(self.start + off);
                    continue;
                }
            };
            out.push(self.start + nr * sl + inside);
        }
        out
    }
}

impl Fs {
    pub fn chunk_at(&self, logical: u64) -> Result<&Chunk> {
        match self.chunks.range(..=logical).next_back() {
            Some((_, c)) if logical < c.start + c.len => Ok(c),
            _ => bad(format!("logical address {logical:#x} is not in any chunk")),
        }
    }

    fn dev_read(&self, devid: u64, phys: u64, buf: &mut [u8]) -> Result<()> {
        match self.devs.get(&devid) {
            Some(d) => d.read_at(phys, buf),
            None => Err(FsError::Unsupported(format!("device {devid} is missing"))),
        }
    }

    /// Reads through copy number `mirror`. For parity profiles mirror 1 is the rebuild.
    pub fn read_mirror(&self, logical: u64, buf: &mut [u8], mirror: usize) -> Result<()> {
        let mut done = 0;
        while done < buf.len() {
            let pos = logical + done as u64;
            let c = self.chunk_at(pos)?;
            let off = pos - c.start;
            let (copies, span) = c.locate(off);
            let n = (span.min((c.len - off).min((buf.len() - done) as u64))) as usize;
            let dst = &mut buf[done..done + n];
            if c.is_parity() && mirror > 0 {
                // Only a lost stripe needs rebuilding. A healthy one in the same read may
                // be unrebuildable because the failed device is part of its row.
                if self.rebuild(c, off, dst).is_err() {
                    let (i, phys) = copies[0];
                    self.dev_read(c.stripes[i].devid, phys, dst)?;
                }
            } else {
                let (i, phys) = copies[mirror % copies.len()];
                self.dev_read(c.stripes[i].devid, phys, dst)?;
            }
            done += n;
        }
        Ok(())
    }

    /// Reconstructs bytes of one data stripe from the rest of its row plus parity.
    fn rebuild(&self, c: &Chunk, off: u64, dst: &mut [u8]) -> Result<()> {
        let (sl, n) = (c.stripe_len, c.stripes.len() as u64);
        let data = n - c.parity_stripes() as u64;
        let (nr, inside) = (off / sl, off % sl);
        let (row, want) = (nr / data, nr % data);
        let read = |i: u64, b: &mut [u8]| {
            let s = &c.stripes[((i + row) % n) as usize];
            self.dev_read(s.devid, s.offset + row * sl + inside, b)
        };
        // P sits right after the data stripes, in the same rotation.
        if read(data, dst).is_ok() {
            let mut t = vec![0u8; dst.len()];
            for i in (0..data).filter(|i| *i != want) {
                read(i, &mut t)?;
                dst.iter_mut().zip(&t).for_each(|(d, s)| *d ^= s);
            }
            return Ok(());
        }
        if c.parity_stripes() < 2 {
            return Err(FsError::Unsupported("too many missing devices".into()));
        }
        // P is gone too: recover from Q, where Q = sum of g^i * D_i over GF(2^8).
        read(data + 1, dst)?;
        let mut t = vec![0u8; dst.len()];
        for i in (0..data).filter(|i| *i != want) {
            read(i, &mut t)?;
            let g = gf_pow2(i as u32);
            dst.iter_mut().zip(&t).for_each(|(d, s)| *d ^= gf_mul(*s, g));
        }
        let inv = gf_inv(gf_pow2(want as u32));
        dst.iter_mut().for_each(|d| *d = gf_mul(*d, inv));
        Ok(())
    }

    /// Reads and accepts the first copy that `verify` passes.
    pub fn read_verified(&self, logical: u64, buf: &mut [u8], verify: &dyn Fn(&[u8]) -> bool) -> Result<()> {
        let mirrors = self.chunk_at(logical)?.mirrors();
        let mut last = None;
        for m in 0..mirrors {
            match self.read_mirror(logical, buf, m) {
                Ok(()) if verify(buf) => return Ok(()),
                Ok(()) => last = Some(FsError::Corrupt(format!("checksum mismatch at {logical:#x}"))),
                Err(e) => last = Some(e),
            }
        }
        Err(last.unwrap_or_else(|| FsError::Corrupt("no readable copy".into())))
    }

    /// Writes to every copy of a logical range.
    pub fn write_logical(&self, logical: u64, data: &[u8]) -> Result<()> {
        let mut done = 0;
        while done < data.len() {
            let pos = logical + done as u64;
            let c = self.chunk_at(pos)?;
            if c.is_parity() {
                return Err(FsError::ReadOnly);
            }
            let off = pos - c.start;
            let (copies, span) = c.locate(off);
            let n = span.min((c.len - off).min((data.len() - done) as u64)) as usize;
            for (i, phys) in copies {
                let devid = c.stripes[i].devid;
                let d = self.devs.get(&devid).ok_or(FsError::ReadOnly)?;
                d.write_at(phys, &data[done..done + n])?;
            }
            done += n;
        }
        Ok(())
    }
}

fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut r = 0;
    while b != 0 {
        if b & 1 != 0 {
            r ^= a;
        }
        a = (a << 1) ^ if a & 0x80 != 0 { 0x1D } else { 0 };
        b >>= 1;
    }
    r
}

fn gf_pow2(n: u32) -> u8 {
    (0..n).fold(1, |v, _| gf_mul(v, 2))
}

fn gf_inv(v: u8) -> u8 {
    (1..=255).find(|x| gf_mul(v, *x) == 1).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunk(ty: u64, n: usize, sub: u64) -> Chunk {
        let stripes =
            (0..n).map(|i| Stripe { devid: i as u64 + 1, offset: 1 << 20, uuid: [0; 16] }).collect();
        Chunk { start: 0, len: 1 << 30, ty, stripe_len: 65536, sub_stripes: sub, stripes }
    }

    #[test]
    fn locate_and_logical_of_are_inverse() {
        for (ty, n, sub) in [(RAID0, 3, 1), (RAID10, 4, 2), (RAID5, 3, 1), (RAID6, 4, 1), (0, 1, 1), (DUP, 2, 1)] {
            let c = chunk(ty, n, sub);
            for off in [0u64, 65536, 131072 + 77, 9 * 65536 + 5] {
                let (copies, _) = c.locate(off);
                for (i, phys) in copies {
                    let back = c.logical_of(c.stripes[i].devid, phys);
                    assert!(back.contains(&off), "ty {ty:#x} off {off}: {back:?}");
                }
            }
        }
    }

    #[test]
    fn galois_inverse() {
        for v in 1..=255u8 {
            assert_eq!(gf_mul(v, gf_inv(v)), 1);
        }
    }
}
