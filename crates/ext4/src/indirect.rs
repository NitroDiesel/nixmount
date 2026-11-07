//! Classic ext2/ext3 block maps: 12 direct pointers, then single, double and triple
//! indirect blocks.
use crate::extent::Run;
use crate::inode::I_BLOCK;
use crate::{corrupt, Fs, Result};
use fscore::{Le, LeMut};

impl Fs {
    /// Splits a logical block into the pointer path that reaches it.
    fn ind_path(&self, lblk: u64) -> Result<(usize, Vec<usize>)> {
        let p = (self.g.bs / 4) as u64;
        if lblk < 12 {
            return Ok((lblk as usize, vec![]));
        }
        let mut l = lblk - 12;
        if l < p {
            return Ok((12, vec![l as usize]));
        }
        l -= p;
        if l < p * p {
            return Ok((13, vec![(l / p) as usize, (l % p) as usize]));
        }
        l -= p * p;
        if l < p * p * p {
            return Ok((14, vec![(l / (p * p)) as usize, (l / p % p) as usize, (l % p) as usize]));
        }
        corrupt("file offset is beyond the indirect map limit")
    }

    fn ind_get(&self, raw: &[u8], lblk: u64) -> Result<u64> {
        let (slot, path) = self.ind_path(lblk)?;
        let mut cur = raw.u32_at(I_BLOCK + slot * 4) as u64;
        for i in path {
            if cur == 0 {
                return Ok(0);
            }
            cur = self.block(cur)?.u32_at(i * 4) as u64;
        }
        Ok(cur)
    }

    /// Finds what backs `lblk`, coalescing physically adjacent blocks into a run.
    pub fn ind_map(&self, raw: &[u8], lblk: u64) -> Result<Run> {
        let first = self.ind_get(raw, lblk)?;
        let mut len = 1;
        while len < 256 {
            let n = self.ind_get(raw, lblk + len).unwrap_or(0);
            if (first == 0) != (n == 0) || (first != 0 && n != first + len) {
                break;
            }
            len += 1;
        }
        Ok(Run { phys: (first != 0).then_some(first), len, unwritten: false })
    }

    /// Records `phys` as the block for `lblk`, allocating map blocks on the way down.
    pub fn ind_set(&mut self, raw: &mut [u8], lblk: u64, phys: u64) -> Result<()> {
        if phys > u32::MAX as u64 {
            return corrupt("indirect files cannot reference 64-bit blocks");
        }
        let (slot, path) = self.ind_path(lblk)?;
        let Some((last, walk)) = path.split_last() else {
            raw.put_u32(I_BLOCK + slot * 4, phys as u32);
            return Ok(());
        };
        let mut cur = raw.u32_at(I_BLOCK + slot * 4) as u64;
        if cur == 0 {
            cur = self.ind_new(raw, phys)?;
            raw.put_u32(I_BLOCK + slot * 4, cur as u32);
        }
        for &i in walk {
            let mut next = self.block(cur)?.u32_at(i * 4) as u64;
            if next == 0 {
                next = self.ind_new(raw, phys)?;
                self.modify(cur)?.put_u32(i * 4, next as u32);
            }
            cur = next;
        }
        self.modify(cur)?.put_u32(last * 4, phys as u32);
        Ok(())
    }

    fn ind_new(&mut self, raw: &mut [u8], goal: u64) -> Result<u64> {
        let (b, _) = self.alloc_blocks(goal, 1)?;
        self.add_i_blocks(raw, 1);
        self.fresh(b)?;
        Ok(b)
    }

    /// Frees everything at or past logical block `from`.
    pub fn ind_truncate(&mut self, raw: &mut [u8], from: u64) -> Result<u64> {
        let p = (self.g.bs / 4) as u64;
        let mut freed = 0;
        for slot in 0..12u64 {
            if slot >= from {
                let b = raw.u32_at(I_BLOCK + slot as usize * 4) as u64;
                if b != 0 {
                    self.free_blocks(b, 1)?;
                    raw.put_u32(I_BLOCK + slot as usize * 4, 0);
                    freed += 1;
                }
            }
        }
        // Each subtree covers `span` logical blocks starting at `base`.
        let levels = [(12usize, 1u32, 12u64), (13, 2, 12 + p), (14, 3, 12 + p + p * p)];
        for (slot, level, base) in levels {
            let root = raw.u32_at(I_BLOCK + slot * 4) as u64;
            if root != 0 && self.ind_free_tree(root, level, base, from, &mut freed)? {
                raw.put_u32(I_BLOCK + slot * 4, 0);
            }
        }
        self.add_i_blocks(raw, -(freed as i64));
        Ok(freed)
    }

    /// Returns true when `n` became empty and was released.
    fn ind_free_tree(&mut self, n: u64, level: u32, base: u64, from: u64, freed: &mut u64) -> Result<bool> {
        let p = (self.g.bs / 4) as u64;
        let span = p.pow(level - 1);
        let mut empty = true;
        for i in 0..p {
            let start = base + i * span;
            let child = self.block(n)?.u32_at(i as usize * 4) as u64;
            if child == 0 {
                continue;
            }
            let gone = if level == 1 {
                if start >= from {
                    self.free_blocks(child, 1)?;
                    *freed += 1;
                    true
                } else {
                    false
                }
            } else if start + span > from {
                self.ind_free_tree(child, level - 1, start, from, freed)?
            } else {
                false
            };
            if gone {
                self.modify(n)?.put_u32(i as usize * 4, 0);
            } else {
                empty = false;
            }
        }
        if empty {
            self.free_blocks(n, 1)?;
            *freed += 1;
        }
        Ok(empty)
    }
}
