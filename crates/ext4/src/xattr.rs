//! Extended attributes, both in-inode and in a shared block.
use crate::inode::Inode;
use crate::{corrupt, Fs, Result};
use fscore::{crc32c_raw, FsError, Le, LeMut};

const MAGIC: u32 = 0xEA02_0000;

pub struct Xattr {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}

fn prefix(index: u8) -> &'static str {
    match index {
        1 => "user.",
        2 => "system.posix_acl_access",
        3 => "system.posix_acl_default",
        4 => "trusted.",
        6 => "security.",
        7 => "system.",
        8 => "system.richacl",
        _ => "",
    }
}

impl Fs {
    /// Decodes an entry table at `o`; values are relative to `vbase`.
    fn parse_xattrs(&self, region: &[u8], mut o: usize, vbase: usize, out: &mut Vec<Xattr>) -> Result<()> {
        while o + 16 <= region.len() && region.u32_at(o) != 0 {
            let (nlen, idx) = (region.u8_at(o) as usize, region.u8_at(o + 1));
            let (voff, vinum, vsize) = (region.u16_at(o + 2) as usize, region.u32_at(o + 4), region.u32_at(o + 8) as usize);
            let name = region.get(o + 16..o + 16 + nlen).ok_or_else(|| FsError::Corrupt("xattr name overruns".into()))?;
            let mut full = prefix(idx).as_bytes().to_vec();
            full.extend_from_slice(name);
            let value = if vinum != 0 {
                self.read_ea_inode(vinum, vsize)?
            } else {
                match region.get(vbase + voff..vbase + voff + vsize) {
                    Some(v) => v.to_vec(),
                    None => return corrupt("xattr value overruns"),
                }
            };
            out.push(Xattr { name: full, value });
            o += (16 + nlen + 3) & !3;
        }
        Ok(())
    }

    fn read_ea_inode(&self, ino: u32, size: usize) -> Result<Vec<u8>> {
        if size > 64 << 20 {
            return corrupt("xattr value too large");
        }
        let raw = self.inode(ino)?;
        let mut v = vec![0; size];
        let n = self.read_data(ino, &raw, 0, &mut v)?;
        v.truncate(n);
        Ok(v)
    }

    pub fn xattrs(&self, raw: &[u8]) -> Result<Vec<Xattr>> {
        let mut out = vec![];
        let start = 128 + raw.extra_isize();
        if raw.len() > start + 4 && raw.u32_at(start) == MAGIC {
            self.parse_xattrs(&raw[start..], 4, 4, &mut out)?;
        }
        let acl = raw.file_acl();
        if acl != 0 {
            let b = self.block(acl)?;
            if b.u32_at(0) != MAGIC {
                return corrupt("bad xattr block");
            }
            self.parse_xattrs(&b, 32, 0, &mut out)?;
        }
        Ok(out)
    }

    /// The overflow of inline data, stored in the in-inode `system.data` attribute.
    pub fn inline_xattr_data(&self, raw: &[u8]) -> Result<Option<Vec<u8>>> {
        let start = 128 + raw.extra_isize();
        if raw.len() <= start + 4 || raw.u32_at(start) != MAGIC {
            return Ok(None);
        }
        let mut out = vec![];
        self.parse_xattrs(&raw[start..], 4, 4, &mut out)?;
        Ok(out.into_iter().find(|x| x.name == b"system.data").map(|x| x.value))
    }

    /// Drops the inode's reference on its xattr block.
    pub fn release_xattr_block(&mut self, raw: &mut [u8]) -> Result<()> {
        let acl = raw.file_acl();
        if acl == 0 {
            return Ok(());
        }
        let b = self.block(acl)?;
        if b.u32_at(0) != MAGIC {
            return corrupt("bad xattr block");
        }
        let refs = b.u32_at(4);
        if refs > 1 {
            self.modify(acl)?.put_u32(4, refs - 1);
            if self.g.metadata_csum {
                let b = self.block(acl)?;
                let c = crc32c_raw(self.g.csum_seed, &acl.to_le_bytes());
                let c = crc32c_raw(c, &b[..16]);
                let c = crc32c_raw(c, &[0; 4]);
                let c = crc32c_raw(c, &b[20..]);
                self.modify(acl)?.put_u32(16, c);
            }
        } else {
            self.free_blocks(acl, 1)?;
        }
        self.add_i_blocks(raw, -1);
        raw.put_u32(0x68, 0);
        raw.put_u16(0x76, 0);
        Ok(())
    }
}
