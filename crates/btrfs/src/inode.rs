//! Inode items, directory items and name hashing.
use crate::*;
use fscore::{crc32c_raw, DirEntry, FileKind, Ino, Le, LeMut, Stat, Time};

pub const INODE_SIZE: usize = 160;
pub const NODATASUM: u64 = 1;
pub const O_MODE: usize = 52;
pub const O_NLINK: usize = 40;
pub const O_SIZE: usize = 16;
pub const O_NBYTES: usize = 24;
pub const O_FLAGS: usize = 64;

pub const S_IFMT: u32 = 0xF000;
pub const S_IFDIR: u32 = 0x4000;
pub const S_IFREG: u32 = 0x8000;
pub const S_IFLNK: u32 = 0xA000;

pub const FT_REG: u8 = 1;
pub const FT_DIR: u8 = 2;
pub const FT_SYMLINK: u8 = 7;

pub fn name_hash(name: &[u8]) -> u64 {
    crc32c_raw(!1, name) as u64
}

pub fn time_at(b: &[u8], o: usize) -> Time {
    Time { sec: b.u64_at(o) as i64, nsec: b.u32_at(o + 8).min(999_999_999) }
}

pub fn put_time(b: &mut [u8], o: usize, t: Time) {
    b.put_u64(o, t.sec as u64);
    b.put_u32(o + 8, t.nsec);
}

pub const O_ATIME: usize = 112;
pub const O_CTIME: usize = 124;
pub const O_MTIME: usize = 136;
pub const O_OTIME: usize = 148;

pub fn kind_of_mode(mode: u32) -> FileKind {
    match mode & S_IFMT {
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

pub fn kind_of_ft(t: u8) -> FileKind {
    match t {
        1 => FileKind::File,
        2 => FileKind::Dir,
        3 => FileKind::CharDev,
        4 => FileKind::BlockDev,
        5 => FileKind::Fifo,
        6 => FileKind::Socket,
        7 => FileKind::Symlink,
        _ => FileKind::Unknown,
    }
}

/// One decoded name inside a DIR_ITEM, DIR_INDEX or XATTR_ITEM.
#[derive(Clone, Debug)]
pub struct DirItem {
    pub location: Key,
    pub ftype: u8,
    pub name: Vec<u8>,
    pub data: Vec<u8>,
}

/// Splits an item into its entries, which share an item when their hashes collide.
pub fn parse_dir_items(b: &[u8]) -> Result<Vec<DirItem>> {
    let mut out = vec![];
    let mut o = 0;
    while o + 30 <= b.len() {
        let (dlen, nlen) = (b.u16_at(o + 25) as usize, b.u16_at(o + 27) as usize);
        let end = o + 30 + nlen + dlen;
        if end > b.len() {
            return bad("directory item overruns");
        }
        out.push(DirItem {
            location: tree::key_at(b, o),
            ftype: b.u8_at(o + 29),
            name: b[o + 30..o + 30 + nlen].to_vec(),
            data: b[o + 30 + nlen..end].to_vec(),
        });
        o = end;
    }
    Ok(out)
}

impl Fs {
    pub fn inode_item(&self, ino: Ino) -> Result<Vec<u8>> {
        let root = self.tree(ino.tree).map_err(|e| match e {
            FsError::NotFound => FsError::Corrupt(format!("subvolume {} is missing", ino.tree)),
            e => e,
        })?;
        match self.get(root, Key::new(ino.id, K_INODE_ITEM, 0))? {
            Some(v) if v.len() >= INODE_SIZE => Ok(v),
            Some(_) => bad("inode item too short"),
            None => Err(FsError::NotFound),
        }
    }

    pub fn stat_of(&self, ino: Ino, b: &[u8]) -> Stat {
        let mode = b.u32_at(O_MODE);
        Stat {
            ino,
            kind: kind_of_mode(mode),
            mode: mode & 0o7777,
            uid: b.u32_at(44),
            gid: b.u32_at(48),
            nlink: b.u32_at(O_NLINK),
            size: b.u64_at(O_SIZE),
            alloc: b.u64_at(O_NBYTES),
            atime: time_at(b, O_ATIME),
            mtime: time_at(b, O_MTIME),
            ctime: time_at(b, O_CTIME),
            crtime: time_at(b, O_OTIME),
        }
    }

    /// Finds `name` in a directory, crossing into a subvolume if the entry is one.
    pub fn dir_lookup(&self, dir: Ino, name: &[u8]) -> Result<Option<(Ino, DirItem)>> {
        let root = self.tree(dir.tree)?;
        let Some(d) = self.get(root, Key::new(dir.id, K_DIR_ITEM, name_hash(name)))? else {
            return Ok(None);
        };
        let Some(e) = parse_dir_items(&d)?.into_iter().find(|e| e.name == name) else {
            return Ok(None);
        };
        match self.resolve_location(dir, &e) {
            Ok(ino) => Ok(Some((ino, e))),
            Err(FsError::NotFound) => Ok(None),
            Err(err) => Err(err),
        }
    }


    /// Turns a directory entry into the inode it names. An entry for a subvolume only
    /// counts if this tree holds a root ref for it: a snapshot inherits the entries of
    /// subvolumes nested in its source, but those are not part of the snapshot.
    pub fn resolve_location(&self, dir: Ino, e: &DirItem) -> Result<Ino> {
        if e.location.ty == K_ROOT_ITEM {
            let sub = e.location.obj;
            if self.get(self.root_tree, Key::new(dir.tree, K_ROOT_REF, sub))?.is_none() {
                return Err(FsError::NotFound);
            }
            let (_, item) = self.root_item(sub)?;
            return Ok(Ino { tree: sub, id: item.u64_at(168) });
        }
        Ok(Ino { tree: dir.tree, id: e.location.obj })
    }
    /// Lists a directory by DIR_INDEX, whose keys double as stable cookies.
    pub fn dir_list(&self, dir: Ino, cookie: u64, out: &mut dyn FnMut(u64, DirEntry) -> bool) -> Result<()> {
        let root = self.tree(dir.tree)?;
        let start = Key::new(dir.id, K_DIR_INDEX, cookie);
        self.scan(root, start, &mut |k, d| {
            if k.obj != dir.id || k.ty != K_DIR_INDEX {
                return Ok(false);
            }
            for e in parse_dir_items(d)? {
                // A subvolume whose root was deleted can leave a dangling entry behind.
                let Ok(ino) = self.resolve_location(dir, &e) else { continue };
                let de = DirEntry { kind: kind_of_ft(e.ftype), name: e.name, ino };
                if !out(k.off + 1, de) {
                    return Ok(false);
                }
            }
            Ok(true)
        })
    }

    pub fn xattrs(&self, ino: Ino) -> Result<Vec<DirItem>> {
        let root = self.tree(ino.tree)?;
        let mut out = vec![];
        self.scan(root, Key::new(ino.id, K_XATTR_ITEM, 0), &mut |k, d| {
            if k.obj != ino.id || k.ty != K_XATTR_ITEM {
                return Ok(false);
            }
            out.extend(parse_dir_items(d)?);
            Ok(true)
        })?;
        Ok(out)
    }
}

/// Encodes one directory entry.
pub fn dir_item(location: Key, transid: u64, ftype: u8, name: &[u8]) -> Vec<u8> {
    let mut b = vec![0u8; 30 + name.len()];
    b.put_u64(0, location.obj);
    b.put_u8(8, location.ty);
    b.put_u64(9, location.off);
    b.put_u64(17, transid);
    b.put_u16(27, name.len() as u16);
    b.put_u8(29, ftype);
    b[30..].copy_from_slice(name);
    b
}

/// Encodes one INODE_REF entry.
pub fn inode_ref(index: u64, name: &[u8]) -> Vec<u8> {
    let mut b = vec![0u8; 10 + name.len()];
    b.put_u64(0, index);
    b.put_u16(8, name.len() as u16);
    b[10..].copy_from_slice(name);
    b
}

/// A parent link of an inode.
#[derive(Debug, Clone)]
pub struct Link {
    pub parent: u64,
    pub index: u64,
    pub name: Vec<u8>,
    pub ext: bool,
}

/// Decodes the entries of an INODE_REF item keyed by `parent`.
pub fn parse_inode_refs(parent: u64, b: &[u8]) -> Result<Vec<Link>> {
    let mut out = vec![];
    let mut o = 0;
    while o + 10 <= b.len() {
        let n = b.u16_at(o + 8) as usize;
        let Some(name) = b.get(o + 10..o + 10 + n) else { return bad("inode ref overruns") };
        out.push(Link { parent, index: b.u64_at(o), name: name.to_vec(), ext: false });
        o += 10 + n;
    }
    Ok(out)
}

/// Decodes an INODE_EXTREF item.
pub fn parse_extrefs(b: &[u8]) -> Result<Vec<Link>> {
    let mut out = vec![];
    let mut o = 0;
    while o + 18 <= b.len() {
        let n = b.u16_at(o + 16) as usize;
        let Some(name) = b.get(o + 18..o + 18 + n) else { return bad("inode extref overruns") };
        out.push(Link { parent: b.u64_at(o), index: b.u64_at(o + 8), name: name.to_vec(), ext: true });
        o += 18 + n;
    }
    Ok(out)
}
