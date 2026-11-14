//! The [`Filesystem`] implementation: each mutating call is one rollback-protected step
//! of the running transaction.
use crate::dir::ftype;
use crate::extent::init_root;
use crate::inode::*;
use crate::mount::Ext4;
use crate::{corrupt, Fs, Result, ROOT_INO};
use fscore::{
    CheckReport, DirEntry, FileKind, Filesystem, FsError, Ino, LeMut, NewNode, Owner, SetAttr, Stat, Time, VolumeInfo,
};
use std::sync::{RwLockReadGuard, RwLockWriteGuard};

const MAX_LINKS: u16 = 65000;
const FAST_SYMLINK: usize = 60;

fn check_name(name: &[u8]) -> Result<()> {
    if name.is_empty() || name == b"." || name == b".." || name.contains(&b'/') || name.contains(&0) {
        return Err(FsError::Invalid("bad file name"));
    }
    if name.len() > 255 {
        return Err(FsError::NameTooLong);
    }
    Ok(())
}

fn id(ino: Ino) -> Result<u32> {
    u32::try_from(ino.id).map_err(|_| FsError::Invalid("inode number out of range"))
}

fn inc_links(r: &mut [u8]) {
    let n = r.links().saturating_add(1);
    r.put_u16(0x1A, n);
}

/// A directory always keeps `.` and its parent entry counted.
fn dec_dir_links(r: &mut [u8]) {
    let n = r.links().saturating_sub(1).max(2);
    r.put_u16(0x1A, n);
}

fn ino_of(n: u32) -> Ino {
    Ino { tree: 0, id: n as u64 }
}

impl Fs {
    /// Builds a new inode image, all fields initialised.
    fn new_inode(&self, ino: u32, mode: u16, owner: Owner, flags: u32) -> Vec<u8> {
        let mut r = vec![0u8; self.g.isize];
        r.put_u16(0, mode);
        set_uid(&mut r, owner.uid);
        set_gid(&mut r, owner.gid);
        r.put_u16(0x1A, 1);
        r.put_u32(0x20, flags);
        let now = Time::now();
        r.put_u32(0x64, now.nsec ^ ino.rotate_left(16));
        if self.g.isize > 128 {
            r.put_u16(0x80, self.g.want_extra.min(self.g.isize as u16 - 128));
        }
        set_atime(&mut r, now);
        set_ctime(&mut r, now);
        set_mtime(&mut r, now);
        set_crtime(&mut r, now);
        if flags & F_EXTENTS != 0 {
            init_root(&mut r);
        }
        r
    }

    fn data_flags(&self) -> u32 {
        if self.g.extents {
            F_EXTENTS
        } else {
            0
        }
    }

    fn touch_dir(&self, raw: &mut [u8]) {
        let now = Time::now();
        set_mtime(raw, now);
        set_ctime(raw, now);
    }

    fn op_create(&mut self, dir: u32, name: &[u8], node: &NewNode, owner: Owner) -> Result<u32> {
        check_name(name)?;
        let mut parent = self.inode(dir)?;
        if self.dir_lookup(dir, &parent, name)?.is_some() {
            return Err(FsError::Exists);
        }
        let perm = (owner.mode & 0o7777) as u16;
        let is_dir = matches!(node, NewNode::Dir);
        let ino = self.alloc_inode(dir, is_dir)?;
        let (mut raw, kind) = match node {
            NewNode::File => (self.new_inode(ino, S_IFREG | perm, owner, self.data_flags()), FileKind::File),
            NewNode::Dir => {
                let mut r = self.new_inode(ino, S_IFDIR | perm, owner, self.data_flags());
                r.put_u16(0x1A, 2);
                self.dir_init(ino, &mut r, dir)?;
                (r, FileKind::Dir)
            }
            NewNode::Symlink(target) => {
                if target.is_empty() || target.len() >= self.g.bs {
                    return Err(FsError::Invalid("bad symlink target"));
                }
                let mut r;
                if target.len() < FAST_SYMLINK {
                    r = self.new_inode(ino, S_IFLNK | 0o777, owner, 0);
                    r[I_BLOCK..I_BLOCK + target.len()].copy_from_slice(target);
                    set_size(&mut r, target.len() as u64);
                } else {
                    r = self.new_inode(ino, S_IFLNK | 0o777, owner, self.data_flags());
                    self.write_data(ino, &mut r, 0, target)?;
                }
                (r, FileKind::Symlink)
            }
        };
        self.put_inode(ino, &mut raw)?;
        self.dir_add(dir, &mut parent, name, ino, ftype(kind))?;
        self.touch_dir(&mut parent);
        if is_dir {
            inc_links(&mut parent);
        }
        self.put_inode(dir, &mut parent)?;
        Ok(ino)
    }

    /// Releases an inode whose last link is gone.
    pub fn drop_inode(&mut self, ino: u32, raw: &mut [u8]) -> Result<()> {
        let is_dir = raw.is_dir();
        let has_blocks = raw.kind() != FileKind::Symlink || self.i_blocks(raw) > 0;
        if has_blocks && raw.flags() & F_INLINE == 0 {
            self.truncate_to(ino, raw, 0)?;
        }
        self.release_xattr_block(raw)?;
        raw.put_u16(0x1A, 0);
        raw.put_u32(0x14, Time::now().sec as u32);
        set_size(raw, 0);
        self.put_inode(ino, raw)?;
        self.free_inode(ino, is_dir)
    }

    fn op_link(&mut self, ino: u32, dir: u32, name: &[u8]) -> Result<()> {
        check_name(name)?;
        let mut raw = self.inode(ino)?;
        if raw.is_dir() {
            return Err(FsError::IsDir);
        }
        if raw.links() >= MAX_LINKS {
            return Err(FsError::TooManyLinks);
        }
        let mut parent = self.inode(dir)?;
        if self.dir_lookup(dir, &parent, name)?.is_some() {
            return Err(FsError::Exists);
        }
        self.dir_add(dir, &mut parent, name, ino, ftype(raw.kind()))?;
        self.touch_dir(&mut parent);
        self.put_inode(dir, &mut parent)?;
        inc_links(&mut raw);
        set_ctime(&mut raw, Time::now());
        self.put_inode(ino, &mut raw)
    }

    fn op_unlink(&mut self, dir: u32, name: &[u8]) -> Result<()> {
        let mut parent = self.inode(dir)?;
        let e = self.dir_lookup(dir, &parent, name)?.ok_or(FsError::NotFound)?;
        let mut raw = self.inode(e.ino)?;
        if raw.is_dir() {
            return Err(FsError::IsDir);
        }
        self.remove_name(dir, &mut parent, &e.name)?;
        self.put_inode(dir, &mut parent)?;
        self.dec_link(e.ino, &mut raw)
    }

    fn dec_link(&mut self, ino: u32, raw: &mut [u8]) -> Result<()> {
        if raw.links() <= 1 {
            return self.drop_inode(ino, raw);
        }
        { let n = raw.links() - 1; raw.put_u16(0x1A, n); }
        set_ctime(raw, Time::now());
        self.put_inode(ino, raw)
    }

    fn remove_name(&mut self, dir: u32, parent: &mut [u8], name: &[u8]) -> Result<()> {
        self.dir_remove(dir, parent, name)?;
        self.touch_dir(parent);
        Ok(())
    }

    fn op_rmdir(&mut self, dir: u32, name: &[u8]) -> Result<()> {
        let mut parent = self.inode(dir)?;
        let e = self.dir_lookup(dir, &parent, name)?.ok_or(FsError::NotFound)?;
        let mut raw = self.inode(e.ino)?;
        if !raw.is_dir() {
            return Err(FsError::NotDir);
        }
        if !self.dir_is_empty(e.ino, &raw)? {
            return Err(FsError::NotEmpty);
        }
        self.remove_name(dir, &mut parent, &e.name)?;
        dec_dir_links(&mut parent);
        self.put_inode(dir, &mut parent)?;
        self.drop_inode(e.ino, &mut raw)
    }

    /// Refuses to move a directory underneath itself.
    fn check_not_ancestor(&self, moved: u32, target_dir: u32) -> Result<()> {
        let mut cur = target_dir;
        for _ in 0..4096 {
            if cur == moved {
                return Err(FsError::Invalid("cannot move a directory into itself"));
            }
            if cur == ROOT_INO {
                return Ok(());
            }
            let raw = self.inode(cur)?;
            cur = self.dir_parent(cur, &raw)?;
        }
        corrupt("directory tree is too deep or has a cycle")
    }

    fn op_rename(&mut self, from: u32, name: &[u8], to: u32, new_name: &[u8], replace: bool) -> Result<()> {
        check_name(new_name)?;
        let mut src_dir = self.inode(from)?;
        let e = self.dir_lookup(from, &src_dir, name)?.ok_or(FsError::NotFound)?;
        let mut dst_dir = if from == to { src_dir.clone() } else { self.inode(to)? };
        if !dst_dir.is_dir() {
            return Err(FsError::NotDir);
        }
        let mut moved = self.inode(e.ino)?;
        if moved.is_dir() && from != to {
            self.check_not_ancestor(e.ino, to)?;
        }
        if let Some(t) = self.dir_lookup(to, &dst_dir, new_name)? {
            if t.ino == e.ino {
                return if t.name == e.name { Ok(()) } else { self.rename_case(from, &mut src_dir, &e, new_name) };
            }
            if !replace {
                return Err(FsError::Exists);
            }
            let mut victim = self.inode(t.ino)?;
            match (victim.is_dir(), moved.is_dir()) {
                (true, false) => return Err(FsError::IsDir),
                (false, true) => return Err(FsError::NotDir),
                (true, true) => {
                    if !self.dir_is_empty(t.ino, &victim)? {
                        return Err(FsError::NotEmpty);
                    }
                    dec_dir_links(&mut dst_dir);
                    self.dir_remove(to, &dst_dir, &t.name)?;
                    self.drop_inode(t.ino, &mut victim)?;
                }
                (false, false) => {
                    self.dir_remove(to, &dst_dir, &t.name)?;
                    self.dec_link(t.ino, &mut victim)?;
                }
            }
        }
        if from == to {
            self.dir_remove(from, &dst_dir, &e.name)?;
            self.dir_add(to, &mut dst_dir, new_name, e.ino, ftype(moved.kind()))?;
            self.touch_dir(&mut dst_dir);
            self.put_inode(to, &mut dst_dir)?;
        } else {
            self.dir_add(to, &mut dst_dir, new_name, e.ino, ftype(moved.kind()))?;
            self.dir_remove(from, &src_dir, &e.name)?;
            self.touch_dir(&mut src_dir);
            self.touch_dir(&mut dst_dir);
            if moved.is_dir() {
                self.dir_set_parent(e.ino, &moved, to)?;
                dec_dir_links(&mut src_dir);
                inc_links(&mut dst_dir);
            }
            self.put_inode(from, &mut src_dir)?;
            self.put_inode(to, &mut dst_dir)?;
        }
        set_ctime(&mut moved, Time::now());
        self.put_inode(e.ino, &mut moved)
    }

    /// Same file, different case, in a casefold-style match: rewrite the name only.
    fn rename_case(&mut self, dir: u32, raw: &mut Vec<u8>, e: &crate::dir::Ent, new_name: &[u8]) -> Result<()> {
        self.dir_remove(dir, raw, &e.name)?;
        self.dir_add(dir, raw, new_name, e.ino, e.ftype)?;
        self.put_inode(dir, raw)
    }

    fn op_write(&mut self, ino: u32, off: u64, data: &[u8]) -> Result<usize> {
        let mut raw = self.inode(ino)?;
        match raw.kind() {
            FileKind::File => {}
            FileKind::Dir => return Err(FsError::IsDir),
            _ => return Err(FsError::Invalid("not a regular file")),
        }
        if raw.flags() & F_INLINE != 0 {
            return Err(FsError::ReadOnly);
        }
        let n = self.write_data(ino, &mut raw, off, data)?;
        let now = Time::now();
        set_mtime(&mut raw, now);
        set_ctime(&mut raw, now);
        self.put_inode(ino, &mut raw)?;
        Ok(n)
    }

    fn op_set_attr(&mut self, ino: u32, a: &SetAttr) -> Result<Stat> {
        let mut raw = self.inode(ino)?;
        if let Some(size) = a.size {
            if raw.kind() != FileKind::File {
                return Err(FsError::Invalid("not a regular file"));
            }
            if size != raw.size() {
                self.truncate_to(ino, &mut raw, size)?;
                set_mtime(&mut raw, Time::now());
            }
        }
        if let Some(m) = a.mode {
            let v = (raw.mode() & S_IFMT) | (m & 0o7777) as u16;
            raw.put_u16(0, v);
        }
        if let Some(u) = a.uid {
            set_uid(&mut raw, u);
        }
        if let Some(g) = a.gid {
            set_gid(&mut raw, g);
        }
        if let Some(t) = a.atime {
            set_atime(&mut raw, t);
        }
        if let Some(t) = a.mtime {
            set_mtime(&mut raw, t);
        }
        if let Some(t) = a.crtime {
            set_crtime(&mut raw, t);
        }
        set_ctime(&mut raw, Time::now());
        self.put_inode(ino, &mut raw)?;
        Ok(self.stat_of(ino, &raw))
    }

    /// Walks all in-use inodes, validating metadata checksums and block references.
    fn scrub_all(&self, progress: &mut dyn FnMut(u64, u64)) -> Result<CheckReport> {
        let mut rep = CheckReport::default();
        let total = self.g.inodes as u64;
        for g in 0..self.g.groups {
            if self.gd_flags(g) & crate::alloc::BG_INODE_UNINIT != 0 {
                continue;
            }
            let bm = self.block(self.inode_bitmap_loc(g))?;
            for bit in 0..self.g.ipg as usize {
                if bm[bit / 8] & (1 << (bit % 8)) == 0 {
                    continue;
                }
                let ino = g * self.g.ipg + bit as u32 + 1;
                let check = |ino: u32| -> Result<u64> {
                    let raw = self.inode(ino)?;
                    if raw.flags() & F_EXTENTS != 0 {
                        self.ext_verify(ino, &raw)?;
                    }
                    if raw.is_dir() {
                        self.dir_verify(ino, &raw)?;
                    }
                    Ok(self.i_blocks(&raw) * 512)
                };
                match check(ino) {
                    Ok(n) => rep.scanned_bytes += n,
                    Err(e) => rep.errors.push(format!("inode {ino}: {e}")),
                }
                if ino.is_multiple_of(4096) {
                    progress(ino as u64, total);
                }
            }
        }
        progress(total, total);
        Ok(rep)
    }
}

impl Ext4 {
    fn read_lock(&self) -> Result<RwLockReadGuard<'_, Fs>> {
        self.fs.read().map_err(|_| FsError::Corrupt("engine stopped after an internal error".into()))
    }

    fn write_lock(&self) -> Result<RwLockWriteGuard<'_, Fs>> {
        self.fs.write().map_err(|_| FsError::Corrupt("engine stopped after an internal error".into()))
    }

    /// Runs one mutation as an atomic step of the transaction.
    fn op<T>(&self, f: impl FnOnce(&mut Fs) -> Result<T>) -> Result<T> {
        let mut fs = self.write_lock()?;
        fs.require_write()?;
        fs.make_room()?;
        fs.begin_op();
        match f(&mut fs) {
            Ok(v) => {
                fs.undo = None;
                Ok(v)
            }
            Err(FsError::NoSpace) if !fs.pending_free.is_empty() => {
                // Space freed earlier in this transaction becomes usable after a commit,
                // but the failed call must be retried by the caller.
                fs.rollback_op();
                fs.commit()?;
                Err(FsError::NoSpace)
            }
            Err(e) => {
                fs.rollback_op();
                Err(e)
            }
        }
    }
}

impl Filesystem for Ext4 {
    fn info(&self) -> VolumeInfo {
        self.read_lock().map(|f| f.volume_info()).unwrap_or_default()
    }

    fn root(&self) -> Ino {
        ino_of(ROOT_INO)
    }

    fn lookup(&self, dir: Ino, name: &[u8]) -> Result<Ino> {
        let f = self.read_lock()?;
        let d = id(dir)?;
        let raw = f.inode(d)?;
        let e = f.dir_lookup(d, &raw, name)?.ok_or(FsError::NotFound)?;
        Ok(ino_of(e.ino))
    }

    fn stat(&self, ino: Ino) -> Result<Stat> {
        let f = self.read_lock()?;
        let n = id(ino)?;
        Ok(f.stat_of(n, &f.inode(n)?))
    }

    fn read_dir(&self, dir: Ino, start: u64, out: &mut dyn FnMut(u64, DirEntry) -> bool) -> Result<()> {
        let f = self.read_lock()?;
        let d = id(dir)?;
        let raw = f.inode(d)?;
        if !raw.is_dir() {
            return Err(FsError::NotDir);
        }
        f.dir_list(d, &raw, start, &mut |next, e| {
            let kind = if f.g.filetype {
                FileKind::from_dirent(e.ftype)
            } else {
                f.inode(e.ino).map_or(FileKind::Unknown, |r| r.kind())
            };
            out(next, DirEntry { name: e.name, ino: ino_of(e.ino), kind })
        })
    }

    fn read(&self, ino: Ino, off: u64, buf: &mut [u8]) -> Result<usize> {
        let f = self.read_lock()?;
        let n = id(ino)?;
        let raw = f.inode(n)?;
        if raw.is_dir() {
            return Err(FsError::IsDir);
        }
        f.read_data(n, &raw, off, buf)
    }

    fn read_link(&self, ino: Ino) -> Result<Vec<u8>> {
        let f = self.read_lock()?;
        let n = id(ino)?;
        let raw = f.inode(n)?;
        if raw.kind() != FileKind::Symlink {
            return Err(FsError::Invalid("not a symlink"));
        }
        let size = raw.size() as usize;
        if size > f.g.bs.max(FAST_SYMLINK) {
            return corrupt("symlink target too long");
        }
        if f.i_blocks(&raw) == 0 && raw.flags() & (F_EXTENTS | F_INLINE) == 0 && size < FAST_SYMLINK {
            return Ok(raw[I_BLOCK..I_BLOCK + size].to_vec());
        }
        let mut v = vec![0; size];
        let got = f.read_data(n, &raw, 0, &mut v)?;
        v.truncate(got);
        Ok(v)
    }

    fn list_xattrs(&self, ino: Ino) -> Result<Vec<Vec<u8>>> {
        let f = self.read_lock()?;
        let raw = f.inode(id(ino)?)?;
        Ok(f.xattrs(&raw)?.into_iter().map(|x| x.name).collect())
    }

    fn get_xattr(&self, ino: Ino, name: &[u8]) -> Result<Vec<u8>> {
        let f = self.read_lock()?;
        let raw = f.inode(id(ino)?)?;
        let x = f.xattrs(&raw)?.into_iter().find(|x| x.name == name);
        x.map(|x| x.value).ok_or(FsError::NotFound)
    }

    fn create(&self, dir: Ino, name: &[u8], node: NewNode, owner: Owner) -> Result<Ino> {
        let d = id(dir)?;
        self.op(|f| f.op_create(d, name, &node, owner)).map(ino_of)
    }

    fn link(&self, ino: Ino, dir: Ino, name: &[u8]) -> Result<()> {
        let (n, d) = (id(ino)?, id(dir)?);
        self.op(|f| f.op_link(n, d, name))
    }

    fn unlink(&self, dir: Ino, name: &[u8]) -> Result<()> {
        let d = id(dir)?;
        self.op(|f| f.op_unlink(d, name))
    }

    fn rmdir(&self, dir: Ino, name: &[u8]) -> Result<()> {
        let d = id(dir)?;
        self.op(|f| f.op_rmdir(d, name))
    }

    fn rename(&self, from: Ino, name: &[u8], to: Ino, new_name: &[u8], replace: bool) -> Result<()> {
        let (a, b) = (id(from)?, id(to)?);
        self.op(|f| f.op_rename(a, name, b, new_name, replace))
    }

    fn write(&self, ino: Ino, off: u64, data: &[u8]) -> Result<usize> {
        let n = id(ino)?;
        self.op(|f| f.op_write(n, off, data))
    }

    fn set_attr(&self, ino: Ino, attr: &SetAttr) -> Result<Stat> {
        let n = id(ino)?;
        self.op(|f| f.op_set_attr(n, attr))
    }

    fn sync(&self) -> Result<()> {
        self.write_lock()?.commit()
    }

    fn unmount(&self) -> Result<()> {
        self.write_lock()?.clean_unmount()
    }

    fn scrub(&self, progress: &mut dyn FnMut(u64, u64)) -> Result<CheckReport> {
        self.read_lock()?.scrub_all(progress)
    }
}
