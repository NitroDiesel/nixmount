//! The [`Filesystem`] implementation. Operations validate first and mutate after, so a
//! request that is merely invalid can never leave the transaction half-changed; anything
//! worse aborts the whole transaction, which copy-on-write makes free of consequences.
use crate::file::{FileExtent, E_INLINE};
use crate::inode::*;
use crate::mount::Btrfs;
use crate::*;
use fscore::{
    crc32c_raw, CheckReport, DirEntry, FileKind, Filesystem, Ino, Le, LeMut, NewNode, Owner, SetAttr, Stat, Subvolume, Time,
    VolumeInfo,
};
use std::sync::{RwLockReadGuard, RwLockWriteGuard};

pub fn check_name(name: &[u8]) -> Result<()> {
    if name.is_empty() || name == b"." || name == b".." || name.contains(&b'/') || name.contains(&0) {
        return Err(FsError::Invalid("bad file name"));
    }
    if name.len() > 255 {
        return Err(FsError::NameTooLong);
    }
    Ok(())
}

fn ftype_of(k: FileKind) -> u8 {
    match k {
        FileKind::File => FT_REG,
        FileKind::Dir => FT_DIR,
        FileKind::Symlink => FT_SYMLINK,
        FileKind::CharDev => 3,
        FileKind::BlockDev => 4,
        FileKind::Fifo => 5,
        FileKind::Socket => 6,
        FileKind::Unknown => 0,
    }
}

impl Fs {
    /// A brand new empty leaf owned by `tree`.
    pub fn fresh_leaf(&mut self, tree: u64) -> Result<u64> {
        self.new_leaf_block(tree)
    }

    fn next_ino(&self, tree: u64) -> Result<u64> {
        let root = self.tree(tree)?;
        let top = self.find_le(root, Key::new(LAST_FREE, 255, u64::MAX))?;
        Ok(top.map_or(FIRST_FREE, |(k, _)| k.obj + 1).max(FIRST_FREE + 1))
    }

    pub fn next_dir_index(&self, dir: Ino) -> Result<u64> {
        let root = self.tree(dir.tree)?;
        let last = self.find_le(root, Key::new(dir.id, K_DIR_INDEX, u64::MAX))?;
        Ok(match last {
            Some((k, _)) if k.obj == dir.id && k.ty == K_DIR_INDEX => k.off + 1,
            _ => 2,
        })
    }

    pub fn write_inode(&mut self, ino: Ino, item: &[u8]) -> Result<()> {
        let gen = self.txn.gen;
        let seq = item.u64_at(72) + 1;
        let mut v = item.to_vec();
        v.put_u64(8, gen);
        v.put_u64(72, seq);
        self.update_item(ino.tree, Key::new(ino.id, K_INODE_ITEM, 0), |d| d.copy_from_slice(&v))
    }

    /// Adds DIR_ITEM and DIR_INDEX entries. Names with equal hashes share one DIR_ITEM.
    pub fn add_dir_entries(&mut self, dir: Ino, loc: Key, ft: u8, name: &[u8], index: u64) -> Result<()> {
        let e = dir_item(loc, self.txn.gen, ft, name);
        let k = Key::new(dir.id, K_DIR_ITEM, name_hash(name));
        let root = self.tree(dir.tree)?;
        match self.get(root, k)? {
            Some(mut old) => {
                old.extend_from_slice(&e);
                self.put_item(dir.tree, k, &old)?;
            }
            None => self.insert_item(dir.tree, k, &e)?,
        }
        self.insert_item(dir.tree, Key::new(dir.id, K_DIR_INDEX, index), &e)
    }

    pub fn remove_dir_entries(&mut self, dir: Ino, name: &[u8], index: u64) -> Result<()> {
        let k = Key::new(dir.id, K_DIR_ITEM, name_hash(name));
        let root = self.tree(dir.tree)?;
        let Some(d) = self.get(root, k)? else { return bad("directory entry vanished") };
        let rest: Vec<DirItem> = parse_dir_items(&d)?.into_iter().filter(|e| e.name != name).collect();
        if rest.is_empty() {
            self.delete_item(dir.tree, k)?;
        } else {
            let mut v = vec![];
            for e in rest {
                let mut b = dir_item(e.location, self.txn.gen, e.ftype, &e.name);
                let dl = e.data.len() as u16;
                b.put_u16(25, dl);
                b.extend_from_slice(&e.data);
                v.extend_from_slice(&b);
            }
            self.put_item(dir.tree, k, &v)?;
        }
        self.delete_item(dir.tree, Key::new(dir.id, K_DIR_INDEX, index))
    }

    /// Adds the inode-side backreference for a new name.
    fn add_inode_ref(&mut self, ino: Ino, parent: u64, index: u64, name: &[u8]) -> Result<()> {
        let k = Key::new(ino.id, K_INODE_REF, parent);
        let root = self.tree(ino.tree)?;
        let e = inode_ref(index, name);
        match self.get(root, k)? {
            Some(mut old) => {
                if old.len() + e.len() > self.nodesize / 2 {
                    return Err(FsError::TooManyLinks);
                }
                old.extend_from_slice(&e);
                self.put_item(ino.tree, k, &old)
            }
            None => self.insert_item(ino.tree, k, &e),
        }
    }

    fn extref_key(ino: u64, parent: u64, name: &[u8]) -> Key {
        Key::new(ino, K_INODE_EXTREF, crc32c_raw(parent as u32, name) as u64)
    }

    /// Finds the link `name` under `parent`, in either backreference form.
    fn find_link(&self, ino: Ino, parent: u64, name: &[u8]) -> Result<Link> {
        let root = self.tree(ino.tree)?;
        if let Some(d) = self.get(root, Key::new(ino.id, K_INODE_REF, parent))? {
            if let Some(l) = parse_inode_refs(parent, &d)?.into_iter().find(|l| l.name == name) {
                return Ok(l);
            }
        }
        if let Some(d) = self.get(root, Self::extref_key(ino.id, parent, name))? {
            if let Some(l) = parse_extrefs(&d)?.into_iter().find(|l| l.name == name && l.parent == parent) {
                return Ok(l);
            }
        }
        bad("inode has no back reference for this name")
    }

    fn remove_link(&mut self, ino: Ino, l: &Link) -> Result<()> {
        let root = self.tree(ino.tree)?;
        if !l.ext {
            let k = Key::new(ino.id, K_INODE_REF, l.parent);
            let Some(d) = self.get(root, k)? else { return bad("inode ref vanished") };
            let rest: Vec<Link> = parse_inode_refs(l.parent, &d)?.into_iter().filter(|x| x.name != l.name).collect();
            if rest.is_empty() {
                return self.delete_item(ino.tree, k);
            }
            let v: Vec<u8> = rest.iter().flat_map(|x| inode_ref(x.index, &x.name)).collect();
            return self.put_item(ino.tree, k, &v);
        }
        let k = Self::extref_key(ino.id, l.parent, &l.name);
        let Some(d) = self.get(root, k)? else { return bad("inode extref vanished") };
        let rest: Vec<Link> = parse_extrefs(&d)?
            .into_iter()
            .filter(|x| !(x.name == l.name && x.parent == l.parent))
            .collect();
        if rest.is_empty() {
            return self.delete_item(ino.tree, k);
        }
        let mut v = vec![];
        for x in rest {
            let mut b = vec![0u8; 18 + x.name.len()];
            b.put_u64(0, x.parent);
            b.put_u64(8, x.index);
            b.put_u16(16, x.name.len() as u16);
            b[18..].copy_from_slice(&x.name);
            v.extend_from_slice(&b);
        }
        self.put_item(ino.tree, k, &v)
    }

    pub fn bump_dir(&self, item: &mut [u8], delta: i64) {
        let size = (item.u64_at(O_SIZE) as i64 + delta).max(0) as u64;
        item.put_u64(O_SIZE, size);
        let now = Time::now();
        put_time(item, O_MTIME, now);
        put_time(item, O_CTIME, now);
    }

    fn new_inode_item(&self, mode: u32, owner: Owner, nlink: u32) -> Vec<u8> {
        let mut b = vec![0u8; INODE_SIZE];
        b.put_u64(0, self.txn.gen);
        b.put_u64(8, self.txn.gen);
        b.put_u32(O_NLINK, nlink);
        b.put_u32(44, owner.uid);
        b.put_u32(48, owner.gid);
        b.put_u32(O_MODE, mode);
        let now = Time::now();
        for o in [O_ATIME, O_CTIME, O_MTIME, O_OTIME] {
            put_time(&mut b, o, now);
        }
        b
    }

    fn max_inline(&self) -> usize {
        (self.sectorsize - 1).min(self.nodesize - tree::HDR - tree::LEAF_ITEM - 21 - 256)
    }

    fn op_create(&mut self, dir: Ino, name: &[u8], node: &NewNode, owner: Owner) -> Result<Ino> {
        check_name(name)?;
        self.check_writable_tree(dir.tree)?;
        let mut parent = self.inode_item(dir)?;
        if FileKind::from_mode(parent.u32_at(O_MODE)) != FileKind::Dir {
            return Err(FsError::NotDir);
        }
        if self.dir_lookup(dir, name)?.is_some() {
            return Err(FsError::Exists);
        }
        if let NewNode::Symlink(t) = node {
            if t.is_empty() || t.len() > self.max_inline() {
                return Err(FsError::Invalid("bad symlink target"));
            }
        }
        let id = self.next_ino(dir.tree)?;
        let ino = Ino { tree: dir.tree, id };
        let perm = owner.mode & 0o7777;
        let (mode, ft) = match node {
            NewNode::File => (S_IFREG | perm, FT_REG),
            NewNode::Dir => (S_IFDIR | perm, FT_DIR),
            NewNode::Symlink(_) => (S_IFLNK | 0o777, FT_SYMLINK),
        };
        let mut item = self.new_inode_item(mode, owner, 1);
        if let NewNode::Symlink(t) = node {
            item.put_u64(O_SIZE, t.len() as u64);
            item.put_u64(O_NBYTES, t.len() as u64);
            let mut e = vec![0u8; 21];
            e.put_u64(0, self.txn.gen);
            e.put_u64(8, t.len() as u64);
            e.extend_from_slice(t);
            self.insert_item(dir.tree, Key::new(id, K_EXTENT_DATA, 0), &e)?;
        }
        self.insert_item(dir.tree, Key::new(id, K_INODE_ITEM, 0), &item)?;
        let index = self.next_dir_index(dir)?;
        self.add_inode_ref(ino, dir.id, index, name)?;
        self.add_dir_entries(dir, Key::new(id, K_INODE_ITEM, 0), ft, name, index)?;
        self.bump_dir(&mut parent, 2 * name.len() as i64);
        self.write_inode(dir, &parent)?;
        Ok(ino)
    }

    fn lookup_entry(&self, dir: Ino, name: &[u8]) -> Result<(Ino, DirItem)> {
        self.dir_lookup(dir, name)?.ok_or(FsError::NotFound)
    }

    /// Deletes every item of an inode whose last link is gone.
    fn drop_inode(&mut self, ino: Ino, item: &mut [u8]) -> Result<()> {
        self.drop_extents(ino, item, 0, u64::MAX)?;
        let root = self.tree(ino.tree)?;
        let mut keys = vec![];
        self.scan(root, Key::new(ino.id, 0, 0), &mut |k, _| {
            if k.obj != ino.id {
                return Ok(false);
            }
            keys.push(k);
            Ok(true)
        })?;
        for k in keys {
            self.delete_item(ino.tree, k)?;
        }
        Ok(())
    }

    fn unlink_name(&mut self, dir: Ino, parent: &mut [u8], ino: Ino, name: &[u8]) -> Result<Link> {
        let link = self.find_link(ino, dir.id, name)?;
        self.remove_dir_entries(dir, name, link.index)?;
        self.remove_link(ino, &link)?;
        self.bump_dir(parent, -2 * name.len() as i64);
        Ok(link)
    }

    fn dec_link(&mut self, ino: Ino, item: &mut Vec<u8>) -> Result<()> {
        let links = item.u32_at(O_NLINK);
        if links <= 1 {
            return self.drop_inode(ino, item);
        }
        item.put_u32(O_NLINK, links - 1);
        put_time(item, O_CTIME, Time::now());
        self.write_inode(ino, item)
    }

    fn op_unlink(&mut self, dir: Ino, name: &[u8]) -> Result<()> {
        self.check_writable_tree(dir.tree)?;
        let (ino, e) = self.lookup_entry(dir, name)?;
        if e.ftype == FT_DIR {
            return Err(FsError::IsDir);
        }
        let mut parent = self.inode_item(dir)?;
        let mut item = self.inode_item(ino)?;
        self.unlink_name(dir, &mut parent, ino, name)?;
        self.write_inode(dir, &parent)?;
        self.dec_link(ino, &mut item)
    }

    fn dir_is_empty(&self, dir: Ino) -> Result<bool> {
        let mut empty = true;
        self.dir_list(dir, 0, &mut |_, _| {
            empty = false;
            false
        })?;
        Ok(empty)
    }

    fn op_rmdir(&mut self, dir: Ino, name: &[u8]) -> Result<()> {
        self.check_writable_tree(dir.tree)?;
        let (ino, e) = self.lookup_entry(dir, name)?;
        if e.ftype != FT_DIR {
            return Err(FsError::NotDir);
        }
        if e.location.ty == K_ROOT_ITEM {
            return Err(FsError::Unsupported("deleting subvolumes is not supported yet".into()));
        }
        if !self.dir_is_empty(ino)? {
            return Err(FsError::NotEmpty);
        }
        let mut parent = self.inode_item(dir)?;
        let mut item = self.inode_item(ino)?;
        self.unlink_name(dir, &mut parent, ino, name)?;
        self.write_inode(dir, &parent)?;
        self.drop_inode(ino, &mut item)
    }

    fn op_link(&mut self, ino: Ino, dir: Ino, name: &[u8]) -> Result<()> {
        check_name(name)?;
        self.check_writable_tree(dir.tree)?;
        if ino.tree != dir.tree {
            return Err(FsError::CrossDevice);
        }
        let mut item = self.inode_item(ino)?;
        let kind = FileKind::from_mode(item.u32_at(O_MODE));
        if kind == FileKind::Dir {
            return Err(FsError::IsDir);
        }
        if self.dir_lookup(dir, name)?.is_some() {
            return Err(FsError::Exists);
        }
        let links = item.u32_at(O_NLINK);
        if links >= 65535 {
            return Err(FsError::TooManyLinks);
        }
        let mut parent = self.inode_item(dir)?;
        let index = self.next_dir_index(dir)?;
        self.add_inode_ref(ino, dir.id, index, name)?;
        self.add_dir_entries(dir, Key::new(ino.id, K_INODE_ITEM, 0), ftype_of(kind), name, index)?;
        self.bump_dir(&mut parent, 2 * name.len() as i64);
        self.write_inode(dir, &parent)?;
        item.put_u32(O_NLINK, links + 1);
        put_time(&mut item, O_CTIME, Time::now());
        self.write_inode(ino, &item)
    }

    fn parent_of(&self, ino: Ino) -> Result<Option<u64>> {
        let root = self.tree(ino.tree)?;
        let mut out = None;
        self.scan(root, Key::new(ino.id, K_INODE_REF, 0), &mut |k, _| {
            if k.obj == ino.id && k.ty == K_INODE_REF {
                out = Some(k.off);
            }
            Ok(false)
        })?;
        Ok(out)
    }

    fn check_not_ancestor(&self, moved: Ino, target: Ino) -> Result<()> {
        let mut cur = target.id;
        for _ in 0..4096 {
            if cur == moved.id {
                return Err(FsError::Invalid("cannot move a directory into itself"));
            }
            match self.parent_of(Ino { tree: moved.tree, id: cur })? {
                Some(p) if p != cur => cur = p,
                _ => return Ok(()),
            }
        }
        bad("directory tree is too deep or has a cycle")
    }

    fn op_rename(&mut self, from: Ino, name: &[u8], to: Ino, new_name: &[u8], replace: bool) -> Result<()> {
        check_name(new_name)?;
        self.check_writable_tree(from.tree)?;
        if from.tree != to.tree {
            return Err(FsError::CrossDevice);
        }
        let (ino, e) = self.lookup_entry(from, name)?;
        if e.location.ty == K_ROOT_ITEM {
            return Err(FsError::Unsupported("moving subvolumes is not supported yet".into()));
        }
        let is_dir = e.ftype == FT_DIR;
        if is_dir && from != to {
            self.check_not_ancestor(ino, to)?;
        }
        let target = self.dir_lookup(to, new_name)?;
        if let Some((t, te)) = &target {
            if *t == ino {
                return Ok(());
            }
            if !replace {
                return Err(FsError::Exists);
            }
            if te.location.ty == K_ROOT_ITEM {
                return Err(FsError::Exists);
            }
            match (te.ftype == FT_DIR, is_dir) {
                (true, false) => return Err(FsError::IsDir),
                (false, true) => return Err(FsError::NotDir),
                (true, true) if !self.dir_is_empty(*t)? => return Err(FsError::NotEmpty),
                _ => {}
            }
        }
        if let Some((t, te)) = target {
            let mut dst = self.inode_item(to)?;
            let mut victim = self.inode_item(t)?;
            self.unlink_name(to, &mut dst, t, new_name)?;
            self.write_inode(to, &dst)?;
            if te.ftype == FT_DIR {
                self.drop_inode(t, &mut victim)?;
            } else {
                self.dec_link(t, &mut victim)?;
            }
        }
        let mut src = self.inode_item(from)?;
        self.unlink_name(from, &mut src, ino, name)?;
        self.write_inode(from, &src)?;
        let mut dst = self.inode_item(to)?;
        let index = self.next_dir_index(to)?;
        self.add_inode_ref(ino, to.id, index, new_name)?;
        self.add_dir_entries(to, e.location, e.ftype, new_name, index)?;
        self.bump_dir(&mut dst, 2 * new_name.len() as i64);
        self.write_inode(to, &dst)?;
        let mut item = self.inode_item(ino)?;
        put_time(&mut item, O_CTIME, Time::now());
        self.write_inode(ino, &item)
    }

    fn op_write(&mut self, ino: Ino, off: u64, data: &[u8]) -> Result<usize> {
        self.check_writable_tree(ino.tree)?;
        let mut item = self.inode_item(ino)?;
        match FileKind::from_mode(item.u32_at(O_MODE)) {
            FileKind::File => {}
            FileKind::Dir => return Err(FsError::IsDir),
            _ => return Err(FsError::Invalid("not a regular file")),
        }
        if off.checked_add(data.len() as u64).is_none_or(|e| e > i64::MAX as u64) {
            return Err(FsError::Invalid("file would exceed the maximum size"));
        }
        self.write_file(ino, &mut item, off, data)?;
        self.write_inode(ino, &item)?;
        self.txn.touched = true;
        Ok(data.len())
    }

    fn op_set_attr(&mut self, ino: Ino, a: &SetAttr) -> Result<Stat> {
        self.check_writable_tree(ino.tree)?;
        let mut item = self.inode_item(ino)?;
        if let Some(size) = a.size {
            if FileKind::from_mode(item.u32_at(O_MODE)) != FileKind::File {
                return Err(FsError::Invalid("not a regular file"));
            }
            self.truncate_file(ino, &mut item, size)?;
        }
        if let Some(m) = a.mode {
            let v = (item.u32_at(O_MODE) & S_IFMT) | (m & 0o7777);
            item.put_u32(O_MODE, v);
        }
        if let Some(u) = a.uid {
            item.put_u32(44, u);
        }
        if let Some(g) = a.gid {
            item.put_u32(48, g);
        }
        if let Some(t) = a.atime {
            put_time(&mut item, O_ATIME, t);
        }
        if let Some(t) = a.mtime {
            put_time(&mut item, O_MTIME, t);
        }
        if let Some(t) = a.crtime {
            put_time(&mut item, O_OTIME, t);
        }
        put_time(&mut item, O_CTIME, Time::now());
        self.write_inode(ino, &item)?;
        Ok(self.stat_of(ino, &item))
    }

    fn read_symlink(&self, ino: Ino) -> Result<Vec<u8>> {
        let root = self.tree(ino.tree)?;
        let Some(d) = self.get(root, Key::new(ino.id, K_EXTENT_DATA, 0))? else {
            return bad("symlink has no target");
        };
        let e = FileExtent::parse(&d)?;
        if e.kind != E_INLINE {
            return bad("symlink target is not inline");
        }
        let mut v = vec![0u8; e.ram_bytes.min(65536) as usize];
        let item = self.inode_item(ino)?;
        let n = self.read_file(ino, &item, 0, &mut v)?;
        v.truncate(n);
        Ok(v)
    }
}

impl Btrfs {
    fn read_lock(&self) -> Result<RwLockReadGuard<'_, Fs>> {
        self.fs.read().map_err(|_| FsError::Corrupt("engine stopped after an internal error".into()))
    }

    fn write_lock(&self) -> Result<RwLockWriteGuard<'_, Fs>> {
        self.fs.write().map_err(|_| FsError::Corrupt("engine stopped after an internal error".into()))
    }

    /// Runs one mutation, reserving space for it up front.
    fn op<T>(&self, data: u64, f: impl FnOnce(&mut Fs) -> Result<T>) -> Result<T> {
        let mut fs = self.write_lock()?;
        if fs.read_only {
            return Err(FsError::ReadOnly);
        }
        fs.ensure_space(data)?;
        match f(&mut fs) {
            Ok(v) => {
                fs.maybe_commit()?;
                Ok(v)
            }
            // These are all raised before anything changes.
            Err(
                e @ (FsError::NotFound
                | FsError::Exists
                | FsError::NotDir
                | FsError::IsDir
                | FsError::NotEmpty
                | FsError::NameTooLong
                | FsError::TooManyLinks
                | FsError::ReadOnly
                | FsError::CrossDevice
                | FsError::Invalid(_)
                | FsError::Unsupported(_)),
            ) => Err(e),
            Err(e) => {
                fs.abort(&e);
                Err(e)
            }
        }
    }
}

impl Filesystem for Btrfs {
    fn info(&self) -> VolumeInfo {
        self.read_lock().map(|f| f.volume_info()).unwrap_or_default()
    }

    fn root(&self) -> Ino {
        let tree = self.read_lock().map_or(FS_TREE, |f| f.default_subvol);
        Ino { tree, id: FIRST_FREE }
    }

    fn lookup(&self, dir: Ino, name: &[u8]) -> Result<Ino> {
        let f = self.read_lock()?;
        f.dir_lookup(dir, name)?.map(|x| x.0).ok_or(FsError::NotFound)
    }

    fn stat(&self, ino: Ino) -> Result<Stat> {
        let f = self.read_lock()?;
        let item = f.inode_item(ino)?;
        Ok(f.stat_of(ino, &item))
    }

    fn read_dir(&self, dir: Ino, start: u64, out: &mut dyn FnMut(u64, DirEntry) -> bool) -> Result<()> {
        let f = self.read_lock()?;
        if FileKind::from_mode(f.inode_item(dir)?.u32_at(O_MODE)) != FileKind::Dir {
            return Err(FsError::NotDir);
        }
        f.dir_list(dir, start, out)
    }

    fn read(&self, ino: Ino, off: u64, buf: &mut [u8]) -> Result<usize> {
        let f = self.read_lock()?;
        let item = f.inode_item(ino)?;
        if FileKind::from_mode(item.u32_at(O_MODE)) == FileKind::Dir {
            return Err(FsError::IsDir);
        }
        f.read_file(ino, &item, off, buf)
    }

    fn read_link(&self, ino: Ino) -> Result<Vec<u8>> {
        self.read_lock()?.read_symlink(ino)
    }

    fn list_xattrs(&self, ino: Ino) -> Result<Vec<Vec<u8>>> {
        Ok(self.read_lock()?.xattrs(ino)?.into_iter().map(|x| x.name).collect())
    }

    fn get_xattr(&self, ino: Ino, name: &[u8]) -> Result<Vec<u8>> {
        let x = self.read_lock()?.xattrs(ino)?.into_iter().find(|x| x.name == name);
        x.map(|x| x.data).ok_or(FsError::NotFound)
    }

    fn create(&self, dir: Ino, name: &[u8], node: NewNode, owner: Owner) -> Result<Ino> {
        self.op(0, |f| f.op_create(dir, name, &node, owner))
    }

    fn link(&self, ino: Ino, dir: Ino, name: &[u8]) -> Result<()> {
        self.op(0, |f| f.op_link(ino, dir, name))
    }

    fn unlink(&self, dir: Ino, name: &[u8]) -> Result<()> {
        self.op(0, |f| f.op_unlink(dir, name))
    }

    fn rmdir(&self, dir: Ino, name: &[u8]) -> Result<()> {
        self.op(0, |f| f.op_rmdir(dir, name))
    }

    fn rename(&self, from: Ino, name: &[u8], to: Ino, new_name: &[u8], replace: bool) -> Result<()> {
        self.op(0, |f| f.op_rename(from, name, to, new_name, replace))
    }

    fn write(&self, ino: Ino, off: u64, data: &[u8]) -> Result<usize> {
        self.op(data.len() as u64 + 2 * 65536, |f| f.op_write(ino, off, data))
    }

    fn set_attr(&self, ino: Ino, attr: &SetAttr) -> Result<Stat> {
        self.op(2 * 65536, |f| f.op_set_attr(ino, attr))
    }

    fn sync(&self) -> Result<()> {
        self.write_lock()?.commit()
    }

    fn unmount(&self) -> Result<()> {
        let mut f = self.write_lock()?;
        f.commit()?;
        f.read_only = true;
        Ok(())
    }

    fn scrub(&self, progress: &mut dyn FnMut(u64, u64)) -> Result<CheckReport> {
        self.read_lock()?.scrub_all(progress)
    }

    fn create_subvolume(&self, dir: Ino, name: &[u8]) -> Result<Ino> {
        self.op(0, |f| f.op_create_subvol(dir, name))
    }

    fn snapshot(&self, src: Ino, dir: Ino, name: &[u8], read_only: bool) -> Result<Ino> {
        self.op(0, |f| f.op_snapshot(src, dir, name, read_only))
    }

    fn subvolumes(&self, dir: Ino) -> Result<Vec<Subvolume>> {
        self.read_lock()?.list_subvols(dir)
    }

    fn delete_subvolume(&self, dir: Ino, name: &[u8]) -> Result<()> {
        self.op(0, |f| f.op_delete_subvol(dir, name))
    }
}
