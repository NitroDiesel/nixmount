//! Subvolumes and snapshots.
use crate::inode::*;
use crate::tree::{level, nritems};
use crate::*;
use fscore::{Ino, Le, LeMut, Time};
use sha2::{Digest, Sha256};

const ROOT_ITEM_SIZE: usize = 439;
const RDONLY: u64 = 1;

impl Fs {
    /// A fresh identifier. Uniqueness only matters within this filesystem's lifetime.
    fn new_uuid(&self, salt: u64) -> [u8; 16] {
        let now = Time::now();
        let mut h = Sha256::new();
        h.update(self.fsid);
        h.update(salt.to_le_bytes());
        h.update(now.sec.to_le_bytes());
        h.update(now.nsec.to_le_bytes());
        h.update(self.txn.gen.to_le_bytes());
        let mut u = [0u8; 16];
        u.copy_from_slice(&h.finalize()[..16]);
        u[6] = (u[6] & 0x0F) | 0x40;
        u[8] = (u[8] & 0x3F) | 0x80;
        u
    }

    fn next_root_id(&self) -> Result<u64> {
        let probe = Key::new(LAST_FREE, 255, u64::MAX);
        let id = self.find_le(self.root_tree, probe)?.map_or(0, |(k, _)| k.obj);
        Ok(id.max(FIRST_FREE - 1) + 1)
    }

    /// Links subvolume `id` into a directory: root refs in both directions plus the
    /// two directory entries.
    fn link_subvol(&mut self, id: u64, dir: Ino, name: &[u8]) -> Result<()> {
        let mut parent = self.inode_item(dir)?;
        let index = self.next_dir_index(dir)?;
        let mut r = vec![0u8; 18 + name.len()];
        r.put_u64(0, dir.id);
        r.put_u64(8, index);
        r.put_u16(16, name.len() as u16);
        r[18..].copy_from_slice(name);
        self.insert_item(ROOT_TREE, Key::new(dir.tree, K_ROOT_REF, id), &r)?;
        self.insert_item(ROOT_TREE, Key::new(id, K_ROOT_BACKREF, dir.tree), &r)?;
        let loc = Key::new(id, K_ROOT_ITEM, u64::MAX);
        self.add_dir_entries(dir, loc, FT_DIR, name, index)?;
        let size = parent.u64_at(O_SIZE) + 2 * name.len() as u64;
        parent.put_u64(O_SIZE, size);
        let now = Time::now();
        put_time(&mut parent, O_MTIME, now);
        put_time(&mut parent, O_CTIME, now);
        self.write_inode(dir, &parent)
    }

    fn register_uuid(&mut self, uuid: &[u8], id: u64) -> Result<()> {
        if self.root_item(UUID_TREE).is_err() {
            return Ok(());
        }
        let k = Key::new(uuid.u64_at(0), K_UUID_SUBVOL, uuid.u64_at(8));
        self.insert_item(UUID_TREE, k, &id.to_le_bytes())
    }

    /// Creates an empty subvolume in `dir`.
    pub fn op_create_subvol(&mut self, dir: Ino, name: &[u8]) -> Result<Ino> {
        ops::check_name(name)?;
        self.check_writable_tree(dir.tree)?;
        if self.dir_lookup(dir, name)?.is_some() {
            return Err(FsError::Exists);
        }
        let id = self.next_root_id()?;
        let gen = self.txn.gen;
        let now = Time::now();
        let uuid = self.new_uuid(id);

        let mut item = vec![0u8; ROOT_ITEM_SIZE];
        item.put_u64(0, 1);
        item.put_u64(O_SIZE, 3);
        item.put_u64(O_NBYTES, self.nodesize as u64);
        item.put_u32(O_NLINK, 1);
        item.put_u32(O_MODE, S_IFDIR | 0o755);
        item.put_u64(160, gen);
        item.put_u64(168, FIRST_FREE);
        item.put_u32(216, 1);
        item.put_u64(239, gen);
        item[247..263].copy_from_slice(&uuid);
        item.put_u64(295, gen);
        item.put_u64(303, gen);
        put_time(&mut item, 327, now);
        put_time(&mut item, 339, now);
        let root = self.alloc_subvol_root(id)?;
        item.put_u64(176, root.bytenr);
        self.insert_item(ROOT_TREE, Key::new(id, K_ROOT_ITEM, 0), &item)?;
        self.txn.written.insert(id, root);

        let mut inode = vec![0u8; INODE_SIZE];
        inode.put_u64(0, gen);
        inode.put_u64(8, gen);
        inode.put_u32(O_NLINK, 1);
        inode.put_u32(O_MODE, S_IFDIR | 0o755);
        for o in [O_ATIME, O_CTIME, O_MTIME, O_OTIME] {
            put_time(&mut inode, o, now);
        }
        self.insert_item(id, Key::new(FIRST_FREE, K_INODE_ITEM, 0), &inode)?;
        self.insert_item(id, Key::new(FIRST_FREE, K_INODE_REF, FIRST_FREE), &inode_ref(0, b".."))?;
        self.link_subvol(id, dir, name)?;
        self.register_uuid(&uuid, id)?;
        Ok(Ino { tree: id, id: FIRST_FREE })
    }

    fn alloc_subvol_root(&mut self, id: u64) -> Result<Root> {
        let bytenr = self.fresh_leaf(id)?;
        let r = Root { bytenr, level: 0 };
        self.set_root(id, r);
        Ok(r)
    }

    /// Snapshots the subvolume containing `src` into `dir`. Runs between two commits so
    /// that nothing in the source can be modified in place while it is being shared.
    pub fn op_snapshot(&mut self, src: Ino, dir: Ino, name: &[u8], read_only: bool) -> Result<Ino> {
        ops::check_name(name)?;
        self.check_writable_tree(dir.tree)?;
        if self.dir_lookup(dir, name)?.is_some() {
            return Err(FsError::Exists);
        }
        self.commit()?;
        let (src_key, mut item) = self.root_item(src.tree)?;
        if item.len() < ROOT_ITEM_SIZE {
            return bad("source root item is too old to snapshot");
        }
        let id = self.next_root_id()?;
        let gen = self.txn.gen;
        let now = Time::now();
        let uuid = self.new_uuid(id);

        // Copy the source root under the new tree's id.
        let source = self.cow_root_for_snapshot(src.tree)?;
        let copy = self.copy_root(id, source)?;
        self.update_item(ROOT_TREE, src_key, |d| d.put_u64(200, gen))?;
        let (lvl, node) = (copy.level, self.node(copy.bytenr, Some(copy.level))?);
        debug_assert_eq!(level(&node), lvl);
        debug_assert!(nritems(&node) > 0 || lvl == 0);
        self.ref_children_for_snapshot(&node, id)?;

        let parent_uuid = item[247..263].to_vec();
        item.put_u64(160, gen);
        item.put_u64(176, copy.bytenr);
        item.put_u8(238, copy.level);
        item.put_u64(200, gen);
        let flags = item.u64_at(208) & !RDONLY | if read_only { RDONLY } else { 0 };
        item.put_u64(208, flags);
        item.put_u32(216, 1);
        item.put_u64(239, gen);
        item[247..263].copy_from_slice(&uuid);
        item[263..279].copy_from_slice(&parent_uuid);
        item[279..295].fill(0);
        item.put_u64(295, gen);
        item.put_u64(303, gen);
        item.put_u64(311, 0);
        item.put_u64(319, 0);
        put_time(&mut item, 327, now);
        put_time(&mut item, 339, now);
        self.insert_item(ROOT_TREE, Key::new(id, K_ROOT_ITEM, gen), &item)?;
        self.txn.written.insert(id, copy);
        self.link_subvol(id, dir, name)?;
        self.register_uuid(&uuid, id)?;
        self.commit()?;
        Ok(Ino { tree: id, id: item.u64_at(168) })
    }

    pub fn check_writable_tree(&self, tree: u64) -> Result<()> {
        if self.root_item(tree)?.1.u64_at(208) & RDONLY != 0 {
            return Err(FsError::ReadOnly);
        }
        Ok(())
    }
}
