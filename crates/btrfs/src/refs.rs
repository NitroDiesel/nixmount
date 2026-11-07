//! Extent reference counting. Changes queue up during an operation and are applied to
//! the extent tree in batches, because editing the extent tree itself needs new blocks.
use crate::file::{FileExtent, E_INLINE};
use crate::mount::{crc_le, IN_SKINNY};
use crate::tree::*;
use crate::*;
use fscore::{Le, LeMut};

const EF_DATA: u64 = 1;
const EF_TREE: u64 = 2;
pub const EF_FULL_BACKREF: u64 = 0x100;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ref {
    Tree { root: u64 },
    SharedTree { parent: u64 },
    Data { root: u64, ino: u64, offset: u64 },
    SharedData { parent: u64 },
}

#[derive(Clone, Copy, Debug)]
pub enum Action {
    /// First reference of a newly allocated extent.
    Create,
    Add,
    Drop,
    SetFullBackref,
}

#[derive(Clone, Copy, Debug)]
pub struct Delayed {
    pub bytenr: u64,
    pub size: u64,
    /// Tree level for metadata, None for data.
    pub level: Option<u8>,
    pub r: Ref,
    pub action: Action,
}

fn ref_hash(root: u64, ino: u64, offset: u64) -> u64 {
    let high = crc_le(!0, root);
    let low = crc_le(crc_le(!0, ino), offset);
    ((high as u64) << 31) ^ low as u64
}

/// One decoded inline reference.
#[derive(Clone, Debug)]
struct Inline {
    r: Ref,
    count: u32,
}

impl Inline {
    fn ty(&self) -> u8 {
        match self.r {
            Ref::Tree { .. } => K_TREE_BLOCK_REF,
            Ref::Data { .. } => K_EXTENT_DATA_REF,
            Ref::SharedTree { .. } => K_SHARED_BLOCK_REF,
            Ref::SharedData { .. } => K_SHARED_DATA_REF,
        }
    }
    /// Inline refs sort by type ascending, then by this value descending.
    fn seq(&self) -> u64 {
        match self.r {
            Ref::Tree { root } => root,
            Ref::SharedTree { parent } | Ref::SharedData { parent } => parent,
            Ref::Data { root, ino, offset } => ref_hash(root, ino, offset),
        }
    }
    fn encoded(&self) -> usize {
        match self.r {
            Ref::Tree { .. } | Ref::SharedTree { .. } => 9,
            Ref::Data { .. } => 29,
            Ref::SharedData { .. } => 13,
        }
    }
    fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.ty());
        match self.r {
            Ref::Tree { root } => out.extend_from_slice(&root.to_le_bytes()),
            Ref::SharedTree { parent } => out.extend_from_slice(&parent.to_le_bytes()),
            Ref::Data { root, ino, offset } => {
                out.extend_from_slice(&root.to_le_bytes());
                out.extend_from_slice(&ino.to_le_bytes());
                out.extend_from_slice(&offset.to_le_bytes());
                out.extend_from_slice(&self.count.to_le_bytes());
            }
            Ref::SharedData { parent } => {
                out.extend_from_slice(&parent.to_le_bytes());
                out.extend_from_slice(&self.count.to_le_bytes());
            }
        }
    }
}

/// A decoded extent item.
struct ExtentItem {
    refs: u64,
    generation: u64,
    flags: u64,
    /// `tree_block_info`, present on non-skinny metadata items.
    info: Vec<u8>,
    inline: Vec<Inline>,
}

impl ExtentItem {
    fn parse(key: Key, b: &[u8]) -> Result<ExtentItem> {
        if b.len() < 24 {
            return bad("extent item too short");
        }
        let flags = b.u64_at(16);
        let mut o = 24;
        let mut info = vec![];
        if key.ty == K_EXTENT_ITEM && flags & EF_TREE != 0 {
            let Some(i) = b.get(24..42) else { return bad("extent item too short") };
            info = i.to_vec();
            o = 42;
        }
        let mut inline = vec![];
        while o < b.len() {
            let ty = b.u8_at(o);
            let (r, count, size) = match ty {
                K_TREE_BLOCK_REF => (Ref::Tree { root: b.u64_at(o + 1) }, 1, 9),
                K_SHARED_BLOCK_REF => (Ref::SharedTree { parent: b.u64_at(o + 1) }, 1, 9),
                K_EXTENT_DATA_REF => {
                    let r = Ref::Data { root: b.u64_at(o + 1), ino: b.u64_at(o + 9), offset: b.u64_at(o + 17) };
                    (r, b.u32_at(o + 25), 29)
                }
                K_SHARED_DATA_REF => (Ref::SharedData { parent: b.u64_at(o + 1) }, b.u32_at(o + 9), 13),
                _ => return bad("unknown inline extent ref"),
            };
            if o + size > b.len() {
                return bad("inline ref overruns");
            }
            inline.push(Inline { r, count });
            o += size;
        }
        Ok(ExtentItem { refs: b.u64_at(0), generation: b.u64_at(8), flags, info, inline })
    }

    fn encode(&self) -> Vec<u8> {
        let mut v = vec![0u8; 24];
        v.put_u64(0, self.refs);
        v.put_u64(8, self.generation);
        v.put_u64(16, self.flags);
        v.extend_from_slice(&self.info);
        for i in &self.inline {
            i.encode(&mut v);
        }
        v
    }

    fn add_inline(&mut self, i: Inline) {
        let pos = self
            .inline
            .iter()
            .position(|x| x.ty() > i.ty() || (x.ty() == i.ty() && x.seq() < i.seq()))
            .unwrap_or(self.inline.len());
        self.inline.insert(pos, i);
    }
}

impl Fs {
    fn extent_tree(&self) -> Result<Root> {
        self.tree(EXTENT_TREE)
    }

    pub fn queue(&mut self, d: Delayed) {
        match d.action {
            Action::Add | Action::Create => *self.txn.delta.entry(d.bytenr).or_insert(0) += 1,
            Action::Drop => *self.txn.delta.entry(d.bytenr).or_insert(0) -= 1,
            Action::SetFullBackref => {
                self.txn.full_backref.insert(d.bytenr);
            }
        }
        self.txn.delayed.push(d);
    }

    pub fn queue_new_tree_block(&mut self, bytenr: u64, tree: u64, level: u8) {
        let size = self.nodesize as u64;
        self.queue(Delayed { bytenr, size, level: Some(level), r: Ref::Tree { root: tree }, action: Action::Create });
    }

    /// Releases a tree block that was unlinked from `tree`.
    pub fn drop_tree_block(&mut self, tree: u64, bytenr: u64, level: u8) {
        self.txn.nodes.remove(&bytenr);
        let size = self.nodesize as u64;
        self.queue(Delayed { bytenr, size, level: Some(level), r: Ref::Tree { root: tree }, action: Action::Drop });
    }

    pub fn queue_new_data(&mut self, bytenr: u64, size: u64, root: u64, ino: u64, offset: u64) {
        let r = Ref::Data { root, ino, offset };
        self.queue(Delayed { bytenr, size, level: None, r, action: Action::Create });
    }

    pub fn queue_data_ref(&mut self, bytenr: u64, size: u64, root: u64, ino: u64, offset: u64, delta: i64) {
        let r = Ref::Data { root, ino, offset };
        let action = if delta > 0 { Action::Add } else { Action::Drop };
        self.queue(Delayed { bytenr, size, level: None, r, action });
    }

    fn metadata_key(&self, bytenr: u64, level: u8) -> Key {
        if self.incompat & IN_SKINNY != 0 {
            Key::new(bytenr, K_METADATA_ITEM, level as u64)
        } else {
            Key::new(bytenr, K_EXTENT_ITEM, self.nodesize as u64)
        }
    }

    /// Finds an extent's item, accepting either metadata encoding.
    fn find_extent(&self, bytenr: u64, size: u64, level: Option<u8>) -> Result<Option<(Key, Vec<u8>)>> {
        let root = self.extent_tree()?;
        if let Some(l) = level {
            let k = Key::new(bytenr, K_METADATA_ITEM, l as u64);
            if let Some(v) = self.get(root, k)? {
                return Ok(Some((k, v)));
            }
        }
        let k = Key::new(bytenr, K_EXTENT_ITEM, size);
        Ok(self.get(root, k)?.map(|v| (k, v)))
    }

    /// Reference count and flags of a tree block, including queued changes.
    fn extent_info(&self, bytenr: u64, level: u8) -> Result<(u64, u64)> {
        let delta = self.txn.delta.get(&bytenr).copied().unwrap_or(0);
        let (mut refs, mut flags) = match self.find_extent(bytenr, self.nodesize as u64, Some(level))? {
            Some((_, v)) => (v.u64_at(0) as i64, v.u64_at(16)),
            // Created in this transaction and still queued.
            None => (0, EF_TREE),
        };
        refs += delta;
        if self.txn.full_backref.contains(&bytenr) {
            flags |= EF_FULL_BACKREF;
        }
        if refs < 1 {
            return bad(format!("tree block {bytenr:#x} has no references"));
        }
        refs = refs.max(1);
        Ok((refs as u64, flags))
    }

    fn is_shareable(tree: u64) -> bool {
        tree == FS_TREE || (FIRST_FREE..=LAST_FREE).contains(&tree)
    }

    fn last_snapshot(&self, tree: u64) -> Result<u64> {
        Ok(self.root_item(tree)?.1.u64_at(200))
    }

    /// Adds or drops a reference for everything `block` points at.
    fn child_refs(&mut self, block: &[u8], root: u64, parent: Option<u64>, action: Action) -> Result<()> {
        let n = nritems(block);
        let lvl = level(block);
        if lvl > 0 {
            let size = self.nodesize as u64;
            for i in 0..n {
                let bytenr = node_ptr(block, i);
                let r = parent.map_or(Ref::Tree { root }, |parent| Ref::SharedTree { parent });
                self.queue(Delayed { bytenr, size, level: Some(lvl - 1), r, action });
            }
            return Ok(());
        }
        for i in 0..n {
            let k = item_key(block, i);
            if k.ty != K_EXTENT_DATA {
                continue;
            }
            let e = FileExtent::parse(item_data(block, i))?;
            if e.kind == E_INLINE || e.is_hole() {
                continue;
            }
            let r = match parent {
                Some(parent) => Ref::SharedData { parent },
                None => Ref::Data { root, ino: k.obj, offset: k.off - e.offset },
            };
            self.queue(Delayed { bytenr: e.disk_bytenr, size: e.disk_bytes, level: None, r, action });
        }
        Ok(())
    }

    /// Reference bookkeeping when `old` is replaced by a copy in `tree`. A block still
    /// shared with a snapshot keeps its children alive for both parents.
    pub fn update_refs_for_cow(&mut self, tree: u64, old: &[u8], _new: u64) -> Result<()> {
        let logical = old.u64_at(0x30);
        let lvl = level(old);
        if Self::is_shareable(tree) {
            let root = self.tree(tree)?;
            let shared = root.bytenr != logical && generation(old) <= self.last_snapshot(tree)?;
            let (refs, flags) = if shared { self.extent_info(logical, lvl)? } else { (1, 0) };
            if refs > 1 {
                if owner(old) == tree && flags & EF_FULL_BACKREF == 0 {
                    self.child_refs(old, tree, Some(logical), Action::Add)?;
                    let size = self.nodesize as u64;
                    let r = Ref::Tree { root: tree };
                    self.queue(Delayed { bytenr: logical, size, level: Some(lvl), r, action: Action::SetFullBackref });
                } else {
                    self.child_refs(old, tree, None, Action::Add)?;
                }
            } else if flags & EF_FULL_BACKREF != 0 {
                self.child_refs(old, tree, None, Action::Add)?;
                self.child_refs(old, tree, Some(logical), Action::Drop)?;
            }
        }
        let size = self.nodesize as u64;
        let r = Ref::Tree { root: tree };
        self.queue(Delayed { bytenr: logical, size, level: Some(lvl), r, action: Action::Drop });
        Ok(())
    }

    /// Adds `tree` as a referrer of everything below a freshly copied root.
    pub fn ref_children_for_snapshot(&mut self, block: &[u8], tree: u64) -> Result<()> {
        self.child_refs(block, tree, None, Action::Add)
    }

    /// Applies all queued changes. Additions go first so a count can't touch zero early.
    pub fn run_delayed(&mut self) -> Result<()> {
        let mut batch = std::mem::take(&mut self.txn.delayed);
        self.txn.delta.clear();
        self.txn.full_backref.clear();
        batch.sort_by_key(|d| match d.action {
            Action::Create => 0,
            Action::Add => 1,
            Action::SetFullBackref => 2,
            Action::Drop => 3,
        });
        for d in batch {
            match d.action {
                Action::Create => self.create_extent(&d)?,
                Action::Add => self.add_ref(&d)?,
                Action::Drop => self.drop_ref(&d)?,
                Action::SetFullBackref => self.set_full_backref(&d)?,
            }
        }
        Ok(())
    }

    fn create_extent(&mut self, d: &Delayed) -> Result<()> {
        let count = 1;
        let mut item = ExtentItem {
            refs: 1,
            generation: self.txn.gen,
            flags: if d.level.is_some() { EF_TREE } else { EF_DATA },
            info: vec![],
            inline: vec![Inline { r: d.r, count }],
        };
        let key = match d.level {
            Some(l) => {
                let k = self.metadata_key(d.bytenr, l);
                if k.ty == K_EXTENT_ITEM {
                    // Older layout: first key is unknown here and only advisory.
                    item.info = vec![0u8; 18];
                    item.info[17] = l;
                }
                k
            }
            None => Key::new(d.bytenr, K_EXTENT_ITEM, d.size),
        };
        self.insert_item(EXTENT_TREE, key, &item.encode())?;
        self.account_extent(d.bytenr, d.size, true)
    }

    fn inline_limit(&self) -> usize {
        ((self.nodesize - HDR) >> 4).saturating_sub(LEAF_ITEM)
    }

    fn keyed(r: Ref) -> (u8, Option<u64>) {
        match r {
            Ref::Tree { root } => (K_TREE_BLOCK_REF, Some(root)),
            Ref::SharedTree { parent } => (K_SHARED_BLOCK_REF, Some(parent)),
            Ref::SharedData { parent } => (K_SHARED_DATA_REF, Some(parent)),
            Ref::Data { .. } => (K_EXTENT_DATA_REF, None),
        }
    }

    /// Locates a keyed data ref; colliding hashes occupy consecutive offsets.
    fn find_data_ref(&self, bytenr: u64, r: Ref) -> Result<(Key, Option<Vec<u8>>)> {
        let Ref::Data { root, ino, offset } = r else { return bad("not a data ref") };
        let tree = self.extent_tree()?;
        let mut k = Key::new(bytenr, K_EXTENT_DATA_REF, ref_hash(root, ino, offset));
        loop {
            match self.get(tree, k)? {
                None => return Ok((k, None)),
                Some(v) if v.u64_at(0) == root && v.u64_at(8) == ino && v.u64_at(16) == offset => {
                    return Ok((k, Some(v)));
                }
                Some(_) => k.off += 1,
            }
        }
    }

    fn add_keyed(&mut self, bytenr: u64, r: Ref) -> Result<()> {
        let tree = self.extent_tree()?;
        match r {
            Ref::Tree { .. } | Ref::SharedTree { .. } => {
                let (ty, off) = Self::keyed(r);
                self.insert_item(EXTENT_TREE, Key::new(bytenr, ty, off.unwrap_or(0)), &[])
            }
            Ref::SharedData { parent } => {
                let k = Key::new(bytenr, K_SHARED_DATA_REF, parent);
                match self.get(tree, k)? {
                    Some(v) => {
                        let c = v.u32_at(0) + 1;
                        self.update_item(EXTENT_TREE, k, |d| d.put_u32(0, c))
                    }
                    None => self.insert_item(EXTENT_TREE, k, &1u32.to_le_bytes()),
                }
            }
            Ref::Data { root, ino, offset } => {
                let (k, found) = self.find_data_ref(bytenr, r)?;
                match found {
                    Some(v) => {
                        let c = v.u32_at(24) + 1;
                        self.update_item(EXTENT_TREE, k, |d| d.put_u32(24, c))
                    }
                    None => {
                        let mut b = vec![0u8; 28];
                        b.put_u64(0, root);
                        b.put_u64(8, ino);
                        b.put_u64(16, offset);
                        b.put_u32(24, 1);
                        self.insert_item(EXTENT_TREE, k, &b)
                    }
                }
            }
        }
    }

    fn add_ref(&mut self, d: &Delayed) -> Result<()> {
        let Some((key, raw)) = self.find_extent(d.bytenr, d.size, d.level)? else {
            return bad(format!("reference to unknown extent {:#x}", d.bytenr));
        };
        let mut item = ExtentItem::parse(key, &raw)?;
        item.refs += 1;
        if let Some(i) = item.inline.iter_mut().find(|i| i.r == d.r) {
            i.count += 1;
        } else {
            let new = Inline { r: d.r, count: 1 };
            // A keyed ref of the same identity must keep absorbing counts.
            let keyed_exists = match d.r {
                Ref::Data { .. } => self.find_data_ref(d.bytenr, d.r)?.1.is_some(),
                Ref::SharedData { parent } => {
                    self.get(self.extent_tree()?, Key::new(d.bytenr, K_SHARED_DATA_REF, parent))?.is_some()
                }
                _ => false,
            };
            if !keyed_exists && raw.len() + new.encoded() < self.inline_limit() {
                item.add_inline(new);
            } else {
                self.add_keyed(d.bytenr, d.r)?;
            }
        }
        self.put_item(EXTENT_TREE, key, &item.encode())
    }

    fn drop_keyed(&mut self, bytenr: u64, r: Ref) -> Result<()> {
        let tree = self.extent_tree()?;
        match r {
            Ref::Tree { .. } | Ref::SharedTree { .. } => {
                let (ty, off) = Self::keyed(r);
                let k = Key::new(bytenr, ty, off.unwrap_or(0));
                if self.get(tree, k)?.is_none() {
                    return bad(format!("missing back reference on {bytenr:#x}"));
                }
                self.delete_item(EXTENT_TREE, k)
            }
            Ref::SharedData { parent } => {
                let k = Key::new(bytenr, K_SHARED_DATA_REF, parent);
                let Some(v) = self.get(tree, k)? else { return bad("missing shared data ref") };
                match v.u32_at(0) {
                    0 | 1 => self.delete_item(EXTENT_TREE, k),
                    c => self.update_item(EXTENT_TREE, k, |d| d.put_u32(0, c - 1)),
                }
            }
            Ref::Data { .. } => {
                let (k, found) = self.find_data_ref(bytenr, r)?;
                let Some(v) = found else { return bad(format!("missing data ref on {bytenr:#x}")) };
                match v.u32_at(24) {
                    0 | 1 => self.delete_item(EXTENT_TREE, k),
                    c => self.update_item(EXTENT_TREE, k, |d| d.put_u32(24, c - 1)),
                }
            }
        }
    }

    fn drop_ref(&mut self, d: &Delayed) -> Result<()> {
        let Some((key, raw)) = self.find_extent(d.bytenr, d.size, d.level)? else {
            return bad(format!("dropping reference to unknown extent {:#x}", d.bytenr));
        };
        let mut item = ExtentItem::parse(key, &raw)?;
        match item.inline.iter().position(|i| i.r == d.r) {
            Some(p) => {
                item.inline[p].count -= 1;
                if item.inline[p].count == 0 {
                    item.inline.remove(p);
                }
            }
            None => self.drop_keyed(d.bytenr, d.r)?,
        }
        item.refs = item.refs.saturating_sub(1);
        if item.refs == 0 {
            self.delete_item(EXTENT_TREE, key)?;
            if d.level.is_none() {
                self.delete_csums(d.bytenr, d.size)?;
            }
            self.cache.remove(d.bytenr);
            return self.account_extent(d.bytenr, d.size, false);
        }
        self.put_item(EXTENT_TREE, key, &item.encode())
    }

    fn set_full_backref(&mut self, d: &Delayed) -> Result<()> {
        let Some((key, _)) = self.find_extent(d.bytenr, d.size, d.level)? else {
            return bad("flagging unknown extent");
        };
        self.update_item(EXTENT_TREE, key, |b| {
            let f = b.u64_at(16) | EF_FULL_BACKREF;
            b.put_u64(16, f);
        })
    }
}
