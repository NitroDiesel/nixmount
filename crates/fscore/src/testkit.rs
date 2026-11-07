//! Test tools shared by the engines: a reference model driven by random operations, and
//! a device that simulates power loss. Built only with the `testkit` feature.
use crate::dev::BlockDev;
use crate::vfs::*;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Mutex;

/// Small deterministic generator (xorshift64*), so failures reproduce from their seed.
pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Content {
    File(Vec<u8>),
    Dir,
    Link(Vec<u8>),
}

pub type Tree = BTreeMap<String, Content>;

/// Reads a whole volume into a path-to-content map.
pub fn walk(fs: &dyn Filesystem) -> Result<Tree> {
    let mut out = Tree::new();
    walk_dir(fs, fs.root(), "", &mut out, 0)?;
    Ok(out)
}

fn walk_dir(fs: &dyn Filesystem, dir: Ino, prefix: &str, out: &mut Tree, depth: u32) -> Result<()> {
    if depth > 64 {
        return Err(FsError::Corrupt("directory walk too deep".into()));
    }
    let mut ents = vec![];
    fs.read_dir(dir, 0, &mut |_, e| {
        ents.push(e);
        true
    })?;
    for e in ents {
        let name = String::from_utf8_lossy(&e.name).into_owned();
        if prefix.is_empty() && name == "lost+found" {
            continue;
        }
        let path = format!("{prefix}/{name}");
        let st = fs.stat(e.ino)?;
        match st.kind {
            FileKind::Dir => {
                out.insert(path.clone(), Content::Dir);
                walk_dir(fs, e.ino, &path, out, depth + 1)?;
            }
            FileKind::Symlink => {
                out.insert(path, Content::Link(fs.read_link(e.ino)?));
            }
            FileKind::File => {
                out.insert(path, Content::File(read_all(fs, e.ino, st.size)?));
            }
            _ => {}
        }
    }
    Ok(())
}

pub fn read_all(fs: &dyn Filesystem, ino: Ino, size: u64) -> Result<Vec<u8>> {
    if size > 1 << 31 {
        return Err(FsError::Corrupt("file too large for a test".into()));
    }
    let mut v = vec![0; size as usize];
    let mut done = 0;
    while done < v.len() {
        let n = fs.read(ino, done as u64, &mut v[done..])?;
        if n == 0 {
            return Err(FsError::Corrupt(format!("short read at {done} of {size}")));
        }
        done += n;
    }
    Ok(v)
}

/// Reads a host directory tree into the same shape as [`walk`].
pub fn host_tree(root: &Path) -> Tree {
    fn go(dir: &Path, prefix: &str, out: &mut Tree) {
        for e in std::fs::read_dir(dir).unwrap() {
            let e = e.unwrap();
            let name = e.file_name().to_string_lossy().into_owned();
            let path = format!("{prefix}/{name}");
            let t = e.file_type().unwrap();
            if t.is_symlink() {
                let target = std::fs::read_link(e.path()).unwrap();
                out.insert(path, Content::Link(target.to_string_lossy().as_bytes().to_vec()));
            } else if t.is_dir() {
                out.insert(path.clone(), Content::Dir);
                go(&e.path(), &path, out);
            } else {
                out.insert(path, Content::File(std::fs::read(e.path()).unwrap()));
            }
        }
    }
    let mut out = Tree::new();
    go(root, "", &mut out);
    out
}

/// Panics with the first difference between two trees.
pub fn assert_same(got: &Tree, want: &Tree, ctx: &str) {
    for (p, w) in want {
        match got.get(p) {
            None => panic!("{ctx}: missing {p}"),
            Some(g) if g != w => panic!("{ctx}: {p} differs: {}", describe(g, w)),
            _ => {}
        }
    }
    if let Some(p) = got.keys().find(|p| !want.contains_key(*p)) {
        panic!("{ctx}: unexpected {p}");
    }
}

fn describe(g: &Content, w: &Content) -> String {
    match (g, w) {
        (Content::File(a), Content::File(b)) => {
            let at = a.iter().zip(b.iter()).position(|(x, y)| x != y);
            format!("file sizes {} vs {}, first difference at {at:?}", a.len(), b.len())
        }
        _ => format!("{g:?} vs {w:?}"),
    }
}

#[derive(Clone, Debug)]
enum Node {
    File(u32),
    Dir,
    Link(Vec<u8>),
}

/// Expected state of a volume, with hard links modelled as shared file ids.
#[derive(Default)]
pub struct Model {
    nodes: BTreeMap<String, Node>,
    files: BTreeMap<u32, Vec<u8>>,
    next: u32,
}

const OWNER: Owner = Owner { mode: 0o644, uid: 1000, gid: 1000 };

impl Model {
    pub fn from_tree(t: &Tree) -> Model {
        let mut m = Model::default();
        for (p, c) in t {
            let n = match c {
                Content::Dir => Node::Dir,
                Content::Link(l) => Node::Link(l.clone()),
                Content::File(d) => {
                    m.next += 1;
                    m.files.insert(m.next, d.clone());
                    Node::File(m.next)
                }
            };
            m.nodes.insert(p.clone(), n);
        }
        m
    }

    pub fn tree(&self) -> Tree {
        self.nodes
            .iter()
            .map(|(p, n)| {
                let c = match n {
                    Node::Dir => Content::Dir,
                    Node::Link(l) => Content::Link(l.clone()),
                    Node::File(i) => Content::File(self.files[i].clone()),
                };
                (p.clone(), c)
            })
            .collect()
    }

    fn dirs(&self) -> Vec<String> {
        let mut v = vec![String::new()];
        v.extend(self.nodes.iter().filter(|n| matches!(n.1, Node::Dir)).map(|n| n.0.clone()));
        v
    }

    fn of_kind(&self, f: impl Fn(&Node) -> bool) -> Vec<String> {
        self.nodes.iter().filter(|n| f(n.1)).map(|n| n.0.clone()).collect()
    }

    fn children(&self, dir: &str) -> bool {
        let p = format!("{dir}/");
        self.nodes.keys().any(|k| k.starts_with(&p))
    }
}

fn split(path: &str) -> (&str, &str) {
    path.rsplit_once('/').unwrap_or(("", path))
}

fn pick<'a>(r: &mut Rng, v: &'a [String]) -> Option<&'a String> {
    if v.is_empty() {
        return None;
    }
    Some(&v[r.below(v.len() as u64) as usize])
}

fn name(r: &mut Rng) -> String {
    let len = match r.below(10) {
        0 => 100 + r.below(150),
        _ => 3 + r.below(12),
    };
    let mut s = format!("n{:x}-", r.next() & 0xFFFF);
    while (s.len() as u64) < len {
        s.push((b'a' + r.below(26) as u8) as char);
    }
    s
}

fn bytes(r: &mut Rng, n: usize) -> Vec<u8> {
    let seed = r.next();
    (0..n).map(|i| (seed.wrapping_mul(i as u64 + 1) >> 13) as u8).collect()
}

fn parent_of(fs: &dyn Filesystem, path: &str) -> Result<(Ino, Vec<u8>)> {
    let (d, n) = split(path);
    Ok((resolve(fs, d)?, n.as_bytes().to_vec()))
}

/// Applies `ops` random operations to both the volume and the model. Volume-full errors
/// are legal and leave the model untouched; any other error fails the test.
pub fn random_ops(fs: &dyn Filesystem, m: &mut Model, r: &mut Rng, ops: usize, max_write: usize) {
    for i in 0..ops {
        if let Err(e) = step(fs, m, r, max_write) {
            panic!("op {i} failed: {e}");
        }
    }
}

fn step(fs: &dyn Filesystem, m: &mut Model, r: &mut Rng, max_write: usize) -> Result<()> {
    let tolerate = |res: Result<()>| match res {
        Err(FsError::NoSpace) => Ok(false),
        Err(e) => Err(e),
        Ok(()) => Ok(true),
    };
    let dirs = m.dirs();
    let files = m.of_kind(|n| matches!(n, Node::File(_)));
    match r.below(100) {
        0..=24 => {
            let d = pick(r, &dirs).unwrap().clone();
            let path = format!("{d}/{}", name(r));
            if m.nodes.contains_key(&path) {
                return Ok(());
            }
            let dir = resolve(fs, &d)?;
            let n = split(&path).1.as_bytes().to_vec();
            if tolerate(fs.create(dir, &n, NewNode::File, OWNER).map(|_| ()))? {
                m.next += 1;
                m.files.insert(m.next, vec![]);
                m.nodes.insert(path, Node::File(m.next));
            }
        }
        25..=49 => {
            let Some(p) = pick(r, &files) else { return Ok(()) };
            let Node::File(id) = m.nodes[p] else { return Ok(()) };
            let ino = resolve(fs, p)?;
            let size = m.files[&id].len() as u64;
            let off = if r.below(2) == 0 { size } else { r.below(size + (1 << 18)) };
            let data = bytes(r, r_size(r, max_write));
            match fs.write(ino, off, &data) {
                Ok(n) => {
                    let f = m.files.get_mut(&id).unwrap();
                    let end = off as usize + n;
                    if f.len() < end {
                        f.resize(end, 0);
                    }
                    f[off as usize..end].copy_from_slice(&data[..n]);
                }
                Err(FsError::NoSpace) => {}
                Err(e) => return Err(e),
            }
        }
        50..=59 => {
            let Some(p) = pick(r, &files) else { return Ok(()) };
            let Node::File(id) = m.nodes[p] else { return Ok(()) };
            let size = m.files[&id].len() as u64;
            let new = r.below(size * 2 + 4096);
            let attr = SetAttr { size: Some(new), ..SetAttr::default() };
            if tolerate(fs.set_attr(resolve(fs, p)?, &attr).map(|_| ()))? {
                m.files.get_mut(&id).unwrap().resize(new as usize, 0);
            }
        }
        60..=69 => {
            let d = pick(r, &dirs).unwrap().clone();
            if d.matches('/').count() > 6 {
                return Ok(());
            }
            let path = format!("{d}/{}", name(r));
            let dir = resolve(fs, &d)?;
            let own = Owner { mode: 0o755, ..OWNER };
            if tolerate(fs.create(dir, split(&path).1.as_bytes(), NewNode::Dir, own).map(|_| ()))? {
                m.nodes.insert(path, Node::Dir);
            }
        }
        70..=76 => {
            let Some(p) = pick(r, &files) else { return Ok(()) };
            let (dir, n) = parent_of(fs, p)?;
            fs.unlink(dir, &n)?;
            let Some(Node::File(id)) = m.nodes.remove(p) else { return Ok(()) };
            if !m.nodes.values().any(|n| matches!(n, Node::File(i) if *i == id)) {
                m.files.remove(&id);
            }
        }
        77..=81 => {
            let empty: Vec<String> = dirs.iter().filter(|d| !d.is_empty() && !m.children(d)).cloned().collect();
            let Some(p) = pick(r, &empty) else { return Ok(()) };
            let (dir, n) = parent_of(fs, p)?;
            fs.rmdir(dir, &n)?;
            m.nodes.remove(p);
        }
        82..=89 => {
            let all: Vec<String> = m.nodes.keys().cloned().collect();
            let Some(src) = pick(r, &all) else { return Ok(()) };
            let d = pick(r, &dirs).unwrap().clone();
            if d == *src || d.starts_with(&format!("{src}/")) {
                return Ok(());
            }
            let dst = format!("{d}/{}", name(r));
            if m.nodes.contains_key(&dst) {
                return Ok(());
            }
            let (from, n) = parent_of(fs, src)?;
            let to = resolve(fs, &d)?;
            if tolerate(fs.rename(from, &n, to, split(&dst).1.as_bytes(), false))? {
                let prefix = format!("{src}/");
                let moved: Vec<String> = m.nodes.keys().filter(|k| k.starts_with(&prefix) || *k == src).cloned().collect();
                for k in moved {
                    let v = m.nodes.remove(&k).unwrap();
                    m.nodes.insert(format!("{dst}{}", &k[src.len()..]), v);
                }
            }
        }
        90..=94 => {
            let Some(p) = pick(r, &files) else { return Ok(()) };
            let Node::File(id) = m.nodes[p] else { return Ok(()) };
            let d = pick(r, &dirs).unwrap().clone();
            let dst = format!("{d}/{}", name(r));
            if m.nodes.contains_key(&dst) {
                return Ok(());
            }
            if tolerate(fs.link(resolve(fs, p)?, resolve(fs, &d)?, split(&dst).1.as_bytes()))? {
                m.nodes.insert(dst, Node::File(id));
            }
        }
        95..=97 => {
            let d = pick(r, &dirs).unwrap().clone();
            let path = format!("{d}/{}", name(r));
            if m.nodes.contains_key(&path) {
                return Ok(());
            }
            let long = r.below(3) == 0;
            let target: Vec<u8> = if long { vec![b'x'; 200] } else { b"some/target".to_vec() };
            let dir = resolve(fs, &d)?;
            let n = split(&path).1.as_bytes().to_vec();
            if tolerate(fs.create(dir, &n, NewNode::Symlink(&target), OWNER).map(|_| ()))? {
                m.nodes.insert(path, Node::Link(target));
            }
        }
        _ => fs.sync()?,
    }
    Ok(())
}

fn r_size(r: &mut Rng, max: usize) -> usize {
    match r.below(4) {
        0 => r.below(64) as usize,
        1 => r.below(5000) as usize,
        _ => r.below(max as u64) as usize,
    }
}

/// Records writes between barriers so any moment of a power cut can be rebuilt.
pub struct CrashDev {
    base: Vec<u8>,
    log: Mutex<Vec<Event>>,
    live: crate::dev::MemDev,
}

enum Event {
    Write(u64, Vec<u8>),
    Flush,
}

impl CrashDev {
    pub fn new(image: Vec<u8>) -> Self {
        CrashDev { live: crate::dev::MemDev::new(image.clone()), base: image, log: Mutex::new(vec![]) }
    }

    pub fn events(&self) -> usize {
        self.log.lock().unwrap().len()
    }

    /// The disk after power fails following `cut` events. Writes since the last barrier
    /// are in the drive's cache, so a random subset of them is lost, as on real hardware.
    pub fn image_at(&self, cut: usize, r: &mut Rng) -> Vec<u8> {
        let log = self.log.lock().unwrap();
        let cut = cut.min(log.len());
        let barrier = log[..cut].iter().rposition(|e| matches!(e, Event::Flush)).map_or(0, |i| i + 1);
        let mut img = self.base.clone();
        for (i, e) in log[..cut].iter().enumerate() {
            if let Event::Write(off, d) = e {
                if i >= barrier && r.below(2) == 0 {
                    continue;
                }
                img[*off as usize..*off as usize + d.len()].copy_from_slice(d);
            }
        }
        img
    }
}

impl BlockDev for CrashDev {
    fn read_at(&self, off: u64, buf: &mut [u8]) -> Result<()> {
        self.live.read_at(off, buf)
    }
    fn write_at(&self, off: u64, data: &[u8]) -> Result<()> {
        self.log.lock().unwrap().push(Event::Write(off, data.to_vec()));
        self.live.write_at(off, data)
    }
    fn flush(&self) -> Result<()> {
        self.log.lock().unwrap().push(Event::Flush);
        Ok(())
    }
    fn len(&self) -> u64 {
        self.live.len()
    }
}
