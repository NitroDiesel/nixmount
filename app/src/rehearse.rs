//! A rehearsal of writing to a real volume, run by hand before trusting one to `--rw`.
//!
//! The disk is opened read-only, so Windows itself refuses any write to it, and everything
//! the engine writes lands in memory and is dropped at the end. The volume is walked, then
//! written to the way a mount would be (new files, edits to existing ones, a snapshot),
//! then opened again and walked once more: what was written must read back, and nothing
//! else may have changed.
//!
//! Run the test binary as administrator with `NIXMOUNT_REHEARSE=<disk>:<partition>`, or the
//! path of an image file, and for an encrypted volume `NIXMOUNT_PASSPHRASE`:
//!
//! ```text
//! nixmount-<hash>.exe --ignored --nocapture rehearse
//! ```
//!
//! It reports counts and errors, never a name from the volume.
use crate::disk::RawDev;
use fscore::part::{self, FsKind};
use fscore::{BlockDev, FileKind, Filesystem, FsError, Ino, MountOpts, NewNode, Owner, Result, SetAttr};
use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::Instant;

const BLOCK: u64 = 4096;
/// More than a rehearsal writes; a runaway stops here instead of taking the machine's memory.
const MOST_BLOCKS: usize = (4 << 30) / BLOCK as usize;
const OWNER: Owner = Owner { mode: 0o644, uid: 0, gid: 0 };
const FOLDER: &[u8] = b"nixmount-rehearsal";

/// A device that reads from `base` and keeps every write to itself.
struct Overlay {
    base: Arc<dyn BlockDev>,
    blocks: Mutex<BTreeMap<u64, Vec<u8>>>,
    flushes: AtomicU64,
}

impl BlockDev for Overlay {
    fn read_at(&self, off: u64, buf: &mut [u8]) -> Result<()> {
        self.base.read_at(off, buf)?;
        if buf.is_empty() {
            return Ok(());
        }
        let end = off + buf.len() as u64;
        for (&n, b) in self.blocks.lock().unwrap().range(off / BLOCK..=(end - 1) / BLOCK) {
            let start = n * BLOCK;
            let (from, to) = (off.max(start), end.min(start + b.len() as u64));
            buf[(from - off) as usize..(to - off) as usize].copy_from_slice(&b[(from - start) as usize..(to - start) as usize]);
        }
        Ok(())
    }

    fn write_at(&self, off: u64, data: &[u8]) -> Result<()> {
        let end = off + data.len() as u64;
        if end > self.base.len() {
            return Err(FsError::Invalid("write past the end of the device"));
        }
        if data.is_empty() {
            return Ok(());
        }
        let mut blocks = self.blocks.lock().unwrap();
        for n in off / BLOCK..=(end - 1) / BLOCK {
            let start = n * BLOCK;
            let size = BLOCK.min(self.base.len() - start);
            let (from, to) = (off.max(start), end.min(start + size));
            if !blocks.contains_key(&n) {
                if blocks.len() >= MOST_BLOCKS {
                    return Err(FsError::NoSpace);
                }
                let mut b = vec![0u8; size as usize];
                if to - from < size {
                    self.base.read_at(start, &mut b)?;
                }
                blocks.insert(n, b);
            }
            let b = blocks.get_mut(&n).unwrap();
            b[(from - start) as usize..(to - start) as usize].copy_from_slice(&data[(from - off) as usize..(to - off) as usize]);
        }
        Ok(())
    }

    fn flush(&self) -> Result<()> {
        self.flushes.fetch_add(1, Relaxed);
        Ok(())
    }

    fn len(&self) -> u64 {
        self.base.len()
    }
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(n + 8);
        while v.len() < n {
            v.extend_from_slice(&self.next().to_le_bytes());
        }
        v.truncate(n);
        v
    }
}

fn hash_of(parts: &[&[u8]]) -> u64 {
    let mut h = DefaultHasher::new();
    for p in parts {
        p.hash(&mut h);
    }
    h.finish()
}

/// An error with anything that might be a name taken out.
fn plain(e: &FsError) -> String {
    let mut out = String::new();
    let mut quoted = false;
    for c in e.to_string().chars().take(160) {
        if c == '\'' || c == '"' {
            quoted = !quoted;
            out.push(c);
        } else if !quoted {
            out.push(c);
        }
    }
    out
}

#[derive(Default)]
struct Tally(BTreeMap<String, u64>);

impl Tally {
    fn add(&mut self, what: &str, e: &FsError) {
        *self.0.entry(format!("{what}: {}", plain(e))).or_default() += 1;
    }

    fn print(&self, title: &str) {
        println!("{title}: {}", if self.0.is_empty() { "none".to_string() } else { self.0.values().sum::<u64>().to_string() });
        for (k, n) in &self.0 {
            println!("  {n} x {k}");
        }
    }
}

fn read_all(fs: &dyn Filesystem, ino: Ino) -> Result<Vec<u8>> {
    let mut out = vec![];
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = fs.read(ino, out.len() as u64, &mut buf)?;
        if n == 0 {
            return Ok(out);
        }
        out.extend_from_slice(&buf[..n]);
    }
}

fn write_all(fs: &dyn Filesystem, ino: Ino, mut off: u64, mut data: &[u8]) -> Result<()> {
    while !data.is_empty() {
        let n = fs.write(ino, off, &data[..data.len().min(1 << 20)])?;
        if n == 0 {
            return Err(FsError::Invalid("a write made no progress"));
        }
        off += n as u64;
        data = &data[n..];
    }
    Ok(())
}

fn resolve(fs: &dyn Filesystem, path: &[Vec<u8>]) -> Result<Ino> {
    path.iter().try_fold(fs.root(), |dir, name| fs.lookup(dir, name))
}

/// An existing file chosen to be edited.
struct Victim {
    path: Vec<Vec<u8>>,
    key: u64,
    parent: u64,
    content: Vec<u8>,
}

/// One pass over the whole volume.
#[derive(Default)]
struct Seen {
    /// Each entry by the hash of its path, with a digest of what `stat` says about it.
    entries: HashMap<u64, u64>,
    /// A sample of files, by the same key, with a digest of their contents.
    contents: HashMap<u64, u64>,
    dirs: u64,
    files: u64,
    links: u64,
    errors: Tally,
    victims: Vec<Victim>,
}

struct Walk<'a> {
    fs: &'a dyn Filesystem,
    seen: Seen,
    /// Entries left out altogether, by key.
    skip: &'a HashSet<u64>,
    choose: bool,
    path: Vec<Vec<u8>>,
}

impl Walk<'_> {
    fn dir(&mut self, dir: Ino, key: u64, depth: u32) {
        if depth > 200 {
            self.seen.errors.add("walk", &FsError::Invalid("too deep"));
            return;
        }
        let mut ents = vec![];
        if let Err(e) = self.fs.read_dir(dir, 0, &mut |_, e| {
            ents.push(e);
            true
        }) {
            self.seen.errors.add("list", &e);
        }
        for e in ents {
            let k = hash_of(&[&key.to_le_bytes(), &e.name]);
            if self.skip.contains(&k) {
                continue;
            }
            let st = match self.fs.stat(e.ino) {
                Ok(st) => st,
                Err(err) => {
                    self.seen.errors.add("stat", &err);
                    continue;
                }
            };
            let mut about = format!("{:?} {} {:o} {} {} {} {:?} {:?}", st.kind, st.size, st.mode, st.uid, st.gid, st.nlink, st.mtime, st.ctime);
            match st.kind {
                FileKind::Dir => {
                    self.seen.dirs += 1;
                    self.path.push(e.name.clone());
                    self.dir(e.ino, k, depth + 1);
                    self.path.pop();
                }
                FileKind::Symlink => {
                    self.seen.links += 1;
                    match self.fs.read_link(e.ino) {
                        Ok(t) => about.push_str(&format!(" {}", hash_of(&[&t]))),
                        Err(err) => self.seen.errors.add("read link", &err),
                    }
                }
                FileKind::File => {
                    self.seen.files += 1;
                    let wanted = self.choose && self.seen.victims.len() < 60 && st.nlink == 1 && k.is_multiple_of(211) && (32 << 10..512 << 10).contains(&st.size);
                    if wanted || (k.is_multiple_of(31) && st.size <= 256 << 10) {
                        match read_all(self.fs, e.ino) {
                            Ok(content) => {
                                self.seen.contents.insert(k, hash_of(&[&content]));
                                if wanted {
                                    let mut path = self.path.clone();
                                    path.push(e.name.clone());
                                    self.seen.victims.push(Victim { path, key: k, parent: key, content });
                                }
                            }
                            Err(err) => self.seen.errors.add("read", &err),
                        }
                    }
                }
                _ => {}
            }
            self.seen.entries.insert(k, hash_of(&[about.as_bytes()]));
        }
    }
}

fn walk(fs: &dyn Filesystem, skip: &HashSet<u64>, choose: bool) -> Seen {
    let mut w = Walk { fs, seen: Seen::default(), skip, choose, path: vec![] };
    w.dir(fs.root(), 0, 0);
    w.seen
}

/// What a rehearsal folder must hold afterwards.
struct Made {
    parent: Vec<Vec<u8>>,
    files: Vec<(Vec<Vec<u8>>, Vec<u8>)>,
    link: Vec<u8>,
    absent: Vec<Vec<Vec<u8>>>,
}

/// Fills a new folder under `parent` the way ordinary use would, in two commits.
fn exercise(fs: &dyn Filesystem, parent: &[Vec<u8>], rng: &mut Rng, step: &mut &'static str) -> Result<Made> {
    let dir_owner = Owner { mode: 0o755, ..OWNER };
    *step = "create folder";
    let t = fs.create(resolve(fs, parent)?, FOLDER, NewNode::Dir, dir_owner)?;
    *step = "create files";
    fs.create(t, b"empty", NewNode::File, OWNER)?;
    let small = rng.bytes(100);
    write_all(fs, fs.create(t, b"small", NewNode::File, OWNER)?, 0, &small)?;
    let mut medium = rng.bytes(300 << 10);
    let medium_ino = fs.create(t, b"medium", NewNode::File, OWNER)?;
    write_all(fs, medium_ino, 0, &medium)?;
    let mut large = rng.bytes(6 << 20);
    let large_ino = fs.create(t, b"large", NewNode::File, OWNER)?;
    write_all(fs, large_ino, 0, &large)?;
    *step = "create many files";
    let many = fs.create(t, b"many", NewNode::Dir, dir_owner)?;
    let mut kept = vec![];
    for i in 0..400u32 {
        let name = format!("f{i:03}").into_bytes();
        let body = rng.bytes((i as usize * 37) % 2000);
        write_all(fs, fs.create(many, &name, NewNode::File, OWNER)?, 0, &body)?;
        kept.push((name, body));
    }
    *step = "create link";
    fs.create(t, b"link", NewNode::Symlink(b"small"), OWNER)?;
    *step = "first commit";
    fs.sync()?;

    *step = "overwrite";
    let patch = rng.bytes(1 << 20);
    write_all(fs, large_ino, 5 << 19, &patch)?;
    large[5 << 19..(5 << 19) + patch.len()].copy_from_slice(&patch);
    *step = "append";
    let more = rng.bytes(100 << 10);
    write_all(fs, medium_ino, medium.len() as u64, &more)?;
    medium.extend_from_slice(&more);
    *step = "truncate";
    fs.set_attr(large_ino, &SetAttr { size: Some(4 << 20), ..SetAttr::default() })?;
    fs.set_attr(large_ino, &SetAttr { size: Some(5 << 20), ..SetAttr::default() })?;
    large.truncate(4 << 20);
    large.resize(5 << 20, 0);
    *step = "rename";
    fs.rename(t, b"small", t, b"renamed", false)?;
    *step = "hard link";
    fs.link(medium_ino, t, b"hard")?;
    *step = "delete files";
    for (name, _) in kept.drain(..200) {
        fs.unlink(many, &name)?;
    }
    *step = "remove folder";
    fs.create(t, b"gone", NewNode::Dir, dir_owner)?;
    fs.rmdir(t, b"gone")?;
    *step = "second commit";
    fs.sync()?;

    let at = |names: &[&[u8]]| names.iter().map(|n| n.to_vec()).collect::<Vec<_>>();
    let mut files = vec![
        (at(&[b"empty"]), vec![]),
        (at(&[b"renamed"]), small),
        (at(&[b"medium"]), medium.clone()),
        (at(&[b"hard"]), medium),
        (at(&[b"large"]), large),
    ];
    files.extend(kept.into_iter().map(|(name, body)| (vec![b"many".to_vec(), name], body)));
    let absent = vec![at(&[b"small"]), at(&[b"gone"]), at(&[b"many", b"f000"]), at(&[b"many", b"f199"])];
    Ok(Made { parent: parent.to_vec(), files, link: b"small".to_vec(), absent })
}

/// Counts what a rehearsal folder holds that it shouldn't, or lacks that it should.
fn wrong_in(fs: &dyn Filesystem, made: &Made, errors: &mut Tally) -> u64 {
    let mut wrong = 0;
    let mut base = made.parent.clone();
    base.push(FOLDER.to_vec());
    let under = |rest: &[Vec<u8>]| base.iter().chain(rest).cloned().collect::<Vec<_>>();
    for (rest, want) in &made.files {
        match resolve(fs, &under(rest)).and_then(|ino| read_all(fs, ino)) {
            Ok(got) if got == *want => {}
            Ok(_) => wrong += 1,
            Err(e) => {
                wrong += 1;
                errors.add("reading back", &e);
            }
        }
    }
    match resolve(fs, &under(&[b"link".to_vec()])).and_then(|ino| fs.read_link(ino)) {
        Ok(t) if t == made.link => {}
        _ => wrong += 1,
    }
    for rest in &made.absent {
        if !matches!(resolve(fs, &under(rest)), Err(FsError::NotFound)) {
            wrong += 1;
        }
    }
    let mut left = 0;
    if let Ok(many) = resolve(fs, &under(&[b"many".to_vec()])) {
        let _ = fs.read_dir(many, 0, &mut |_, _| {
            left += 1;
            true
        });
    }
    wrong + u64::from(left != 200)
}

fn open(dev: Arc<dyn BlockDev>, write: bool) -> Result<Arc<dyn Filesystem>> {
    let opts = MountOpts { write, cache_bytes: 0 };
    Ok(match part::probe(dev.as_ref()) {
        FsKind::Ext(_) => Arc::new(ext4::Ext4::open(dev, opts)?),
        FsKind::Btrfs => Arc::new(btrfs::Btrfs::open(vec![dev], opts)?),
        k => return Err(FsError::Unsupported(format!("{} volumes can't be mounted", k.name()))),
    })
}

#[test]
#[ignore = "run by hand against a real volume, as administrator"]
fn rehearse() {
    let Ok(target) = std::env::var("NIXMOUNT_REHEARSE") else {
        println!("NIXMOUNT_REHEARSE is not set, so there is nothing to rehearse on");
        return;
    };
    let clock = Instant::now();
    let since = |c: &Instant| format!("{:.1} s", c.elapsed().as_secs_f64());

    // Opened without write access: nothing below can change the disk, whatever it does.
    let numbers = target.split_once(':').and_then(|(d, p)| Some((d.parse().ok()?, p.parse().ok()?)));
    let raw: Arc<dyn BlockDev> = match numbers {
        Some((disk, part_no)) => Arc::new(RawDev::open(disk, part_no, false).unwrap()),
        None => Arc::new(fscore::FileDev::open(std::path::Path::new(&target), false).unwrap()),
    };
    assert!(!raw.writable());
    let overlay = Arc::new(Overlay { base: raw, blocks: Mutex::default(), flushes: AtomicU64::new(0) });
    let mut dev: Arc<dyn BlockDev> = overlay.clone();
    if part::probe(dev.as_ref()) == FsKind::Luks {
        let pass = std::env::var("NIXMOUNT_PASSPHRASE").expect("an encrypted volume needs NIXMOUNT_PASSPHRASE");
        let header = luks::read_header(dev.as_ref()).unwrap();
        let key = header.unlock(dev.as_ref(), pass.as_bytes()).expect("unlocking");
        dev = Arc::new(header.open(dev.clone(), &key).unwrap());
        println!("unlocked in {}", since(&clock));
    }

    // Before: the whole volume, as it is on the disk.
    let t = Instant::now();
    let fs = open(dev.clone(), false).unwrap();
    let before_info = fs.info();
    let nothing = HashSet::new();
    let mut before = walk(fs.as_ref(), &nothing, true);
    drop(fs);
    println!("before: {} folders, {} files, {} links, {} files sampled, in {}", before.dirs, before.files, before.links, before.contents.len(), since(&t));
    before.errors.print("errors reading before");

    // The rehearsal itself.
    let t = Instant::now();
    let fs = open(dev.clone(), true).unwrap();
    let info = fs.info();
    println!("opened for writing: read_only={}, reasons {:?}, notes {:?}", info.read_only, info.ro_reasons, info.notes);
    if info.read_only {
        println!("the engine declined to write, so there is nothing more to rehearse");
        return;
    }
    let mut errors = Tally::default();
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let mut tops: Vec<Vec<Vec<u8>>> = vec![vec![]];
    let _ = fs.read_dir(fs.root(), 0, &mut |_, e| {
        if e.kind == FileKind::Dir {
            tops.push(vec![e.name]);
        }
        true
    });
    let mut made = vec![];
    for parent in &tops {
        let mut step = "start";
        match exercise(fs.as_ref(), parent, &mut rng, &mut step) {
            Ok(m) => made.push(m),
            Err(e) => errors.add(&format!("new folder, {step}"), &e),
        }
    }
    println!("new folders filled: {} of {} places", made.len(), tops.len());

    // Existing files: overwritten, grown, cut short, deleted.
    let mut victims = std::mem::take(&mut before.victims);
    let mut edited = [0u64; 4];
    let mut expect: Vec<(usize, Option<Vec<u8>>)> = vec![];
    for (i, v) in victims.iter_mut().enumerate() {
        let (dir, name) = (resolve(fs.as_ref(), &v.path[..v.path.len() - 1]), v.path.last().unwrap().clone());
        let done = (|| -> Result<Option<Vec<u8>>> {
            let ino = resolve(fs.as_ref(), &v.path)?;
            let mut c = std::mem::take(&mut v.content);
            match i % 4 {
                0 => {
                    let patch = rng.bytes(4096);
                    let at = c.len() / 2;
                    write_all(fs.as_ref(), ino, at as u64, &patch)?;
                    let end = (at + patch.len()).max(c.len());
                    c.resize(end, 0);
                    c[at..at + patch.len()].copy_from_slice(&patch);
                }
                1 => {
                    let more = rng.bytes(10 << 10);
                    write_all(fs.as_ref(), ino, c.len() as u64, &more)?;
                    c.extend_from_slice(&more);
                }
                2 => {
                    c.truncate(c.len() / 2);
                    fs.set_attr(ino, &SetAttr { size: Some(c.len() as u64), ..SetAttr::default() })?;
                }
                _ => {
                    fs.unlink(dir?, &name)?;
                    return Ok(None);
                }
            }
            Ok(Some(c))
        })();
        match done {
            Ok(c) => {
                edited[i % 4] += 1;
                expect.push((i, c));
            }
            Err(e) => errors.add(["overwrite", "append", "truncate", "delete"][i % 4], &e),
        }
    }
    println!("existing files: {} overwritten, {} grown, {} cut short, {} deleted", edited[0], edited[1], edited[2], edited[3]);

    // A snapshot of a real subvolume, changed without the original changing.
    let mut snapshot_key = None;
    let subvolumes = fs.subvolumes(fs.root()).unwrap_or_default();
    println!("subvolumes at the top: {} ({} read-only)", subvolumes.len(), subvolumes.iter().filter(|s| s.read_only).count());
    if let Some(s) = subvolumes.iter().find(|s| !s.read_only) {
        let name: &[u8] = b"nixmount-rehearsal-snapshot";
        let taken = (|| -> Result<()> {
            let src = fs.lookup(fs.root(), &s.name)?;
            let snap = fs.snapshot(src, fs.root(), name, false)?;
            write_all(fs.as_ref(), fs.create(snap, b"only-in-the-snapshot", NewNode::File, OWNER)?, 0, b"snapshot")?;
            match fs.lookup(src, b"only-in-the-snapshot") {
                Err(FsError::NotFound) => Ok(()),
                _ => Err(FsError::Invalid("the snapshot's new file shows in the original")),
            }
        })();
        match taken {
            Ok(()) => {
                snapshot_key = Some(hash_of(&[&0u64.to_le_bytes(), name]));
                println!("snapshot taken and changed on its own");
            }
            Err(e) => errors.add("snapshot", &e),
        }
    }
    if let Err(e) = fs.unmount() {
        errors.add("final commit", &e);
    }
    drop(fs);
    let written = overlay.blocks.lock().unwrap().len() as u64 * BLOCK;
    println!("writing took {}: {:.1} MB kept in memory, {} flushes", since(&t), written as f64 / 1e6, overlay.flushes.load(Relaxed));
    errors.print("errors while writing");

    // After: opened afresh from what was written.
    let t = Instant::now();
    let fs = open(dev.clone(), false).unwrap();
    let after_info = fs.info();
    let mut readback = Tally::default();
    let wrong: u64 = made.iter().map(|m| wrong_in(fs.as_ref(), m, &mut readback)).sum();
    println!("new folders: {} things wrong on reading back", wrong);
    let mut bad_edits = 0;
    for (i, want) in &expect {
        let got = resolve(fs.as_ref(), &victims[*i].path).and_then(|ino| read_all(fs.as_ref(), ino));
        match (got, want) {
            (Ok(g), Some(w)) if g == *w => {}
            (Err(FsError::NotFound), None) => {}
            (Err(e), _) => {
                bad_edits += 1;
                readback.add("edited file", &e);
            }
            _ => bad_edits += 1,
        }
    }
    println!("existing files: {} of {} edits wrong on reading back", bad_edits, expect.len());

    // Everything that wasn't touched must be exactly as it was.
    let mut skip: HashSet<u64> = snapshot_key.into_iter().collect();
    let mut touched: HashSet<u64> = HashSet::new();
    // A folder that failed part-way still counts as touched.
    for place in &tops {
        let parent = place.iter().fold(0u64, |k, name| hash_of(&[&k.to_le_bytes(), name]));
        skip.insert(hash_of(&[&parent.to_le_bytes(), FOLDER]));
        touched.insert(parent);
    }
    for (i, want) in &expect {
        touched.insert(victims[*i].key);
        if want.is_none() {
            touched.insert(victims[*i].parent);
        }
    }
    let after = walk(fs.as_ref(), &skip, false);
    drop(fs);
    after.errors.print("errors reading after");
    readback.print("errors reading back");
    let differs = |k: &u64, v: &u64, other: &HashMap<u64, u64>| !touched.contains(k) && other.get(k) != Some(v);
    let changed = before.entries.iter().filter(|(k, v)| after.entries.contains_key(*k) && differs(k, v, &after.entries)).count();
    let vanished = before.entries.keys().filter(|k| !touched.contains(*k) && !after.entries.contains_key(*k)).count();
    let appeared = after.entries.keys().filter(|k| !touched.contains(*k) && !before.entries.contains_key(*k)).count();
    let contents = before.contents.iter().filter(|(k, v)| differs(k, v, &after.contents)).count();
    println!("after: {} folders, {} files, {} links, in {}", after.dirs, after.files, after.links, since(&t));
    println!("untouched entries: {changed} changed, {vanished} vanished, {appeared} appeared, of {}", before.entries.len());
    println!("untouched file contents: {contents} of {} differ", before.contents.len());
    println!("space in use: {} bytes before, {} after", before_info.total_bytes - before_info.free_bytes, after_info.total_bytes - after_info.free_bytes);

    if std::env::var_os("NIXMOUNT_REHEARSE_SCRUB").is_some() {
        let t = Instant::now();
        let fs = open(dev, false).unwrap();
        match fs.scrub(&mut |_, _| {}) {
            Ok(rep) => {
                println!("checksums: {:.1} GB verified in {}, {} errors", rep.scanned_bytes as f64 / 1e9, since(&t), rep.errors.len());
                for e in rep.errors.iter().take(10) {
                    println!("  {}", plain(&FsError::Corrupt(e.clone())));
                }
            }
            Err(e) => println!("checksums: the pass stopped: {}", plain(&e)),
        }
    }
    println!("nothing reached the disk; the whole rehearsal took {}", since(&clock));
}
