#![cfg(unix)]
//! Judges the engine against `mkfs.btrfs` and `btrfs check`, on the Linux CI job.
use btrfs::Btrfs;
use fscore::testkit::*;
use fscore::{resolve, BlockDev, FileDev, Filesystem, MemDev, MountOpts, NewNode, Owner};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

const RW: MountOpts = MountOpts { write: true, cache_bytes: 0 };
const RO: MountOpts = MountOpts { write: false, cache_bytes: 0 };
const OWNER: Owner = Owner { mode: 0o644, uid: 0, gid: 0 };

fn have_tools() -> bool {
    Command::new("btrfs").arg("--version").output().is_ok()
}

fn out_dir() -> PathBuf {
    let d = std::env::var("CAUSEWAY_OUT").map_or_else(|_| std::env::temp_dir().join("causeway-oracle"), PathBuf::from);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn seed_tree(root: &Path) {
    use std::fs;
    let _ = fs::remove_dir_all(root);
    fs::create_dir_all(root.join("deep/a/b/c")).unwrap();
    fs::create_dir_all(root.join("wide")).unwrap();
    fs::write(root.join("hello.txt"), b"hello from linux\n").unwrap();
    fs::write(root.join("deep/a/b/c/leaf"), vec![7u8; 5000]).unwrap();
    let big: Vec<u8> = (0..3_000_000u32).map(|i| (i.wrapping_mul(2654435761) >> 24) as u8).collect();
    fs::write(root.join("big.bin"), &big).unwrap();
    fs::write(root.join("üñí-çödé.txt"), "unicode\n").unwrap();
    for i in 0..2000 {
        fs::write(root.join(format!("wide/file-with-a-longish-name-{i:05}")), format!("{i}")).unwrap();
    }
    std::os::unix::fs::symlink("hello.txt", root.join("short-link")).unwrap();
}

fn make_images(tag: &str, devices: usize, size: u64) -> Vec<PathBuf> {
    let out = out_dir();
    (0..devices)
        .map(|i| {
            let p = if devices == 1 { out.join(format!("{tag}.img")) } else { out.join(format!("{tag}.{i}.img")) };
            let _ = std::fs::remove_file(&p);
            std::fs::File::create(&p).unwrap().set_len(size).unwrap();
            p
        })
        .collect()
}

fn mkfs(imgs: &[PathBuf], src: &Path, args: &[&str]) {
    let root: Vec<&std::ffi::OsStr> =
        if imgs.len() == 1 { vec!["--rootdir".as_ref(), src.as_os_str()] } else { vec![] };
    let st = Command::new("mkfs.btrfs")
        .args(["-q", "-f"])
        .args(root)
        .args(args)
        .args(imgs)
        .status()
        .expect("mkfs.btrfs");
    assert!(st.success(), "mkfs.btrfs {args:?} failed");
}

fn check(img: &Path, ctx: &str) {
    let o = Command::new("btrfs").args(["check", "--check-data-csum"]).arg(img).output().unwrap();
    assert!(
        o.status.success(),
        "{ctx}: btrfs check exit {:?}\n{}\n{}",
        o.status.code(),
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
}


/// `btrfs check` finds a filesystem's other devices through the kernel, so multi-device
/// volumes go through loop devices.
fn check_all(imgs: &[PathBuf], ctx: &str) {
    if imgs.len() == 1 {
        return check(&imgs[0], ctx);
    }
    let run = |args: &[&std::ffi::OsStr]| Command::new("sudo").args(args).output().unwrap();
    let loops: Vec<String> = imgs
        .iter()
        .map(|p| {
            let o = run(&["losetup".as_ref(), "-f".as_ref(), "--show".as_ref(), p.as_os_str()]);
            String::from_utf8_lossy(&o.stdout).trim().to_string()
        })
        .collect();
    for l in &loops {
        run(&["btrfs".as_ref(), "device".as_ref(), "scan".as_ref(), l.as_ref()]);
    }
    let o = run(&["btrfs".as_ref(), "check".as_ref(), "--check-data-csum".as_ref(), loops[0].as_ref()]);
    for l in &loops {
        run(&["losetup".as_ref(), "-d".as_ref(), l.as_ref()]);
    }
    assert!(
        o.status.success(),
        "{ctx}: btrfs check exit {:?}\n{}\n{}",
        o.status.code(),
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
}

fn open(imgs: &[PathBuf], opts: MountOpts) -> Btrfs {
    let devs: Vec<Arc<dyn BlockDev>> =
        imgs.iter().map(|p| Arc::new(FileDev::open(p, opts.write).unwrap()) as Arc<dyn BlockDev>).collect();
    Btrfs::open(devs, opts).unwrap()
}

fn dump(tree: &Tree, dir: &Path) {
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir).unwrap();
    for (p, c) in tree {
        let host = dir.join(p.trim_start_matches('/'));
        match c {
            Content::Dir => std::fs::create_dir_all(&host).unwrap(),
            Content::File(d) => {
                std::fs::create_dir_all(host.parent().unwrap()).unwrap();
                std::fs::write(&host, d).unwrap();
            }
            Content::Link(t) => {
                std::fs::create_dir_all(host.parent().unwrap()).unwrap();
                std::os::unix::fs::symlink(String::from_utf8_lossy(t).as_ref(), &host).unwrap();
            }
        }
    }
}


/// `mkfs --rootdir` is single-device only, so multi-device tests load content themselves.
fn populate(fs: &dyn Filesystem, tree: &Tree) {
    for (p, c) in tree {
        let (d, n) = p.rsplit_once('/').unwrap();
        let dir = resolve(fs, d).unwrap();
        match c {
            Content::Dir => {
                fs.create(dir, n.as_bytes(), NewNode::Dir, Owner { mode: 0o755, ..OWNER }).unwrap();
            }
            Content::Link(t) => {
                fs.create(dir, n.as_bytes(), NewNode::Symlink(t), OWNER).unwrap();
            }
            Content::File(data) => {
                let f = fs.create(dir, n.as_bytes(), NewNode::File, OWNER).unwrap();
                if !data.is_empty() {
                    fs.write(f, 0, data).unwrap();
                }
            }
        }
    }
}

fn round(tag: &str, devices: usize, args: &[&str]) {
    if !have_tools() {
        eprintln!("skipping {tag}: btrfs-progs not installed");
        return;
    }
    let out = out_dir();
    let src = out.join(format!("{tag}.src"));
    seed_tree(&src);
    let imgs = make_images(tag, devices, 512 << 20);
    mkfs(&imgs, &src, args);
    let want = host_tree(&src);
    if devices > 1 {
        let fs = open(&imgs, RW);
        populate(&fs, &want);
        fs.unmount().unwrap();
        drop(fs);
        check_all(&imgs, &format!("{tag}: populated"));
    }

    let fs = open(&imgs, RO);
    assert_same(&walk(&fs).unwrap(), &want, &format!("{tag}: read"));
    let rep = fs.scrub(&mut |_, _| {}).unwrap();
    assert!(rep.errors.is_empty(), "{tag}: scrub of a fresh image failed: {:?}", rep.errors);
    drop(fs);

    let mut model = Model::from_tree(&want);
    let mut rng = Rng(0xB7F5 ^ tag.len() as u64);
    for pass in 0..3 {
        let fs = open(&imgs, RW);
        assert!(!fs.info().read_only, "{tag}: refused write: {:?}", fs.info().ro_reasons);
        random_ops(&fs, &mut model, &mut rng, 1000, 150_000);
        assert_same(&walk(&fs).unwrap(), &model.tree(), &format!("{tag}: live pass {pass}"));
        fs.unmount().unwrap();
        drop(fs);
        check_all(&imgs, &format!("{tag}: pass {pass}"));
        let fs = open(&imgs, RO);
        assert_same(&walk(&fs).unwrap(), &model.tree(), &format!("{tag}: reread pass {pass}"));
        let rep = fs.scrub(&mut |_, _| {}).unwrap();
        assert!(rep.errors.is_empty(), "{tag}: scrub after pass {pass}: {:?}", rep.errors);
    }
    if devices == 1 {
        dump(&model.tree(), &out.join(format!("{tag}.expected")));
    }
    let _ = std::fs::remove_dir_all(&src);
}

#[test]
fn btrfs_default() {
    round("btrfs-default", 1, &[]);
}

#[test]
fn btrfs_small_nodes_dup() {
    round("btrfs-n4k", 1, &["-n", "4096", "-m", "dup", "-d", "single"]);
}

#[test]
fn btrfs_legacy_layout() {
    // No skinny extents, explicit holes, v1 space cache.
    round("btrfs-legacy", 1, &["-O", "^no-holes,^skinny-metadata", "-R", "^free-space-tree"]);
}

#[test]
fn btrfs_block_group_tree() {
    round("btrfs-bgt", 1, &["-O", "block-group-tree"]);
}

#[test]
fn btrfs_sha256() {
    round("btrfs-sha256", 1, &["--csum", "sha256"]);
}

#[test]
fn btrfs_xxhash() {
    round("btrfs-xxhash", 1, &["--csum", "xxhash"]);
}

#[test]
fn btrfs_blake2() {
    round("btrfs-blake2", 1, &["--csum", "blake2"]);
}

#[test]
fn btrfs_raid1() {
    round("btrfs-raid1", 2, &["-d", "raid1", "-m", "raid1"]);
}

#[test]
fn btrfs_raid0() {
    round("btrfs-raid0", 2, &["-d", "raid0", "-m", "raid1"]);
}

#[test]
fn btrfs_raid10() {
    round("btrfs-raid10", 4, &["-d", "raid10", "-m", "raid10"]);
}

#[test]
fn btrfs_raid1c3() {
    round("btrfs-raid1c3", 3, &["-d", "raid1c3", "-m", "raid1c3"]);
}


/// Snapshots share blocks: writing to either side must never show through to the other.
#[test]
fn snapshots_stay_independent() {
    if !have_tools() {
        return;
    }
    let tag = "btrfs-snap";
    let out = out_dir();
    let src = out.join(format!("{tag}.src"));
    seed_tree(&src);
    let imgs = make_images(tag, 1, 512 << 20);
    mkfs(&imgs, &src, &[]);
    let original = host_tree(&src);

    let fs = open(&imgs, RW);
    let root = fs.root();
    let snap = fs.snapshot(root, root, b"snap", false).unwrap();
    let frozen = fs.snapshot(root, root, b"frozen", true).unwrap();
    let sub = fs.create_subvolume(root, b"sub").unwrap();
    let f = fs.create(sub, b"inside", NewNode::File, OWNER).unwrap();
    fs.write(f, 0, b"in a new subvolume").unwrap();

    // Churn the source and the writable snapshot differently.
    let mut rng = Rng(5);
    let mut live = Model::from_tree(&original);
    random_ops(&fs, &mut live, &mut Rng(11), 0, 1);
    let view = |ino| {
        let mut t = Tree::new();
        collect(&fs, ino, "", &mut t);
        t
    };
    assert_same(&view(snap), &original, "snapshot content");
    assert_same(&view(frozen), &original, "read-only snapshot content");
    let hello = fs.lookup(snap, b"hello.txt").unwrap();
    fs.write(hello, 0, b"CHANGED").unwrap();
    let big = fs.lookup(root, b"big.bin").unwrap();
    fs.write(big, 4096, &vec![9u8; 100_000]).unwrap();
    for _ in 0..200 {
        let n = format!("churn{}", rng.below(50));
        let _ = fs.create(root, n.as_bytes(), NewNode::File, OWNER);
        let _ = fs.unlink(snap, format!("churn{}", rng.below(50)).as_bytes());
        let name = format!("wide/file-with-a-longish-name-{:05}", rng.below(2000));
        if let Ok(i) = resolve_in(&fs, snap, &name) {
            let _ = fs.write(i, 0, b"snapshot-side edit");
        }
    }
    assert_same(&view(frozen), &original, "frozen after churn");
    assert!(matches!(fs.write(fs.lookup(frozen, b"hello.txt").unwrap(), 0, b"x"), Err(fscore::FsError::ReadOnly)));

    // Deleting is the way back out. The kernel cleaner finishes the job in kernel-check.sh.
    fs.delete_subvolume(root, b"snap").unwrap();
    assert!(matches!(fs.lookup(root, b"snap"), Err(fscore::FsError::NotFound)));
    let left: Vec<Vec<u8>> = fs.subvolumes(root).unwrap().into_iter().map(|s| s.name).collect();
    assert_eq!(left.len(), 2, "{left:?}");
    fs.unmount().unwrap();
    drop(fs);
    check(&imgs[0], tag);

    let fs = open(&imgs, RO);
    let frozen = fs.lookup(fs.root(), b"frozen").unwrap();
    let mut t = Tree::new();
    collect(&fs, frozen, "", &mut t);
    assert_same(&t, &original, "frozen after remount");
    let _ = std::fs::remove_dir_all(&src);
}

fn resolve_in(fs: &dyn Filesystem, mut cur: fscore::Ino, path: &str) -> fscore::Result<fscore::Ino> {
    for p in path.split('/') {
        cur = fs.lookup(cur, p.as_bytes())?;
    }
    Ok(cur)
}

fn collect(fs: &dyn Filesystem, dir: fscore::Ino, prefix: &str, out: &mut Tree) {
    let mut ents = vec![];
    fs.read_dir(dir, 0, &mut |_, e| {
        ents.push(e);
        true
    })
    .unwrap();
    for e in ents {
        let name = String::from_utf8_lossy(&e.name).into_owned();
        let path = format!("{prefix}/{name}");
        let st = fs.stat(e.ino).unwrap();
        match st.kind {
            fscore::FileKind::Dir => {
                out.insert(path.clone(), Content::Dir);
                collect(fs, e.ino, &path, out);
            }
            fscore::FileKind::Symlink => {
                out.insert(path, Content::Link(fs.read_link(e.ino).unwrap()));
            }
            _ => {
                out.insert(path, Content::File(read_all(fs, e.ino, st.size).unwrap()));
            }
        }
    }
}

/// Filling a volume must fail cleanly, and it must stay possible to delete files to recover.
#[test]
fn full_disk() {
    if !have_tools() {
        return;
    }
    let tag = "btrfs-full";
    let out = out_dir();
    let src = out.join(format!("{tag}.src"));
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("seed"), b"seed").unwrap();
    let imgs = make_images(tag, 1, 256 << 20);
    mkfs(&imgs, &src, &[]);
    let fs = open(&imgs, RW);
    let mut model = Model::from_tree(&walk(&fs).unwrap());
    random_ops(&fs, &mut model, &mut Rng(0xF011), 1500, 3_000_000);
    assert!(fs.info().free_bytes < 64 << 20, "{tag}: the test never filled the volume");
    assert!(!fs.info().read_only, "{tag}: {:?}", fs.info().ro_reasons);
    assert_same(&walk(&fs).unwrap(), &model.tree(), &format!("{tag}: live"));
    fs.unmount().unwrap();
    drop(fs);
    check(&imgs[0], tag);
    let fs = open(&imgs, RO);
    assert_same(&walk(&fs).unwrap(), &model.tree(), &format!("{tag}: reread"));
}

/// Power cut at sampled points: the volume must always open at a commit boundary.
#[test]
fn power_loss() {
    if !have_tools() {
        return;
    }
    let tag = "btrfs-crash";
    let out = out_dir();
    let src = out.join(format!("{tag}.src"));
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("seed"), b"seed").unwrap();
    let imgs = make_images(tag, 1, 256 << 20);
    mkfs(&imgs, &src, &[]);
    let base = std::fs::read(&imgs[0]).unwrap();

    let dev = Arc::new(CrashDev::new(base));
    let fs = Btrfs::open(vec![dev.clone() as Arc<dyn BlockDev>], RW).unwrap();
    let initial = walk(&fs).unwrap();
    let mut model = Model::from_tree(&initial);
    let mut rng = Rng(78);
    let mut synced: Vec<(usize, Tree)> = vec![];
    for _ in 0..10 {
        random_ops_no_sync(&fs, &mut model, &mut rng, 50, 40_000);
        fs.sync().unwrap();
        synced.push((dev.events(), model.tree()));
    }
    let total = dev.events();
    drop(fs);

    let cut_path = out.join(format!("{tag}.cut.img"));
    for cut in (0..total).step_by((total / 60).max(1)) {
        let crashed = dev.image_at(cut, &mut rng);
        let mem = Arc::new(MemDev::new(crashed));
        let opened = Btrfs::open(vec![mem.clone() as Arc<dyn BlockDev>], RW);
        let fs = opened.unwrap_or_else(|e| panic!("{tag} cut {cut}: mount: {e}"));
        let got = walk(&fs).unwrap_or_else(|e| panic!("{tag} cut {cut}: walk: {e}"));
        let i = synced.iter().rposition(|(at, _)| *at <= cut);
        let older = i.map_or(&initial, |i| &synced[i].1);
        let newer = synced.get(i.map_or(0, |i| i + 1)).map(|s| &s.1);
        // Copy-on-write makes this exact, file contents included.
        assert!(got == *older || Some(&got) == newer, "{tag} cut {cut}: state is not a commit boundary");
        drop(fs);
        std::fs::write(&cut_path, mem.snapshot()).unwrap();
        check(&cut_path, &format!("{tag} cut {cut}"));
    }
    let _ = resolve;
}
