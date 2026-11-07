#![cfg(unix)]
//! Judges the engine against the real tools. Needs `mke2fs`/`e2fsck`, so it runs on the
//! Linux CI job; elsewhere each test skips. Images and the expected trees are left in
//! `$CAUSEWAY_OUT` for `ci/kernel-check.sh`, which has the Linux kernel read them.
use ext4::Ext4;
use fscore::testkit::*;
use fscore::{Filesystem, FileDev, MemDev, MountOpts};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

const RW: MountOpts = MountOpts { write: true, cache_bytes: 0 };
const RO: MountOpts = MountOpts { write: false, cache_bytes: 0 };

fn have_tools() -> bool {
    Command::new("e2fsck").arg("-V").output().is_ok()
}

fn out_dir() -> PathBuf {
    let d = std::env::var("CAUSEWAY_OUT").map_or_else(|_| std::env::temp_dir().join("causeway-oracle"), PathBuf::from);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A source tree exercising small, large, sparse-ish, deep, linked and wide content.
fn seed_tree(root: &Path) {
    use std::fs;
    let _ = fs::remove_dir_all(root);
    fs::create_dir_all(root.join("deep/a/b/c/d")).unwrap();
    fs::create_dir_all(root.join("wide")).unwrap();
    fs::write(root.join("hello.txt"), b"hello from linux\n").unwrap();
    fs::write(root.join("deep/a/b/c/d/leaf"), vec![7u8; 5000]).unwrap();
    let big: Vec<u8> = (0..3_000_000u32).map(|i| (i.wrapping_mul(2654435761) >> 24) as u8).collect();
    fs::write(root.join("big.bin"), &big).unwrap();
    fs::write(root.join("üñí-çödé.txt"), "unicode\n").unwrap();
    for i in 0..3000 {
        fs::write(root.join(format!("wide/file-with-a-longish-name-{i:05}")), format!("{i}")).unwrap();
    }
    std::os::unix::fs::symlink("hello.txt", root.join("short-link")).unwrap();
    std::os::unix::fs::symlink("x".repeat(150), root.join("long-link")).unwrap();
}

fn mkfs(img: &Path, src: &Path, args: &[&str]) {
    let _ = std::fs::remove_file(img);
    let f = std::fs::File::create(img).unwrap();
    f.set_len(96 << 20).unwrap();
    drop(f);
    let st = Command::new("mke2fs")
        .args(["-q", "-F", "-d"])
        .arg(src)
        .args(args)
        .arg(img)
        .status()
        .expect("mke2fs");
    assert!(st.success(), "mke2fs {args:?} failed");
}

fn fsck(img: &Path, ctx: &str) {
    let o = Command::new("e2fsck").args(["-fn", "-E", "no_optimize_extents"]).arg(img).output().unwrap();
    assert!(
        o.status.success(),
        "{ctx}: e2fsck exit {:?}\n{}\n{}",
        o.status.code(),
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
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

fn open(img: &Path, opts: MountOpts) -> Ext4 {
    Ext4::open(Arc::new(FileDev::open(img, opts.write).unwrap()), opts).unwrap()
}

/// Read, mutate, fsck, re-read: one full round for a set of mkfs options.
fn round(tag: &str, args: &[&str]) {
    if !have_tools() {
        eprintln!("skipping {tag}: e2fsprogs not installed");
        return;
    }
    let out = out_dir();
    let src = out.join(format!("{tag}.src"));
    seed_tree(&src);
    let img = out.join(format!("{tag}.img"));
    mkfs(&img, &src, args);
    fsck(&img, &format!("{tag}: fresh image"));
    let want = host_tree(&src);

    let fs = open(&img, RO);
    assert_same(&walk(&fs).unwrap(), &want, &format!("{tag}: read"));
    drop(fs);

    let mut model = Model::from_tree(&want);
    let mut rng = Rng(0x5EED ^ tag.len() as u64);
    for pass in 0..3 {
        let fs = open(&img, RW);
        assert!(!fs.info().read_only, "{tag}: refused write: {:?}", fs.info().ro_reasons);
        random_ops(&fs, &mut model, &mut rng, 1500, 200_000);
        assert_same(&walk(&fs).unwrap(), &model.tree(), &format!("{tag}: live pass {pass}"));
        fs.unmount().unwrap();
        drop(fs);
        fsck(&img, &format!("{tag}: pass {pass}"));
        let fs = open(&img, RO);
        assert_same(&walk(&fs).unwrap(), &model.tree(), &format!("{tag}: reread pass {pass}"));
    }
    dump(&model.tree(), &out.join(format!("{tag}.expected")));
    let _ = std::fs::remove_dir_all(&src);
}

#[test]
fn ext4_default() {
    round("ext4-default", &["-t", "ext4", "-J", "size=8"]);
}

#[test]
fn ext4_1k_no_csum() {
    round("ext4-1k-nocsum", &["-t", "ext4", "-b", "1024", "-O", "^metadata_csum,^64bit,uninit_bg", "-J", "size=4"]);
}

#[test]
fn ext4_large_dir_64bit() {
    round("ext4-largedir", &["-t", "ext4", "-O", "64bit,metadata_csum,large_dir", "-J", "size=8"]);
}

#[test]
fn ext4_meta_bg() {
    round("ext4-metabg", &["-t", "ext4", "-O", "meta_bg,^resize_inode", "-J", "size=8"]);
}

#[test]
fn ext4_small_inodes() {
    round("ext4-i128", &["-t", "ext4", "-I", "128", "-J", "size=8"]);
}

#[test]
fn ext3_1k() {
    round("ext3-1k", &["-t", "ext3", "-b", "1024", "-J", "size=4"]);
}

#[test]
fn ext3_4k() {
    round("ext3-4k", &["-t", "ext3", "-b", "4096", "-J", "size=8"]);
}

#[test]
fn ext2_2k() {
    round("ext2-2k", &["-t", "ext2", "-b", "2048"]);
}

/// Running out of space must fail cleanly: every failed operation rolls back, partial writes
/// keep exact accounting, and the volume still passes fsck.
#[test]
fn full_disk() {
    if !have_tools() {
        return;
    }
    for (tag, args) in [
        ("full-ext4", &["-t", "ext4", "-J", "size=4"][..]),
        ("full-ext3", &["-t", "ext3", "-b", "1024", "-J", "size=1"][..]),
        ("full-ext2", &["-t", "ext2", "-b", "1024"][..]),
    ] {
        let out = out_dir();
        let src = out.join(format!("{tag}.src"));
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("seed"), b"seed").unwrap();
        let img = out.join(format!("{tag}.img"));
        let _ = std::fs::remove_file(&img);
        std::fs::File::create(&img).unwrap().set_len(16 << 20).unwrap();
        let st = Command::new("mke2fs").args(["-q", "-F", "-d"]).arg(&src).args(args).arg(&img).status().unwrap();
        assert!(st.success());

        let fs = open(&img, RW);
        let mut model = Model::from_tree(&walk(&fs).unwrap());
        let mut rng = Rng(0xF011);
        random_ops(&fs, &mut model, &mut rng, 1500, 1_500_000);
        assert!(fs.info().free_bytes < 2 << 20, "{tag}: the test never filled the volume");
        assert_same(&walk(&fs).unwrap(), &model.tree(), &format!("{tag}: live"));
        fs.unmount().unwrap();
        drop(fs);
        fsck(&img, tag);
        let fs = open(&img, RO);
        assert_same(&walk(&fs).unwrap(), &model.tree(), &format!("{tag}: reread"));
    }
}

/// Features that force read-only must still read correctly and must never be written.
fn read_only_round(tag: &str, args: &[&str]) {
    if !have_tools() {
        return;
    }
    let out = out_dir();
    let src = out.join(format!("{tag}.src"));
    seed_tree(&src);
    let img = out.join(format!("{tag}.img"));
    mkfs(&img, &src, args);
    let before = std::fs::read(&img).unwrap();
    let fs = open(&img, RW);
    let info = fs.info();
    assert!(info.read_only && !info.ro_reasons.is_empty(), "{tag}: should be read-only");
    assert_same(&walk(&fs).unwrap(), &host_tree(&src), tag);
    assert!(matches!(fs.sync(), Ok(())));
    assert!(fs.unmount().is_ok());
    drop(fs);
    assert!(std::fs::read(&img).unwrap() == before, "{tag}: read-only mount changed the image");
    let _ = std::fs::remove_dir_all(&src);
}

#[test]
fn inline_data_reads() {
    read_only_round("ext4-inline", &["-t", "ext4", "-O", "inline_data", "-J", "size=8"]);
}

#[test]
fn bigalloc_reads() {
    read_only_round("ext4-bigalloc", &["-t", "ext4", "-O", "bigalloc", "-C", "16384", "-J", "size=8"]);
}

/// Cuts power at sampled points of a busy session: every outcome must recover to a
/// filesystem e2fsck accepts, containing everything acknowledged by the last sync.
#[test]
fn power_loss() {
    if !have_tools() {
        return;
    }
    for (tag, args) in [
        ("crash-csum", &["-t", "ext4", "-J", "size=4"][..]),
        ("crash-ext3", &["-t", "ext3", "-b", "1024", "-J", "size=4"][..]),
    ] {
        let out = out_dir();
        let src = out.join(format!("{tag}.src"));
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("seed"), b"seed").unwrap();
        let img = out.join(format!("{tag}.img"));
        mkfs(&img, &src, args);
        let base = std::fs::read(&img).unwrap();

        let dev = Arc::new(CrashDev::new(base));
        let fs = Ext4::open(dev.clone(), RW).unwrap();
        let initial = walk(&fs).unwrap();
        let mut model = Model::from_tree(&initial);
        let mut rng = Rng(77);
        let mut synced: Vec<(usize, Tree)> = vec![];
        for _ in 0..12 {
            random_ops_no_sync(&fs, &mut model, &mut rng, 60, 40_000);
            fs.sync().unwrap();
            synced.push((dev.events(), model.tree()));
        }
        let total = dev.events();
        drop(fs);

        let step = (total / 150).max(1);
        for cut in (0..total).step_by(step) {
            let crashed = dev.image_at(cut, &mut rng);
            let mem = Arc::new(MemDev::new(crashed));

            // A read-only look must not change the disk, and must see the same data.
            let before = mem.snapshot();
            let ro = Ext4::open(mem.clone(), RO).unwrap_or_else(|e| panic!("{tag} cut {cut}: ro mount: {e}"));
            let seen = walk(&ro).unwrap_or_else(|e| panic!("{tag} cut {cut}: ro walk: {e}"));
            assert!(mem.snapshot() == before, "{tag} cut {cut}: read-only mount wrote to the disk");
            drop(ro);

            let fs = Ext4::open(mem.clone(), RW).unwrap_or_else(|e| panic!("{tag} cut {cut}: mount: {e}"));
            let got = walk(&fs).unwrap_or_else(|e| panic!("{tag} cut {cut}: walk: {e}"));
            assert_same(&got, &seen, &format!("{tag} cut {cut}: replay vs overlay"));
            // Recovery lands on a commit boundary: the last completed sync or the next.
            let i = synced.iter().rposition(|(at, _)| *at <= cut);
            let names = |t: &Tree| t.keys().cloned().collect::<Vec<_>>();
            let have = names(&got);
            let older = i.map_or(names(&initial), |i| names(&synced[i].1));
            let newer = synced.get(i.map_or(0, |i| i + 1)).map(|s| names(&s.1));
            assert!(
                have == older || Some(&have) == newer.as_ref(),
                "{tag} cut {cut}: recovered tree is neither the last sync nor the next"
            );
            fs.unmount().unwrap();
            drop(fs);

            let path = out.join(format!("{tag}.cut.img"));
            std::fs::write(&path, mem.snapshot()).unwrap();
            fsck(&path, &format!("{tag} cut {cut}"));
        }
    }
}
