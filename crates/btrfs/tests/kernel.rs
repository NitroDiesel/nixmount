#![cfg(unix)]
//! Reads and edits images made by the real kernel (see `ci/kernel-check.sh`): compressed
//! extents in every codec, and snapshots with genuinely shared trees.
use btrfs::Btrfs;
use fscore::testkit::*;
use fscore::{BlockDev, FileDev, Filesystem, MountOpts};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

fn dir() -> Option<PathBuf> {
    std::env::var("NIXMOUNT_OUT").ok().map(PathBuf::from)
}

fn open(p: &Path, write: bool) -> Btrfs {
    let d: Arc<dyn BlockDev> = Arc::new(FileDev::open(p, write).unwrap());
    Btrfs::open(vec![d], MountOpts { write, cache_bytes: 0 }).unwrap()
}

#[test]
fn reads_every_codec() {
    let Some(out) = dir() else { return };
    for codec in ["zlib", "lzo", "zstd"] {
        let img = out.join(format!("kernel-{codec}.image"));
        if !img.exists() {
            continue;
        }
        let want = host_tree(&out.join(format!("kernel-{codec}.src")));
        let fs = open(&img, false);
        assert!(fs.info().features.iter().any(|f| !f.is_empty()));
        assert_same(&walk(&fs).unwrap(), &want, codec);
    }
}

#[test]
fn edits_kernel_snapshots() {
    let Some(out) = dir() else { return };
    let img = out.join("kernel-snap.image");
    if !img.exists() {
        return;
    }
    let want = host_tree(&out.join("kernel-snap.src"));
    let fs = open(&img, true);
    assert!(!fs.info().read_only, "{:?}", fs.info().ro_reasons);
    let live = fs.root();
    let snap = fs.lookup(live, b"snap").unwrap();
    let mut rng = Rng(3);
    for i in 0..3000 {
        let n = format!("f{:04}", rng.below(4000));
        let (dir, other) = if i % 2 == 0 { (live, snap) } else { (snap, live) };
        if let Ok(ino) = fs.lookup(dir, n.as_bytes()) {
            let _ = fs.write(ino, rng.below(8192), &[i as u8; 300]);
            if i % 7 == 0 {
                fs.unlink(other, n.as_bytes()).ok();
            }
        }
        if i % 500 == 0 {
            fs.sync().unwrap();
        }
    }
    fs.unmount().unwrap();
    drop(fs);
    let o = Command::new("btrfs").args(["check", "--check-data-csum"]).arg(&img).output().unwrap();
    assert!(o.status.success(), "{}\n{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    let fs = open(&img, false);
    let frozen = fs.lookup(fs.root(), b"frozen").unwrap();
    let mut seen = 0;
    fs.read_dir(frozen, 0, &mut |_, _| {
        seen += 1;
        true
    })
    .unwrap();
    assert_eq!(seen, want.keys().filter(|k| k.matches('/').count() == 1).count());
}

/// A volume shaped like a real install: a block group tree, a filesystem id changed after
/// the fact, and files the kernel compressed. Everything on it is then overwritten, cut
/// short, moved and deleted here, with `btrfs check` and the kernel judging the result.
#[test]
fn edits_a_lived_in_volume() {
    let Some(out) = dir() else { return };
    let img = out.join("kernel-lived.image");
    if !img.exists() {
        return;
    }
    let want = host_tree(&out.join("kernel-lived.src"));
    let fs = open(&img, false);
    let features = fs.info().features;
    for f in ["block_group_tree", "metadata_uuid", "compress_zstd"] {
        assert!(features.iter().any(|x| x == f), "the image lacks {f}: {features:?}");
    }
    assert_same(&walk(&fs).unwrap(), &want, "lived: read");
    drop(fs);

    let check = |ctx: &str| {
        let o = Command::new("btrfs").args(["check", "--check-data-csum"]).arg(&img).output().unwrap();
        assert!(o.status.success(), "{ctx}\n{}\n{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    };
    let mut model = Model::from_tree(&want);
    let mut rng = Rng(0x11FE);
    for pass in 0..3 {
        let fs = open(&img, true);
        assert!(!fs.info().read_only, "lived: refused write: {:?}", fs.info().ro_reasons);
        random_ops(&fs, &mut model, &mut rng, 800, 150_000);
        assert_same(&walk(&fs).unwrap(), &model.tree(), &format!("lived: live pass {pass}"));
        fs.unmount().unwrap();
        drop(fs);
        check(&format!("lived: pass {pass}"));
        let fs = open(&img, false);
        assert_same(&walk(&fs).unwrap(), &model.tree(), &format!("lived: reread pass {pass}"));
        let rep = fs.scrub(&mut |_, _| {}).unwrap();
        assert!(rep.errors.is_empty(), "lived: scrub after pass {pass}: {:?}", rep.errors);
    }

    // The kernel must read back exactly what the model holds.
    let (model_dir, mnt) = (out.join("kernel-lived.model"), out.join("kernel-lived.mnt"));
    dump(&model.tree(), &model_dir);
    std::fs::create_dir_all(&mnt).unwrap();
    let sudo = |args: &[&std::ffi::OsStr]| Command::new("sudo").args(args).output().unwrap();
    let mounted = sudo(&["mount".as_ref(), "-o".as_ref(), "loop,ro".as_ref(), img.as_os_str(), mnt.as_os_str()]);
    assert!(mounted.status.success(), "the kernel refused the volume: {}", String::from_utf8_lossy(&mounted.stderr));
    let diff = sudo(&["diff".as_ref(), "-r".as_ref(), "--no-dereference".as_ref(), mnt.as_os_str(), model_dir.as_os_str()]);
    sudo(&["umount".as_ref(), mnt.as_os_str()]);
    assert!(diff.status.success(), "the kernel reads it differently:\n{}", String::from_utf8_lossy(&diff.stdout));
}

/// Parity profiles must read correctly, refuse writes, and survive a lost device.
#[test]
fn raid5_reads_and_rebuilds() {
    let Some(out) = dir() else { return };
    let imgs: Vec<PathBuf> = (0..3).map(|i| out.join(format!("kernel-raid5.{i}.image"))).collect();
    if !imgs[0].exists() {
        return;
    }
    let want = host_tree(&out.join("kernel-raid5.src"));
    let mount = |paths: &[PathBuf]| {
        let devs: Vec<Arc<dyn BlockDev>> =
            paths.iter().map(|p| Arc::new(FileDev::open(p, false).unwrap()) as Arc<dyn BlockDev>).collect();
        Btrfs::open(devs, MountOpts { write: true, cache_bytes: 0 }).unwrap()
    };
    let fs = mount(&imgs);
    assert!(fs.info().read_only);
    assert_same(&walk(&fs).unwrap(), &want, "raid5");
    drop(fs);
    for skip in 0..3 {
        let some: Vec<PathBuf> = imgs.iter().enumerate().filter(|(i, _)| *i != skip).map(|x| x.1.clone()).collect();
        let fs = mount(&some);
        assert_same(&walk(&fs).unwrap(), &want, &format!("raid5 without device {skip}"));
    }
}
