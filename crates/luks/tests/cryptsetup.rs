#![cfg(unix)]
//! Volumes made by cryptsetup and filled by the Linux kernel (`ci/luks-check.sh make`),
//! opened here: the independent check that headers, key derivation and sector encryption
//! match dm-crypt. The test then edits them, and `ci/luks-check.sh verify` has Linux
//! decrypt and judge the result.
use fscore::testkit::*;
use fscore::{BlockDev, FileDev, Filesystem, MountOpts, Result};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

fn dir() -> Option<PathBuf> {
    let d = std::env::var_os("NIXMOUNT_LUKS").map(PathBuf::from);
    if d.is_none() {
        eprintln!("skipped: NIXMOUNT_LUKS is not set");
    }
    d
}

/// Each line of volumes.txt: name, filesystem, passphrase, then any other passphrases.
fn volumes(dir: &Path) -> Vec<Vec<String>> {
    let list = std::fs::read_to_string(dir.join("volumes.txt")).unwrap();
    list.lines().filter(|l| !l.trim().is_empty()).map(|l| l.split_whitespace().map(str::to_string).collect()).collect()
}

fn image(dir: &Path, name: &str, write: bool) -> Arc<dyn BlockDev> {
    Arc::new(FileDev::open(&dir.join(format!("{name}.img")), write).unwrap())
}

fn open_fs(kind: &str, dev: Arc<dyn BlockDev>, write: bool) -> Box<dyn Filesystem> {
    let opts = MountOpts { write, cache_bytes: 0 };
    match kind {
        "ext4" => Box::new(ext4::Ext4::open(dev, opts).unwrap()),
        _ => Box::new(btrfs::Btrfs::open(vec![dev], opts).unwrap()),
    }
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

#[test]
fn opens_and_edits_what_cryptsetup_made() {
    let Some(dir) = dir() else { return };
    let want = host_tree(&dir.join("src"));
    for v in volumes(&dir) {
        let (name, kind, pass) = (&v[0], &v[1], &v[2]);
        let file = image(&dir, name, true);
        let h = luks::read_header(file.as_ref()).unwrap();
        eprintln!("{name}: LUKS{}, {}", h.version, h.summary().join(", "));
        assert!(h.unlock(file.as_ref(), b"not the passphrase").is_err(), "{name}: a wrong passphrase unlocked it");
        let t = Instant::now();
        let key = h.unlock(file.as_ref(), pass.as_bytes()).unwrap();
        eprintln!("{name}: unlocked in {:.1?}", t.elapsed());
        for other in &v[3..] {
            let k = h.unlock(file.as_ref(), other.as_bytes()).unwrap();
            assert_eq!(k.as_bytes(), key.as_bytes(), "{name}: keyslots disagree about the key");
        }
        let dev: Arc<dyn BlockDev> = Arc::new(h.open(file.clone(), &key).unwrap());

        let fs = open_fs(kind, dev.clone(), false);
        assert_same(&walk(fs.as_ref()).unwrap(), &want, &format!("{name}: what the kernel wrote"));
        drop(fs);

        let mut model = Model::from_tree(&want);
        let mut rng = Rng(0x10C5 ^ name.len() as u64);
        let fs = open_fs(kind, dev.clone(), true);
        assert!(!fs.info().read_only, "{name}: refused write: {:?}", fs.info().ro_reasons);
        random_ops(fs.as_ref(), &mut model, &mut rng, 400, 100_000);
        fs.unmount().unwrap();
        drop(fs);
        let fs = open_fs(kind, dev, false);
        assert_same(&walk(fs.as_ref()).unwrap(), &model.tree(), &format!("{name}: reread"));
        dump(&model.tree(), &dir.join(format!("{name}.expected")));
    }
}

/// A device with one byte flipped, standing in for a damaged sector.
struct Flipped {
    inner: Arc<dyn BlockDev>,
    at: u64,
}

impl BlockDev for Flipped {
    fn read_at(&self, off: u64, buf: &mut [u8]) -> Result<()> {
        self.inner.read_at(off, buf)?;
        if (off..off + buf.len() as u64).contains(&self.at) {
            buf[(self.at - off) as usize] ^= 0xFF;
        }
        Ok(())
    }
    fn write_at(&self, off: u64, data: &[u8]) -> Result<()> {
        self.inner.write_at(off, data)
    }
    fn flush(&self) -> Result<()> {
        self.inner.flush()
    }
    fn len(&self) -> u64 {
        self.inner.len()
    }
}

#[test]
fn falls_back_to_the_second_header_copy() {
    let Some(dir) = dir() else { return };
    for v in volumes(&dir) {
        let file = image(&dir, &v[0], false);
        if luks::read_header(file.as_ref()).unwrap().version != 2 {
            continue;
        }
        // Inside the primary copy's JSON, so only its checksum notices.
        let damaged = Flipped { inner: file, at: 4096 + 40 };
        let h = luks::read_header(&damaged).unwrap();
        h.unlock(&damaged, v[2].as_bytes()).unwrap();
        eprintln!("{}: opened from the second header copy", v[0]);
    }
}
