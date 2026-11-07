//! Corrupted images must produce errors, never a panic, hang or out-of-bounds access.
use btrfs::Btrfs;
use flate2::read::GzDecoder;
use fscore::testkit::*;
use fscore::{BlockDev, Filesystem, MemDev, MountOpts};
use std::io::Read;
use std::path::PathBuf;
use std::sync::Arc;

fn fixtures() -> Vec<(String, Vec<u8>)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
    let mut out = vec![];
    for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if name.starts_with("btrfs") && name.ends_with(".img.gz") {
            let mut v = vec![];
            GzDecoder::new(std::fs::File::open(e.path()).unwrap()).read_to_end(&mut v).unwrap();
            out.push((name, v));
        }
    }
    out
}

fn open(img: Vec<u8>, write: bool) -> fscore::Result<Btrfs> {
    let d: Arc<dyn BlockDev> = Arc::new(MemDev::new(img));
    Btrfs::open(vec![d], MountOpts { write, cache_bytes: 1 << 20 })
}

#[test]
fn survives_bit_rot() {
    let mut rng = Rng(0xFEEDBAD);
    for (name, base) in fixtures() {
        // Without forging checksums bit flips stop at verification, so the interesting
        // input is the region before that: superblocks and system chunks.
        for round in 0..200 {
            let mut img = base.clone();
            for _ in 0..1 + rng.below(30) {
                let at = 0x10000 + rng.below(4096) as usize;
                img[at] = rng.next() as u8;
                let at = rng.below(img.len() as u64) as usize;
                img[at] = rng.next() as u8;
            }
            if let Ok(fs) = open(img, round % 2 == 0) {
                let _ = fs.info();
                let _ = walk(&fs);
                let _ = fs.scrub(&mut |_, _| {});
                let _ = fs.sync();
            }
            let _ = &name;
        }
    }
}

#[test]
fn fixtures_round_trip() {
    for (name, img) in fixtures() {
        let d = Arc::new(MemDev::new(img));
        let dev: Arc<dyn BlockDev> = d.clone();
        let fs = Btrfs::open(vec![dev.clone()], MountOpts { write: true, cache_bytes: 0 }).unwrap();
        let mut m = Model::from_tree(&walk(&fs).unwrap());
        random_ops(&fs, &mut m, &mut Rng(9), 500, 80_000);
        assert_same(&walk(&fs).unwrap(), &m.tree(), &name);
        fs.unmount().unwrap();
        let again = Btrfs::open(vec![dev], MountOpts::default()).unwrap();
        assert_same(&walk(&again).unwrap(), &m.tree(), &format!("{name} after remount"));
    }
}
