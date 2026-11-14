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
                img[at] = rng.next_u64() as u8;
                let at = rng.below(img.len() as u64) as usize;
                img[at] = rng.next_u64() as u8;
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

/// An attacker can compute checksums, so damage that passes verification is the real test
/// of the structural checks behind it. Tree blocks are found by their filesystem id, damaged,
/// and re-signed.
#[test]
fn survives_forged_checksums() {
    let mut rng = Rng(0xF06ED);
    for (name, base) in fixtures() {
        let node = u32::from_le_bytes(base[0x10094..0x10098].try_into().unwrap()) as usize;
        let fsid = base[0x10020..0x10030].to_vec();
        let nodes: Vec<usize> =
            (0..base.len() - node).step_by(node).filter(|o| base[o + 0x20..o + 0x30] == fsid[..]).collect();
        assert!(nodes.len() > 8, "{name}: no tree blocks found");
        for round in 0..400u64 {
            let mut img = base.clone();
            for _ in 0..1 + rng.below(3) {
                let o = nodes[rng.below(nodes.len() as u64) as usize];
                for _ in 0..1 + rng.below(6) {
                    // Headers and the item table first: that is where the structure lives.
                    let span = if rng.below(3) == 0 { node - 0x30 } else { 512 };
                    img[o + 0x30 + rng.below(span as u64) as usize] = rng.next_u64() as u8;
                }
                let c = crc32c::crc32c(&img[o + 0x20..o + node]);
                img[o..o + 4].copy_from_slice(&c.to_le_bytes());
            }
            let write = round % 3 == 0;
            let Ok(fs) = open(img, write) else { continue };
            let _ = fs.info();
            let _ = walk(&fs);
            let _ = fs.scrub(&mut |_, _| {});
            if write {
                let mut m = Model::default();
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    random_ops(&fs, &mut m, &mut Rng(round), 20, 8_000);
                }))
                .map_err(|e| {
                    let s = e.downcast_ref::<String>().cloned().unwrap_or_default();
                    assert!(s.starts_with("op "), "{name} round {round}: engine panicked: {s}");
                });
            }
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
