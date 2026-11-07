//! Corrupted images must produce errors, never a panic, hang or out-of-bounds write.
//! Runs anywhere: fixtures are real `mke2fs` images stored compressed in the repository.
use ext4::Ext4;
use flate2::read::GzDecoder;
use fscore::testkit::*;
use fscore::{Filesystem, MemDev, MountOpts};
use std::io::Read;
use std::path::PathBuf;
use std::sync::Arc;

fn fixtures() -> Vec<(String, Vec<u8>)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
    let mut out = vec![];
    for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if name.starts_with("ext") && name.ends_with(".img.gz") {
            let mut v = vec![];
            GzDecoder::new(std::fs::File::open(e.path()).unwrap()).read_to_end(&mut v).unwrap();
            out.push((name, v));
        }
    }
    out
}

/// Exercises every read path, tolerating errors.
fn poke(fs: &dyn Filesystem) {
    let _ = fs.info();
    let _ = walk(fs);
    let _ = fs.scrub(&mut |_, _| {});
}

#[test]
fn survives_bit_rot() {
    let mut rng = Rng(0xBAD5EED);
    for (name, base) in fixtures() {
        // Metadata concentrates at the front and in group headers, so aim there.
        for round in 0..300 {
            let mut img = base.clone();
            for _ in 0..1 + rng.below(40) {
                let span = if rng.below(2) == 0 { 1 << 20 } else { img.len() as u64 };
                let at = rng.below(span) as usize;
                img[at] = rng.next() as u8;
            }
            let write = round % 3 == 0;
            let dev = Arc::new(MemDev::new(img));
            if let Ok(fs) = Ext4::open(dev, MountOpts { write, cache_bytes: 1 << 20 }) {
                poke(&fs);
                if write {
                    let mut m = Model::default();
                    // Failures are fine here; only panics are bugs.
                    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        random_ops(&fs, &mut m, &mut Rng(round), 30, 10_000);
                    }))
                    .map_err(|e| {
                        let s = e.downcast_ref::<String>().cloned().unwrap_or_default();
                        assert!(s.starts_with("op "), "{name} round {round}: engine panicked: {s}");
                    });
                }
            }
        }
    }
}

#[test]
fn fixtures_round_trip() {
    for (name, img) in fixtures() {
        let dev = Arc::new(MemDev::new(img));
        let fs = Ext4::open(dev.clone(), MountOpts { write: true, cache_bytes: 0 }).unwrap();
        if fs.info().read_only {
            walk(&fs).unwrap();
            continue;
        }
        let mut m = Model::from_tree(&walk(&fs).unwrap());
        random_ops(&fs, &mut m, &mut Rng(9), 800, 100_000);
        assert_same(&walk(&fs).unwrap(), &m.tree(), &name);
        fs.unmount().unwrap();
        let again = Ext4::open(dev, MountOpts::default()).unwrap();
        assert_same(&walk(&again).unwrap(), &m.tree(), &format!("{name} after remount"));
    }
}
