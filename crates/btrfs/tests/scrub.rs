//! Scrub must find damage, say where it is, and mend a copy that has a good twin.
use btrfs::Btrfs;
use flate2::read::GzDecoder;
use fscore::{BlockDev, CheckReport, Filesystem, MemDev, MountOpts};
use std::io::Read;
use std::sync::Arc;

/// A real `mkfs.btrfs` image: metadata kept twice, data once, one 200,000-byte file of `x`.
fn image() -> Vec<u8> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/btrfs-default.img.gz");
    let mut v = vec![];
    GzDecoder::new(std::fs::File::open(path).unwrap()).read_to_end(&mut v).unwrap();
    v
}

fn find(hay: &[u8], needle: &[u8]) -> Vec<usize> {
    (0..hay.len() - needle.len()).filter(|&i| hay[i..].starts_with(needle)).collect()
}

fn scrub(img: Vec<u8>, write: bool) -> (CheckReport, Vec<u8>) {
    let dev = Arc::new(MemDev::new(img));
    let fs = Btrfs::open(vec![dev.clone() as Arc<dyn BlockDev>], MountOpts { write, cache_bytes: 0 }).unwrap();
    let rep = fs.scrub(&mut |_, _| {}).unwrap();
    if write {
        fs.unmount().unwrap();
    }
    drop(fs);
    (rep, dev.snapshot())
}

#[test]
fn a_sound_volume_scrubs_clean() {
    let (rep, _) = scrub(image(), false);
    assert!(rep.errors.is_empty(), "{:?}", rep.errors);
    assert_eq!(rep.repaired, 0);
    assert!(rep.scanned_bytes >= 200_000);
}

/// Data has one copy here, so a bad sector can only be reported. The sectors around it
/// must still be checked.
#[test]
fn a_damaged_data_sector_is_reported_alone() {
    let mut img = image();
    let (clean, _) = scrub(img.clone(), false);
    let run = find(&img, &[b'x'; 8192])[0];
    let sector = run.next_multiple_of(4096);
    img[sector + 100] ^= 1;
    for write in [false, true] {
        let (rep, _) = scrub(img.clone(), write);
        assert_eq!(rep.errors.len(), 1, "{:?}", rep.errors);
        assert!(rep.errors[0].contains("no good copy"), "{:?}", rep.errors);
        assert_eq!((rep.repaired, rep.scanned_bytes), (0, clean.scanned_bytes));
    }
}

/// Damage spread over a run of sectors is counted sector by sector, wherever it falls.
#[test]
fn every_damaged_sector_in_a_run_is_counted() {
    let mut img = image();
    let first = find(&img, &[b'x'; 8192])[0].next_multiple_of(4096);
    for sector in [0, 1, 7, 30] {
        img[first + sector * 4096 + sector] ^= 0x80;
    }
    let (rep, _) = scrub(img, false);
    assert_eq!(rep.errors.len(), 4, "{:?}", rep.errors);
}

/// Metadata is kept twice. One bad copy is reported when the volume can't be written, and
/// rewritten from its twin when it can.
#[test]
fn a_damaged_metadata_copy_is_mended_from_its_twin() {
    let base = image();
    // The small file's contents sit inside tree blocks. Take a place where damage is noticed.
    let damaged = |at: usize| {
        let mut img = base.clone();
        img[at] ^= 1;
        img
    };
    let live: Vec<usize> =
        find(&base, b"hello from linux\n").into_iter().filter(|&at| !scrub(damaged(at), false).0.errors.is_empty()).collect();
    assert!(live.len() >= 2 && live.len().is_multiple_of(2), "live tree blocks are stored twice: {live:?}");
    let at = live[0];

    let (rep, _) = scrub(damaged(at), false);
    assert_eq!(rep.errors.len(), 1, "{:?}", rep.errors);
    assert!(rep.errors[0].contains("is bad"), "{:?}", rep.errors);

    let (rep, mended) = scrub(damaged(at), true);
    assert!(rep.errors.is_empty(), "{:?}", rep.errors);
    assert_eq!(rep.repaired, 1);
    assert_eq!(mended[at..at + 17], base[at..at + 17]);
    let (rep, _) = scrub(mended, false);
    assert!(rep.errors.is_empty() && rep.repaired == 0, "{:?}", rep.errors);
}
