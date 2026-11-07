//! Replays a journal left dirty by the real Linux kernel (made by `ci/kernel-check.sh`).
use ext4::Ext4;
use fscore::testkit::*;
use fscore::{resolve, Filesystem, MemDev, MountOpts};
use std::process::Command;
use std::sync::Arc;

#[test]
fn replays_linux_journal() {
    let Ok(out) = std::env::var("NIXMOUNT_OUT") else { return };
    let path = std::path::Path::new(&out).join("dirty.img");
    let Ok(img) = std::fs::read(&path) else { return };

    // Read-only: recovered in memory, disk untouched.
    let mem = Arc::new(MemDev::new(img.clone()));
    let ro = Ext4::open(mem.clone(), MountOpts::default()).unwrap();
    let info = ro.info();
    assert!(info.notes.iter().any(|n| n.contains("in memory")), "expected a dirty journal: {:?}", info.notes);
    let seen = walk(&ro).unwrap();
    assert!(mem.snapshot() == img, "read-only recovery wrote to the disk");
    assert_eq!(seen.keys().filter(|k| k.starts_with("/journaled/")).count(), 200);

    // Read-write: replayed to disk, and e2fsck agrees.
    let mem = Arc::new(MemDev::new(img));
    let fs = Ext4::open(mem.clone(), MountOpts { write: true, cache_bytes: 0 }).unwrap();
    assert_same(&walk(&fs).unwrap(), &seen, "replay");
    let f = resolve(&fs, "/journaled/f7").unwrap();
    assert_eq!(read_all(&fs, f, 7).unwrap(), b"file-7\n");
    fs.unmount().unwrap();
    let done = path.with_extension("replayed.img");
    std::fs::write(&done, mem.snapshot()).unwrap();
    let st = Command::new("e2fsck").args(["-fn"]).arg(&done).status().unwrap();
    assert!(st.success());
}
