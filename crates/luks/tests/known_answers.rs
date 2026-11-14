//! Images and answers from cryptsetup's own test suite (tests/compat-test, compat-test2): the
//! reference implementation's view of what they hold. Runs everywhere, unlike the Linux check.
use fscore::{BlockDev, MemDev};
use sha2::Digest;
use std::io::Read;
use std::sync::Arc;

fn image(name: &str) -> Arc<dyn BlockDev> {
    let path = format!("{}/../../tests/fixtures/cryptsetup/{name}.img.gz", env!("CARGO_MANIFEST_DIR"));
    let mut data = vec![];
    flate2::read::GzDecoder::new(std::fs::File::open(path).unwrap()).read_to_end(&mut data).unwrap();
    Arc::new(MemDev::new(data))
}

fn decrypted(dev: &Arc<dyn BlockDev>, passphrase: &[u8]) -> Vec<u8> {
    let h = luks::read_header(dev.as_ref()).unwrap();
    assert!(h.unlock(dev.as_ref(), b"compatkey!").is_err(), "a wrong passphrase unlocked it");
    let key = h.unlock(dev.as_ref(), passphrase).unwrap();
    let plain = h.open(dev.clone(), &key).unwrap();
    let mut all = vec![0u8; plain.len() as usize];
    plain.read_at(0, &mut all).unwrap();
    all
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn luks1_cbc_essiv_decrypts_as_cryptsetup_does() {
    let data = decrypted(&image("luks1-cbc-essiv"), b"compatkey");
    assert_eq!(hex(&sha2::Sha256::digest(&data)), "7428e8f2436882a07eb32765086f5c899474c08b5576f556b573d2aabdf923e8");
}

/// The LUKS 1.0 layout, whose first keyslot isn't aligned.
#[test]
fn luks1_v1_0_cbc_plain_decrypts_as_cryptsetup_does() {
    let data = decrypted(&image("luks1-v1.0-cbc-plain"), b"compatkey");
    assert_eq!(hex(&sha1::Sha1::digest(&data)), "51b48c2471a7593ceaf14dc5e66bca86ed05f6cc");
}

/// The largest LUKS2 metadata area, which also moves the second header copy.
#[test]
fn luks2_with_4_mib_of_metadata_unlocks() {
    let dev = image("luks2-metadata-4m");
    let h = luks::read_header(dev.as_ref()).unwrap();
    assert_eq!(h.version, 2);
    assert!(h.unlock(dev.as_ref(), b"Qx3qn46vq0w").is_err(), "a wrong passphrase unlocked it");
    h.unlock(dev.as_ref(), b"Qx3qn46vq0v").unwrap();
}

/// A changed byte anywhere in a keyslot's material must make that keyslot useless, not
/// yield a different key that happens to pass.
#[test]
fn a_damaged_keyslot_fails_cleanly() {
    let dev = image("luks1-cbc-essiv");
    let mut all = vec![0u8; dev.len() as usize];
    dev.read_at(0, &mut all).unwrap();
    // Keyslot 0's material starts at sector 8 in this image.
    all[8 * 512 + 100] ^= 1;
    let damaged: Arc<dyn BlockDev> = Arc::new(MemDev::new(all));
    let h = luks::read_header(damaged.as_ref()).unwrap();
    assert!(h.unlock(damaged.as_ref(), b"compatkey").is_err());
}

/// A header can ask for any amount of key-derivation work. One asking for far more than a
/// real volume would is refused when it is read, before a passphrase is ever tried.
#[test]
fn a_header_asking_for_endless_work_is_refused() {
    let dev = image("luks1-cbc-essiv");
    let mut all = vec![0u8; dev.len() as usize];
    dev.read_at(0, &mut all).unwrap();
    // The iteration count of keyslot 0, and then of the key digest.
    for at in [208 + 4, 164] {
        let mut hostile = all.clone();
        hostile[at..at + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        let e = luks::read_header(&MemDev::new(hostile)).unwrap_err();
        assert!(e.to_string().contains("key-derivation work"), "{e}");
    }
}
