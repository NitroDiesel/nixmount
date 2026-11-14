//! Saved state: which volumes mount automatically, and remembered image files.
//!
//! It lives in `settings` beside the installed program. Only administrators can create
//! anything in `Program Files`, so nobody else can put a folder there first, hold it open, or
//! swap it for a link, which a folder in `%ProgramData%` allowed.
use crate::mounts::MountRequest;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::ptr::null_mut;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    GetNamedSecurityInfoW, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, SECURITY_ATTRIBUTES};
use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Automount {
    /// Filesystem UUID: stable across drive reordering, unlike a disk number.
    pub uuid: String,
    pub mount: MountRequest,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub automounts: Vec<Automount>,
    #[serde(default)]
    pub images: Vec<PathBuf>,
}

const FILE: &str = "config.json";
const TEMPORARY: &str = "config.tmp";

fn dir() -> PathBuf {
    crate::install::program_dir().join("settings")
}

/// Where versions up to 0.2.1 kept their settings.
fn old_dir() -> PathBuf {
    let base = std::env::var_os("ProgramData").map_or_else(|| PathBuf::from(r"C:\ProgramData"), PathBuf::from);
    base.join("NixMount")
}

impl Config {
    pub fn load() -> Config {
        std::fs::read(dir().join(FILE)).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
    }

    /// Writes through a temporary file, so a crash can't leave half a config behind.
    pub fn save(&self) -> Result<(), String> {
        let d = dir();
        prepare()?;
        let tmp = d.join(TEMPORARY);
        let body = serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(&tmp, body).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, d.join(FILE)).map_err(|e| e.to_string())
    }
}

/// The settings folder's permissions: owned by Administrators, full control for SYSTEM and
/// Administrators that everything inside inherits, and nothing inherited from above. What the
/// service mounts is nobody else's to read, let alone change.
const LOCKED: &str = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

/// Whether a folder with these permissions, in SDDL, belongs to SYSTEM or Administrators and
/// gives nobody else anything.
fn only_admins(sddl: &str) -> bool {
    let Some((owner, dacl)) = sddl.split_once("D:") else { return false };
    let mut aces = dacl.split('(').skip(1).map(|ace| ace.split(';').nth(5).map(|sid| sid.trim_end_matches(')')));
    matches!(owner, "O:BA" | "O:SY") && dacl.contains('(') && aces.all(|sid| matches!(sid, Some("SY" | "BA")))
}

/// Whether `d` is a folder an install locked, rather than one anybody could have put in its
/// place: a real folder, not a link, that only administrators control.
fn locked_down(d: &Path) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    let real = std::fs::symlink_metadata(d).is_ok_and(|m| m.is_dir() && m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0);
    let path = crate::wide(&d.to_string_lossy());
    let which = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    let (mut sd, mut text) = (null_mut(), null_mut());
    // SAFETY: on success `sd` and then `text` are LocalAlloc'd, and both are freed below.
    // `text` is NUL-terminated.
    unsafe {
        if !real || GetNamedSecurityInfoW(path.as_ptr(), SE_FILE_OBJECT, which, null_mut(), null_mut(), null_mut(), null_mut(), &mut sd) != 0 {
            return false;
        }
        let ok = ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, 1, which, &mut text, null_mut()) != 0;
        LocalFree(sd);
        if !ok {
            return false;
        }
        let len = (0..).take_while(|i| *text.add(*i) != 0).count();
        let sddl = String::from_utf16_lossy(std::slice::from_raw_parts(text, len));
        LocalFree(text.cast());
        only_admins(&sddl)
    }
}

/// Creates the folder with its permissions already in place.
fn create_locked(d: &Path) -> Result<(), String> {
    let (sddl, path) = (crate::wide(LOCKED), crate::wide(&d.to_string_lossy()));
    let mut sd = null_mut();
    // SAFETY: strings are NUL-terminated; on success `sd` is LocalAlloc'd and freed below.
    unsafe {
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), 1, &mut sd, null_mut()) == 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let sa = SECURITY_ATTRIBUTES { nLength: size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: sd, bInheritHandle: 0 };
        let made = CreateDirectoryW(path.as_ptr(), &sa);
        let e = std::io::Error::last_os_error();
        LocalFree(sd);
        if made == 0 {
            return Err(format!("could not create {}: {e}", d.display()));
        }
    }
    Ok(())
}

/// Makes sure the settings folder exists. The first time, settings an earlier version saved
/// are brought over.
pub fn prepare() -> Result<(), String> {
    let d = dir();
    if d.exists() {
        return Ok(());
    }
    if let Some(program) = d.parent() {
        std::fs::create_dir_all(program).map_err(|e| e.to_string())?;
    }
    create_locked(&d)?;
    bring_over(&old_dir(), &d);
    Ok(())
}

/// Moves settings from where versions up to 0.2.1 kept them. Any user could create that
/// folder, so it is believed only if its permissions show that an install locked it, and
/// otherwise left exactly as it is: it isn't ours.
fn bring_over(old: &Path, new: &Path) {
    if locked_down(old) {
        move_settings(old, new);
    }
}

/// The old copy goes only once the new one is in place: settings that can't be copied stay
/// where they were, not nowhere.
fn move_settings(old: &Path, new: &Path) {
    let from = old.join(FILE);
    if !from.exists() || std::fs::copy(&from, new.join(FILE)).is_ok() {
        remove_from(old);
    }
}

fn remove_from(d: &Path) {
    let _ = std::fs::remove_file(d.join(FILE));
    let _ = std::fs::remove_file(d.join(TEMPORARY));
    let _ = std::fs::remove_dir(d);
}

/// Deletes saved settings when uninstalling.
pub fn remove() {
    remove_from(&dir());
    if locked_down(&old_dir()) {
        remove_from(&old_dir());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_folder_locked_to_administrators_is_trusted() {
        assert!(only_admins(LOCKED));
        assert!(only_admins("O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"));
        assert!(only_admins("O:SYD:P(A;;FA;;;SY)"));
        // Somebody else owns it, or has any entry at all, or there are no entries to speak of.
        assert!(!only_admins("O:S-1-5-21-1-2-3-1001D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"));
        assert!(!only_admins("O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;BU)"));
        assert!(!only_admins("O:BAD:AI(A;OICIID;FA;;;SY)(A;OICIID;0x1200a9;;;BU)"));
        assert!(!only_admins("O:BAD:NO_ACCESS_CONTROL"));
        assert!(!only_admins("O:BAD:P"));
        assert!(!only_admins("O:BA"));
        assert!(!locked_down(&std::env::temp_dir()));
    }

    /// A folder anybody could have made is neither believed nor touched.
    #[test]
    fn settings_in_an_unlocked_folder_stay_where_they_are() {
        let base = std::env::temp_dir().join(format!("nixmount-settings-{}", std::process::id()));
        let (old, new) = (base.join("old"), base.join("new"));
        std::fs::create_dir_all(&old).unwrap();
        std::fs::create_dir_all(&new).unwrap();
        std::fs::write(old.join(FILE), r#"{"images":["C:\\planted.img"]}"#).unwrap();
        bring_over(&old, &new);
        assert!(old.join(FILE).exists() && !new.join(FILE).exists());
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn settings_move_whole_or_not_at_all() {
        let base = std::env::temp_dir().join(format!("nixmount-move-{}", std::process::id()));
        let (old, new) = (base.join("old"), base.join("new"));
        std::fs::create_dir_all(&old).unwrap();
        std::fs::write(old.join(FILE), "{}").unwrap();
        // Nowhere to copy to: the settings stay where they were.
        move_settings(&old, &new);
        assert!(old.join(FILE).exists());
        std::fs::create_dir_all(&new).unwrap();
        move_settings(&old, &new);
        assert!(new.join(FILE).exists() && !old.exists());
        std::fs::remove_dir_all(&base).unwrap();
    }
}
