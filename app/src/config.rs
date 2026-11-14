//! Saved state: which volumes mount automatically, and remembered image files.
//! Lives in `%ProgramData%\NixMount`, writable only by administrators and SYSTEM.
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

fn dir() -> PathBuf {
    let base = std::env::var_os("ProgramData").map_or_else(|| PathBuf::from(r"C:\ProgramData"), PathBuf::from);
    base.join("NixMount")
}

fn path() -> PathBuf {
    dir().join("config.json")
}

impl Config {
    pub fn load() -> Config {
        std::fs::read(path()).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
    }

    /// Writes through a temporary file, so a crash can't leave half a config behind.
    pub fn save(&self) -> Result<(), String> {
        let d = dir();
        if !d.exists() {
            secure_directory(false)?;
        }
        let tmp = d.join("config.tmp");
        let body = serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(&tmp, body).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, path()).map_err(|e| e.to_string())
    }
}

/// Changes one path's permissions, never a tree: `/T` walks through junctions, so a planted
/// one would aim this at any file on the machine. `/L` likewise acts on a link, not its target.
fn icacls(path: &Path, args: &[&str]) -> Result<(), String> {
    let tool = crate::install::system_dir().join("icacls.exe");
    let ok = std::process::Command::new(tool).arg(path).args(args).arg("/L").output().is_ok_and(|o| o.status.success());
    ok.then_some(()).ok_or_else(|| format!("could not secure {}", path.display()))
}

/// The settings folder's permissions: owned by Administrators, full control for SYSTEM and
/// Administrators that everything inside inherits, and nothing inherited from above.
const LOCKED: &str = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

/// Whether a folder with these permissions, in SDDL, belongs to SYSTEM or Administrators and
/// gives nobody else anything.
fn only_admins(sddl: &str) -> bool {
    let Some((owner, dacl)) = sddl.split_once("D:") else { return false };
    let mut aces = dacl.split('(').skip(1).map(|ace| ace.split(';').nth(5).map(|sid| sid.trim_end_matches(')')));
    matches!(owner, "O:BA" | "O:SY") && dacl.contains('(') && aces.all(|sid| matches!(sid, Some("SY" | "BA")))
}

/// Whether `d` is a folder an earlier install locked, rather than one anybody could have
/// put in its place since: a real folder, not a link, that only administrators control.
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

/// Creates the folder with its permissions already in place, so there is never a moment when
/// someone else can write into it. Fails if something is already there.
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

/// Makes sure the configuration folder is one only SYSTEM and Administrators can write, since
/// it decides what the service mounts. Any user can create folders in `%ProgramData%`, so a
/// folder found there is kept only if `keep_settings` asks and its permissions show that an
/// earlier install locked it. Anything else goes, whatever it holds, and the install stops if
/// it can't be made to.
pub fn secure_directory(keep_settings: bool) -> Result<(), String> {
    let d = dir();
    if keep_settings && locked_down(&d) {
        // Versions before 0.1.2 left this file with no permissions at all when upgrading.
        // Inheriting from the folder brings it back.
        let _ = icacls(&path(), &["/reset"]);
        return Ok(());
    }
    if std::fs::symlink_metadata(&d).is_ok() {
        icacls(&d, &["/setowner", "*S-1-5-32-544"])?;
        icacls(&d, &["/grant", "*S-1-5-32-544:(F)"])?;
        // This removes links rather than following them. Something inside that refuses to go
        // moves aside with the whole folder: out of the way is enough.
        if std::fs::remove_dir_all(&d).is_err() {
            let aside = d.with_extension(format!("removed-{}", std::process::id()));
            std::fs::rename(&d, aside).map_err(|e| format!("could not clear {}: {e}", d.display()))?;
        }
    }
    create_locked(&d)
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
}

/// Deletes saved settings when uninstalling.
pub fn remove() {
    let d = dir();
    let _ = std::fs::remove_file(path());
    let _ = std::fs::remove_file(d.join("config.tmp"));
    let _ = std::fs::remove_dir(d);
}
