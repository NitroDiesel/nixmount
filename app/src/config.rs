//! Saved state: which volumes mount automatically, and remembered image files.
//! Lives in `%ProgramData%\NixMount`, writable only by administrators and SYSTEM.
use crate::mounts::MountRequest;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

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

/// Makes the configuration folder writable by SYSTEM and Administrators only, since it
/// decides what the service mounts. Any user can create folders in `%ProgramData%`, so before
/// a first install it may hold anything, and with `keep_settings` false all of that goes: the
/// install stops if it can't. Pass true only for a folder an earlier install secured.
pub fn secure_directory(keep_settings: bool) -> Result<(), String> {
    const ADMINS: &str = "*S-1-5-32-544";
    let d = dir();
    if !keep_settings && std::fs::symlink_metadata(&d).is_ok() {
        icacls(&d, &["/setowner", ADMINS])?;
        icacls(&d, &["/grant", "*S-1-5-32-544:(F)"])?;
        // This removes links rather than following them.
        std::fs::remove_dir_all(&d).map_err(|e| format!("could not clear {}: {e}", d.display()))?;
    }
    std::fs::create_dir_all(&d).map_err(|e| e.to_string())?;
    icacls(&d, &["/setowner", ADMINS])?;
    icacls(&d, &["/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "/grant:r", "*S-1-5-32-544:(OI)(CI)F"])?;
    // Versions before 0.1.2 left this file with no permissions at all when upgrading. Inheriting
    // from the folder brings it back, and on a first install there is simply nothing to do.
    let _ = icacls(&path(), &["/reset"]);
    Ok(())
}

/// Deletes saved settings when uninstalling.
pub fn remove() {
    let d = dir();
    let _ = std::fs::remove_file(path());
    let _ = std::fs::remove_file(d.join("config.tmp"));
    let _ = std::fs::remove_dir(d);
}
