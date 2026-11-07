//! Saved state: which volumes mount automatically, and remembered image files.
//! Lives in `%ProgramData%\Causeway`, writable only by administrators and SYSTEM.
use crate::mounts::MountRequest;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

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
    base.join("Causeway")
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
            secure_directory()?;
        }
        let tmp = d.join("config.tmp");
        let body = serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(&tmp, body).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, path()).map_err(|e| e.to_string())
    }
}

/// Makes the configuration folder writable by SYSTEM and Administrators only, since it
/// decides what the service mounts. Any user can create folders in `%ProgramData%`, so one
/// may already exist with a hostile owner, ACL or contents: all of that gets replaced, and
/// the install stops if it can't be.
pub fn secure_directory() -> Result<(), String> {
    let d = dir();
    std::fs::create_dir_all(&d).map_err(|e| e.to_string())?;
    let steps: [&[&str]; 3] = [
        &["/setowner", "*S-1-5-32-544", "/T", "/C"],
        &["/reset", "/T", "/C"],
        &["/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "/grant:r", "*S-1-5-32-544:(OI)(CI)F", "/T", "/C"],
    ];
    for args in steps {
        let ok = std::process::Command::new("icacls").arg(&d).args(args).output().is_ok_and(|o| o.status.success());
        if !ok {
            return Err(format!("could not secure {}", d.display()));
        }
    }
    Ok(())
}
