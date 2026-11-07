//! Causeway: one executable holding the interface, the service and the command line.
#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(windows)]
mod canvas;
#[cfg(windows)]
mod cli;
#[cfg(windows)]
mod config;
#[cfg(windows)]
mod disk;
#[cfg(windows)]
mod gui;
#[cfg(windows)]
mod ipc;
#[cfg(windows)]
mod mounts;
mod names;
#[cfg(windows)]
mod service;
#[cfg(windows)]
mod volumes;
#[cfg(windows)]
mod winfsp;

#[cfg(windows)]
fn main() {
    use windows_sys::Win32::System::Console::{AttachConsole, ATTACH_PARENT_PROCESS};
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().is_some_and(|a| a == "render") {
        let dark = args.get(2).is_none_or(|t| t != "light");
        let scene = args.get(3).map_or("default", String::as_str);
        return gui::screenshot(std::path::Path::new(&args[1]), dark, scene);
    }
    if args.is_empty() {
        return gui::run();
    }
    // A GUI-subsystem program has no console unless it borrows its parent's.
    // SAFETY: no pointers involved.
    unsafe { AttachConsole(ATTACH_PARENT_PROCESS) };
    if let Err(e) = cli::run(args) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("Causeway runs on Windows. The filesystem engines are portable; see crates/.");
}
