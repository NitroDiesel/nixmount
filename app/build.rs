fn main() {
    println!("cargo:rerun-if-changed=res/app.rc");
    println!("cargo:rerun-if-changed=res/app.manifest");
    println!("cargo:rerun-if-changed=res/nixmount.ico");
    let version = ["MAJOR", "MINOR", "PATCH"].map(|part| {
        let number = std::env::var(format!("CARGO_PKG_VERSION_{part}")).unwrap();
        format!("V_{part}={number}")
    });
    embed_resource::compile("res/app.rc", version).manifest_required().unwrap();
    // Setup runs elevated from wherever it was downloaded to, usually a folder others can
    // write to. This makes the loader take imported DLLs from System32 only, not from there.
    println!("cargo:rustc-link-arg=/DEPENDENTLOADFLAG:0x800");
}
