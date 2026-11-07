fn main() {
    println!("cargo:rerun-if-changed=res/app.rc");
    println!("cargo:rerun-if-changed=res/app.manifest");
    println!("cargo:rerun-if-changed=res/nixmount.ico");
    embed_resource::compile("res/app.rc", embed_resource::NONE).manifest_required().unwrap();
    // Setup runs elevated from wherever it was downloaded to, usually a folder others can
    // write to. This makes the loader take imported DLLs from System32 only, not from there.
    println!("cargo:rustc-link-arg=/DEPENDENTLOADFLAG:0x800");
}
