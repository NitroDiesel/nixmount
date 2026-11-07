fn main() {
    println!("cargo:rerun-if-changed=res/app.rc");
    println!("cargo:rerun-if-changed=res/app.manifest");
    println!("cargo:rerun-if-changed=res/causeway.ico");
    embed_resource::compile("res/app.rc", embed_resource::NONE).manifest_required().unwrap();
}
