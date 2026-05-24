// build.rs — Link flags for bare-metal Windows x64 implant
fn main() {
    println!("cargo:rustc-link-arg=/NODEFAULTLIB");
    println!("cargo:rustc-link-arg=/ENTRY:main");
    println!("cargo:rustc-link-arg=/SUBSYSTEM:CONSOLE");
    println!("cargo:rustc-link-arg=/MERGE:.rdata=.text");
    println!("cargo:rustc-link-arg=/MERGE:.pdata=.text");
    println!("cargo:rustc-link-arg=/FIXED");
}
