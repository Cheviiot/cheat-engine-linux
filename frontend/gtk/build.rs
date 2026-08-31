fn main() {
    cxx_build::bridge("src/bridge.rs")
        .file("../../bridge/engine_facade.cpp")
        .include("../..")
        .std("c++23")
        .compile("ce_gtk_cxx_bridge");

    if let Ok(lib_dir) = std::env::var("CECORE_LIB_DIR") {
        println!("cargo:rustc-link-search=native={lib_dir}");
        println!("cargo:rustc-link-lib=dylib=cecore");
    }

    println!("cargo:rerun-if-env-changed=CECORE_LIB_DIR");
    println!("cargo:rerun-if-changed=src/bridge.rs");
    println!("cargo:rerun-if-changed=../../bridge/engine_facade.hpp");
    println!("cargo:rerun-if-changed=../../bridge/engine_facade.cpp");
    println!("cargo:rerun-if-changed=../../core/version.hpp");
    println!("cargo:rerun-if-changed=../../core/target_profile.hpp");
    println!("cargo:rerun-if-changed=../../core/types.hpp");
    println!("cargo:rerun-if-changed=../../platform/process_api.hpp");
    println!("cargo:rerun-if-changed=../../platform/linux/linux_process.hpp");
    println!("cargo:rerun-if-changed=../../scanner/memory_scanner.hpp");
}
