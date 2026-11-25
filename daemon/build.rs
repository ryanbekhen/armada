//! The runtime pack armadad carries (ADR 0055, "What ships"): with the
//! bundle feature, the pack `make runtime-bundle` built for the target
//! (internal/runtime/embedded/bundle/linux_ARCH.pack), or the file
//! ARMADA_RUNTIME_PACK names, compiled in with include_bytes!; without
//! either, none, as Go's build without the bundle tag.

fn main() {
    println!("cargo::rustc-check-cfg=cfg(armada_bundle)");
    println!("cargo:rerun-if-env-changed=ARMADA_RUNTIME_PACK");
    let mut pack = std::env::var("ARMADA_RUNTIME_PACK").unwrap_or_default();
    if pack.is_empty() && std::env::var_os("CARGO_FEATURE_BUNDLE").is_some() {
        let arch = match std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
            Ok("x86_64") => "amd64",
            Ok("aarch64") => "arm64",
            Ok(a) => panic!("no runtime pack for {a}"),
            Err(_) => panic!("no target architecture"),
        };
        let root = std::env::var("CARGO_MANIFEST_DIR").expect("manifest dir");
        pack = format!("{root}/../internal/runtime/embedded/bundle/linux_{arch}.pack");
    }
    if pack.is_empty() {
        return;
    }
    let path = std::fs::canonicalize(&pack)
        .unwrap_or_else(|e| panic!("runtime pack {pack}: {e} (make runtime-bundle builds it)"));
    println!("cargo:rerun-if-changed={}", path.display());
    println!("cargo:rustc-cfg=armada_bundle");
    println!("cargo:rustc-env=ARMADA_PACK_PATH={}", path.display());
}
