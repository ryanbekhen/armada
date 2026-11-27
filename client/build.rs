//! The compiler's version for `armada version`, written as
//! "rust<version>" (e.g. "rust1.92.0").

fn main() {
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
    let version = std::process::Command::new(rustc)
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.split_whitespace().nth(1).map(str::to_string))
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=ARMADA_RUSTC_VERSION=rust{version}");
    println!("cargo:rerun-if-env-changed=ARMADA_VERSION");
    println!("cargo:rerun-if-env-changed=ARMADA_COMMIT");
    println!("cargo:rerun-if-env-changed=ARMADA_DATE");
}
