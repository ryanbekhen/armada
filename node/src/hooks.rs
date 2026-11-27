//! Test hooks: the ARMADA_NODE_TEST_* variables tests set to
//! reach what a test cannot arrange from outside (a volume entry swapped
//! mid-archive, the free space a restore sees, a bucket on a loopback
//! address). Only a binary built with the `test-hooks` feature reads them
//! (`make node-test-hooks`); release builds (`make node`) ignore them, so
//! nothing in a node's environment can turn one on.
//!
//!   armada-node test-hooks
//!       stdout: {"testHooks": BOOL}, whether this binary reads them

/// Whether this binary reads the test hooks.
pub const ENABLED: bool = cfg!(feature = "test-hooks");

/// The hook's value, or None in a build without hooks.
pub fn var_os(name: &str) -> Option<std::ffi::OsString> {
    if ENABLED {
        std::env::var_os(name)
    } else {
        None
    }
}

/// The hook's value as text, or None in a build without hooks.
pub fn var(name: &str) -> Option<String> {
    var_os(name).and_then(|v| v.into_string().ok())
}

/// `--extra-ca FILE`, the CA the parity tests' registries and buckets are
/// signed with: an option only of builds with test hooks, so nothing can
/// make a release build trust another CA.
pub fn extra_ca(file: &str) -> Result<Option<&str>, String> {
    if ENABLED {
        Ok(Some(file))
    } else {
        Err("--extra-ca is only in builds with test hooks (make node-test-hooks)".into())
    }
}

pub fn command() -> Result<(), String> {
    println!("{}", serde_json::json!({ "testHooks": ENABLED }));
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn hooks_only_with_the_feature() {
        // SAFETY: the variable is only read by this test.
        unsafe { std::env::set_var("ARMADA_NODE_TEST_HOOKS_PROBE", "x") };
        assert_eq!(
            super::var("ARMADA_NODE_TEST_HOOKS_PROBE").is_some(),
            cfg!(feature = "test-hooks")
        );
    }
}
