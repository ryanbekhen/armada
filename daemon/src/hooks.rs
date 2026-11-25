//! The ARMADA_DAEMON_TEST_* hooks of Go's daemon parity tests: read only
//! by builds with the test-hooks feature (`make daemon-parity`), never by
//! release builds. Each stands for what Go's tests replace in the package
//! (runDir, upgrade's paths, being root, the version).

/// The hook's value, or None (always None without the feature).
pub fn get(name: &str) -> Option<String> {
    #[cfg(feature = "test-hooks")]
    {
        std::env::var(format!("ARMADA_DAEMON_TEST_{name}")).ok()
    }
    #[cfg(not(feature = "test-hooks"))]
    {
        let _ = name;
        None
    }
}
