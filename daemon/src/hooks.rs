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

/// The time now: the machine's clock, moved in test-hooks builds so it
/// starts at ARMADA_DAEMON_TEST_NOW (Unix nanoseconds) when that is set.
/// The replay of the parity cases recorded from Go (tests/parity) sets it
/// to the time Go's run started, for what doctor and a restore's checks
/// read of certificates' times.
pub fn now() -> std::time::SystemTime {
    let wall = std::time::SystemTime::now();
    #[cfg(feature = "test-hooks")]
    {
        use std::time::{Duration, UNIX_EPOCH};
        static OFFSET: std::sync::OnceLock<i128> = std::sync::OnceLock::new();
        let off = *OFFSET.get_or_init(|| {
            let real = wall
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos() as i128);
            get("NOW")
                .and_then(|v| v.parse::<i128>().ok())
                .map_or(0, |t| t - real)
        });
        if off >= 0 {
            wall + Duration::from_nanos(off as u64)
        } else {
            wall - Duration::from_nanos(off.unsigned_abs() as u64)
        }
    }
    #[cfg(not(feature = "test-hooks"))]
    wall
}
