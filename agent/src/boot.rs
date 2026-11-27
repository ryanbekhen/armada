//! The machine's boot time and capacity.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// When the machine last booted, from /proc/stat; None where it is not
/// reported.
pub fn machine_boot() -> Option<SystemTime> {
    std::fs::read("/proc/stat")
        .ok()
        .and_then(|b| parse_boot_time(&b))
}

/// The btime line of /proc/stat.
pub fn parse_boot_time(stat: &[u8]) -> Option<SystemTime> {
    String::from_utf8_lossy(stat).lines().find_map(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() == 2 && f[0] == "btime" {
            let sec: i64 = f[1].parse().ok()?;
            (sec > 0).then(|| UNIX_EPOCH + Duration::from_secs(sec as u64))
        } else {
            None
        }
    })
}

/// The node's CPU (millicores) and memory (bytes, 0 when unknown).
pub fn detect_capacity() -> (i64, i64) {
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1) as i64;
    let mem = std::fs::read("/proc/meminfo")
        .map(|b| parse_mem_total(&b))
        .unwrap_or(0);
    (cpus * 1000, mem)
}

/// MemTotal of /proc/meminfo in bytes.
pub fn parse_mem_total(meminfo: &[u8]) -> i64 {
    for l in String::from_utf8_lossy(meminfo).lines() {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() == 3
            && f[0] == "MemTotal:"
            && f[2] == "kB"
            && let Ok(kb) = f[1].parse::<i64>()
            && kb > 0
        {
            return kb * 1024;
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_and_memory() {
        assert_eq!(
            parse_boot_time(b"cpu 1 2\nbtime 1700000000\n"),
            Some(UNIX_EPOCH + Duration::from_secs(1_700_000_000))
        );
        assert_eq!(parse_boot_time(b"btime x\n"), None);
        assert_eq!(parse_mem_total(b"MemTotal:  2048 kB\n"), 2048 * 1024);
        assert_eq!(parse_mem_total(b"MemTotal: 2048 MB\n"), 0);
    }
}
