//! The agent's clock, Go's durations, and times as Go prints them.

use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Where the agent reads the time: the system's, or a test clock in the
/// parity tests (Go's `Agent.now`).
pub trait Clock: Send + Sync + 'static {
    fn now(&self) -> SystemTime;
}

/// The system's clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// A clock set by hand.
#[derive(Debug)]
pub struct TestClock(Mutex<SystemTime>);

impl TestClock {
    pub fn new(t: SystemTime) -> TestClock {
        TestClock(Mutex::new(t))
    }

    pub fn set(&self, t: SystemTime) {
        *self.0.lock().unwrap_or_else(|p| p.into_inner()) = t;
    }
}

impl Clock for TestClock {
    fn now(&self) -> SystemTime {
        *self.0.lock().unwrap_or_else(|p| p.into_inner())
    }
}

/// Nanoseconds since the Unix epoch (negative before it).
pub fn unix_nanos(t: SystemTime) -> i128 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_nanos() as i128,
        Err(e) => -(e.duration().as_nanos() as i128),
    }
}

/// The time `n` nanoseconds after the Unix epoch.
pub fn from_unix_nanos(n: i128) -> SystemTime {
    if n >= 0 {
        UNIX_EPOCH + Duration::from_nanos(n.min(u64::MAX as i128) as u64)
    } else {
        UNIX_EPOCH - Duration::from_nanos((-n).min(u64::MAX as i128) as u64)
    }
}

/// a − b in nanoseconds, as Go's Time.Sub (saturating to a Duration).
pub fn sub(a: SystemTime, b: SystemTime) -> i64 {
    let d = unix_nanos(a) - unix_nanos(b);
    d.clamp(i64::MIN as i128, i64::MAX as i128) as i64
}

/// Go's `Duration.Round(m)`: halfway values away from zero.
pub fn round(d: i64, m: i64) -> i64 {
    if m <= 0 {
        return d;
    }
    let mut r = d % m;
    if d < 0 {
        r = -r;
        if r + r < m {
            return d + r;
        }
        return d.saturating_sub(m).saturating_add(r);
    }
    if r + r < m {
        return d - r;
    }
    d.saturating_add(m).saturating_sub(r)
}

/// Go's `Duration.String`.
pub fn duration_string(d: i64) -> String {
    if d == 0 {
        return "0s".to_string();
    }
    let neg = d < 0;
    let mut u = d.unsigned_abs();
    let mut out = String::new();
    if u < 1_000_000_000 {
        // Below a second: ns, µs, or ms with a fraction.
        let (unit, prec) = if u < 1_000 {
            ("ns", 0)
        } else if u < 1_000_000 {
            ("µs", 3)
        } else {
            ("ms", 6)
        };
        out.push_str(&fraction(u, prec));
        out.push_str(unit);
    } else {
        let secs_frac = fraction(u % 60_000_000_000, 9);
        out.push_str(&secs_frac);
        out.push('s');
        u /= 60_000_000_000;
        if u > 0 {
            let mins = u % 60;
            u /= 60;
            out = format!("{mins}m{out}");
            if u > 0 {
                out = format!("{u}h{out}");
            }
        }
    }
    if neg {
        out.insert(0, '-');
    }
    out
}

/// v / 10^prec with the fraction's trailing zeros dropped.
fn fraction(v: u64, prec: u32) -> String {
    let p = 10u64.pow(prec);
    let whole = v / p;
    let frac = v % p;
    if frac == 0 {
        return whole.to_string();
    }
    let s = format!("{frac:0width$}", width = prec as usize);
    format!("{whole}.{}", s.trim_end_matches('0'))
}

/// `t` in RFC 3339 with nanoseconds, UTC (log lines).
pub fn rfc3339_nano(t: SystemTime) -> String {
    let n = unix_nanos(t);
    let secs = n.div_euclid(1_000_000_000) as i64;
    let nanos = n.rem_euclid(1_000_000_000) as u32;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil(days);
    let mut s = format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    );
    if nanos > 0 {
        let f = format!("{nanos:09}");
        s.push('.');
        s.push_str(f.trim_end_matches('0'));
    }
    s.push('Z');
    s
}

/// The civil date of a day count since 1970-01-01.
fn civil(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_as_go_prints_them() {
        let s = 1_000_000_000;
        for (d, want) in [
            (0, "0s"),
            (s, "1s"),
            (30 * s, "30s"),
            (64 * s, "1m4s"),
            (300 * s, "5m0s"),
            (3600 * s, "1h0m0s"),
            (1_500_000_000, "1.5s"),
            (1_500_000, "1.5ms"),
            (1_000, "1µs"),
            (999, "999ns"),
            (-2 * s, "-2s"),
        ] {
            assert_eq!(duration_string(d), want, "{d}");
        }
    }

    #[test]
    fn rounding_as_go_does() {
        let s = 1_000_000_000;
        assert_eq!(round(1_499_999_999, s), s);
        assert_eq!(round(1_500_000_000, s), 2 * s);
        assert_eq!(round(-1_500_000_000, s), -2 * s);
        assert_eq!(round(400_000_000, s), 0);
    }

    #[test]
    fn rfc3339() {
        assert_eq!(rfc3339_nano(UNIX_EPOCH), "1970-01-01T00:00:00Z");
        assert_eq!(
            rfc3339_nano(UNIX_EPOCH + Duration::new(1_767_225_600, 5_000)),
            "2026-01-01T00:00:00.000005Z"
        );
    }
}
