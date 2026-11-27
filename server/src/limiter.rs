//! Token buckets.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use armada_spec::gotime::Time;

/// A keyed limiter that holds this many keys starts over,
/// which only ever makes it more lenient.
const MAX_KEYS: usize = 4096;

/// A token bucket: burst tokens, one more every refill.
pub struct Bucket {
    burst: f64,
    refill: Duration,
    st: Mutex<(f64, Instant)>,
}

impl Bucket {
    pub fn new(burst: u32, refill: Duration) -> Bucket {
        Bucket {
            burst: f64::from(burst),
            refill,
            st: Mutex::new((f64::from(burst), Instant::now())),
        }
    }

    pub fn allow(&self, now: Instant) -> bool {
        let mut st = self.st.lock().unwrap_or_else(|p| p.into_inner());
        if now > st.1 {
            let add = (now - st.1).as_secs_f64() / self.refill.as_secs_f64();
            st.0 = (st.0 + add).min(self.burst);
            st.1 = now;
        }
        if st.0 < 1.0 {
            return false;
        }
        st.0 -= 1.0;
        true
    }
}

/// A token bucket per key (a source address, a node, a user).
pub struct Keyed {
    burst: u32,
    refill: Duration,
    buckets: Mutex<HashMap<String, std::sync::Arc<Bucket>>>,
}

impl Keyed {
    pub fn new(burst: u32, refill: Duration) -> Keyed {
        Keyed {
            burst,
            refill,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    pub fn allow(&self, key: &str, now: Instant) -> bool {
        let b = {
            let mut m = self.buckets.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(b) = m.get(key) {
                b.clone()
            } else {
                if m.len() >= MAX_KEYS {
                    m.clear();
                }
                let b = std::sync::Arc::new(Bucket::new(self.burst, self.refill));
                m.insert(key.to_string(), b.clone());
                b
            }
        };
        b.allow(now)
    }
}

/// A token bucket per key read on the server's clock (the wake limit). A
/// new bucket starts full at the wall clock's time, and refills only once the given time passes it.
pub struct ClockKeyed {
    burst: f64,
    refill_nanos: f64,
    buckets: Mutex<HashMap<String, (f64, Time)>>,
}

impl ClockKeyed {
    pub fn new(burst: u32, refill: Duration) -> ClockKeyed {
        ClockKeyed {
            burst: f64::from(burst),
            refill_nanos: refill.as_nanos() as f64,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    pub fn allow(&self, key: &str, now: &Time) -> bool {
        let mut m = self.buckets.lock().unwrap_or_else(|p| p.into_inner());
        if !m.contains_key(key) && m.len() >= MAX_KEYS {
            m.clear();
        }
        let b = m
            .entry(key.to_string())
            .or_insert_with(|| (self.burst, armada_store::gojson::now()));
        if now.after(&b.1) {
            let d = crate::reconcile::sub(now, &b.1) as f64;
            b.0 = (b.0 + d / self.refill_nanos).min(self.burst);
            b.1 = now.clone();
        }
        if b.0 < 1.0 {
            return false;
        }
        b.0 -= 1.0;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_refills() {
        let b = Bucket::new(2, Duration::from_secs(1));
        let start = Instant::now();
        assert!(b.allow(start));
        assert!(b.allow(start));
        assert!(!b.allow(start));
        assert!(b.allow(start + Duration::from_secs(1)));
        assert!(!b.allow(start + Duration::from_secs(1)));
    }

    #[test]
    fn keys_apart() {
        let now = Instant::now();
        let k = Keyed::new(1, Duration::from_secs(60));
        assert!(k.allow("a", now));
        assert!(!k.allow("a", now));
        assert!(k.allow("b", now));
    }
}
