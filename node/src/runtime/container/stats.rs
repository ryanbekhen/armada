//! What the Go driver samples of the supervisor runtime's containers
//! (internal/runtime/containerd stats.go and members.go, on
//! internal/runtime/supervisor's container.go and cgroup.go), for many
//! containers in one call: each one's record, its shim's state, its
//! cgroup (v2), and its network namespace's counters, a replica's init
//! containers and sidecars added to it.
//!
//! A container whose sample Go would answer with an error, or whose shim
//! Go would find gone (and then end its containers), is answered "redo":
//! Go samples that one itself, so its errors and what it does about a
//! shim that is gone stay Go's.

use super::bundle::{self, Record};
use super::shim::{self, CallError};
use crate::runtime::gopath;
use serde::Deserialize;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

/// The driver's labels (internal/runtime/containerd).
const LABEL_KIND: &str = "armada.runtime/kind";
const LABEL_POD: &str = "armada.runtime/pod";

/// What `runtime stats` reads.
#[derive(Deserialize, Default)]
#[serde(default)]
pub struct StatsRequest {
    /// The bundles' directory (supervisor.Bundles.Dir).
    pub dir: String,
    /// The shims' directory (supervisor.Shims.Dir).
    #[serde(rename = "shimDir")]
    pub shim_dir: String,
    /// Where cgroup v2 is mounted, and procfs (tests name fixtures).
    #[serde(rename = "cgroupRoot")]
    pub cgroup_root: String,
    pub proc: String,
    #[serde(deserialize_with = "crate::runtime::nullable")]
    pub ids: Vec<String>,
    #[serde(rename = "timeoutMs")]
    pub timeout_ms: u64,
}

/// One container's answer.
#[derive(Debug, PartialEq)]
pub enum Sample {
    Stats(Stats),
    NotFound,
    Redo(String),
}

/// runtime.Stats, CPU in nanoseconds.
#[derive(Debug, PartialEq, Default, Clone, Copy)]
pub struct Stats {
    pub cpu: i64,
    pub memory: i64,
    pub egress: i64,
    pub network_lost: bool,
    pub oom_kills: i64,
}

/// Where a container's task was found.
pub enum Located {
    /// Its process ID as taskProc.Pid gives it.
    Task(u32),
    NotFound,
    Redo(String),
}

/// container.Task: the shim's state of rec's container.
pub fn locate(shim_dir: &str, rec: &Record, deadline: Option<Instant>) -> Located {
    let socket = Path::new(shim_dir).join(format!("{}.sock", shim::shim_name(&rec.group)));
    let timeout = deadline.map(|d| {
        d.saturating_duration_since(Instant::now())
            .max(Duration::from_millis(1))
    });
    match shim::call(&socket, &["state".to_string(), rec.id.clone()], timeout) {
        Ok(out) => match parse_state(&out) {
            Some(pid) => Located::Task((pid.max(0)) as u32),
            // Go abandons the shim on an answer it cannot read.
            None => Located::Redo("unexpected state".into()),
        },
        Err(CallError::Shim(t)) if t.ends_with(" not found") => Located::NotFound,
        Err(e) => Located::Redo(e.text().to_string()),
    }
}

/// parseState: "created|running PID" or "exited CODE"; the process ID of
/// an exited container is 0.
fn parse_state(out: &str) -> Option<i64> {
    let w: Vec<&str> = out.split_whitespace().collect();
    if w.len() != 2 {
        return None;
    }
    let n = go_atoi(w[1])?;
    match w[0] {
        "created" | "running" => Some(n),
        "exited" => Some(0),
        _ => None,
    }
}

/// strconv.Atoi (64-bit int): an optional sign, then decimal digits.
fn go_atoi(s: &str) -> Option<i64> {
    let digits = s.strip_prefix(['+', '-']).unwrap_or(s);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// strconv.ParseUint(s, 10, 64).
fn go_parse_uint(s: &[u8]) -> Option<u64> {
    if s.is_empty() || !s.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(s).ok()?.parse().ok()
}

/// bufio.Scanner's longest line (MaxScanTokenSize).
const MAX_LINE: usize = 64 * 1024;

/// keyed: a cgroup file of "key value" lines, the value a number; lines
/// that are not are skipped, and a later key replaces an earlier one.
fn keyed(path: &Path) -> Option<Vec<(Vec<u8>, u64)>> {
    let data = fs::read(path).ok()?;
    let mut out: Vec<(Vec<u8>, u64)> = Vec::new();
    let mut rest = &data[..];
    while !rest.is_empty() {
        let (mut line, next) = match rest.iter().position(|&b| b == b'\n') {
            Some(i) => (&rest[..i], &rest[i + 1..]),
            None => (rest, &rest[rest.len()..]),
        };
        if line.len() >= MAX_LINE {
            return None;
        }
        rest = next;
        if let Some(l) = line.strip_suffix(b"\r") {
            line = l;
        }
        let Some(sp) = line.iter().position(|&b| b == b' ') else {
            continue;
        };
        if let Some(n) = go_parse_uint(&line[sp + 1..]) {
            let k = &line[..sp];
            match out.iter_mut().find(|(key, _)| key == k) {
                Some(e) => e.1 = n,
                None => out.push((k.to_vec(), n)),
            }
        }
    }
    Some(out)
}

fn get(m: &[(Vec<u8>, u64)], k: &str) -> u64 {
    m.iter()
        .find(|(key, _)| key == k.as_bytes())
        .map_or(0, |e| e.1)
}

/// readCgroup and statsFromCgroup: CPU time, memory in use without
/// inactive file pages, and out-of-memory kills; None where Go errs.
pub fn read_cgroup(dir: &Path) -> Option<Stats> {
    let cpu = keyed(&dir.join("cpu.stat"))?;
    let mem = keyed(&dir.join("memory.stat"))?;
    let events = keyed(&dir.join("memory.events"))?;
    let current = fs::read(dir.join("memory.current")).ok()?;
    let current: u64 = go_parse_uint(std::str::from_utf8(&current).ok()?.trim().as_bytes())?;
    let usec = get(&cpu, "usage_usec").min(u64::MAX / 2 / 1000);
    let inactive = get(&mem, "inactive_file");
    let used = current.saturating_sub(inactive);
    Some(Stats {
        cpu: (usec as i64).wrapping_mul(1000),
        memory: used.min(1 << 62) as i64,
        oom_kills: get(&events, "oom_kill").min(1 << 62) as i64,
        ..Stats::default()
    })
}

/// strings.Lines: each line with its "\n".
fn lines(s: &str) -> impl Iterator<Item = &str> {
    s.split_inclusive('\n')
}

/// hasInterface and egressFromNetDev of /proc/PID/net/dev.
pub fn net_dev(text: &str) -> (i64, bool) {
    let mut egress = None;
    for line in lines(text) {
        let Some((name, counters)) = line.split_once(':') else {
            continue;
        };
        if name.trim() != "eth0" {
            continue;
        }
        let f: Vec<&str> = counters.split_whitespace().collect();
        egress = Some(match f.get(8).and_then(|v| v.parse::<i64>().ok()) {
            Some(n) if n >= 0 => n,
            _ => 0,
        });
        break;
    }
    (egress.unwrap_or(0), egress.is_some())
}

/// taskStats on a located task: its cgroup (from its bundle's spec) and
/// its network namespace's counters; None where Go errs.
fn task_stats(r: &StatsRequest, rec: &Record, pid: u32) -> Option<Stats> {
    let spec = fs::read(Path::new(&r.dir).join(&rec.id).join("config.json")).ok()?;
    let spec: serde_json::Value = serde_json::from_slice(&spec).ok()?;
    let cgroups = spec.get("linux")?.get("cgroupsPath")?;
    let cgroups = match cgroups {
        serde_json::Value::Null => "",
        v => v.as_str()?,
    };
    if cgroups.is_empty() {
        return None;
    }
    let dir = gopath::join(&r.cgroup_root, &gopath::clean(&format!("/{cgroups}")));
    let mut st = read_cgroup(Path::new(&dir))?;
    // Go reads /proc/PID/net/dev with the uint32 process ID, 0 for an
    // exited container (which has none).
    let netdev = Path::new(&r.proc).join(pid.to_string()).join("net/dev");
    if let Ok(b) = fs::read(netdev) {
        let (egress, has) = net_dev(&String::from_utf8_lossy(&b));
        st.egress = egress;
        st.network_lost = !has;
    }
    Some(st)
}

/// Driver.Stats of one container.
fn sample(r: &StatsRequest, recs: &[Record], id: &str, deadline: Option<Instant>) -> Sample {
    let Some(rec) = recs.iter().find(|r| r.id == id) else {
        return Sample::NotFound;
    };
    let pid = match locate(&r.shim_dir, rec, deadline) {
        Located::Task(p) => p,
        Located::NotFound => return Sample::NotFound,
        Located::Redo(why) => return Sample::Redo(why),
    };
    let Some(mut st) = task_stats(r, rec, pid) else {
        return Sample::Redo("no sample".into());
    };
    if rec.labels.get(LABEL_KIND).map(String::as_str) == Some("app") {
        for m in recs
            .iter()
            .filter(|m| m.labels.get(LABEL_POD).map(String::as_str) == Some(id))
        {
            let one = match locate(&r.shim_dir, m, deadline) {
                Located::Task(p) => task_stats(r, m, p),
                Located::NotFound => None,
                // Go would end the containers of a member's shim that is
                // gone: it samples the replica itself.
                Located::Redo(why) => return Sample::Redo(why),
            };
            if let Some(one) = one {
                st.cpu = st.cpu.wrapping_add(one.cpu);
                st.memory = st.memory.wrapping_add(one.memory);
                st.oom_kills = st.oom_kills.wrapping_add(one.oom_kills);
            }
        }
    }
    Sample::Stats(st)
}

/// Every requested container's sample, in order; Err when the bundles
/// cannot be listed (Go's LoadContainer fails on each).
pub fn stats(r: &StatsRequest) -> Result<Vec<Sample>, String> {
    let deadline = (r.timeout_ms > 0).then(|| Instant::now() + Duration::from_millis(r.timeout_ms));
    let (recs, skipped) = match bundle::records(&r.dir) {
        Ok(v) => v,
        Err(e) => return Ok(r.ids.iter().map(|_| Sample::Redo(e.clone())).collect()),
    };
    // A container whose record could not be read is left to Go, alone.
    Ok(r.ids
        .iter()
        .map(|id| match skipped.iter().find(|s| &s.id == id) {
            Some(s) => Sample::Redo(s.error.clone()),
            None => sample(r, &recs, id, deadline),
        })
        .collect())
}

pub fn sample_json(s: &Sample) -> serde_json::Value {
    match s {
        Sample::Stats(st) => serde_json::json!({
            "cpu": st.cpu, "memory": st.memory, "egress": st.egress,
            "networkLost": st.network_lost, "oomKills": st.oom_kills,
        }),
        Sample::NotFound => serde_json::json!({ "notFound": true }),
        Sample::Redo(why) => serde_json::json!({ "redo": why }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn net_dev_counts_eth0() {
        let text = "Inter-|   Receive\n face |bytes\n    lo: 1 2 3 4 5 6 7 8 9 10\n  eth0: 10 0 0 0 0 0 0 0 4096 3\n";
        assert_eq!(net_dev(text), (4096, true));
        assert_eq!(net_dev("  lo: 1 2\n"), (0, false));
        assert_eq!(net_dev("eth0: 1 2 3\n"), (0, true));
        assert_eq!(net_dev("eth0: 0 0 0 0 0 0 0 0 -5\n"), (0, true));
        assert_eq!(net_dev("eth0: 0 0 0 0 0 0 0 0 +5\n"), (5, true));
    }

    #[test]
    fn numbers_as_go_parses_them() {
        assert_eq!(go_parse_uint(b"+1"), None);
        assert_eq!(go_parse_uint(b"18446744073709551615"), Some(u64::MAX));
        assert_eq!(go_parse_uint(b"18446744073709551616"), None);
        assert_eq!(go_atoi("+7"), Some(7));
        assert_eq!(go_atoi("-7"), Some(-7));
        assert_eq!(go_atoi("7x"), None);
        assert_eq!(parse_state("running 42"), Some(42));
        assert_eq!(parse_state("exited 137"), Some(0));
        assert_eq!(parse_state("paused 1"), None);
    }
}
