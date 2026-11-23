//! Platforms as containerd's platforms package matches and orders them for
//! this node (platforms.Default), and the platform strings the driver
//! reports (platformStrings).

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct Platform {
    #[serde(default)]
    pub architecture: String,
    #[serde(default)]
    pub os: String,
    #[serde(
        rename = "os.version",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub os_version: String,
    #[serde(
        rename = "os.features",
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "crate::runtime::nullable"
    )]
    pub os_features: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub variant: String,
}

/// The OS this program runs on (runtime.GOOS).
const HOST_OS: &str = "linux";

/// runtime.GOARCH of this program.
pub fn host_arch() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "arm64"
    } else if cfg!(target_arch = "x86_64") {
        "amd64"
    } else if cfg!(target_arch = "arm") {
        "arm"
    } else {
        "unknown"
    }
}

fn normalize_arch(arch: &str, variant: &str) -> (String, String) {
    let (mut arch, mut variant) = (arch.to_lowercase(), variant.to_lowercase());
    match arch.as_str() {
        "i386" => {
            arch = "386".into();
            variant.clear();
        }
        "x86_64" | "x86-64" | "amd64" => {
            arch = "amd64".into();
            if variant == "v1" {
                variant.clear();
            }
        }
        "aarch64" | "arm64" => {
            arch = "arm64".into();
            match variant.as_str() {
                "8" | "v8" | "v8.0" => variant.clear(),
                "9" | "9.0" | "v9.0" => variant = "v9".into(),
                _ => {}
            }
        }
        "armhf" => {
            arch = "arm".into();
            variant = "v7".into();
        }
        "armel" => {
            arch = "arm".into();
            variant = "v6".into();
        }
        "arm" => match variant.as_str() {
            "" | "7" => variant = "v7".into(),
            "5" | "6" | "8" => variant = format!("v{variant}"),
            _ => {}
        },
        _ => {}
    }
    (arch, variant)
}

/// platforms.Normalize. An empty OS is this host's.
pub fn normalize(p: &Platform) -> Platform {
    let mut n = p.clone();
    n.os = if p.os.is_empty() {
        HOST_OS.into()
    } else {
        let os = p.os.to_lowercase();
        if os == "macos" { "darwin".into() } else { os }
    };
    (n.architecture, n.variant) = normalize_arch(&p.architecture, &p.variant);
    if !n.os_features.is_empty() {
        n.os_features.sort();
        n.os_features.dedup();
    }
    n
}

/// One platform a matcher accepts (platforms.NewMatcher).
fn matches(m: &Platform, p: &Platform) -> bool {
    let n = normalize(p);
    if m.os != n.os || m.architecture != n.architecture || m.variant != n.variant {
        return false;
    }
    if n.os_features.is_empty() {
        return true;
    }
    if m.os_features.len() < n.os_features.len() {
        return false;
    }
    let mut j = 0;
    for feature in &n.os_features {
        let mut found = false;
        while j < m.os_features.len() {
            if *feature == m.os_features[j] {
                found = true;
                j += 1;
                break;
            }
            if *feature < m.os_features[j] {
                return false;
            }
            j += 1;
        }
        if !found {
            return false;
        }
    }
    true
}

/// platforms.Only(p): p and the platforms it also runs, best first.
pub struct Matcher {
    order: Vec<Platform>,
}

fn arm64_versions(variant: &str) -> Option<(&'static [i32], &'static [i32])> {
    Some(match variant {
        "v8" | "v8.0" => (&[8], &[0]),
        "v8.1" => (&[8], &[1]),
        "v8.2" => (&[8], &[2]),
        "v8.3" => (&[8], &[3]),
        "v8.4" => (&[8], &[4]),
        "v8.5" => (&[8], &[5]),
        "v8.6" => (&[8], &[6]),
        "v8.7" => (&[8], &[7]),
        "v8.8" => (&[8], &[8]),
        "v8.9" => (&[8], &[9]),
        "v9" | "v9.0" => (&[9, 8], &[0, 5]),
        "v9.1" => (&[9, 8], &[1, 6]),
        "v9.2" => (&[9, 8], &[2, 7]),
        "v9.3" => (&[9, 8], &[3, 8]),
        "v9.4" => (&[9, 8], &[4, 9]),
        "v9.5" => (&[9, 8], &[5, 9]),
        "v9.6" => (&[9, 8], &[6, 9]),
        "v9.7" => (&[9, 8], &[7, 9]),
        _ => return None,
    })
}

fn variant_number(v: &str) -> Option<i32> {
    v.strip_prefix('v').unwrap_or(v).parse().ok()
}

/// platformVector.
fn platform_vector(p: &Platform) -> Vec<Platform> {
    let like = |arch: &str, variant: String| Platform {
        architecture: arch.into(),
        os: p.os.clone(),
        os_version: p.os_version.clone(),
        os_features: p.os_features.clone(),
        variant,
    };
    let mut vector = vec![p.clone()];
    match p.architecture.as_str() {
        "amd64" => {
            if let Some(mut v) = variant_number(&p.variant).filter(|v| *v > 1) {
                v -= 1;
                while v >= 1 {
                    vector.push(like("amd64", format!("v{v}")));
                    v -= 1;
                }
            }
            vector.push(like("386", String::new()));
        }
        "arm" => {
            if let Some(mut v) = variant_number(&p.variant).filter(|v| *v > 5) {
                v -= 1;
                while v >= 5 {
                    vector.push(like("arm", format!("v{v}")));
                    v -= 1;
                }
            }
        }
        "arm64" => {
            let mut variant = if p.variant.is_empty() {
                "v8".to_string()
            } else {
                p.variant.clone()
            };
            vector.clear();
            if let Some((majors, minors)) = arm64_versions(&variant) {
                for (i, major) in majors.iter().enumerate() {
                    let mut minor = minors[i];
                    while minor >= 0 {
                        let v = if minor == 0 {
                            format!("v{major}")
                        } else {
                            format!("v{major}.{minor}")
                        };
                        vector.push(like("arm64", v));
                        minor -= 1;
                    }
                }
            }
            if variant.starts_with("v8") || variant.starts_with("v9") {
                variant = "v8".into();
            }
            vector.extend(platform_vector(&like("arm", variant)));
        }
        _ => {}
    }
    vector
}

impl Matcher {
    pub fn only(p: &Platform) -> Matcher {
        Matcher {
            order: platform_vector(&normalize(p))
                .iter()
                .map(normalize)
                .collect(),
        }
    }

    /// platforms.Default(): this node.
    pub fn default_for_node() -> Matcher {
        Matcher::only(&default_spec())
    }

    pub fn matches(&self, p: &Platform) -> bool {
        self.order.iter().any(|m| matches(m, p))
    }

    /// orderedPlatformComparer.Less.
    pub fn less(&self, p1: &Platform, p2: &Platform) -> bool {
        for m in &self.order {
            let (a, b) = (matches(m, p1), matches(m, p2));
            if a && !b {
                return true;
            }
            if a || b {
                if a && b && p1.os_features.len() != p2.os_features.len() {
                    return p1.os_features.len() > p2.os_features.len();
                }
                return false;
            }
        }
        if !p1.os_features.is_empty() || !p2.os_features.is_empty() {
            let (mut a, mut b) = (p1.clone(), p2.clone());
            a.os_features.clear();
            b.os_features.clear();
            return self.less(&a, &b);
        }
        false
    }
}

/// platforms.DefaultSpec(): this node's OS, architecture, and (on ARM)
/// the CPU variant from /proc/cpuinfo.
pub fn default_spec() -> Platform {
    let arch = host_arch();
    let variant = if arch == "arm64" || arch == "arm" {
        cpu_variant(
            &std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default(),
            arch,
        )
    } else {
        String::new()
    };
    Platform {
        os: HOST_OS.into(),
        architecture: arch.into(),
        variant,
        ..Default::default()
    }
}

/// getCPUVariant from /proc/cpuinfo's "CPU architecture" line, else the
/// machine's architecture name.
fn cpu_variant(cpuinfo: &str, goarch: &str) -> String {
    let field = |pattern: &str| {
        cpuinfo.lines().find_map(|line| {
            let mut parts = line.split(':');
            let key = parts.next()?;
            let value = parts.next()?;
            key.trim()
                .eq_ignore_ascii_case(pattern)
                .then(|| value.trim().to_string())
        })
    };
    let mut variant = match field("Cpu architecture") {
        Some(v) => v,
        None => {
            let machine = machine_arch().to_lowercase();
            if machine == "aarch64" {
                "8".into()
            } else if machine.len() >= 5 && machine.starts_with("armv") {
                match &machine[3..5] {
                    "v8" => "8".into(),
                    "v7" => "7".into(),
                    "v6" => "6".into(),
                    "v5" => "5".into(),
                    "v4" => "4".into(),
                    "v3" => "3".into(),
                    _ => "unknown".into(),
                }
            } else {
                return String::new();
            }
        }
    };
    if goarch == "arm"
        && variant == "7"
        && field("model name").is_some_and(|m| m.to_lowercase().starts_with("armv6-compatible"))
    {
        variant = "6".into();
    }
    match variant.to_lowercase().as_str() {
        "8" | "aarch64" => "v8",
        "7" | "7m" | "?(12)" | "?(13)" | "?(14)" | "?(15)" | "?(16)" | "?(17)" => "v7",
        "6" | "6tej" => "v6",
        "5" | "5t" | "5te" | "5tej" => "v5",
        "4" | "4t" => "v4",
        "3" => "v3",
        _ => "unknown",
    }
    .into()
}

fn machine_arch() -> String {
    // SAFETY: uname fills the struct it is given.
    let mut u: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut u) } != 0 {
        return String::new();
    }
    let m: Vec<u8> = u
        .machine
        .iter()
        .take_while(|c| **c != 0)
        .map(|c| *c as u8)
        .collect();
    String::from_utf8_lossy(&m).into_owned()
}

/// The node's platform as "os/arch" (nodePlatform).
pub fn node_platform() -> String {
    let p = default_spec();
    format!("{}/{}", p.os, p.architecture)
}

/// maxPlatforms bounds the platforms reported for one image.
pub const MAX_PLATFORMS: usize = 32;

/// platformStrings: sorted, unique "os/arch", variants and attestation
/// manifests ("unknown") dropped.
pub fn platform_strings(ps: &[Platform]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for p in ps {
        if p.os.is_empty()
            || p.architecture.is_empty()
            || p.os == "unknown"
            || p.architecture == "unknown"
        {
            continue;
        }
        let n = normalize(p);
        let s = format!("{}/{}", n.os, n.architecture);
        if !out.contains(&s) {
            out.push(s);
        }
    }
    out.sort();
    out.truncate(MAX_PLATFORMS);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(os: &str, arch: &str, variant: &str) -> Platform {
        Platform {
            os: os.into(),
            architecture: arch.into(),
            variant: variant.into(),
            ..Default::default()
        }
    }

    #[test]
    fn strings_as_go() {
        let got = platform_strings(&[
            p("linux", "arm64", "v8"),
            p("linux", "aarch64", ""),
            p("linux", "x86_64", ""),
            p("linux", "arm", "v7"),
            p("unknown", "unknown", ""),
            p("", "amd64", ""),
        ]);
        assert_eq!(got, ["linux/amd64", "linux/arm", "linux/arm64"]);
    }

    #[test]
    fn amd64_runs_386_after_itself() {
        let m = Matcher::only(&p("linux", "amd64", ""));
        assert!(m.matches(&p("linux", "amd64", "")));
        assert!(m.matches(&p("linux", "386", "")));
        assert!(m.matches(&p("", "x86_64", "")));
        assert!(!m.matches(&p("linux", "arm64", "")));
        assert!(!m.matches(&p("linux", "amd64", "v2")));
        assert!(m.less(&p("linux", "amd64", ""), &p("linux", "386", "")));
        assert!(!m.less(&p("linux", "386", ""), &p("linux", "amd64", "")));
    }

    #[test]
    fn arm64_runs_arm() {
        let m = Matcher::only(&p("linux", "arm64", "v8"));
        assert!(m.matches(&p("linux", "arm64", "")));
        assert!(m.matches(&p("linux", "arm64", "v8")));
        assert!(m.matches(&p("linux", "arm", "v7")));
        assert!(!m.matches(&p("linux", "arm64", "v8.2")));
        assert!(m.less(&p("linux", "arm64", ""), &p("linux", "arm", "v7")));
    }

    #[test]
    fn reads_cpu_variant() {
        assert_eq!(cpu_variant("CPU architecture: 8\n", "arm64"), "v8");
        assert_eq!(cpu_variant("cpu architecture\t: 7\n", "arm"), "v7");
    }
}
