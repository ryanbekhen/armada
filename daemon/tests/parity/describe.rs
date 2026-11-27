//! What the replay compares, in the recording's form: the case
//! directory's files, the etcd keyspace's summary, archives, client
//! configs, and the normalized output.

use std::collections::BTreeMap;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use armada_daemon::manifest::{Created, Manifest};
use armada_pki::ExtKeyUsage;
use sha2::{Digest, Sha256};

/// Bytes as a JSON string holds them: each byte that
/// is not part of valid UTF-8 becomes U+FFFD (the recording is JSON).
pub fn go_lossy(b: &[u8]) -> String {
    let mut out = String::new();
    let mut rest = b;
    while !rest.is_empty() {
        match std::str::from_utf8(rest) {
            Ok(s) => {
                out.push_str(s);
                break;
            }
            Err(e) => {
                let (ok, bad) = rest.split_at(e.valid_up_to());
                out.push_str(std::str::from_utf8(ok).unwrap());
                out.push('\u{FFFD}');
                rest = &bad[1..];
            }
        }
    }
    out
}

/// What judges whether an archive's times are recent: the time a file
/// at a path with these bytes is judged against (Unix seconds).
pub type Now<'a> = &'a dyn Fn(&str, &[u8]) -> i64;

/// collect: every file left in the case directory. now tells the time an
/// archive's "recent" is judged against: an archive the case started with
/// was recent when it was recorded.
pub fn collect(dir: &Path, now: Now<'_>) -> Vec<String> {
    let mut out = Vec::new();
    walk(dir, "", &mut out, now);
    out
}

fn walk(dir: &Path, rel: &str, out: &mut Vec<String>, now: Now<'_>) {
    let mut names: Vec<String> = match std::fs::read_dir(dir.join(rel)) {
        Ok(r) => r
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect(),
        Err(_) => return,
    };
    names.sort();
    for n in names {
        let r = if rel.is_empty() {
            n
        } else {
            format!("{rel}/{n}")
        };
        let p = dir.join(&r);
        let Ok(md) = std::fs::symlink_metadata(&p) else {
            continue;
        };
        let skip = r == "home" || r == "cache" || r.starts_with("standins-no-cosign");
        let mode = md.permissions().mode() & 0o777;
        if md.is_dir() {
            if !skip && let Some(what) = summarize_etcd(&p) {
                out.push(format!("{r}/ {mode:04o} {what}"));
                continue;
            }
            if !skip {
                out.push(format!("{r}/ {mode:04o}"));
            }
            walk(dir, &r, out, now);
            continue;
        }
        if skip {
            continue;
        }
        if md.file_type().is_symlink() {
            let target = std::fs::read_link(&p).unwrap_or_default();
            out.push(format!("{r} -> {}", target.display()));
            continue;
        }
        let b = std::fs::read(&p).unwrap_or_default();
        out.push(format!("{r} {mode:04o}\n{}", describe(&r, &b, now(&r, &b))));
    }
}

/// Extended key usages as the recording names them: in brackets,
/// separated by spaces.
fn usages(u: &[ExtKeyUsage]) -> String {
    let n: Vec<&str> = u
        .iter()
        .map(|x| match x {
            ExtKeyUsage::Any => "anyExtendedKeyUsage",
            ExtKeyUsage::ServerAuth => "serverAuth",
            ExtKeyUsage::ClientAuth => "clientAuth",
            ExtKeyUsage::CodeSigning => "codeSigning",
            ExtKeyUsage::EmailProtection => "emailProtection",
            ExtKeyUsage::IpsecEndSystem => "ipsecEndSystem",
            ExtKeyUsage::IpsecTunnel => "ipsecTunnel",
            ExtKeyUsage::IpsecUser => "ipsecUser",
            ExtKeyUsage::TimeStamping => "timeStamping",
            ExtKeyUsage::OcspSigning => "OCSPSigning",
            ExtKeyUsage::MicrosoftServerGatedCrypto => "msSGC",
            ExtKeyUsage::NetscapeServerGatedCrypto => "nsSGC",
            ExtKeyUsage::MicrosoftCommercialCodeSigning => "msCodeCom",
            ExtKeyUsage::MicrosoftKernelCodeSigning => "msKernelCode",
        })
        .collect();
    format!("[{}]", n.join(" "))
}

fn days(c: &armada_pki::Certificate) -> i64 {
    // int(NotAfter.Sub(NotBefore).Hours()/24)
    ((c.not_after - c.not_before) as f64 / 3600.0 / 24.0) as i64
}

/// describe: a file's content as compared.
pub fn describe(rel: &str, b: &[u8], now: i64) -> String {
    if rel.ends_with("member.crt") {
        return match armada_pki::parse_cert_pem(b) {
            Ok(c) => {
                let ips: Vec<String> = c.ip_addresses.iter().map(|i| i.to_string()).collect();
                format!(
                    "certificate {} for [{}], {} days, usages {}",
                    c.common_name,
                    ips.join(" "),
                    days(&c),
                    usages(&c.ext_key_usage)
                )
            }
            Err(e) => format!("bad certificate: {e}"),
        };
    }
    if rel.ends_with("member.key") {
        return format!("a key: {}", contains(b, b"PRIVATE KEY"));
    }
    if rel.ends_with(".tar") && b.starts_with(&[0x1f, 0x8b]) {
        return describe_archive(b, now);
    }
    if rel.ends_with(".config") {
        return describe_client_config(b);
    }
    go_lossy(b)
}

fn contains(b: &[u8], what: &[u8]) -> bool {
    b.windows(what.len()).any(|w| w == what)
}

fn summarize_etcd(p: &Path) -> Option<String> {
    let md = std::fs::metadata(p.join("member/snap/db")).ok()?;
    if md.len() < 4096 {
        return None;
    }
    let wals = std::fs::read_dir(p.join("member/wal"))
        .map(|r| {
            r.flatten()
                .filter(|e| e.file_name().to_string_lossy().ends_with(".wal"))
                .count()
        })
        .unwrap_or(0);
    Some(format!(
        "an etcd member's data: a database, {} write-ahead log(s)",
        wals.min(1)
    ))
}

fn describe_client_config(b: &[u8]) -> String {
    let Ok(serde_json::Value::Object(cc)) = serde_json::from_slice::<serde_json::Value>(b) else {
        return String::from_utf8_lossy(b).into_owned();
    };
    let mut out = String::from_utf8_lossy(b).into_owned();
    let mut swap = |v: &str, desc: String| {
        let q = serde_json::to_string(v).unwrap();
        let d = serde_json::to_string(&desc).unwrap();
        out = out.replacen(&q, &d, 1);
    };
    if let Some(serde_json::Value::String(cert)) = cc.get("cert") {
        let desc = match armada_pki::parse_cert_pem(cert.as_bytes()) {
            Ok(c) => format!(
                "certificate {}, {} days, usages {}",
                c.common_name,
                days(&c),
                usages(&c.ext_key_usage)
            ),
            Err(e) => format!("bad certificate: {e}"),
        };
        swap(cert, desc);
    }
    if let Some(serde_json::Value::String(key)) = cc.get("key") {
        swap(key, format!("a key: {}", key.contains("PRIVATE KEY")));
    }
    out
}

/// One tar header as read.
struct Hdr {
    name: String,
    mode: i64,
    typeflag: u8,
    uid: i64,
    gid: i64,
    uname: String,
    gname: String,
    format: &'static str,
    size: i64,
    mtime: i64,
    mtime_nsec: i64,
    pax: BTreeMap<String, String>,
}

fn cstr(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

fn octal(b: &[u8]) -> i64 {
    if b.first().is_some_and(|c| c & 0x80 != 0) {
        // base-256
        let mut v: i64 = (b[0] & 0x7f) as i64;
        for c in &b[1..] {
            v = (v << 8) | *c as i64;
        }
        return v;
    }
    let s = cstr(b);
    i64::from_str_radix(s.trim_matches(|c: char| c == ' ' || c == '\0'), 8).unwrap_or(0)
}

/// The entries of a tar stream (USTAR, PAX, GNU long names), with their
/// data, and how the reading ended when not at the archive's end: a
/// `read: ...` or `read NAME: ...` line (a cut stream is unexpected EOF).
fn read_tar(b: &[u8], cut: bool) -> (Vec<(Hdr, Vec<u8>)>, Option<String>) {
    let eof = "unexpected EOF";
    let mut out = Vec::new();
    let mut i = 0;
    let mut pax: BTreeMap<String, String> = BTreeMap::new();
    let mut long_name: Option<String> = None;
    loop {
        if i == b.len() && !cut {
            return (out, None);
        }
        if i + 512 > b.len() {
            return (out, Some(format!("read: {eof}\n")));
        }
        let h = &b[i..i + 512];
        if h.iter().all(|&c| c == 0) {
            return (out, None);
        }
        let size = octal(&h[124..136]);
        let flag = h[156];
        let mut name = cstr(&h[0..100]);
        let data_start = i + 512;
        let data_end = data_start + size as usize;
        if data_end > b.len() {
            if let Some(n) = long_name.take() {
                name = n;
            }
            if let Some(p) = pax.get("path") {
                name = p.clone();
            }
            return (out, Some(format!("read {name}: {eof}\n")));
        }
        let data = b[data_start..data_end].to_vec();
        i = data_start + (size as usize).div_ceil(512) * 512;
        i = i.min(b.len());
        match flag {
            b'x' => {
                let mut rest = &data[..];
                while let Some(sp) = rest.iter().position(|&c| c == b' ') {
                    let Some(n) = std::str::from_utf8(&rest[..sp])
                        .ok()
                        .and_then(|s| s.parse::<usize>().ok())
                        .filter(|n| *n > sp + 1 && *n <= rest.len())
                    else {
                        break;
                    };
                    let rec = String::from_utf8_lossy(&rest[sp + 1..n - 1]).into_owned();
                    if let Some((k, v)) = rec.split_once('=') {
                        pax.insert(k.to_string(), v.to_string());
                    }
                    rest = &rest[n..];
                }
                continue;
            }
            b'g' => continue,
            b'L' => {
                long_name = Some(cstr(&data));
                continue;
            }
            _ => {}
        }
        let magic = &h[257..263];
        let version = &h[263..265];
        let format: &'static str = if magic == b"ustar\0" && version == b"00" {
            "USTAR"
        } else if magic == b"ustar " && version == b" \0" {
            "GNU"
        } else {
            "V7"
        };
        if format == "USTAR" {
            let prefix = cstr(&h[345..500]);
            if !prefix.is_empty() {
                name = format!("{prefix}/{name}");
            }
        }
        if let Some(n) = long_name.take() {
            name = n;
        }
        let mut hdr = Hdr {
            name,
            mode: octal(&h[100..108]),
            typeflag: flag,
            uid: octal(&h[108..116]),
            gid: octal(&h[116..124]),
            uname: cstr(&h[265..297]),
            gname: cstr(&h[297..329]),
            format,
            size,
            mtime: octal(&h[136..148]),
            mtime_nsec: 0,
            pax: std::mem::take(&mut pax),
        };
        if !hdr.pax.is_empty() {
            hdr.format = "PAX";
            if let Some(p) = hdr.pax.get("path") {
                hdr.name = p.clone();
            }
            if let Some(m) = hdr.pax.get("mtime") {
                let (s, f) = m.split_once('.').unwrap_or((m, ""));
                hdr.mtime = s.parse().unwrap_or(hdr.mtime);
                let f = format!("{f:0<9}");
                hdr.mtime_nsec = f[..9].parse().unwrap_or(0);
            }
            if let Some(s) = hdr.pax.get("size") {
                hdr.size = s.parse().unwrap_or(hdr.size);
            }
        }
        out.push((hdr, data));
    }
}

/// A manifest decoded loosely: unknown fields left out (the
/// restore's own decoder refuses them, not this description).
fn unmarshal(data: &[u8]) -> Result<Manifest, String> {
    const KNOWN: [&str; 8] = [
        "format",
        "armadaVersion",
        "created",
        "schema",
        "listen",
        "masterKeyId",
        "caFingerprint",
        "files",
    ];
    match serde_json::from_slice::<serde_json::Value>(data) {
        Err(e) if e.is_eof() => Err("unexpected end of JSON input".to_string()),
        Ok(serde_json::Value::Object(mut o)) => {
            o.retain(|k, _| KNOWN.contains(&k.as_str()));
            Manifest::decode(&serde_json::to_vec(&o).unwrap())
        }
        _ => Manifest::decode(data),
    }
}

/// A string of printable ASCII (what tar's names hold) in double quotes,
/// " and \ escaped.
fn quote(s: &str) -> String {
    serde_json::to_string(s).unwrap()
}

fn sha(b: &[u8]) -> String {
    Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

pub fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

const FILE_STATE: &str = "etcd.snapshot";

pub fn describe_archive(b: &[u8], now: i64) -> String {
    if b.len() < 10 || b[0] != 0x1f || b[1] != 0x8b || b[2] != 8 {
        return "not a gzip stream: gzip: invalid header".to_string();
    }
    // As much as the stream holds: a cut stream gives what came before the
    // cut, and tar's reads end there.
    let mut raw = Vec::new();
    let cut = flate2::read::MultiGzDecoder::new(b)
        .read_to_end(&mut raw)
        .is_err();
    let mut out = String::new();
    let mut m: Option<Manifest> = None;
    let mut sums: BTreeMap<String, String> = BTreeMap::new();
    let (entries, end) = read_tar(&raw, cut);
    for (hdr, data) in &entries {
        sums.insert(hdr.name.clone(), sha(data));
        let recent = now - hdr.mtime < 600 && hdr.mtime_nsec == 0;
        let size = if hdr.name == FILE_STATE {
            "SIZE".to_string()
        } else {
            hdr.size.to_string()
        };
        let pax: Vec<String> = hdr.pax.iter().map(|(k, v)| format!("{k}:{v}")).collect();
        out.push_str(&format!(
            "{} mode {:04o} type {} uid {} gid {} user {} group {} format {} size {} recent {} pax map[{}]\n",
            hdr.name,
            hdr.mode,
            hdr.typeflag as char,
            hdr.uid,
            hdr.gid,
            quote(&hdr.uname),
            quote(&hdr.gname),
            hdr.format,
            size,
            recent,
            pax.join(" ")
        ));
        if hdr.name == "manifest.json" {
            match unmarshal(data) {
                Ok(x) => m = Some(x),
                Err(e) => out.push_str(&format!("manifest: {e}\n")),
            }
        }
    }
    if let Some(e) = end {
        out.push_str(&e);
    }
    let mut m = m.unwrap_or_default();
    let created = !m.created.zero
        && now - m.created.unix < 600
        && m.created.nsec == 0
        && m.created.offset.is_none();
    let files = m.files.clone().unwrap_or_default();
    let snapshot_listed = files.get(FILE_STATE) == sums.get(FILE_STATE);
    let matches = files.iter().all(|(n, s)| sums.get(n) == Some(s));
    m.created = Created {
        unix: 0,
        nsec: 0,
        offset: None,
        zero: true,
    };
    if let Some(f) = m.files.as_mut() {
        f.insert(FILE_STATE.to_string(), "SNAPSHOT".to_string());
    }
    out.push_str(&format!(
        "manifest (created now: {created}, snapshot listed: {snapshot_listed}, files match: {matches}):\n{}\n",
        m.to_json()
    ));
    out
}

fn word(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn boundary(s: &[u8], i: usize) -> bool {
    let before = i > 0 && word(s[i - 1]);
    let after = i < s.len() && word(s[i]);
    before != after
}

/// `\b(go[0-9][0-9.a-z]*|rust[0-9][0-9.a-z-]*)\b`.
fn toolchain(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::new();
    let (mut i, mut last) = (0, 0);
    while i < b.len() {
        if boundary(b, i) {
            let found = [("go", false), ("rust", true)]
                .iter()
                .find_map(|(p, dash)| {
                    let start = i + p.len();
                    if !b[i..].starts_with(p.as_bytes())
                        || start >= b.len()
                        || !b[start].is_ascii_digit()
                    {
                        return None;
                    }
                    let mut end = start + 1;
                    while end < b.len()
                        && (b[end].is_ascii_digit()
                            || b[end] == b'.'
                            || b[end].is_ascii_lowercase()
                            || (*dash && b[end] == b'-'))
                    {
                        end += 1;
                    }
                    while end > start + 1 && !boundary(b, end) {
                        end -= 1;
                    }
                    boundary(b, end).then_some(end)
                });
            if let Some(end) = found {
                out.push_str(&s[last..i]);
                out.push_str("TOOLCHAIN");
                i = end;
                last = end;
                continue;
            }
        }
        i += 1;
    }
    out.push_str(&s[last..]);
    out
}

/// `\.(backup|inspect|restore|etcd|etcd-start)-[0-9]+` →
/// `.$1-N`.
fn state_temp(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::new();
    let (mut i, mut last) = (0, 0);
    'scan: while i < b.len() {
        if b[i] == b'.' {
            // Alternatives in order, as RE2 tries them (leftmost first).
            for w in ["backup", "inspect", "restore", "etcd", "etcd-start"] {
                let rest = &b[i + 1..];
                if rest.starts_with(w.as_bytes()) && rest.get(w.len()) == Some(&b'-') {
                    let d = i + 1 + w.len() + 1;
                    let mut e = d;
                    while e < b.len() && b[e].is_ascii_digit() {
                        e += 1;
                    }
                    if e > d {
                        out.push_str(&s[last..i]);
                        out.push_str(&format!(".{w}-N"));
                        i = e;
                        last = e;
                        continue 'scan;
                    }
                }
            }
        }
        i += 1;
    }
    out.push_str(&s[last..]);
    out
}

/// elapsed: `\b(in|after) [0-9][0-9.]*(ms|s|m[0-9.]*s?)\b` → `$1 ELAPSED`.
fn elapsed(s: &str) -> String {
    let b = s.as_bytes();
    let num = |c: u8| c.is_ascii_digit() || c == b'.';
    let mut out = String::new();
    let (mut i, mut last) = (0, 0);
    while i < b.len() {
        if boundary(b, i) {
            let word_end = ["in ", "after "]
                .iter()
                .find(|w| b[i..].starts_with(w.as_bytes()))
                .map(|w| (i + w.len() - 1, i + w.len()));
            if let Some((wend, d)) = word_end
                && d < b.len()
                && b[d].is_ascii_digit()
            {
                let mut max = d + 1;
                while max < b.len() && num(b[max]) {
                    max += 1;
                }
                // [0-9.]* from greedy down; then ms | s | m[0-9.]*s?.
                let mut end = None;
                'outer: for k in (d + 1..=max).rev() {
                    let r = &b[k..];
                    if r.starts_with(b"ms") && boundary(b, k + 2) {
                        end = Some(k + 2);
                        break;
                    }
                    if r.starts_with(b"s") && boundary(b, k + 1) {
                        end = Some(k + 1);
                        break;
                    }
                    if r.starts_with(b"m") {
                        let mut m = k + 1;
                        while m < b.len() && num(b[m]) {
                            m += 1;
                        }
                        for j in (k + 1..=m).rev() {
                            if b.get(j) == Some(&b's') && boundary(b, j + 1) {
                                end = Some(j + 1);
                                break 'outer;
                            }
                            if boundary(b, j) {
                                end = Some(j);
                                break 'outer;
                            }
                        }
                    }
                }
                if let Some(e) = end {
                    out.push_str(&s[last..i]);
                    out.push_str(&s[i..wend]);
                    out.push_str(" ELAPSED");
                    i = e;
                    last = e;
                    continue;
                }
            }
        }
        i += 1;
    }
    out.push_str(&s[last..]);
    out
}

/// Output normalized as the recording is, and the date a renewed
/// certificate is valid until
/// (worked out from the machine's clock by the CA, which no hook moves).
pub fn normalize(s: &str) -> String {
    let s = elapsed(&state_temp(&toolchain(s)));
    valid_until(&s)
}

fn valid_until(s: &str) -> String {
    const P: &str = "valid until ";
    let mut out = String::new();
    let mut rest = s;
    while let Some(at) = rest.find(P) {
        let d = &rest[at + P.len()..];
        let date = d.len() >= 10
            && d.as_bytes()[..10].iter().enumerate().all(|(i, c)| {
                if i == 4 || i == 7 {
                    *c == b'-'
                } else {
                    c.is_ascii_digit()
                }
            });
        out.push_str(&rest[..at + P.len()]);
        if date {
            out.push_str("DATE");
            rest = &d[10..];
        } else {
            rest = d;
        }
    }
    out.push_str(rest);
    out
}
