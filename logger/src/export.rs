//! `armada-log export`: reads app output not yet sent to the cluster's log
//! store and renders it as the requests the node agent sends (ADR 0044).
//! The agent keeps the cursors, and compresses and sends the requests.
//!
//!   armada-log export --format loki|otlp --node NAME --now NS
//!                     --batch-records N --batch-bytes N --budget N --share N
//!
//! Standard input names what to read, one tab-separated line each:
//!
//!   c SEND SPACE APP REPLICA REVISION CONTAINER AFTER
//!   f OFFSET SIZE PATH
//!
//! A `c` line starts a container: SEND is 0 when its output is read but not
//! sent, AFTER is `-` or the time (`SECONDS.NANOS`) its entries must be
//! after. Its `f` lines are its files from where reading starts, oldest
//! first, OFFSET where it starts in the first (0 in the others), SIZE what
//! armadad saw. Containers share --budget bytes, each taking at most
//! --share, in order; complete lines are read only.
//!
//! The output is each request as `body LENGTH` and LENGTH bytes of JSON,
//! then `cursor CONTAINER FILE OFFSET TIME` for each container read from,
//! with FILE the index of the last of its files read, OFFSET where reading
//! ended in it, and TIME (`SECONDS.NANOS`, or `-` when unchanged) its last
//! entry's time, and last `end SIZE`: the bytes of output the requests
//! carry.

use crate::search::{decoded, entry, newline, parse_time};
use crate::{json_safe, json_string};
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead, Read, Seek, SeekFrom, Write};

/// The zero time an entry without a time has: 0001-01-01 UTC.
const ZERO_TIME: i128 = -62_135_596_800 * 1_000_000_000;

#[derive(Clone, Copy, PartialEq)]
enum Format {
    Loki,
    Otlp,
}

struct Args {
    format: Format,
    node: Vec<u8>,
    now: i128,
    batch_records: usize,
    batch_bytes: usize,
    budget: i64,
    share: i64,
}

struct Container {
    send: bool,
    space: Vec<u8>,
    app: Vec<u8>,
    replica: Vec<u8>,
    revision: Vec<u8>,
    container: Vec<u8>,
    after: Option<i128>,
    files: Vec<Source>,
}

struct Source {
    offset: i64,
    size: i64,
    path: String,
}

pub fn run(args: &[String]) -> Result<(), String> {
    let a = parse(args)?;
    let containers = read_plan(io::stdin().lock())?;
    let out = io::stdout();
    let mut w = io::BufWriter::with_capacity(1 << 20, out.lock());
    let mut enc = Encoder::new(&a);
    let mut budget = a.budget;
    let mut cursors = Vec::new();
    for (i, c) in containers.iter().enumerate() {
        if budget <= 0 {
            break;
        }
        let ctr = enc.container(c);
        let take = a.share.min(budget);
        let (cur, n) = read_container(c, take, |time, stderr, log| {
            if c.send {
                enc.add(&mut w, ctr, time, stderr, log)
            } else {
                Ok(())
            }
        })
        .map_err(|e| e.to_string())?;
        budget -= n;
        if cur.file.is_some() || cur.time.is_some() {
            cursors.push((i, cur));
        }
    }
    enc.flush(&mut w).map_err(|e| e.to_string())?;
    for (i, c) in cursors {
        let file = c
            .file
            .map_or("-".to_string(), |(f, off)| format!("{f} {off}"));
        let time = c.time.map_or("-".to_string(), format_time);
        if c.file.is_some() {
            writeln!(w, "cursor {i} {file} {time}")
        } else {
            writeln!(w, "cursor {i} - - {time}")
        }
        .map_err(|e| e.to_string())?;
    }
    writeln!(w, "end {}", enc.sent).map_err(|e| e.to_string())?;
    w.flush().map_err(|e| e.to_string())
}

fn parse(args: &[String]) -> Result<Args, String> {
    let mut a = Args {
        format: Format::Loki,
        node: Vec::new(),
        now: 0,
        batch_records: 0,
        batch_bytes: 0,
        budget: 0,
        share: 0,
    };
    let mut format = None;
    let mut it = args.iter();
    while let Some(k) = it.next() {
        let v = it.next().ok_or_else(|| format!("{k} needs a value"))?;
        let num = || {
            v.parse::<i64>()
                .ok()
                .filter(|n| *n >= 0)
                .ok_or_else(|| format!("{k}: invalid number {v:?}"))
        };
        match k.as_str() {
            "--format" => {
                format = Some(match v.as_str() {
                    "loki" => Format::Loki,
                    "otlp" => Format::Otlp,
                    _ => return Err(format!("unsupported format {v:?}")),
                })
            }
            "--node" => a.node = v.clone().into_bytes(),
            "--now" => a.now = num()? as i128,
            "--batch-records" => a.batch_records = num()? as usize,
            "--batch-bytes" => a.batch_bytes = num()? as usize,
            "--budget" => a.budget = num()?,
            "--share" => a.share = num()?,
            _ => return Err(format!("unknown argument {k:?}")),
        }
    }
    a.format = format.ok_or("--format is required")?;
    if a.batch_records == 0 || a.batch_bytes == 0 {
        return Err("--batch-records and --batch-bytes must be positive".into());
    }
    Ok(a)
}

fn read_plan(r: impl BufRead) -> Result<Vec<Container>, String> {
    let mut out: Vec<Container> = Vec::new();
    for line in r.lines() {
        let line = line.map_err(|e| e.to_string())?;
        let f: Vec<&str> = line.split('\t').collect();
        match f.as_slice() {
            ["c", send, space, app, replica, revision, container, after] => {
                out.push(Container {
                    send: *send == "1",
                    space: space.as_bytes().to_vec(),
                    app: app.as_bytes().to_vec(),
                    replica: replica.as_bytes().to_vec(),
                    revision: revision.as_bytes().to_vec(),
                    container: container.as_bytes().to_vec(),
                    after: match *after {
                        "-" => None,
                        t => Some(parse_secs(t).ok_or_else(|| format!("bad time {t:?}"))?),
                    },
                    files: Vec::new(),
                });
            }
            ["f", offset, size, path] => {
                let c = out.last_mut().ok_or("a file before its container")?;
                let n = |s: &str| s.parse::<i64>().ok().filter(|n| *n >= 0);
                c.files.push(Source {
                    offset: n(offset).ok_or("bad offset")?,
                    size: n(size).ok_or("bad size")?,
                    path: path.to_string(),
                });
            }
            _ => return Err(format!("bad line {:.40?}", line)),
        }
    }
    Ok(out)
}

/// `SECONDS.NANOS`: Unix seconds and the nanoseconds within the second.
fn parse_secs(s: &str) -> Option<i128> {
    let (sec, ns) = s.split_once('.')?;
    let ns: i128 = ns.parse().ok().filter(|n| (0..1_000_000_000).contains(n))?;
    Some(sec.parse::<i128>().ok()? * 1_000_000_000 + ns)
}

fn format_time(t: i128) -> String {
    format!(
        "{}.{}",
        t.div_euclid(1_000_000_000),
        t.rem_euclid(1_000_000_000)
    )
}

/// Nanoseconds since the epoch, wrapping outside int64.
fn unix_nano(t: i128) -> i64 {
    let sec = t.div_euclid(1_000_000_000) as i64;
    let ns = t.rem_euclid(1_000_000_000) as i64;
    sec.wrapping_mul(1_000_000_000).wrapping_add(ns)
}

/// Where a container's sent output ends: its last file read (index and
/// offset), and its last entry's time.
#[derive(Default)]
struct Cursor {
    file: Option<(usize, i64)>,
    time: Option<i128>,
}

/// TailLogs' loop over one container's files: at most take bytes of
/// complete lines; an older file's trailing partial line is skipped.
fn read_container(
    c: &Container,
    mut take: i64,
    mut emit: impl FnMut(i128, bool, Log) -> io::Result<()>,
) -> io::Result<(Cursor, i64)> {
    let mut cur = Cursor::default();
    let mut used = 0;
    for (j, src) in c.files.iter().enumerate() {
        if take <= 0 {
            break;
        }
        let mut o = src.offset;
        if o > src.size {
            o = 0; // the file was replaced
        }
        let limit = take;
        // Only a container that goes on by time skips entries: those not
        // after the last one sent.
        let after = c.after.map(|a| cur.time.unwrap_or(a));
        let (n, last) = read_file(&src.path, o, limit, after, &mut emit)?;
        if last.is_some() {
            cur.time = last;
        }
        let Some(n) = n else {
            break; // gone in between; the next tail finds where it went
        };
        cur.file = Some((j, o + n));
        take -= n;
        used += n;
        if src.size - o > limit {
            break; // the budget ended within this file
        }
    }
    Ok((cur, used))
}

/// Reads complete entries of path from off, at most limit bytes, and
/// returns the bytes the lines took (None when the file could not be read)
/// and the last entry's time. Errors are the writer's.
fn read_file(
    path: &str,
    off: i64,
    limit: i64,
    after: Option<i128>,
    emit: &mut impl FnMut(i128, bool, Log) -> io::Result<()>,
) -> io::Result<(Option<i64>, Option<i128>)> {
    let Ok(mut f) = File::open(path) else {
        return Ok((None, None));
    };
    if f.seek(SeekFrom::Start(off as u64)).is_err() {
        return Ok((None, None));
    }
    let mut left = limit as u64;
    let mut buf = vec![0u8; (1 << 20).min(left as usize).max(1)];
    let mut filled = 0;
    let mut read = 0i64;
    let mut last = None;
    let mut after = after;
    let mut text = Vec::new();
    let mut stream = Vec::new();
    let mut valid = Vec::new();
    loop {
        if filled == buf.len() {
            buf.resize(buf.len() * 2, 0);
        }
        let room = ((buf.len() - filled) as u64).min(left) as usize;
        if room == 0 {
            return Ok((Some(read), last));
        }
        let n = match f.read(&mut buf[filled..filled + room]) {
            Ok(0) => return Ok((Some(read), last)),
            Ok(n) => n,
            // A read error stops the file, keeping what was found.
            Err(_) => return Ok((None, last)),
        };
        left -= n as u64;
        filled += n;
        let mut start = 0;
        while let Some(p) = newline(&buf[start..filled]) {
            let line = &buf[start..start + p];
            read += p as i64 + 1;
            start += p + 1;
            let Some(e) = entry(line) else { continue };
            let time = match e.time {
                None => ZERO_TIME,
                Some(span) => match decoded(line, span, &mut text).and_then(parse_time) {
                    Some(t) => t,
                    None => continue, // an invalid time fails the line
                },
            };
            if after.is_some_and(|a| time <= a) {
                continue;
            }
            let stderr = match e.stream {
                Some(span) => decoded(line, span, &mut stream).is_some_and(|s| s == b"stderr"),
                None => false,
            };
            let log = match e.log {
                // As the writers write it: copied as it is.
                Some(span) => match canonical(&line[span.start..span.end]) {
                    Some(log) => log,
                    None => match decoded(line, span, &mut text) {
                        Some(l) => Log::Text(lossy_string(l, &mut valid)),
                        None => continue,
                    },
                },
                None => Log::Text(&[]),
            };
            emit(time, stderr, log)?;
            last = Some(time);
            after = after.map(|_| time);
        }
        buf.copy_within(start..filled, 0);
        filled -= start;
    }
}

/// An entry's output: its text, or the JSON string the writers wrote, which
/// json_string writes again byte for byte.
#[derive(Clone, Copy)]
pub(crate) enum Log<'a> {
    Text(&'a [u8]),
    /// The string's bytes between its quotes, its text's length, and
    /// whether the text ends with a line break (the escape `\n` last).
    Json {
        raw: &'a [u8],
        len: usize,
        newline: bool,
    },
}

impl Log<'_> {
    fn len(&self) -> usize {
        match self {
            Log::Text(t) => t.len(),
            Log::Json { len, .. } => *len,
        }
    }

    /// Writes the text as a JSON string without one trailing line break
    /// (Record.line).
    fn write_line(&self, out: &mut Vec<u8>) {
        match *self {
            Log::Text(t) => json_string(out, t.strip_suffix(b"\n").unwrap_or(t)),
            Log::Json { raw, newline, .. } => {
                out.push(b'"');
                out.extend_from_slice(if newline { &raw[..raw.len() - 2] } else { raw });
                out.push(b'"');
            }
        }
    }
}

/// The Log of a JSON string's raw bytes when json_string would write its
/// text exactly so (no escape other than json_string's, valid UTF-8, hex in
/// lower case), else None.
fn canonical(raw: &[u8]) -> Option<Log<'_>> {
    let mut len = 0;
    let mut i = 0;
    let mut newline = false;
    while i < raw.len() {
        let run = json_safe(&raw[i..]);
        len += run;
        i += run;
        if run > 0 {
            newline = false;
        }
        if i == raw.len() {
            break;
        }
        newline = false;
        match raw[i] {
            b'\\' => {
                match *raw.get(i + 1)? {
                    b'"' | b'\\' | b'b' | b'f' | b'r' | b't' => {}
                    b'n' => newline = true,
                    b'u' => {
                        let h = raw.get(i + 2..i + 6)?;
                        if !h.iter().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
                            return None;
                        }
                        let v = u32::from_str_radix(std::str::from_utf8(h).ok()?, 16).ok()?;
                        match v {
                            0x2028 | 0x2029 => len += 2,
                            0x08 | 0x0c | 0x0a | 0x0d | 0x09 => return None,
                            0..0x20 | 0x3c | 0x3e | 0x26 => {}
                            _ => return None,
                        }
                        i += 4;
                    }
                    _ => return None,
                }
                len += 1;
                i += 2;
            }
            b @ 0x80.. => {
                let n = match b {
                    0xc2..=0xdf => 2,
                    0xe0..=0xef => 3,
                    0xf0..=0xf4 => 4,
                    _ => return None,
                };
                let c = raw.get(i..i + n)?;
                if std::str::from_utf8(c).is_err()
                    || c == "\u{2028}".as_bytes()
                    || c == "\u{2029}".as_bytes()
                {
                    return None;
                }
                len += n;
                i += n;
            }
            _ => return None, // a quote or control character as it is
        }
    }
    Some(Log::Json { raw, len, newline })
}

/// s as a JSON decoder reads it into a string: each byte that is not
/// part of valid UTF-8 becomes U+FFFD.
fn lossy_string<'a>(s: &'a [u8], buf: &'a mut Vec<u8>) -> &'a [u8] {
    if std::str::from_utf8(s).is_ok() {
        return s;
    }
    buf.clear();
    let mut i = 0;
    while i < s.len() {
        let n = match s[i] {
            0x00..=0x7f => 1,
            0xc2..=0xdf => 2,
            0xe0..=0xef => 3,
            0xf0..=0xf4 => 4,
            _ => 0,
        };
        if n > 0 && i + n <= s.len() && std::str::from_utf8(&s[i..i + n]).is_ok() {
            buf.extend_from_slice(&s[i..i + n]);
            i += n;
        } else {
            buf.extend_from_slice("\u{fffd}".as_bytes());
            i += 1;
        }
    }
    buf
}

/// One container's labels, rendered once.
struct Labels {
    /// Loki: the stream's labels for stdout and stderr, and the structured
    /// metadata of each value.
    loki_key: [Vec<u8>; 2],
    loki_stream: [Vec<u8>; 2],
    loki_meta: Vec<u8>,
    /// OTLP: the resource's key and its attributes.
    otlp_key: Vec<u8>,
    otlp_resource: Vec<u8>,
}

/// A stream (Loki) or resource (OTLP) of the request being built: its
/// opening and its values so far.
struct Group {
    head: Vec<u8>,
    values: Vec<u8>,
}

struct Encoder<'a> {
    a: &'a Args,
    labels: Vec<Labels>,
    groups: Vec<Group>,
    index: HashMap<Vec<u8>, usize>,
    records: usize,
    bytes: usize,
    /// Output bytes of every record added.
    sent: u64,
    now: Vec<u8>,
}

impl<'a> Encoder<'a> {
    fn new(a: &'a Args) -> Self {
        Encoder {
            a,
            labels: Vec::new(),
            groups: Vec::new(),
            index: HashMap::new(),
            records: 0,
            bytes: 0,
            sent: 0,
            now: unix_nano(a.now).to_string().into_bytes(),
        }
    }

    fn container(&mut self, c: &Container) -> usize {
        let node = &self.a.node;
        let join = |parts: &[&[u8]]| parts.join(&0u8);
        let loki_stream = |stream: &[u8]| {
            let mut b = Vec::new();
            for (i, (k, v)) in [
                ("app", &c.app[..]),
                ("container", &c.container[..]),
                ("node", &node[..]),
                ("source", b"armada"),
                ("space", &c.space[..]),
                ("stream", stream),
            ]
            .iter()
            .enumerate()
            {
                b.push(if i == 0 { b'{' } else { b',' });
                json_string(&mut b, k.as_bytes());
                b.push(b':');
                json_string(&mut b, v);
            }
            b.push(b'}');
            b
        };
        let mut meta = b"{\"replica\":".to_vec();
        json_string(&mut meta, &c.replica);
        if !c.revision.is_empty() {
            meta.extend_from_slice(b",\"revision\":");
            json_string(&mut meta, &c.revision);
        }
        meta.push(b'}');
        let mut res = Vec::new();
        for (i, (k, v)) in [
            ("service.name", &c.app),
            ("service.namespace", &c.space),
            ("service.instance.id", &c.replica),
            ("service.version", &c.revision),
            ("host.name", node),
            ("container.name", &c.container),
            ("armada.app", &c.app),
            ("armada.space", &c.space),
            ("armada.replica", &c.replica),
            ("armada.revision", &c.revision),
            ("armada.node", node),
        ]
        .iter()
        .enumerate()
        {
            if i > 0 {
                res.push(b',');
            }
            attr(&mut res, k.as_bytes(), v);
        }
        self.labels.push(Labels {
            loki_key: [
                join(&[&c.app, &c.space, &c.container, b"stdout", node]),
                join(&[&c.app, &c.space, &c.container, b"stderr", node]),
            ],
            loki_stream: [loki_stream(b"stdout"), loki_stream(b"stderr")],
            loki_meta: meta,
            otlp_key: join(&[&c.space, &c.app, &c.replica, &c.container, node]),
            otlp_resource: res,
        });
        self.labels.len() - 1
    }

    /// Adds one entry, first sending the request when it is full (by the
    /// batch's record and byte bounds).
    fn add(
        &mut self,
        w: &mut impl Write,
        ctr: usize,
        time: i128,
        stderr: bool,
        log: Log,
    ) -> io::Result<()> {
        if self.records > 0
            && (self.records >= self.a.batch_records || self.bytes + log.len() > self.a.batch_bytes)
        {
            self.flush(w)?;
        }
        self.records += 1;
        self.bytes += log.len();
        self.sent += log.len() as u64;
        let l = &self.labels[ctr];
        let s = usize::from(stderr);
        let key = match self.a.format {
            Format::Loki => &l.loki_key[s],
            Format::Otlp => &l.otlp_key,
        };
        let g = match self.index.get(key) {
            Some(&g) => g,
            None => {
                let head = match self.a.format {
                    Format::Loki => l.loki_stream[s].clone(),
                    Format::Otlp => l.otlp_resource.clone(),
                };
                self.groups.push(Group {
                    head,
                    values: Vec::new(),
                });
                self.index.insert(key.clone(), self.groups.len() - 1);
                self.groups.len() - 1
            }
        };
        let v = &mut self.groups[g].values;
        if !v.is_empty() {
            v.push(b',');
        }
        let ns = unix_nano(time).to_string();
        match self.a.format {
            Format::Loki => {
                v.extend_from_slice(b"[\"");
                v.extend_from_slice(ns.as_bytes());
                v.extend_from_slice(b"\",");
                log.write_line(v);
                v.push(b',');
                v.extend_from_slice(&l.loki_meta);
                v.push(b']');
            }
            Format::Otlp => {
                v.extend_from_slice(b"{\"timeUnixNano\":\"");
                v.extend_from_slice(ns.as_bytes());
                v.extend_from_slice(b"\",\"observedTimeUnixNano\":\"");
                v.extend_from_slice(&self.now);
                v.extend_from_slice(b"\",\"body\":{\"stringValue\":");
                log.write_line(v);
                v.extend_from_slice(b"},\"attributes\":[");
                attr(
                    v,
                    b"log.iostream",
                    if stderr { b"stderr" } else { b"stdout" },
                );
                v.extend_from_slice(b"]}");
            }
        }
        Ok(())
    }

    /// Writes the request built so far, if any.
    fn flush(&mut self, w: &mut impl Write) -> io::Result<()> {
        if self.records == 0 {
            return Ok(());
        }
        let mut body = Vec::with_capacity(
            self.groups
                .iter()
                .map(|g| g.head.len() + g.values.len() + 96)
                .sum::<usize>()
                + 32,
        );
        match self.a.format {
            Format::Loki => body.extend_from_slice(b"{\"streams\":["),
            Format::Otlp => body.extend_from_slice(b"{\"resourceLogs\":["),
        }
        for (i, g) in self.groups.iter().enumerate() {
            if i > 0 {
                body.push(b',');
            }
            match self.a.format {
                Format::Loki => {
                    body.extend_from_slice(b"{\"stream\":");
                    body.extend_from_slice(&g.head);
                    body.extend_from_slice(b",\"values\":[");
                    body.extend_from_slice(&g.values);
                    body.extend_from_slice(b"]}");
                }
                Format::Otlp => {
                    body.extend_from_slice(b"{\"resource\":{\"attributes\":[");
                    body.extend_from_slice(&g.head);
                    body.extend_from_slice(
                        b"]},\"scopeLogs\":[{\"scope\":{\"name\":\"armada\"},\"logRecords\":[",
                    );
                    body.extend_from_slice(&g.values);
                    body.extend_from_slice(b"]}]}");
                }
            }
        }
        body.extend_from_slice(b"]}");
        writeln!(w, "body {}", body.len())?;
        w.write_all(&body)?;
        self.groups.clear();
        self.index.clear();
        self.records = 0;
        self.bytes = 0;
        Ok(())
    }
}

/// An OTLP attribute with a string value.
fn attr(out: &mut Vec<u8>, k: &[u8], v: &[u8]) {
    out.extend_from_slice(b"{\"key\":");
    json_string(out, k);
    out.extend_from_slice(b",\"value\":{\"stringValue\":");
    json_string(out, v);
    out.extend_from_slice(b"}}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times() {
        assert_eq!(parse_secs("-62135596800.0"), Some(ZERO_TIME));
        assert_eq!(parse_secs("5.000000007"), Some(5_000_000_007));
        assert_eq!(parse_secs("5.1000000000"), None);
        assert_eq!(format_time(-1), "-1.999999999");
        assert_eq!(parse_secs(&format_time(-1)), Some(-1));
        assert_eq!(unix_nano(ZERO_TIME), -6_795_364_578_871_345_152);
    }

    #[test]
    fn invalid_utf8_like_go() {
        let mut buf = Vec::new();
        assert_eq!(lossy_string(b"ok \xc3\xa9", &mut buf), "ok é".as_bytes());
        assert_eq!(
            lossy_string(b"a\xff\xe2\x80Z\xed\xa0\x80", &mut buf),
            "a\u{fffd}\u{fffd}\u{fffd}Z\u{fffd}\u{fffd}\u{fffd}".as_bytes()
        );
    }

    #[test]
    fn canonical_strings() {
        let text = |raw: &[u8]| {
            let mut out = Vec::new();
            canonical(raw).map(|l| {
                l.write_line(&mut out);
                (out, l.len())
            })
        };
        // json_string's own output is copied, a line break dropped.
        for s in [
            &b"plain"[..],
            b"q\" b\\s <a> & \x01 \x1f",
            "\u{e9}\u{20ac}\u{1f600} \u{2028}\u{2029}".as_bytes(),
            b"ends\n",
            b"a\\\nnot a line break at the end\\",
            b"\x08\x0c\n\r\t",
        ] {
            let mut raw = Vec::new();
            json_string(&mut raw, s);
            let raw = &raw[1..raw.len() - 1];
            let mut want = Vec::new();
            json_string(&mut want, s.strip_suffix(b"\n").unwrap_or(s));
            assert_eq!(text(raw), Some((want, s.len())), "{s:?}");
        }
        // Anything else is decoded and written again.
        for raw in [
            &br"\/"[..],
            br"\u00e9",
            br"\u003C",
            br"\u000a",
            br"\ud800",
            b"raw \xff",
            "\u{2028}".as_bytes(),
            br"\x",
            br"\u00",
        ] {
            assert!(text(raw).is_none(), "{raw:?}");
        }
    }

    #[test]
    fn plan() {
        let p = read_plan(
            &b"c\t1\tprod\tweb\tweb.prod-r1-a\tweb.prod--r1\tapp\t-\nf\t10\t20\t/x/a.log\n"[..],
        )
        .unwrap();
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].files[0].offset, 10);
        assert!(read_plan(&b"f\t1\t2\t/x\n"[..]).is_err());
        assert!(read_plan(&b"c\t1\n"[..]).is_err());
    }
}
