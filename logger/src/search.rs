//! `armada-log search`: the scan behind a log history search (ADR 0043),
//! for the node agent, which picks the files and reads them itself when
//! there is no armada-log.
//!
//!   armada-log search --since NS [--until NS] [--grep TEXT] --limit N
//!                     --max-bytes N [--deadline-ms N]
//!
//! Standard input names the files, one path per line, in the order to read
//! them (newest output first). Each file whose modification time is not
//! before the window is read whole, unless that would pass --max-bytes;
//! entries inside the window whose text contains the ASCII --grep, ignoring
//! case, are kept, at most the newest --limit, and printed oldest first as
//! `INDEX LINE`, with INDEX the file's position on standard input and LINE
//! the entry's JSON line as stored. The last line is `end ok|budget|timeout
//! BYTES`: whether every file was read, or the byte budget or the deadline
//! stopped the scan first, and how many bytes were read.

use std::fs::File;
use std::io::{self, BufRead, Read, Write};
use std::time::{Duration, Instant, UNIX_EPOCH};

struct Query {
    since: i128,
    until: Option<i128>,
    grep: Vec<u8>,
    limit: usize,
    max_bytes: u64,
    deadline: Option<Instant>,
}

struct Found {
    time: i128,
    file: usize,
    /// The line's bytes in Kept::bytes.
    at: usize,
    len: usize,
}

pub fn run(args: &[String]) -> Result<(), String> {
    let q = parse(args)?;
    let mut files = Vec::new();
    for line in io::stdin().lock().lines() {
        files.push(line.map_err(|e| e.to_string())?);
    }
    let mut kept = Kept {
        found: Vec::new(),
        bytes: Vec::new(),
        floor: None,
    };
    let mut read = 0u64;
    let mut end = "ok";
    for (i, path) in files.iter().enumerate() {
        if q.deadline.is_some_and(|d| Instant::now() >= d) {
            end = "timeout";
            break;
        }
        let Ok(meta) = std::fs::metadata(path) else {
            continue;
        };
        // A file last written before the window holds nothing in it.
        let modified = meta
            .modified()
            .ok()
            .and_then(|m| m.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_nanos() as i128);
        if modified < q.since {
            continue;
        }
        if read + meta.len() > q.max_bytes {
            end = "budget";
            break;
        }
        let Ok(f) = File::open(path) else { continue };
        read += scan(f, i, &q, &mut kept);
    }
    kept.trim(q.limit);
    let out = io::stdout();
    let mut w = io::BufWriter::new(out.lock());
    for f in &kept.found {
        write!(w, "{} ", f.file).map_err(|e| e.to_string())?;
        w.write_all(kept.line(f)).map_err(|e| e.to_string())?;
        w.write_all(b"\n").map_err(|e| e.to_string())?;
    }
    writeln!(w, "end {end} {read}").map_err(|e| e.to_string())?;
    w.flush().map_err(|e| e.to_string())
}

fn parse(args: &[String]) -> Result<Query, String> {
    let mut q = Query {
        since: i128::MIN,
        until: None,
        grep: Vec::new(),
        limit: 0,
        max_bytes: 0,
        deadline: None,
    };
    let mut it = args.iter();
    while let Some(k) = it.next() {
        let v = it.next().ok_or_else(|| format!("{k} needs a value"))?;
        let num = || {
            v.parse::<i128>()
                .map_err(|_| format!("{k}: invalid number {v:?}"))
        };
        match k.as_str() {
            "--since" => q.since = num()?,
            "--until" => q.until = Some(num()?),
            "--grep" => {
                if !v.is_ascii() {
                    return Err("--grep must be ASCII".into());
                }
                q.grep = v.to_ascii_lowercase().into_bytes();
            }
            "--limit" => q.limit = usize::try_from(num()?).map_err(|_| "--limit out of range")?,
            "--max-bytes" => {
                q.max_bytes = u64::try_from(num()?).map_err(|_| "--max-bytes out of range")?
            }
            "--deadline-ms" => {
                let ms = u64::try_from(num()?).map_err(|_| "--deadline-ms out of range")?;
                q.deadline = Some(Instant::now() + Duration::from_millis(ms));
            }
            _ => return Err(format!("unknown argument {k:?}")),
        }
    }
    Ok(q)
}

/// The entries kept so far, and below which time an entry can no longer be
/// among the newest `limit` (once `limit` entries are kept): skipping those
/// leaves the result as it was, without copying lines that would be
/// dropped.
struct Kept {
    found: Vec<Found>,
    /// The kept lines' bytes, one after another: no allocation per line.
    bytes: Vec<u8>,
    floor: Option<i128>,
}

impl Kept {
    fn push(&mut self, time: i128, file: usize, line: &[u8], limit: usize) {
        self.found.push(Found {
            time,
            file,
            at: self.bytes.len(),
            len: line.len(),
        });
        self.bytes.extend_from_slice(line);
        // Keep at most twice the limit before trimming to the newest.
        if self.found.len() > 2 * limit {
            self.trim(limit);
            self.floor = self
                .found
                .first()
                .map(|f| f.time)
                .filter(|_| self.found.len() == limit);
        }
    }

    /// Keeps the newest limit entries (trim), and only their bytes.
    fn trim(&mut self, limit: usize) {
        trim(&mut self.found, limit);
        let mut bytes = Vec::with_capacity(self.found.iter().map(|f| f.len).sum::<usize>() * 2);
        for f in &mut self.found {
            let at = bytes.len();
            bytes.extend_from_slice(&self.bytes[f.at..f.at + f.len]);
            f.at = at;
        }
        self.bytes = bytes;
    }

    fn line(&self, f: &Found) -> &[u8] {
        &self.bytes[f.at..f.at + f.len]
    }
}

/// Reads complete lines of f (a last line without its line break is not
/// read) and returns the bytes read.
fn scan(mut f: File, file: usize, q: &Query, kept: &mut Kept) -> u64 {
    let mut buf = vec![0u8; 1 << 20];
    let mut filled = 0;
    let mut text = Vec::new();
    let mut read = 0u64;
    loop {
        if filled == buf.len() {
            buf.resize(buf.len() * 2, 0);
        }
        let n = match f.read(&mut buf[filled..]) {
            Ok(0) | Err(_) => return read,
            Ok(n) => n,
        };
        filled += n;
        let mut start = 0;
        while let Some(p) = newline(&buf[start..filled]) {
            let line = &buf[start..start + p];
            read += p as u64 + 1;
            start += p + 1;
            if let Some(time) = wanted(line, q, kept.floor, &mut text) {
                kept.push(time, file, line, q.limit);
            }
        }
        buf.copy_within(start..filled, 0);
        filled -= start;
    }
}

/// The time of an entry the search keeps, or None.
fn wanted(line: &[u8], q: &Query, floor: Option<i128>, text: &mut Vec<u8>) -> Option<i128> {
    let outside =
        |t: i128| t < q.since || q.until.is_some_and(|u| t > u) || floor.is_some_and(|f| t < f);
    // Most lines of a search lie outside its window: their time, last in
    // the line as both writers put it, decides without reading the rest.
    let tail = tail_time(line);
    if tail.is_some_and(outside) {
        return None;
    }
    // The whole line is read for what is kept: only valid lines are kept.
    let e = entry(line)?;
    // No time: a zero time, before every window; an invalid one fails the
    // line. The last time is the one at the tail.
    let time = match tail {
        Some(t) => t,
        None => e
            .time
            .and_then(|t| decoded(line, t, text).and_then(parse_time))?,
    };
    if e.time.is_none() || outside(time) {
        return None;
    }
    if !q.grep.is_empty() {
        let log = match e.log {
            Some(span) => decoded(line, span, text)?,
            None => &[][..],
        };
        if !contains_fold(log, &q.grep) {
            return None;
        }
    }
    Some(time)
}

/// The time of a line that ends as the writers end it, `,"time":"..."}`:
/// a quote inside a JSON string is always escaped, so these bytes can only
/// be the last key. None leaves the line to the full reading.
fn tail_time(line: &[u8]) -> Option<i128> {
    const KEY: &[u8] = b",\"time\":\"";
    let body = line.strip_suffix(b"\"}")?;
    let from = body.len().saturating_sub(48);
    let at = body[from..].windows(KEY.len()).rposition(|w| w == KEY)? + from;
    parse_time(&body[at + KEY.len()..])
}

/// The index of the first line break in b, eight bytes at a time.
pub(crate) fn newline(b: &[u8]) -> Option<usize> {
    const LO: u64 = 0x0101_0101_0101_0101;
    const HI: u64 = 0x8080_8080_8080_8080;
    const NL: u64 = LO * b'\n' as u64;
    let mut i = 0;
    while i + 8 <= b.len() {
        let w = u64::from_le_bytes(b[i..i + 8].try_into().unwrap()) ^ NL;
        let z = w.wrapping_sub(LO) & !w & HI;
        if z != 0 {
            return Some(i + (z.trailing_zeros() / 8) as usize);
        }
        i += 8;
    }
    b[i..].iter().position(|&c| c == b'\n').map(|p| i + p)
}

/// Sorts by time, keeping the order of equal times, and keeps the newest
/// limit entries (searchState.trim).
fn trim(found: &mut Vec<Found>, limit: usize) {
    found.sort_by_key(|f| f.time);
    if found.len() > limit {
        found.drain(..found.len() - limit);
    }
}

/// A JSON string in a line: the bytes between its quotes, and whether it
/// has escapes.
#[derive(Clone, Copy)]
pub(crate) struct Span {
    pub(crate) start: usize,
    pub(crate) end: usize,
    escaped: bool,
}

pub(crate) struct Entry {
    pub(crate) log: Option<Span>,
    pub(crate) stream: Option<Span>,
    pub(crate) time: Option<Span>,
}

/// Reads a line as a JSON object of string (or null) values: the last `log` and `time` win, other keys are
/// skipped; anything else fails the line.
pub(crate) fn entry(b: &[u8]) -> Option<Entry> {
    let mut e = Entry {
        log: None,
        stream: None,
        time: None,
    };
    let mut i = skip_ws(b, 0);
    if b.get(i) != Some(&b'{') {
        return None;
    }
    i = skip_ws(b, i + 1);
    if b.get(i) == Some(&b'}') {
        return (skip_ws(b, i + 1) == b.len()).then_some(e);
    }
    loop {
        let (key, next) = string(b, i)?;
        i = skip_ws(b, next);
        if b.get(i) != Some(&b':') {
            return None;
        }
        i = skip_ws(b, i + 1);
        let value = if b[i..].starts_with(b"null") {
            i += 4;
            None
        } else {
            let (v, next) = string(b, i)?;
            i = next;
            Some(v)
        };
        // Keys match without regard to case; these have no escapes.
        let k = &b[key.start..key.end];
        if k.eq_ignore_ascii_case(b"log") {
            e.log = value;
        } else if k.eq_ignore_ascii_case(b"time") {
            e.time = value;
        } else if k.eq_ignore_ascii_case(b"stream") {
            e.stream = value;
        }
        i = skip_ws(b, i);
        match b.get(i) {
            Some(b',') => i = skip_ws(b, i + 1),
            Some(b'}') => return (skip_ws(b, i + 1) == b.len()).then_some(e),
            _ => return None,
        }
    }
}

fn skip_ws(b: &[u8], mut i: usize) -> usize {
    while matches!(b.get(i), Some(b' ' | b'\t' | b'\r' | b'\n')) {
        i += 1;
    }
    i
}

/// The string starting at b[i] (its opening quote), and the index after it.
fn string(b: &[u8], i: usize) -> Option<(Span, usize)> {
    if b.get(i) != Some(&b'"') {
        return None;
    }
    let start = i + 1;
    let mut j = start;
    let mut escaped = false;
    loop {
        j += plain(&b[j..]);
        match *b.get(j)? {
            b'"' => {
                return Some((
                    Span {
                        start,
                        end: j,
                        escaped,
                    },
                    j + 1,
                ));
            }
            b'\\' => {
                escaped = true;
                j += 2;
            }
            c if c < 0x20 => return None,
            _ => j += 1,
        }
    }
}

/// How many bytes at the start of b need no look in a JSON string: no
/// quote, backslash, or control character; eight bytes at a time.
fn plain(b: &[u8]) -> usize {
    const LO: u64 = 0x0101_0101_0101_0101;
    const HI: u64 = 0x8080_8080_8080_8080;
    let zero = |w: u64| w.wrapping_sub(LO) & !w & HI;
    let mut i = 0;
    while i + 8 <= b.len() {
        let w = u64::from_le_bytes(b[i..i + 8].try_into().unwrap());
        // A byte below 0x20, a quote, or a backslash. The first flagged
        // byte is exact; later ones may be false (borrows), never earlier.
        let found = (w.wrapping_sub(LO * 0x20) & !w & HI)
            | zero(w ^ (LO * b'"' as u64))
            | zero(w ^ (LO * b'\\' as u64));
        if found != 0 {
            return i + (found.trailing_zeros() / 8) as usize;
        }
        i += 8;
    }
    i + b[i..]
        .iter()
        .position(|&c| c == b'"' || c == b'\\' || c < 0x20)
        .unwrap_or(b.len() - i)
}

/// The index of the first backslash in b, or its length; eight bytes at a
/// time.
fn backslash(b: &[u8]) -> usize {
    const LO: u64 = 0x0101_0101_0101_0101;
    const HI: u64 = 0x8080_8080_8080_8080;
    let mut i = 0;
    while i + 8 <= b.len() {
        let w = u64::from_le_bytes(b[i..i + 8].try_into().unwrap()) ^ (LO * b'\\' as u64);
        let z = w.wrapping_sub(LO) & !w & HI;
        if z != 0 {
            return i + (z.trailing_zeros() / 8) as usize;
        }
        i += 8;
    }
    i + b[i..]
        .iter()
        .position(|&c| c == b'\\')
        .unwrap_or(b.len() - i)
}

/// The bytes of a string, its escapes decoded into buf when it has any.
pub(crate) fn decoded<'a>(line: &'a [u8], s: Span, buf: &'a mut Vec<u8>) -> Option<&'a [u8]> {
    let raw = &line[s.start..s.end];
    if !s.escaped {
        return Some(raw);
    }
    buf.clear();
    let mut i = 0;
    while i < raw.len() {
        // The run up to the next escape, copied at once.
        let run = backslash(&raw[i..]);
        buf.extend_from_slice(&raw[i..i + run]);
        i += run;
        if i == raw.len() {
            break;
        }
        let c = *raw.get(i + 1)?;
        i += 2;
        let ch = match c {
            b'"' => '"',
            b'\\' => '\\',
            b'/' => '/',
            b'b' => '\u{8}',
            b'f' => '\u{c}',
            b'n' => '\n',
            b'r' => '\r',
            b't' => '\t',
            b'u' => {
                let hi = hex4(raw.get(i..i + 4)?)?;
                i += 4;
                if (0xD800..0xDC00).contains(&hi) && raw.get(i..i + 2) == Some(b"\\u") {
                    if let Some(lo) = raw
                        .get(i + 2..i + 6)
                        .and_then(hex4)
                        .filter(|lo| (0xDC00..0xE000).contains(lo))
                    {
                        i += 6;
                        char::from_u32(0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00))
                            .unwrap_or('\u{fffd}')
                    } else {
                        '\u{fffd}'
                    }
                } else {
                    char::from_u32(hi).unwrap_or('\u{fffd}')
                }
            }
            _ => return None,
        };
        let mut tmp = [0u8; 4];
        buf.extend_from_slice(ch.encode_utf8(&mut tmp).as_bytes());
    }
    Some(buf)
}

fn hex4(b: &[u8]) -> Option<u32> {
    let s = std::str::from_utf8(b).ok()?;
    u32::from_str_radix(s, 16).ok().filter(|_| b.len() == 4)
}

/// runtime.ContainsFold for an ASCII needle already in lower case.
fn contains_fold(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if hay.len() < needle.len() {
        return false;
    }
    let first = needle[0];
    let upper = first.to_ascii_uppercase();
    let last = hay.len() - needle.len();
    let mut i = 0;
    while i <= last {
        match find2(&hay[i..=last], first, upper) {
            None => return false,
            Some(p) => i += p,
        }
        if hay[i + 1..i + needle.len()]
            .iter()
            .zip(&needle[1..])
            .all(|(a, b)| a.to_ascii_lowercase() == *b)
        {
            return true;
        }
        i += 1;
    }
    false
}

/// The index of the first a or b in hay; eight bytes at a time.
fn find2(hay: &[u8], a: u8, b: u8) -> Option<usize> {
    const LO: u64 = 0x0101_0101_0101_0101;
    const HI: u64 = 0x8080_8080_8080_8080;
    let zero = |w: u64| w.wrapping_sub(LO) & !w & HI;
    let mut i = 0;
    while i + 8 <= hay.len() {
        let w = u64::from_le_bytes(hay[i..i + 8].try_into().unwrap());
        let z = zero(w ^ (LO * a as u64)) | zero(w ^ (LO * b as u64));
        if z != 0 {
            return Some(i + (z.trailing_zeros() / 8) as usize);
        }
        i += 8;
    }
    hay[i..]
        .iter()
        .position(|&c| c == a || c == b)
        .map(|p| i + p)
}

/// Nanoseconds since the epoch of an RFC 3339 time as a log entry
/// writes it (`2006-01-02T15:04:05.999999999Z07:00`).
pub(crate) fn parse_time(s: &[u8]) -> Option<i128> {
    let num = |a: usize, b: usize| -> Option<i64> {
        let d = s.get(a..b)?;
        d.iter()
            .all(u8::is_ascii_digit)
            .then(|| d.iter().fold(0i64, |n, c| n * 10 + (c - b'0') as i64))
    };
    if s.len() < 20
        || s[4] != b'-'
        || s[7] != b'-'
        || !matches!(s[10], b'T' | b't')
        || s[13] != b':'
        || s[16] != b':'
    {
        return None;
    }
    let (y, mo, d) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
    let (h, mi, sec) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);
    if !(1..=12).contains(&mo) || d < 1 || d > days_in_month(y, mo) || h > 23 || mi > 59 || sec > 59
    {
        return None;
    }
    let mut i = 19;
    let mut nanos = 0i64;
    if s.get(i) == Some(&b'.') {
        let start = i + 1;
        i = start;
        while s.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
        let digits = &s[start..i];
        if digits.is_empty() || digits.len() > 9 {
            return None;
        }
        nanos = digits.iter().fold(0i64, |n, c| n * 10 + (c - b'0') as i64)
            * 10i64.pow(9 - digits.len() as u32);
    }
    let offset = match s.get(i..)? {
        b"Z" | b"z" => 0,
        [sign @ (b'+' | b'-'), rest @ ..] if rest.len() == 5 && rest[2] == b':' => {
            let oh = num(i + 1, i + 3)?;
            let om = num(i + 4, i + 6)?;
            if oh > 23 || om > 59 {
                return None;
            }
            let o = oh * 3600 + om * 60;
            if *sign == b'+' { o } else { -o }
        }
        _ => return None,
    };
    let days = days_from_civil(y, mo, d);
    let secs = days * 86_400 + h * 3600 + mi * 60 + sec - offset;
    Some(secs as i128 * 1_000_000_000 + nanos as i128)
}

fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        2 if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days since 1970-01-01 of a proleptic Gregorian date.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_bytes() {
        for at in 0..30 {
            for c in [b'"', b'\\', 0x00, 0x1f, b'\n'] {
                let mut v = vec![b'a'; 30];
                v[at] = c;
                assert_eq!(plain(&v), at, "{c:#x} at {at}");
                // Bytes around it that could borrow.
                if at > 0 {
                    v[at - 1] = 0x21;
                }
                assert_eq!(plain(&v), at, "{c:#x} at {at} after 0x21");
            }
        }
        assert_eq!(plain(&[b'a'; 20]), 20);
        let s = "é€😀 \u{7f} ~ !#[]";
        assert_eq!(plain(s.as_bytes()), s.len());
        let line = br#"{"log":"x","stream":"stdout","time":"1970-01-01T00:00:01Z"}"#;
        assert_eq!(tail_time(line), Some(1_000_000_000));
        assert_eq!(
            tail_time(br#"{"time":"1970-01-01T00:00:01Z","log":"x"}"#),
            None
        );
    }

    #[test]
    fn finds() {
        for at in 0..30 {
            let mut v = vec![b'x'; 30];
            v[at] = b'T';
            assert_eq!(find2(&v, b't', b'T'), Some(at));
            v[at] = b't';
            assert_eq!(find2(&v, b't', b'T'), Some(at));
            v[at] = b'u';
            assert_eq!(find2(&v, b't', b'T'), None);
        }
        let hay = "x".repeat(37) + "TiMeOuT" + &"y".repeat(9);
        assert!(contains_fold(hay.as_bytes(), b"timeout"));
        assert!(!contains_fold(hay.as_bytes(), b"timeouts"));
    }

    #[test]
    fn newlines() {
        assert_eq!(newline(b""), None);
        assert_eq!(newline(b"abc"), None);
        assert_eq!(newline(b"\n"), Some(0));
        for at in 0..40 {
            let mut v = vec![b'x'; 40];
            v[at] = b'\n';
            assert_eq!(newline(&v), Some(at));
            v[at] = 0x8a;
            assert_eq!(newline(&v), None);
        }
    }

    #[test]
    fn times() {
        assert_eq!(parse_time(b"1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_time(b"1970-01-01T00:00:01.5Z"), Some(1_500_000_000));
        assert_eq!(
            parse_time(b"2026-11-23T07:00:00+07:00"),
            parse_time(b"2026-11-23T00:00:00Z")
        );
        assert_eq!(
            parse_time(b"2024-02-29T00:00:00Z"),
            Some(1_709_164_800 * 1_000_000_000)
        );
        for bad in [
            &b"2023-02-29T00:00:00Z"[..],
            b"2026-11-23 00:00:00Z",
            b"2026-11-23T00:00:00",
            b"2026-11-23T00:00:00.Z",
            b"2026-11-23T00:00:00.1234567890Z",
            b"2026-13-01T00:00:00Z",
        ] {
            assert_eq!(parse_time(bad), None, "{}", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn entries() {
        let line = br#"{"log":"GET /x \u003cb\u003e Timeout\n","stream":"stdout","time":"2026-11-23T00:00:00.001Z"}"#;
        let e = entry(line).unwrap();
        let mut buf = Vec::new();
        assert_eq!(
            decoded(line, e.log.unwrap(), &mut buf).unwrap(),
            b"GET /x <b> Timeout\n"
        );
        assert!(contains_fold(b"GET /x <b> Timeout\n", b"timeout"));
        assert!(contains_fold(b"<b>", b"<b>"));
        assert!(!contains_fold(b"time out", b"timeout"));
        assert!(contains_fold(b"x", b""));
        for bad in [
            &b"not json"[..],
            b"{\"log\":1}",
            b"{\"log\":\"a\"",
            b"{\"log\":\"a\"} x",
            b"{\"log\":\"a\x01\"}",
        ] {
            assert!(entry(bad).is_none(), "{}", String::from_utf8_lossy(bad));
        }
        let mut buf = Vec::new();
        let pair = br#"{"log":"\ud83d\ude00 \ud800 x"}"#;
        let e = entry(pair).unwrap();
        assert_eq!(
            decoded(pair, e.log.unwrap(), &mut buf).unwrap(),
            "😀 \u{fffd} x".as_bytes()
        );
    }
}
