//! The times volbackup writes and reads as Go's time package does: a
//! manifest's time (RFC 3339 with nanoseconds, as time.Time marshals in
//! JSON), a snapshot's ID ("20060102T150405.000Z", truncated to the
//! millisecond), a bucket's LastModified, and selectKept's calendar.

/// Days since 1970-01-01 of a proleptic Gregorian date.
pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let m = i64::from(m);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The date of a day since 1970-01-01.
pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn leap(y: i64) -> bool {
    y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)
}

fn days_in(y: i64, m: u32) -> u32 {
    match m {
        2 if leap(y) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// A UTC instant as seconds and nanoseconds since 1970.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Instant {
    pub sec: i64,
    pub nsec: u32,
}

impl Instant {
    pub fn from_nanos(n: i128) -> Instant {
        Instant {
            sec: n.div_euclid(1_000_000_000) as i64,
            nsec: n.rem_euclid(1_000_000_000) as u32,
        }
    }

    pub fn nanos(&self) -> i128 {
        i128::from(self.sec) * 1_000_000_000 + i128::from(self.nsec)
    }

    pub fn now() -> Instant {
        let d = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        Instant {
            sec: d.as_secs() as i64,
            nsec: d.subsec_nanos(),
        }
    }

    fn parts(&self) -> (i64, u32, u32, u32, u32, u32) {
        let (y, mo, d) = civil_from_days(self.sec.div_euclid(86400));
        let s = self.sec.rem_euclid(86400) as u32;
        (y, mo, d, s / 3600, s / 60 % 60, s % 60)
    }

    /// Format(time.RFC3339Nano) in UTC: trailing zeros of the fraction
    /// left out.
    pub fn rfc3339_nano(&self) -> String {
        let (y, mo, d, h, mi, s) = self.parts();
        let mut out = format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}");
        if self.nsec != 0 {
            let f = format!("{:09}", self.nsec);
            out.push('.');
            out.push_str(f.trim_end_matches('0'));
        }
        out.push('Z');
        out
    }

    /// Format("20060102T150405.000Z").
    pub fn snapshot_time(&self) -> String {
        let (y, mo, d, h, mi, s) = self.parts();
        format!(
            "{y:04}{mo:02}{d:02}T{h:02}{mi:02}{s:02}.{:03}Z",
            self.nsec / 1_000_000
        )
    }

    /// Format("20060102T150405Z"), SigV4's X-Amz-Date.
    pub fn amz_date(&self) -> String {
        let (y, mo, d, h, mi, s) = self.parts();
        format!("{y:04}{mo:02}{d:02}T{h:02}{mi:02}{s:02}Z")
    }
}

fn digits(b: &[u8]) -> Option<u32> {
    if b.is_empty() || !b.iter().all(u8::is_ascii_digit) {
        return None;
    }
    b.iter().try_fold(0u32, |n, c| {
        n.checked_mul(10)?.checked_add(u32::from(c - b'0'))
    })
}

fn instant(y: i64, mo: u32, d: u32, h: u32, mi: u32, s: u32, nsec: u32) -> Option<Instant> {
    if !(1..=12).contains(&mo) || d < 1 || d > days_in(y, mo) || h > 23 || mi > 59 || s > 59 {
        return None;
    }
    let sec = days_from_civil(y, mo, d) * 86400 + i64::from(h * 3600 + mi * 60 + s);
    Some(Instant { sec, nsec })
}

/// time.Parse("20060102T150405.000Z", s): the snapshot ID's time, or None
/// where Go's Parse fails.
pub fn parse_snapshot_time(s: &str) -> Option<Instant> {
    let b = s.as_bytes();
    if b.len() != 20 || b[8] != b'T' || b[15] != b'.' || b[19] != b'Z' {
        return None;
    }
    let ms = digits(&b[16..19])?;
    instant(
        i64::from(digits(&b[0..4])?),
        digits(&b[4..6])?,
        digits(&b[6..8])?,
        digits(&b[9..11])?,
        digits(&b[11..13])?,
        digits(&b[13..15])?,
        ms * 1_000_000,
    )
}

/// time.Time's UnmarshalJSON (RFC 3339, a fraction of any length, Z or an
/// offset), as an instant.
pub fn parse_rfc3339(s: &str) -> Option<Instant> {
    let b = s.as_bytes();
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let mut i = 19;
    let mut nsec = 0u32;
    if b[i] == b'.' {
        let start = i + 1;
        i = start;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        let f = &b[start..i];
        if f.is_empty() || f.len() > 9 {
            return None;
        }
        nsec = digits(f)? * 10u32.pow(9 - f.len() as u32);
    }
    let off: i64 = match &b[i..] {
        [b'Z'] => 0,
        [sign @ (b'+' | b'-'), h1, h2, b':', m1, m2] => {
            let h = digits(&[*h1, *h2])?;
            let m = digits(&[*m1, *m2])?;
            if h > 23 || m > 59 {
                return None;
            }
            let o = i64::from(h * 3600 + m * 60);
            if *sign == b'-' { -o } else { o }
        }
        _ => return None,
    };
    let t = instant(
        i64::from(digits(&b[0..4])?),
        digits(&b[5..7])?,
        digits(&b[8..10])?,
        digits(&b[11..13])?,
        digits(&b[14..16])?,
        digits(&b[17..19])?,
        nsec,
    )?;
    Some(Instant {
        sec: t.sec - off,
        nsec: t.nsec,
    })
}

/// A zone as the agent sends it: when each offset from UTC starts
/// (seconds since 1970, the first entry covering all earlier times).
pub type Zone = [(i64, i64)];

fn offset(zone: &Zone, sec: i64) -> i64 {
    let i = zone.partition_point(|(start, _)| *start <= sec);
    match i {
        0 => zone.first().map_or(0, |z| z.1),
        i => zone[i - 1].1,
    }
}

/// What selectKept keys on, in the zone: year, day of the year, hour,
/// ISO week year and week, month.
struct Local {
    year: i64,
    yday: u32,
    hour: u32,
    iso_year: i64,
    iso_week: u32,
    month: u32,
}

fn local(zone: &Zone, t: Instant) -> Local {
    let sec = t.sec + offset(zone, t.sec);
    let days = sec.div_euclid(86400);
    let (year, month, _) = civil_from_days(days);
    let yday = (days - days_from_civil(year, 1, 1)) as u32 + 1;
    let hour = (sec.rem_euclid(86400) / 3600) as u32;
    // ISOWeek: the Thursday of the week decides the year.
    let wd = (days + 4).rem_euclid(7); // Sunday = 0
    let shift = if wd == 0 { -3 } else { 4 - wd };
    let thu = days + shift;
    let (iso_year, _, _) = civil_from_days(thu);
    let iso_week = ((thu - days_from_civil(iso_year, 1, 1)) / 7 + 1) as u32;
    Local {
        year,
        yday,
        hour,
        iso_year,
        iso_week,
        month,
    }
}

/// spec.BackupKeep.
#[derive(Clone, Copy, Debug, Default, serde::Deserialize)]
#[serde(default)]
pub struct Keep {
    pub last: i64,
    pub hourly: i64,
    pub daily: i64,
    pub weekly: i64,
    pub monthly: i64,
}

/// selectKept.
pub fn select_kept(times: &[Instant], keep: &Keep, zone: &Zone) -> Vec<bool> {
    let mut order: Vec<usize> = (0..times.len()).collect();
    // Newest first, stable.
    order.sort_by(|a, b| times[*b].cmp(&times[*a]));
    let mut kept = vec![false; times.len()];
    for (n, i) in order.iter().enumerate() {
        if (n as i64) < keep.last {
            kept[*i] = true;
        }
    }
    let locals: Vec<Local> = times.iter().map(|t| local(zone, *t)).collect();
    let mut bucket = |count: i64, key: &dyn Fn(&Local) -> (i64, i64, i64)| {
        let mut seen = std::collections::HashSet::new();
        for i in &order {
            if seen.len() as i64 == count {
                return;
            }
            if seen.insert(key(&locals[*i])) {
                kept[*i] = true;
            }
        }
    };
    bucket(keep.hourly, &|l| {
        (l.year, i64::from(l.yday), i64::from(l.hour))
    });
    bucket(keep.daily, &|l| (l.year, i64::from(l.yday), 0));
    bucket(keep.weekly, &|l| (l.iso_year, i64::from(l.iso_week), 0));
    bucket(keep.monthly, &|l| (l.year, i64::from(l.month), 0));
    kept
}

/// A string as Go's encoding/json writes it: <, >, &, U+2028, and U+2029
/// escaped, each byte of invalid UTF-8 as �.
pub fn json_string(out: &mut String, b: &[u8]) {
    out.push('"');
    for chunk in b.utf8_chunks() {
        for c in chunk.valid().chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                '\u{8}' => out.push_str("\\b"),
                '\u{c}' => out.push_str("\\f"),
                '<' | '>' | '&' | '\u{2028}' | '\u{2029}' => {
                    out.push_str(&format!("\\u{:04x}", c as u32))
                }
                c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
                c => out.push(c),
            }
        }
        for _ in chunk.invalid() {
            out.push_str("\\ufffd");
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_and_parses_as_go() {
        let t = Instant {
            sec: 1_700_000_000,
            nsec: 123_400_000,
        };
        assert_eq!(t.rfc3339_nano(), "2023-11-14T22:13:20.1234Z");
        assert_eq!(t.snapshot_time(), "20231114T221320.123Z");
        assert_eq!(t.amz_date(), "20231114T221320Z");
        assert_eq!(
            parse_snapshot_time("20231114T221320.123Z"),
            Some(Instant {
                sec: 1_700_000_000,
                nsec: 123_000_000
            })
        );
        assert_eq!(parse_snapshot_time("20230229T000000.000Z"), None);
        assert!(parse_snapshot_time("20240229T000000.000Z").is_some());
        assert_eq!(parse_rfc3339("2023-11-14T22:13:20.1234Z"), Some(t));
        assert_eq!(parse_rfc3339("2023-11-14T23:13:20.1234+01:00"), Some(t));
        assert_eq!(parse_rfc3339("2023-11-14T22:13:20.Z"), None);
        for d in [-1_000_000i64, -1, 0, 1, 19_000, 2_932_896] {
            let (y, m, dd) = civil_from_days(d);
            assert_eq!(days_from_civil(y, m, dd), d);
        }
    }

    #[test]
    fn keeps_as_go() {
        // 2021-01-03 is a Sunday in ISO week 2020-53.
        let l = local(
            &[(i64::MIN, 0)],
            Instant {
                sec: days_from_civil(2021, 1, 3) * 86400 + 3600 * 5,
                nsec: 0,
            },
        );
        assert_eq!((l.iso_year, l.iso_week, l.yday, l.hour), (2020, 53, 3, 5));
        let day = |d: i64| Instant {
            sec: 1_700_000_000 + d * 86400,
            nsec: 0,
        };
        let times: Vec<Instant> = (0..10).map(day).collect();
        let keep = Keep {
            last: 2,
            daily: 4,
            ..Keep::default()
        };
        let kept = select_kept(&times, &keep, &[(i64::MIN, 0)]);
        assert_eq!(kept.iter().filter(|k| **k).count(), 4);
        assert!(kept[9] && kept[6] && !kept[5]);
    }

    #[test]
    fn writes_json_strings_as_go() {
        let mut s = String::new();
        json_string(&mut s, b"a<b>&\x01\xff\xe2\x82\"");
        assert_eq!(
            s,
            "\"a\\u003cb\\u003e\\u0026\\u0001\\ufffd\\ufffd\\ufffd\\\"\""
        );
    }
}
