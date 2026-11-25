//! `google.protobuf.Timestamp`, with the JSON Go's protojson reads and
//! writes: RFC 3339 in UTC with a `Z`, and 0, 3, 6, or 9 digits of a
//! second, within years 1 to 9999.

use std::fmt;

/// A point in time: seconds since the Unix epoch and nanoseconds within
/// the second, as protobuf's well-known type carries it.
#[derive(Clone, Copy, PartialEq, Eq, Hash, prost::Message)]
pub struct Timestamp {
    /// Seconds since 1970-01-01T00:00:00Z.
    #[prost(int64, tag = "1")]
    pub seconds: i64,
    /// Nanoseconds within the second, 0 to 999,999,999.
    #[prost(int32, tag = "2")]
    pub nanos: i32,
}

/// 0001-01-01T00:00:00Z.
const MIN_SECONDS: i64 = -62_135_596_800;
/// 9999-12-31T23:59:59Z.
const MAX_SECONDS: i64 = 253_402_300_799;

impl prost::Name for Timestamp {
    const NAME: &'static str = "Timestamp";
    const PACKAGE: &'static str = "google.protobuf";
}

impl Timestamp {
    /// The RFC 3339 text protojson writes, or protojson's error for a
    /// timestamp out of range.
    pub fn to_rfc3339(&self) -> Result<String, String> {
        if !(MIN_SECONDS..=MAX_SECONDS).contains(&self.seconds) {
            return Err(format!(
                "google.protobuf.Timestamp: seconds out of range {}",
                self.seconds
            ));
        }
        if !(0..1_000_000_000).contains(&self.nanos) {
            return Err(format!(
                "google.protobuf.Timestamp: nanos out of range {}",
                self.nanos
            ));
        }
        let days = self.seconds.div_euclid(86_400);
        let secs = self.seconds.rem_euclid(86_400);
        let (y, m, d) = civil_from_days(days);
        let mut s = format!(
            "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}",
            secs / 3600,
            secs / 60 % 60,
            secs % 60
        );
        if self.nanos != 0 {
            let mut frac = format!("{:09}", self.nanos);
            while frac.ends_with("000") {
                frac.truncate(frac.len() - 3);
            }
            s.push('.');
            s.push_str(&frac);
        }
        s.push('Z');
        Ok(s)
    }

    /// Reads RFC 3339 as protojson does: a `Z` or a numeric offset, up to
    /// nine digits of a second, and years 1 to 9999 once in UTC.
    pub fn parse_rfc3339(s: &str) -> Result<Self, String> {
        let bad = || format!("invalid google.protobuf.Timestamp value {s:?}");
        let b = s.as_bytes();
        if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' {
            return Err(bad());
        }
        if b[13] != b':' || b[16] != b':' {
            return Err(bad());
        }
        let num = |from: usize, to: usize| -> Result<i64, String> {
            let part = &b[from..to];
            if !part.iter().all(u8::is_ascii_digit) {
                return Err(bad());
            }
            Ok(part.iter().fold(0, |n, c| n * 10 + i64::from(c - b'0')))
        };
        let (year, month, day) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
        let (hour, min, sec) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);
        if !(1..=12).contains(&month)
            || day < 1
            || day > days_in_month(year, month)
            || hour > 23
            || min > 59
            || sec > 59
        {
            return Err(bad());
        }
        let mut i = 19;
        let mut nanos = 0i64;
        if b[i] == b'.' {
            let start = i + 1;
            i = start;
            while i < b.len() && b[i].is_ascii_digit() {
                i += 1;
            }
            let digits = i - start;
            if digits == 0 || digits > 9 {
                return Err(bad());
            }
            nanos = num(start, i)? * 10i64.pow((9 - digits) as u32);
        }
        let offset = match &b[i..] {
            [b'Z'] => 0,
            [sign @ (b'+' | b'-'), _, _, b':', _, _] => {
                let (hh, mm) = (num(i + 1, i + 3)?, num(i + 4, i + 6)?);
                if hh > 23 || mm > 59 {
                    return Err(bad());
                }
                let off = hh * 3600 + mm * 60;
                if *sign == b'-' { -off } else { off }
            }
            _ => return Err(bad()),
        };
        let seconds =
            days_from_civil(year, month, day) * 86_400 + hour * 3600 + min * 60 + sec - offset;
        if !(MIN_SECONDS..=MAX_SECONDS).contains(&seconds) {
            return Err(bad());
        }
        Ok(Timestamp {
            seconds,
            nanos: nanos as i32,
        })
    }
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days since 1970-01-01 of a date in the proleptic Gregorian calendar.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The date of a number of days since 1970-01-01.
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

impl serde::Serialize for Timestamp {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_rfc3339().map_err(serde::ser::Error::custom)?)
    }
}

impl<'de> serde::Deserialize<'de> for Timestamp {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl serde::de::Visitor<'_> for Visitor {
            type Value = Timestamp;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an RFC 3339 timestamp")
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Timestamp, E> {
                Timestamp::parse_rfc3339(v).map_err(E::custom)
            }
        }
        d.deserialize_str(Visitor)
    }
}

#[cfg(test)]
mod tests {
    use super::Timestamp;

    fn ts(seconds: i64, nanos: i32) -> Timestamp {
        Timestamp { seconds, nanos }
    }

    #[test]
    fn writes_what_protojson_writes() {
        for (t, want) in [
            (ts(0, 0), "1970-01-01T00:00:00Z"),
            (ts(1_795_000_000, 0), "2026-11-18T11:06:40Z"),
            (ts(1_795_000_000, 500_000_000), "2026-11-18T11:06:40.500Z"),
            (ts(1_795_000_000, 1_000), "2026-11-18T11:06:40.000001Z"),
            (ts(1_795_000_000, 1), "2026-11-18T11:06:40.000000001Z"),
            (ts(951_782_400, 0), "2000-02-29T00:00:00Z"),
            (ts(-1, 0), "1969-12-31T23:59:59Z"),
            (ts(super::MIN_SECONDS, 0), "0001-01-01T00:00:00Z"),
            (
                ts(super::MAX_SECONDS, 999_999_999),
                "9999-12-31T23:59:59.999999999Z",
            ),
        ] {
            assert_eq!(t.to_rfc3339().unwrap(), want);
            assert_eq!(Timestamp::parse_rfc3339(want).unwrap(), t, "{want}");
        }
        assert!(ts(super::MAX_SECONDS + 1, 0).to_rfc3339().is_err());
        assert!(ts(0, -1).to_rfc3339().is_err());
        assert!(ts(0, 1_000_000_000).to_rfc3339().is_err());
    }

    #[test]
    fn reads_offsets_and_refuses_the_rest() {
        assert_eq!(
            Timestamp::parse_rfc3339("2026-11-18T18:06:40.5+07:00").unwrap(),
            ts(1_795_000_000, 500_000_000)
        );
        assert_eq!(
            Timestamp::parse_rfc3339("2026-11-18T03:06:40-08:00").unwrap(),
            ts(1_795_000_000, 0)
        );
        for bad in [
            "",
            "2026-11-18T11:06:40",
            "2026-11-18 08:26:40Z",
            "2026-02-29T00:00:00Z",
            "2026-11-18T24:00:00Z",
            "2026-11-18T11:06:40.Z",
            "2026-11-18T11:06:40.1234567890Z",
            "2026-11-18T11:06:40+0700",
            "0000-12-31T23:59:59Z",
            "0001-01-01T00:00:00+00:01",
        ] {
            assert!(Timestamp::parse_rfc3339(bad).is_err(), "{bad}");
        }
    }
}
