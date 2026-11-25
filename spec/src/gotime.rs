//! Go's time.Time and time.Location, as much as schedules use: loading a
//! zone as time.LoadLocation does on Linux, civil fields in a zone, Date's
//! normalization, AddDate, Truncate, and RFC 3339 output.

use std::sync::Arc;

use jiff::Timestamp;
use jiff::tz::{TimeZone, TimeZoneDatabase};

/// A time zone: UTC, or one read from TZif data.
#[derive(Clone, Debug)]
pub struct Location {
    name: String,
    tz: Option<Arc<TimeZone>>,
}

impl PartialEq for Location {
    fn eq(&self, other: &Location) -> bool {
        self.name == other.name
    }
}

impl Location {
    /// time.UTC.
    pub fn utc() -> Location {
        Location {
            name: "UTC".to_string(),
            tz: None,
        }
    }

    /// Location.String: the name it was loaded by.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The offset from UTC in seconds at a Unix time.
    pub fn offset(&self, unix: i64) -> i64 {
        let Some(tz) = &self.tz else { return 0 };
        let ts = Timestamp::from_second(unix).unwrap_or(if unix < 0 {
            Timestamp::MIN
        } else {
            Timestamp::MAX
        });
        i64::from(tz.to_offset(ts).seconds())
    }
}

/// The directories Go reads zones from on Unix (platformZoneSources).
const ZONE_SOURCES: [&str; 4] = [
    "/usr/share/zoneinfo/",
    "/usr/share/lib/zoneinfo/",
    "/usr/lib/locale/TZ/",
    "/etc/zoneinfo/",
];

fn from_tzif(name: &str, data: &[u8]) -> Option<Location> {
    let tz = TimeZone::tzif(name, data).ok()?;
    Some(Location {
        name: name.to_string(),
        tz: Some(Arc::new(tz)),
    })
}

/// Go's loadLocation: the ZONEINFO file or directory, then the system's
/// directories, then the database Go embeds (time/tzdata), here jiff's,
/// whose names must match exactly as Go's zip entries do.
fn load_named(name: &str) -> Option<Location> {
    if let Ok(z) = std::env::var("ZONEINFO")
        && !z.is_empty()
        && let Ok(data) = std::fs::read(format!("{z}/{name}"))
        && let Some(l) = from_tzif(name, &data)
    {
        return Some(l);
    }
    for dir in ZONE_SOURCES {
        if let Ok(data) = std::fs::read(format!("{dir}{name}")) {
            // Go stops at the first file it can read, valid or not.
            return from_tzif(name, &data);
        }
    }
    let db = TimeZoneDatabase::bundled();
    let tz = db.get(name).ok()?;
    if tz.iana_name() != Some(name) {
        return None;
    }
    Some(Location {
        name: name.to_string(),
        tz: Some(Arc::new(tz)),
    })
}

/// time.Local, as Go's initLocal finds it: $TZ, else /etc/localtime, UTC
/// when neither loads. Its name is "Local".
fn local() -> Location {
    let tz = match std::env::var("TZ") {
        Err(_) => std::fs::read("/etc/localtime")
            .ok()
            .and_then(|d| from_tzif("Local", &d)),
        Ok(v) if v.is_empty() => None,
        Ok(v) => {
            let v = v.strip_prefix(':').unwrap_or(&v).to_string();
            if v.starts_with('/') {
                std::fs::read(&v).ok().and_then(|d| from_tzif("Local", &d))
            } else if v != "UTC" {
                load_named(&v)
            } else {
                None
            }
        }
    };
    match tz {
        Some(l) => Location {
            name: "Local".to_string(),
            tz: l.tz,
        },
        None => Location {
            name: "Local".to_string(),
            tz: None,
        },
    }
}

/// time.LoadLocation on Linux.
pub fn load_location(name: &str) -> Option<Location> {
    if name.is_empty() || name == "UTC" {
        return Some(Location::utc());
    }
    if name == "Local" {
        return Some(local());
    }
    if contains_dot_dot(name) || name.starts_with('/') || name.starts_with('\\') {
        return None;
    }
    load_named(name)
}

fn contains_dot_dot(s: &str) -> bool {
    s.split(['/', '\\']).any(|p| p == "..")
}

/// Seconds from 0001-01-01 to 1970-01-01, the Unix time of Go's zero Time.
const ZERO_UNIX: i64 = -62_135_596_800;

/// A time.Time: a Unix time with nanoseconds and the zone it is shown in.
#[derive(Clone, Debug)]
pub struct Time {
    pub unix: i64,
    pub nsec: i64,
    pub loc: Location,
}

/// Days from 1970-01-01 to a proleptic Gregorian date.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The date of a day number (days from 1970-01-01).
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Go's norm: hi and lo with lo moved into [0, base).
fn norm(hi: i64, lo: i64, base: i64) -> (i64, i64) {
    (hi + lo.div_euclid(base), lo.rem_euclid(base))
}

/// The civil fields of a time in its zone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Civil {
    pub year: i64,
    pub month: i64,
    pub day: i64,
    pub hour: i64,
    pub minute: i64,
    pub second: i64,
    /// 0 is Sunday.
    pub weekday: i64,
}

impl Time {
    /// time.Time{}: January 1, year 1, UTC.
    pub fn zero() -> Time {
        Time {
            unix: ZERO_UNIX,
            nsec: 0,
            loc: Location::utc(),
        }
    }

    pub fn is_zero(&self) -> bool {
        self.unix == ZERO_UNIX && self.nsec == 0
    }

    /// time.Date.
    #[allow(clippy::too_many_arguments)]
    pub fn date(
        year: i64,
        month: i64,
        day: i64,
        hour: i64,
        min: i64,
        sec: i64,
        nsec: i64,
        loc: &Location,
    ) -> Time {
        let (year, m) = norm(year, month - 1, 12);
        let month = m + 1;
        let (sec, nsec) = norm(sec, nsec, 1_000_000_000);
        let (min, sec) = norm(min, sec, 60);
        let (hour, min) = norm(hour, min, 60);
        let (day, hour) = norm(day, hour, 24);
        let days = days_from_civil(year, month, 1) + day - 1;
        let mut unix = days * 86_400 + hour * 3600 + min * 60 + sec;
        // As Go: the offset at the wall time read as UTC, then the offset
        // at the instant that gives, unless both are in one zone period.
        let offset = loc.offset(unix);
        if offset != 0 {
            unix -= loc.offset(unix - offset);
        }
        Time {
            unix,
            nsec,
            loc: loc.clone(),
        }
    }

    pub fn civil(&self) -> Civil {
        let local = self.unix + self.loc.offset(self.unix);
        let days = local.div_euclid(86_400);
        let secs = local.rem_euclid(86_400);
        let (year, month, day) = civil_from_days(days);
        Civil {
            year,
            month,
            day,
            hour: secs / 3600,
            minute: secs % 3600 / 60,
            second: secs % 60,
            weekday: (days + 4).rem_euclid(7),
        }
    }

    /// Time.In.
    pub fn in_loc(&self, loc: &Location) -> Time {
        Time {
            unix: self.unix,
            nsec: self.nsec,
            loc: loc.clone(),
        }
    }

    /// Time.Add of nanoseconds.
    pub fn add(&self, d: i64) -> Time {
        let total = self.nsec + d.rem_euclid(1_000_000_000);
        let unix = self.unix + d.div_euclid(1_000_000_000) + total / 1_000_000_000;
        Time {
            unix,
            nsec: total % 1_000_000_000,
            loc: self.loc.clone(),
        }
    }

    /// Time.AddDate.
    pub fn add_date(&self, years: i64, months: i64, days: i64) -> Time {
        let c = self.civil();
        Time::date(
            c.year + years,
            c.month + months,
            c.day + days,
            c.hour,
            c.minute,
            c.second,
            self.nsec,
            &self.loc,
        )
    }

    /// Time.Truncate for a whole number of seconds d (seconds from year 1,
    /// as Go counts, are seconds from 1970 plus a multiple of a minute).
    pub fn truncate_seconds(&self, d: i64) -> Time {
        let r = (self.unix - ZERO_UNIX).rem_euclid(d);
        Time {
            unix: self.unix - r,
            nsec: 0,
            loc: self.loc.clone(),
        }
    }

    pub fn before(&self, o: &Time) -> bool {
        (self.unix, self.nsec) < (o.unix, o.nsec)
    }

    pub fn after(&self, o: &Time) -> bool {
        (self.unix, self.nsec) > (o.unix, o.nsec)
    }

    /// Format(time.RFC3339Nano).
    pub fn rfc3339_nano(&self) -> String {
        let c = self.civil();
        let mut s = String::new();
        if c.year < 0 {
            s.push('-');
        }
        s.push_str(&format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
            c.year.abs(),
            c.month,
            c.day,
            c.hour,
            c.minute,
            c.second
        ));
        if self.nsec != 0 {
            let frac = format!("{:09}", self.nsec);
            s.push('.');
            s.push_str(frac.trim_end_matches('0'));
        }
        let off = self.loc.offset(self.unix);
        if off == 0 {
            s.push('Z');
        } else {
            let (sign, a) = if off < 0 { ('-', -off) } else { ('+', off) };
            s.push_str(&format!("{sign}{:02}:{:02}", a / 3600, a % 3600 / 60));
        }
        s
    }

    /// Format("Mon 15:04 MST"): the weekday, the clock, and the zone's
    /// abbreviation, as the autoscaler names when a schedule window closes.
    pub fn day_clock_zone(&self) -> String {
        const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
        let c = self.civil();
        format!(
            "{} {:02}:{:02} {}",
            DAYS[c.weekday as usize],
            c.hour,
            c.minute,
            self.loc.abbreviation(self.unix)
        )
    }
}

impl Location {
    /// The zone's abbreviation at a Unix time ("UTC", "WIB", "+07"); Go
    /// writes the offset as -0700 where a zone has none.
    pub fn abbreviation(&self, unix: i64) -> String {
        let Some(tz) = &self.tz else {
            return "UTC".to_string();
        };
        let ts = Timestamp::from_second(unix).unwrap_or(if unix < 0 {
            Timestamp::MIN
        } else {
            Timestamp::MAX
        });
        let a = tz.to_offset_info(ts).abbreviation().to_string();
        if !a.is_empty() {
            return a;
        }
        let off = self.offset(unix);
        let (sign, v) = if off < 0 { ('-', -off) } else { ('+', off) };
        format!("{sign}{:02}{:02}", v / 3600, v % 3600 / 60)
    }
}

/// Reads an RFC 3339 time with an optional fraction ("2026-03-29T01:30:00Z"
/// or with an offset) into a time in UTC, for the parity program.
pub fn parse_rfc3339(s: &str) -> Option<Time> {
    let ts: Timestamp = s.parse().ok()?;
    Some(Time {
        unix: ts.as_second(),
        nsec: i64::from(ts.subsec_nanosecond()),
        loc: Location::utc(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        let utc = Location::utc();
        let t = Time::date(2026, 13, 32, 25, 61, 61, 0, &utc);
        assert_eq!(t.rfc3339_nano(), "2027-02-02T02:02:01Z");
        assert_eq!(Time::zero().rfc3339_nano(), "0001-01-01T00:00:00Z");
        let Some(ny) = load_location("America/New_York") else {
            return;
        };
        // 02:30 does not exist on 2026-03-08 in New York; Go's Date lands
        // an hour before it.
        let t = Time::date(2026, 3, 8, 2, 30, 0, 0, &ny);
        assert_eq!(t.rfc3339_nano(), "2026-03-08T01:30:00-05:00");
        assert!(load_location("america/new_york").is_none());
        assert!(load_location("../etc").is_none());
    }

    #[test]
    fn day_clock_zone() {
        let t = Time::date(2026, 11, 11, 18, 5, 0, 0, &Location::utc());
        assert_eq!(t.day_clock_zone(), "Wed 18:05 UTC");
        let Some(jkt) = load_location("Asia/Jakarta") else {
            return;
        };
        assert_eq!(t.in_loc(&jkt).day_clock_zone(), "Thu 01:05 WIB");
        if let Some(ny) = load_location("America/New_York") {
            assert_eq!(t.in_loc(&ny).day_clock_zone(), "Wed 13:05 EST");
        }
    }
}
