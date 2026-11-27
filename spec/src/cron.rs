//! Five-field cron schedules as github.com/robfig/cron/v3 parses them with
//! Minute | Hour | Dom | Month | Dow, and its SpecSchedule.Next.

use crate::go::{atoi, fields};
use crate::gotime::Time;

struct Bounds {
    min: u64,
    max: u64,
    names: &'static [(&'static str, u64)],
}

const MINUTES: Bounds = Bounds {
    min: 0,
    max: 59,
    names: &[],
};
const HOURS: Bounds = Bounds {
    min: 0,
    max: 23,
    names: &[],
};
const DOM: Bounds = Bounds {
    min: 1,
    max: 31,
    names: &[],
};
const MONTHS: Bounds = Bounds {
    min: 1,
    max: 12,
    names: &[
        ("jan", 1),
        ("feb", 2),
        ("mar", 3),
        ("apr", 4),
        ("may", 5),
        ("jun", 6),
        ("jul", 7),
        ("aug", 8),
        ("sep", 9),
        ("oct", 10),
        ("nov", 11),
        ("dec", 12),
    ],
};
const DOW: Bounds = Bounds {
    min: 0,
    max: 6,
    names: &[
        ("sun", 0),
        ("mon", 1),
        ("tue", 2),
        ("wed", 3),
        ("thu", 4),
        ("fri", 5),
        ("sat", 6),
    ],
};

const STAR_BIT: u64 = 1 << 63;

/// A parsed schedule (cron.SpecSchedule; seconds are always 0).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Schedule {
    second: u64,
    minute: u64,
    hour: u64,
    dom: u64,
    month: u64,
    dow: u64,
}

/// `1 << n` on a uint64, 0 once n reaches 64.
fn bit(n: i64) -> u64 {
    if (0..64).contains(&n) { 1u64 << n } else { 0 }
}

fn get_bits(min: u64, max: u64, step: u64) -> u64 {
    if step == 1 {
        let hi = if max + 1 >= 64 {
            0
        } else {
            u64::MAX << (max + 1)
        };
        return !hi & (u64::MAX << min);
    }
    let mut bits = 0;
    let mut i = min;
    while i <= max {
        bits |= bit(i as i64);
        i += step;
    }
    bits
}

fn must_parse_int(expr: &str) -> Result<u64, String> {
    let num = atoi(expr).map_err(|e| format!("failed to parse int from {expr}: {e}"))?;
    if num < 0 {
        return Err(format!("negative number ({num}) not allowed: {expr}"));
    }
    // Read as unsigned.
    Ok(num as u64)
}

fn parse_int_or_name(expr: &str, names: &[(&str, u64)]) -> Result<u64, String> {
    if !names.is_empty() {
        let lower = expr.to_lowercase();
        if let Some(&(_, v)) = names.iter().find(|(n, _)| *n == lower) {
            return Ok(v);
        }
    }
    must_parse_int(expr)
}

fn get_range(expr: &str, r: &Bounds) -> Result<u64, String> {
    let range_and_step: Vec<&str> = expr.split('/').collect();
    let low_and_high: Vec<&str> = range_and_step[0].split('-').collect();
    let single_digit = low_and_high.len() == 1;
    let (start, mut end);
    let mut extra = 0;
    if low_and_high[0] == "*" || low_and_high[0] == "?" {
        start = r.min;
        end = r.max;
        extra = STAR_BIT;
    } else {
        start = parse_int_or_name(low_and_high[0], r.names)?;
        match low_and_high.len() {
            1 => end = start,
            2 => end = parse_int_or_name(low_and_high[1], r.names)?,
            _ => return Err(format!("too many hyphens: {expr}")),
        }
    }
    let step = match range_and_step.len() {
        1 => 1,
        2 => {
            let step = must_parse_int(range_and_step[1])?;
            if single_digit {
                end = r.max;
            }
            if step > 1 {
                extra = 0;
            }
            step
        }
        _ => return Err(format!("too many slashes: {expr}")),
    };
    if start < r.min {
        return Err(format!(
            "beginning of range ({start}) below minimum ({}): {expr}",
            r.min
        ));
    }
    if end > r.max {
        return Err(format!(
            "end of range ({end}) above maximum ({}): {expr}",
            r.max
        ));
    }
    if start > end {
        return Err(format!(
            "beginning of range ({start}) beyond end of range ({end}): {expr}"
        ));
    }
    if step == 0 {
        return Err(format!("step of range should be a positive number: {expr}"));
    }
    Ok(get_bits(start, end, step) | extra)
}

fn get_field(field: &str, r: &Bounds) -> Result<u64, String> {
    let mut bits = 0;
    for expr in field.split(',').filter(|e| !e.is_empty()) {
        bits |= get_range(expr, r)?;
    }
    Ok(bits)
}

impl Schedule {
    /// cron.NewParser(Minute | Hour | Dom | Month | Dow).Parse. The spec
    /// package refuses descriptors and TZ= prefixes before it gets here.
    pub fn parse(spec: &str) -> Result<Schedule, String> {
        if spec.is_empty() {
            return Err("empty spec string".to_string());
        }
        if spec.starts_with("TZ=") || spec.starts_with("CRON_TZ=") {
            return Err("unsupported time zone prefix".to_string());
        }
        if spec.starts_with('@') {
            return Err(format!("parser does not accept descriptors: {spec}"));
        }
        let f = fields(spec);
        if f.len() != 5 {
            return Err(format!(
                "expected exactly 5 fields, found {}: [{}]",
                f.len(),
                f.join(" ")
            ));
        }
        Ok(Schedule {
            second: 1,
            minute: get_field(f[0], &MINUTES)?,
            hour: get_field(f[1], &HOURS)?,
            dom: get_field(f[2], &DOM)?,
            month: get_field(f[3], &MONTHS)?,
            dow: get_field(f[4], &DOW)?,
        })
    }

    fn day_matches(&self, t: &Time) -> bool {
        let c = t.civil();
        let dom_match = bit(c.day) & self.dom > 0;
        let dow_match = bit(c.weekday) & self.dow > 0;
        if self.dom & STAR_BIT > 0 || self.dow & STAR_BIT > 0 {
            return dom_match && dow_match;
        }
        dom_match || dow_match
    }

    /// SpecSchedule.Next with the schedule's location time.Local, as the
    /// parser leaves it: t is used in its own zone. The zero time when
    /// nothing matches within five years.
    pub fn next(&self, t: &Time) -> Time {
        let loc = t.loc.clone();
        let mut t = t.add(crate::go::SECOND - t.nsec);
        let mut added = false;
        let year_limit = t.civil().year + 5;
        'wrap: loop {
            if t.civil().year > year_limit {
                return Time::zero();
            }
            while bit(t.civil().month) & self.month == 0 {
                if !added {
                    added = true;
                    let c = t.civil();
                    t = Time::date(c.year, c.month, 1, 0, 0, 0, 0, &loc);
                }
                t = t.add_date(0, 1, 0);
                if t.civil().month == 1 {
                    continue 'wrap;
                }
            }
            while !self.day_matches(&t) {
                if !added {
                    added = true;
                    let c = t.civil();
                    t = Time::date(c.year, c.month, c.day, 0, 0, 0, 0, &loc);
                }
                t = t.add_date(0, 0, 1);
                let h = t.civil().hour;
                if h != 0 {
                    if h > 12 {
                        t = t.add((24 - h) * crate::go::HOUR);
                    } else {
                        t = t.add(-h * crate::go::HOUR);
                    }
                }
                if t.civil().day == 1 {
                    continue 'wrap;
                }
            }
            while bit(t.civil().hour) & self.hour == 0 {
                if !added {
                    added = true;
                    let c = t.civil();
                    t = Time::date(c.year, c.month, c.day, c.hour, 0, 0, 0, &loc);
                }
                t = t.add(crate::go::HOUR);
                if t.civil().hour == 0 {
                    continue 'wrap;
                }
            }
            while bit(t.civil().minute) & self.minute == 0 {
                if !added {
                    added = true;
                    t = t.truncate_seconds(60);
                }
                t = t.add(crate::go::MINUTE);
                if t.civil().minute == 0 {
                    continue 'wrap;
                }
            }
            while bit(t.civil().second) & self.second == 0 {
                if !added {
                    added = true;
                    t = t.truncate_seconds(1);
                }
                t = t.add(crate::go::SECOND);
                if t.civil().second == 0 {
                    continue 'wrap;
                }
            }
            return t;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gotime::{Location, parse_rfc3339};

    #[test]
    fn parses_like_robfig() {
        assert!(Schedule::parse("*/5 * * * *").is_ok());
        assert_eq!(
            Schedule::parse("* * *").unwrap_err(),
            "expected exactly 5 fields, found 3: [* * *]"
        );
        assert_eq!(
            Schedule::parse("61 * * * *").unwrap_err(),
            "end of range (61) above maximum (59): 61"
        );
        assert_eq!(
            Schedule::parse("x * * * *").unwrap_err(),
            "failed to parse int from x: strconv.Atoi: parsing \"x\": invalid syntax"
        );
        let s = Schedule::parse("30 2 * * mon").unwrap();
        let t = parse_rfc3339("2026-11-25T10:00:00Z")
            .unwrap()
            .in_loc(&Location::utc());
        assert_eq!(s.next(&t).rfc3339_nano(), "2026-11-30T02:30:00Z");
    }
}
