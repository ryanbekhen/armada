//! Flags as spf13/pflag v1.1.0 parses and lists them: the same syntax
//! (`--name value`,
//! `--name=value`, `-n value`, `-nvalue`, `-n=value`, grouped shorthands,
//! `--` ending the flags, flags between arguments), the same error texts,
//! and the same usage lines (FlagUsages).

use armada_spec::go;

/// The kinds of value Armada's commands declare.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Bool(bool),
    Str(String),
    Int(i64),
    Int64(i64),
    Duration(i64),
    /// A string array: every use adds one value, the first replacing the
    /// default.
    StrArray(Vec<String>),
    /// A string slice: every use adds its comma-separated values (CSV),
    /// the first replacing the default.
    StrSlice(Vec<String>),
}

impl Value {
    /// pflag's Value.Type().
    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Bool(_) => "bool",
            Value::Str(_) => "string",
            Value::Int(_) => "int",
            Value::Int64(_) => "int64",
            Value::Duration(_) => "duration",
            Value::StrArray(_) => "stringArray",
            Value::StrSlice(_) => "stringSlice",
        }
    }

    /// pflag's Value.String().
    pub fn string(&self) -> String {
        match self {
            Value::Bool(b) => b.to_string(),
            Value::Str(s) => s.clone(),
            Value::Int(n) | Value::Int64(n) => n.to_string(),
            Value::Duration(d) => go::format_duration(*d),
            Value::StrArray(v) | Value::StrSlice(v) => format!("[{}]", write_as_csv(v)),
        }
    }
}

/// encoding/csv's writer for one record, as stringArray's String uses it.
fn write_as_csv(v: &[String]) -> String {
    let mut out = String::new();
    for (i, f) in v.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let needs = !f.is_empty()
            && (f == "\\." || f.contains([',', '"', '\r', '\n']) || f.starts_with([' ', '\t']));
        if !needs {
            out.push_str(f);
            continue;
        }
        out.push('"');
        for c in f.chars() {
            match c {
                '"' => out.push_str("\"\""),
                '\r' => {}
                c => out.push(c),
            }
        }
        out.push('"');
    }
    out
}

/// The first record encoding/csv reads from s (a comma between
/// fields, double quotes around a field that holds one), with the texts of
/// its errors.
fn read_as_csv(s: &str) -> Result<Vec<String>, String> {
    if s.is_empty() {
        return Ok(Vec::new());
    }
    let b = s.as_bytes();
    let mut i = 0;
    let mut line = 1;
    // csv skips lines that are empty.
    while i < b.len() && (b[i] == b'\n' || (b[i] == b'\r' && b.get(i + 1) == Some(&b'\n'))) {
        i += if b[i] == b'\r' { 2 } else { 1 };
        line += 1;
    }
    if i >= b.len() {
        return Err("EOF".to_string());
    }
    let record_line = line;
    let mut line_start = i;
    let quote_err = |rl: usize, l: usize, col: usize| {
        let msg = format!(
            "parse error on line {l}, column {col}: extraneous or missing \" in quoted-field"
        );
        if rl != l {
            format!("record on line {rl}; {msg}")
        } else {
            msg
        }
    };
    let mut fields = Vec::new();
    loop {
        if b.get(i) == Some(&b'"') {
            let mut f = Vec::new();
            i += 1;
            loop {
                let Some(&c) = b.get(i) else {
                    return Err(quote_err(record_line, line, i - line_start + 1));
                };
                if c == b'"' {
                    if b.get(i + 1) == Some(&b'"') {
                        f.push(b'"');
                        i += 2;
                        continue;
                    }
                    i += 1;
                    break;
                }
                if c == b'\r' && b.get(i + 1) == Some(&b'\n') {
                    i += 1;
                    continue;
                }
                if c == b'\n' {
                    line += 1;
                    line_start = i + 1;
                }
                f.push(c);
                i += 1;
            }
            fields.push(String::from_utf8_lossy(&f).into_owned());
            match b.get(i) {
                None | Some(b'\n') => break,
                Some(b'\r') if matches!(b.get(i + 1), None | Some(b'\n')) => break,
                Some(b',') => {
                    i += 1;
                    continue;
                }
                Some(_) => return Err(quote_err(record_line, line, i - line_start)),
            }
        }
        let start = i;
        while i < b.len() && b[i] != b',' && b[i] != b'\n' {
            if b[i] == b'"' {
                return Err(format!(
                    "parse error on line {line}, column {}: bare \" in non-quoted-field",
                    i - line_start + 1
                ));
            }
            i += 1;
        }
        let f = &s[start..i];
        if i >= b.len() || b[i] == b'\n' {
            fields.push(f.strip_suffix('\r').unwrap_or(f).to_string());
            break;
        }
        fields.push(f.to_string());
        i += 1;
    }
    Ok(fields)
}

/// One flag of a command.
#[derive(Clone, Debug)]
pub struct Flag {
    pub name: String,
    pub shorthand: Option<char>,
    pub usage: String,
    pub value: Value,
    /// The default, as pflag keeps it (DefValue).
    pub def_value: String,
    pub changed: bool,
    /// Declared by a parent command for its children (a persistent flag).
    pub inherited: bool,
    /// The help flag cobra adds to every command it runs.
    pub help: bool,
    /// MarkFlagRequired.
    pub required: bool,
    /// MarkFlagsMutuallyExclusive groups this flag is in ("a b c").
    pub exclusive: Vec<String>,
    /// Hidden for completion (enforceFlagGroupsForCompletion).
    pub hidden: bool,
}

impl Flag {
    fn new(name: &str, shorthand: Option<char>, usage: &str, value: Value) -> Flag {
        Flag {
            name: name.to_string(),
            shorthand,
            usage: usage.to_string(),
            def_value: value.string(),
            value,
            changed: false,
            inherited: false,
            help: false,
            required: false,
            exclusive: Vec::new(),
            hidden: false,
        }
    }

    pub fn bool(name: &str, shorthand: Option<char>, def: bool, usage: &str) -> Flag {
        Flag::new(name, shorthand, usage, Value::Bool(def))
    }

    pub fn string(name: &str, shorthand: Option<char>, def: &str, usage: &str) -> Flag {
        Flag::new(name, shorthand, usage, Value::Str(def.to_string()))
    }

    pub fn int(name: &str, shorthand: Option<char>, def: i64, usage: &str) -> Flag {
        Flag::new(name, shorthand, usage, Value::Int(def))
    }

    pub fn int64(name: &str, shorthand: Option<char>, def: i64, usage: &str) -> Flag {
        Flag::new(name, shorthand, usage, Value::Int64(def))
    }

    pub fn duration(name: &str, shorthand: Option<char>, def: i64, usage: &str) -> Flag {
        Flag::new(name, shorthand, usage, Value::Duration(def))
    }

    pub fn string_array(name: &str, shorthand: Option<char>, usage: &str) -> Flag {
        Flag::new(name, shorthand, usage, Value::StrArray(Vec::new()))
    }

    pub fn string_slice(name: &str, shorthand: Option<char>, usage: &str) -> Flag {
        Flag::new(name, shorthand, usage, Value::StrSlice(Vec::new()))
    }

    /// MarkHidden: left out of help and completion.
    pub fn hide(mut self) -> Flag {
        self.hidden = true;
        self
    }

    /// NoOptDefVal: what the flag is set to when given without a value.
    pub fn no_opt_def_val(&self) -> &'static str {
        match self.value {
            Value::Bool(_) => "true",
            _ => "",
        }
    }

    fn set(&mut self, s: &str) -> Result<(), String> {
        let first = !self.changed;
        match &mut self.value {
            Value::Bool(b) => *b = parse_bool(s).ok_or("must be true or false")?,
            Value::Str(v) => *v = s.to_string(),
            Value::Int(n) | Value::Int64(n) => *n = parse_int(s).ok_or("must be an integer")?,
            Value::Duration(d) => {
                *d =
                    go::parse_duration(s).map_err(|_| r#"must be a duration like "30s" or "5m""#)?
            }
            Value::StrArray(v) => {
                if first {
                    *v = vec![s.to_string()];
                } else {
                    v.push(s.to_string());
                }
            }
            Value::StrSlice(v) => {
                let read = read_as_csv(s)?;
                if first {
                    *v = read;
                } else {
                    v.extend(read);
                }
            }
        }
        self.changed = true;
        Ok(())
    }

    /// defaultIsZeroValue.
    fn default_is_zero(&self) -> bool {
        match self.value {
            Value::Bool(_) => self.def_value == "false" || self.def_value.is_empty(),
            Value::Duration(_) => self.def_value == "0" || self.def_value == "0s",
            Value::Int(_) | Value::Int64(_) => self.def_value == "0",
            Value::Str(_) => self.def_value.is_empty(),
            Value::StrArray(_) | Value::StrSlice(_) => self.def_value == "[]",
        }
    }
}

/// A boolean: 1, t, T, TRUE, true, True, 0, f, F, FALSE, false, or False.
pub fn parse_bool(s: &str) -> Option<bool> {
    match s {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Some(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Some(false),
        _ => None,
    }
}

/// A 64-bit integer: a sign, then decimal, 0x, 0o, 0b, or a
/// leading 0 for octal, with underscores between digits.
pub fn parse_int(s: &str) -> Option<i64> {
    let (neg, u) = match s.as_bytes().first() {
        Some(b'-') => (true, &s[1..]),
        Some(b'+') => (false, &s[1..]),
        _ => (false, s),
    };
    let n = parse_uint0(u)?;
    if neg {
        if n > 1u64 << 63 {
            return None;
        }
        Some((n as i64).wrapping_neg())
    } else {
        i64::try_from(n).ok()
    }
}

fn parse_uint0(s0: &str) -> Option<u64> {
    let b = s0.as_bytes();
    if b.is_empty() {
        return None;
    }
    let lower = |c: u8| c | 0x20;
    let (base, digits): (u64, &[u8]) = if b[0] == b'0' {
        if b.len() >= 3 && matches!(lower(b[1]), b'b' | b'o' | b'x') {
            let base = match lower(b[1]) {
                b'b' => 2,
                b'o' => 8,
                _ => 16,
            };
            (base, &b[2..])
        } else {
            (8, &b[1..])
        }
    } else {
        (10, b)
    };
    let mut n: u64 = 0;
    let mut underscores = false;
    for &c in digits {
        let d = match c {
            b'_' => {
                underscores = true;
                continue;
            }
            b'0'..=b'9' => c - b'0',
            b'a'..=b'z' | b'A'..=b'Z' => lower(c) - b'a' + 10,
            _ => return None,
        };
        if u64::from(d) >= base {
            return None;
        }
        n = n.checked_mul(base)?.checked_add(u64::from(d))?;
    }
    if underscores && !underscore_ok(s0) {
        return None;
    }
    Some(n)
}

fn underscore_ok(s: &str) -> bool {
    let b = s.as_bytes();
    let lower = |c: u8| c | 0x20;
    let mut saw = b'^';
    let mut i = 0;
    let mut hex = false;
    if b.len() >= 2 && b[0] == b'0' && matches!(lower(b[1]), b'b' | b'o' | b'x') {
        i = 2;
        saw = b'0';
        hex = lower(b[1]) == b'x';
    }
    while i < b.len() {
        let c = b[i];
        i += 1;
        if c.is_ascii_digit() || hex && (b'a'..=b'f').contains(&lower(c)) {
            saw = b'0';
            continue;
        }
        if c == b'_' {
            if saw != b'0' {
                return false;
            }
            saw = b'_';
            continue;
        }
        if saw == b'_' {
            return false;
        }
        saw = b'!';
    }
    saw != b'_'
}

/// A parse error, worded as pflag's.
#[derive(Debug, PartialEq)]
pub enum ParseError {
    /// --help or -h when not declared (never for cobra's commands).
    Help,
    Text(String),
}

/// The flags of one command: its own, its parents' persistent ones, and
/// cobra's help flag.
#[derive(Clone, Debug, Default)]
pub struct FlagSet {
    pub flags: Vec<Flag>,
    /// The arguments left after parsing.
    pub args: Vec<String>,
    /// How many arguments came before "--", or -1.
    pub args_len_at_dash: i64,
    /// ParseErrorsWhitelist.UnknownFlags: unknown flags are skipped.
    pub ignore_unknown: bool,
}

impl FlagSet {
    pub fn new(flags: Vec<Flag>) -> FlagSet {
        FlagSet {
            flags,
            args: Vec::new(),
            args_len_at_dash: -1,
            ignore_unknown: false,
        }
    }

    pub fn lookup(&self, name: &str) -> Option<&Flag> {
        self.flags.iter().find(|f| f.name == name)
    }

    pub fn lookup_mut(&mut self, name: &str) -> Option<&mut Flag> {
        self.flags.iter_mut().find(|f| f.name == name)
    }

    pub fn shorthand(&self, c: char) -> Option<&Flag> {
        self.flags.iter().find(|f| f.shorthand == Some(c))
    }

    fn shorthand_index(&self, c: char) -> Option<usize> {
        self.flags.iter().position(|f| f.shorthand == Some(c))
    }

    /// Changed.
    pub fn changed(&self, name: &str) -> bool {
        self.lookup(name).is_some_and(|f| f.changed)
    }

    /// The flags sorted by name, as VisitAll visits them.
    pub fn sorted(&self) -> Vec<&Flag> {
        let mut v: Vec<&Flag> = self.flags.iter().collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        v
    }

    /// Parse, with flags allowed between arguments.
    pub fn parse(&mut self, args: &[String]) -> Result<(), ParseError> {
        let mut args: Vec<String> = args.to_vec();
        args.reverse();
        while let Some(s) = args.pop() {
            if s.len() < 2 || !s.starts_with('-') {
                self.args.push(s);
                continue;
            }
            if s.as_bytes()[1] == b'-' {
                if s.len() == 2 {
                    self.args_len_at_dash = self.args.len() as i64;
                    while let Some(a) = args.pop() {
                        self.args.push(a);
                    }
                    break;
                }
                self.parse_long(&s, &mut args)?;
            } else {
                self.parse_short(&s, &mut args)?;
            }
        }
        Ok(())
    }

    fn parse_long(&mut self, s: &str, args: &mut Vec<String>) -> Result<(), ParseError> {
        let name = &s[2..];
        if name.is_empty() || name.starts_with('-') || name.starts_with('=') {
            return Err(ParseError::Text(format!("bad flag syntax: {s}")));
        }
        let (name, value) = match name.split_once('=') {
            Some((n, v)) => (n, Some(v.to_string())),
            None => (name, None),
        };
        let Some(i) = self.flags.iter().position(|f| f.name == name) else {
            if name == "help" {
                return Err(ParseError::Help);
            }
            if self.ignore_unknown {
                if value.is_none() {
                    strip_unknown_flag_value(args);
                }
                return Ok(());
            }
            return Err(ParseError::Text(format!("unknown flag: --{name}")));
        };
        let value = match value {
            Some(v) => v,
            None if !self.flags[i].no_opt_def_val().is_empty() => {
                self.flags[i].no_opt_def_val().to_string()
            }
            None => match args.pop() {
                Some(v) => v,
                None => {
                    return Err(ParseError::Text(format!(
                        "flag needs an argument: --{name}"
                    )));
                }
            },
        };
        self.set_value(i, &value)
    }

    fn parse_short(&mut self, s: &str, args: &mut Vec<String>) -> Result<(), ParseError> {
        let mut shorthands: &str = &s[1..];
        while !shorthands.is_empty() {
            let c = shorthands.chars().next().expect("not empty");
            let rest = &shorthands[c.len_utf8()..];
            let Some(i) = self.shorthand_index(c) else {
                if c == 'h' {
                    return Err(ParseError::Help);
                }
                if self.ignore_unknown {
                    // '-f=v' ends the group; '-f' or '-fxyz' strips a
                    // value that follows and goes on with the rest.
                    if rest.len() > 1 && rest.starts_with('=') {
                        return Ok(());
                    }
                    strip_unknown_flag_value(args);
                    shorthands = rest;
                    continue;
                }
                return Err(ParseError::Text(format!(
                    "unknown shorthand flag: {} in -{shorthands}",
                    quote_rune(c)
                )));
            };
            let value;
            let mut next = rest;
            if rest.len() > 1 && rest.starts_with('=') {
                value = rest[1..].to_string();
                next = "";
            } else if !self.flags[i].no_opt_def_val().is_empty() {
                value = self.flags[i].no_opt_def_val().to_string();
            } else if !rest.is_empty() {
                value = rest.to_string();
                next = "";
            } else if let Some(v) = args.pop() {
                value = v;
            } else {
                return Err(ParseError::Text(format!(
                    "flag needs an argument: {} in -{shorthands}",
                    quote_rune(c)
                )));
            }
            self.set_value(i, &value)?;
            shorthands = next;
        }
        Ok(())
    }

    fn set_value(&mut self, i: usize, value: &str) -> Result<(), ParseError> {
        let f = &mut self.flags[i];
        f.set(value).map_err(|cause| {
            let name = match f.shorthand {
                Some(c) => format!("-{c}, --{}", f.name),
                None => format!("--{}", f.name),
            };
            ParseError::Text(format!(
                "invalid argument {} for {} flag: {cause}",
                go::quote(value),
                go::quote(&name)
            ))
        })
    }

    /// FlagUsages of the flags filter keeps, sorted by name (hidden ones
    /// left out).
    pub fn usages(&self, filter: impl Fn(&Flag) -> bool) -> String {
        let mut lines = Vec::new();
        let mut maxlen = 0;
        for f in self.sorted() {
            if f.hidden || !filter(f) {
                continue;
            }
            let mut line = match f.shorthand {
                Some(c) => format!("  -{c}, --{}", f.name),
                None => format!("      --{}", f.name),
            };
            let (varname, usage) = unquote_usage(f);
            if matches!(f.value, Value::Bool(_)) {
                line.push_str("[=true|false]");
            } else if !varname.is_empty() {
                line.push(' ');
                line.push_str(&varname);
            }
            line.push('\0');
            maxlen = maxlen.max(line.len());
            line.push_str(&usage);
            if !f.default_is_zero() {
                if matches!(f.value, Value::Str(_)) {
                    line.push_str(&format!(" (default {})", go::quote(&f.def_value)));
                } else {
                    line.push_str(&format!(" (default {})", f.def_value));
                }
            }
            lines.push(line);
        }
        let mut out = String::new();
        for line in lines {
            let sidx = line.find('\0').expect("marker");
            let spacing = " ".repeat(maxlen - sidx);
            let usage = line[sidx + 1..].replace('\n', &format!("\n{}", " ".repeat(maxlen + 2)));
            out.push_str(&format!("{} {} {}\n", &line[..sidx], spacing, usage));
        }
        out
    }
}

/// The value after an unknown flag, unless it is
/// another flag. `args` holds what is left, last first.
fn strip_unknown_flag_value(args: &mut Vec<String>) {
    if let Some(next) = args.last()
        && !next.starts_with('-')
    {
        args.pop();
    }
}

/// %q of a rune.
fn quote_rune(c: char) -> String {
    let q = go::quote(&c.to_string());
    let inner = &q[1..q.len() - 1];
    let inner = if inner == "\\\"" { "\"" } else { inner };
    if inner == "'" {
        return "'\\''".to_string();
    }
    format!("'{inner}'")
}

/// UnquoteUsage: a back-quoted name in the usage, else a name for the
/// value's type.
pub(crate) fn unquote_usage(f: &Flag) -> (String, String) {
    let usage = &f.usage;
    if let Some(i) = usage.find('`')
        && let Some(j) = usage[i + 1..].find('`')
    {
        let name = &usage[i + 1..i + 1 + j];
        let un = format!("{}{}{}", &usage[..i], name, &usage[i + 1 + j + 1..]);
        return (name.to_string(), un);
    }
    let name = match f.value {
        Value::Bool(_) => "",
        Value::Int64(_) => "int",
        Value::StrSlice(_) => "strings",
        ref v => v.type_name(),
    };
    (name.to_string(), usage.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set() -> FlagSet {
        FlagSet::new(vec![
            Flag::string("output", Some('o'), "text", "output format"),
            Flag::bool("yes", None, false, "confirm"),
            Flag::int("min", None, 0, "replicas"),
            Flag::string_array("env", None, "variables"),
            Flag::duration("timeout", None, 15 * go::MINUTE, "how long"),
        ])
    }

    fn parse(args: &[&str]) -> Result<FlagSet, ParseError> {
        let mut f = set();
        let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        f.parse(&args).map(|()| f)
    }

    #[test]
    fn syntax() {
        let f = parse(&[
            "a",
            "-ojson",
            "--yes",
            "b",
            "--env=X=1",
            "--env",
            "Y",
            "--",
            "-c",
        ])
        .unwrap();
        assert_eq!(f.args, ["a", "b", "-c"]);
        assert_eq!(f.lookup("output").unwrap().value, Value::Str("json".into()));
        assert_eq!(
            f.lookup("env").unwrap().value,
            Value::StrArray(vec!["X=1".into(), "Y".into()])
        );
        assert_eq!(f.args_len_at_dash, 2);
        let f = parse(&["-o=yaml", "--min", "0x10"]).unwrap();
        assert_eq!(f.lookup("output").unwrap().value, Value::Str("yaml".into()));
        assert_eq!(f.lookup("min").unwrap().value, Value::Int(16));
    }

    #[test]
    fn errors() {
        let text = |a: &[&str]| match parse(a) {
            Err(ParseError::Text(t)) => t,
            other => panic!("{other:?}"),
        };
        assert_eq!(text(&["--nope"]), "unknown flag: --nope");
        assert_eq!(text(&["-x"]), "unknown shorthand flag: 'x' in -x");
        assert_eq!(text(&["--min"]), "flag needs an argument: --min");
        assert_eq!(text(&["-o"]), "flag needs an argument: 'o' in -o");
        assert_eq!(
            text(&["--min", "abc"]),
            r#"invalid argument "abc" for "--min" flag: must be an integer"#
        );
        assert_eq!(
            text(&["--yes=maybe"]),
            r#"invalid argument "maybe" for "--yes" flag: must be true or false"#
        );
        assert_eq!(text(&["---x"]), "bad flag syntax: ---x");
        assert_eq!(parse(&["--help"]).err(), Some(ParseError::Help));
    }

    #[test]
    fn ints() {
        assert_eq!(parse_int("1_000"), Some(1000));
        assert_eq!(parse_int("0b101"), Some(5));
        assert_eq!(parse_int("017"), Some(15));
        assert_eq!(parse_int("08"), None);
        assert_eq!(parse_int("_1"), None);
        assert_eq!(parse_int("-9223372036854775808"), Some(i64::MIN));
        assert_eq!(parse_int("9223372036854775808"), None);
    }

    #[test]
    fn usages() {
        let u = set().usages(|_| true);
        assert_eq!(
            u,
            "      --env stringArray    variables\n\
             \x20     --min int            replicas\n\
             \x20 -o, --output string      output format (default \"text\")\n\
             \x20     --timeout duration   how long (default 15m0s)\n\
             \x20     --yes[=true|false]   confirm\n"
        );
    }

    #[test]
    fn csv_record() {
        // One CSV record: quotes, doubled quotes, and line ends.
        let ok = |s: &str, want: &[&str]| assert_eq!(read_as_csv(s).unwrap(), want, "{s:?}");
        ok("", &[]);
        ok("a,b\nc", &["a", "b"]);
        ok("\n\na,b", &["a", "b"]);
        ok("\"a\"\"b\",c", &["a\"b", "c"]);
        ok("a\r", &["a"]);
        ok("\"\"", &[""]);
        ok(",", &["", ""]);
        let err = |s: &str, want: &str| assert_eq!(read_as_csv(s).unwrap_err(), want, "{s:?}");
        let quote = "extraneous or missing \" in quoted-field";
        err(
            "\"a\"b",
            &format!("parse error on line 1, column 3: {quote}"),
        );
        err(
            "\"abc",
            &format!("parse error on line 1, column 5: {quote}"),
        );
        err(
            "a,\"b",
            &format!("parse error on line 1, column 5: {quote}"),
        );
        err(
            "x\"y",
            "parse error on line 1, column 2: bare \" in non-quoted-field",
        );
        err(
            " \"a\"",
            "parse error on line 1, column 2: bare \" in non-quoted-field",
        );
        err(
            "\"a\nb\"c",
            &format!("record on line 1; parse error on line 2, column 2: {quote}"),
        );
        err(
            "\"a\nb",
            &format!("record on line 1; parse error on line 2, column 2: {quote}"),
        );
    }
}
