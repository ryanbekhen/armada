//! The parity tests of Go's internal/spec, recorded once from Go before the
//! Go code was removed (ADR 0055, item 20): testdata/<test>.jsonl.gz holds
//! one line per case with the request Go's test sends armada-spec-check and
//! Go's answer in the program's form. These tests send the same requests
//! to armada-spec-check and compare its answers as the Go tests do, with no
//! Go: error texts exactly (lines in any order where Go checks in map
//! order), JSON as written, exports and summaries as JSON values, and
//! Substitute's placeholders masked.

use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};

use serde_json::Value;

/// The recorded cases of one Go test.
fn cases(test: &str) -> Vec<(String, Value, Value)> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/testdata")
        .join(format!("{test}.jsonl.gz"));
    let f = std::fs::File::open(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let mut text = String::new();
    flate2::read::GzDecoder::new(f)
        .read_to_string(&mut text)
        .expect("gzipped UTF-8");
    text.lines()
        .map(|l| {
            let mut v: Value = serde_json::from_str(l).expect("a JSON line");
            let (req, want) = (v["req"].take(), v["want"].take());
            (l.to_string(), req, want)
        })
        .collect()
}

/// Sends every request to armada-spec-check and returns its answers in
/// order.
fn ask(reqs: Vec<String>) -> Vec<Value> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_armada-spec-check"))
        // The recordings were made with TZ=UTC: "Local" is UTC.
        .env("TZ", "UTC")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("start armada-spec-check");
    let mut stdin = child.stdin.take().expect("stdin");
    let n = reqs.len();
    let writer = std::thread::spawn(move || {
        for r in reqs {
            stdin.write_all(r.as_bytes()).expect("write");
            stdin.write_all(b"\n").expect("write");
        }
    });
    let mut out = Vec::with_capacity(n);
    let mut lines = BufReader::new(child.stdout.take().expect("stdout")).lines();
    for _ in 0..n {
        let line = lines
            .next()
            .expect("armada-spec-check answered every request")
            .expect("read");
        out.push(serde_json::from_str(&line).expect("a JSON answer"));
    }
    writer.join().expect("writer");
    let _ = child.wait();
    out
}

/// JSON values as Go's reflect.DeepEqual sees them after json.Unmarshal
/// into any: numbers as float64.
fn same_json(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => x.as_f64() == y.as_f64(),
        (Value::Array(x), Value::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(a, b)| same_json(a, b))
        }
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len()
                && x.iter()
                    .all(|(k, v)| y.get(k).is_some_and(|w| same_json(v, w)))
        }
        _ => a == b,
    }
}

/// Go's randomOrder: error texts whose lines Go writes in map order.
fn random_order(go: &str) -> bool {
    go.matches("is only valid for kind: job").count() > 1
        || (go.contains("ingress.cors.allowHeaders") && go.contains("ingress.cors.exposeHeaders"))
        || go.matches("placement.require").count() > 1
}

fn same_error(go: &str, rust: &str) -> bool {
    if go == rust {
        return true;
    }
    if !random_order(go) {
        return false;
    }
    let mut a: Vec<&str> = go.split('\n').collect();
    let mut b: Vec<&str> = rust.split('\n').collect();
    a.sort_unstable();
    b.sort_unstable();
    a == b
}

/// Substitute's placeholders (`av` + 16 hex digits + `n`), which differ on
/// every call.
fn mask_nonces(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        if b[i..].starts_with(b"av")
            && b.len() >= i + 19
            && b[i + 2..i + 18]
                .iter()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c))
            && b[i + 18] == b'n'
        {
            out.push_str("avNONCEn");
            i += 19;
            continue;
        }
        let ch = s[i..].chars().next().expect("a char");
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn text(v: &Value) -> Option<&str> {
    v.as_str()
}

/// Why Rust's answer differs from Go's, as the Go test would say, or None.
fn differs(req: &Value, want: &Value, got: &Value) -> Option<String> {
    let op = req["op"].as_str().unwrap_or_default();
    let werr = text(&want["error"]);
    match op {
        "parse" | "json" => {
            let gerr = text(&got["error"]);
            match (werr, gerr) {
                (Some(w), Some(g)) => {
                    let same = if op == "parse" {
                        same_error(w, g)
                    } else {
                        w == g
                    };
                    return (!same).then(|| format!("Go:   {w:?}\nRust: {g:?}"));
                }
                (Some(w), None) => return Some(format!("Go: {w:?}; Rust read it")),
                (None, Some(g)) => return Some(format!("Go read it; Rust: {g:?}")),
                (None, None) => {}
            }
            let mut out = Vec::new();
            if want["json"] != got["json"] {
                out.push(format!(
                    "JSON\nGo:   {}\nRust: {}",
                    want["json"], got["json"]
                ));
            }
            if !same_json(&want["export"], &got["export"]) {
                out.push(format!(
                    "export\nGo:   {}\nRust: {}",
                    want["export"], got["export"]
                ));
            }
            if op == "parse" && !same_json(&want["summary"], &got["summary"]) {
                out.push(format!(
                    "summary\nGo:   {}\nRust: {}",
                    want["summary"], got["summary"]
                ));
            }
            if op == "json" {
                match (text(&want["validate"]), text(&got["validate"])) {
                    (None, None) => {}
                    (Some(w), Some(g)) if same_error(w, g) => {}
                    (w, g) => out.push(format!("validate\nGo:   {w:?}\nRust: {g:?}")),
                }
            }
            (!out.is_empty()).then(|| out.join("\n"))
        }
        "substitute" => {
            let gerr = text(&got["error"]).map(mask_nonces);
            let gout = text(&got["out"]).map(mask_nonces);
            match (werr, gerr) {
                (Some(w), Some(g)) => (w != g).then(|| format!("Go:   {w:?}\nRust: {g:?}")),
                (Some(w), None) => Some(format!("Go: {w:?}; Rust: {gout:?}")),
                (None, Some(g)) => Some(format!("Go: {}; Rust: {g:?}", want["out"])),
                (None, None) => {
                    let w = text(&want["out"]);
                    (w != gout.as_deref()).then(|| format!("Go:   {w:?}\nRust: {gout:?}"))
                }
            }
        }
        _ => (!same_json(want, got)).then(|| format!("Go:   {want}\nRust: {got}")),
    }
}

/// Replays one recorded test and fails with its first differences.
fn replay(test: &str, at_least: usize) {
    let cases = cases(test);
    assert!(
        cases.len() >= at_least,
        "{test}: {} cases recorded, expected at least {at_least}",
        cases.len()
    );
    let reqs = cases.iter().map(|(_, r, _)| r.to_string()).collect();
    let got = ask(reqs);
    let mut failed = Vec::new();
    for ((_, req, want), got) in cases.iter().zip(&got) {
        if let Some(why) = differs(req, want, got) {
            failed.push(format!("{req}:\n{why}"));
        }
    }
    if !failed.is_empty() {
        let n = failed.len();
        failed.truncate(25);
        panic!(
            "{test}: {n} of {} cases differ from Go; the first:\n\n{}",
            cases.len(),
            failed.join("\n\n")
        );
    }
}

#[test]
fn parse_matches_go() {
    replay("TestArmadaSpecParseMatchesGo", 10_000);
}

#[test]
fn substitute_matches_go() {
    replay("TestArmadaSpecSubstituteMatchesGo", 5_000);
}

#[test]
fn json_matches_go() {
    replay("TestArmadaSpecJSONMatchesGo", 2_000);
}

#[test]
fn validators_match_go() {
    replay("TestArmadaSpecValidatorsMatchGo", 50_000);
}

#[test]
fn schedules_match_go() {
    replay("TestArmadaSpecSchedulesMatchGo", 5_000);
}

#[test]
fn the_comparison_is_not_vacuous() {
    // A spec that parses, and one that does not, give answers.
    let got = ask(vec![
        r#"{"op":"parse","data":"bmFtZTogd2ViCmltYWdlOiBuZ2lueAo="}"#.into(),
        r#"{"op":"parse","data":"bmFtZTogd2ViCg=="}"#.into(),
    ]);
    assert!(got[0]["error"].is_null());
    assert!(got[0]["json"].as_str().unwrap().contains(r#""name":"web""#));
    assert_eq!(got[1]["error"], "image: is required");
    // And a changed answer is caught.
    let (_, req, want) = &cases("TestArmadaSpecParseMatchesGo")[0];
    let mut wrong = want.clone();
    match wrong.get_mut("error") {
        Some(e) => *e = Value::String("other".into()),
        None => wrong["json"] = Value::String("{}".into()),
    }
    assert!(differs(req, want, &wrong).is_some());
}
