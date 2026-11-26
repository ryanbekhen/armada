//! `armada-pack outdated`: watches the pins of pack/lock.json as
//! Dependabot watches crates, which it cannot see. For every artifact it
//! finds the latest stable release of the GitHub repository its URL names,
//! and the known vulnerabilities of the pinned version:
//!
//! - GitHub's security advisories of that repository (every program),
//! - OSV's (the Go vulnerability database and GitHub's reviewed ones) for
//!   each Go program's main module, every module it links, and the Go
//!   standard library it was built with, read from the build information
//!   of the pinned binaries (downloaded and checked as `bundle` does,
//!   read only, never run).
//!
//! The report is Markdown; the exit code says what it found (EXIT_*).
//! Collecting needs the network; building and rendering the report
//! (`Report::build`, `Report::render`) do not, so the tests feed them
//! recorded answers.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use serde::Deserialize;
use serde_json::Value;

use crate::gomod::{self, BuildInfo};
use crate::http::{self, Body};
use crate::lock::{ARCHES, Artifact, Lock};
use crate::version::{self, Event, Version};

/// Every pin is the latest release and no advisory affects one.
pub const EXIT_CURRENT: u8 = 0;
/// Newer releases exist; no known vulnerability affects a pin.
pub const EXIT_UPDATES: u8 = 1;
/// A known vulnerability affects a pinned version.
pub const EXIT_VULNERABLE: u8 = 2;
/// The check itself failed (network, an answer that cannot be read).
pub const EXIT_ERROR: u8 = 3;

const GITHUB_API: &str = "https://api.github.com";
const OSV_API: &str = "https://api.osv.dev/v1";
const GITHUB_HEADERS: [&str; 2] = [
    "Accept: application/vnd.github+json",
    "X-GitHub-Api-Version: 2022-11-28",
];

/// null read as the default, as for a missing field.
fn null_default<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

/// A release of a GitHub repository.
#[derive(Debug, Clone, Deserialize)]
pub struct Release {
    pub tag_name: String,
    #[serde(default)]
    pub draft: bool,
    #[serde(default)]
    pub prerelease: bool,
}

/// A GitHub repository security advisory.
#[derive(Debug, Clone, Deserialize)]
pub struct GhAdvisory {
    pub ghsa_id: String,
    #[serde(default)]
    pub cve_id: Option<String>,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub html_url: Option<String>,
    #[serde(default)]
    pub withdrawn_at: Option<String>,
    #[serde(default)]
    pub vulnerabilities: Option<Vec<GhVulnerability>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GhVulnerability {
    #[serde(default)]
    pub package: Option<GhPackage>,
    #[serde(default)]
    pub vulnerable_version_range: Option<String>,
    #[serde(default)]
    pub patched_versions: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GhPackage {
    #[serde(default)]
    pub ecosystem: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
}

/// An OSV vulnerability record (the fields the report reads).
#[derive(Debug, Clone, Deserialize)]
pub struct OsvVuln {
    pub id: String,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default, deserialize_with = "null_default")]
    pub aliases: Vec<String>,
    #[serde(default, deserialize_with = "null_default")]
    pub severity: Vec<OsvSeverity>,
    #[serde(default)]
    pub database_specific: Option<Value>,
    #[serde(default, deserialize_with = "null_default")]
    pub affected: Vec<OsvAffected>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OsvSeverity {
    #[serde(default, rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub score: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OsvAffected {
    #[serde(default)]
    pub package: Option<OsvPackage>,
    #[serde(default, deserialize_with = "null_default")]
    pub ranges: Vec<OsvRange>,
    #[serde(default)]
    pub ecosystem_specific: Option<Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OsvPackage {
    #[serde(default)]
    pub name: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OsvRange {
    #[serde(default, rename = "type")]
    pub kind: String,
    #[serde(default, deserialize_with = "null_default")]
    pub events: Vec<BTreeMap<String, String>>,
}

/// One Go program of an artifact, as its build information describes it.
#[derive(Debug, Clone)]
pub struct GoProgram {
    /// Its name in the pack ("runc", "cni/bridge").
    pub name: String,
    pub info: BuildInfo,
}

/// What was found about one artifact.
#[derive(Debug, Clone)]
pub struct PinInput {
    pub name: String,
    pub version: String,
    /// "owner/repo", None when the URL names no GitHub release.
    pub repo: Option<String>,
    pub releases: Vec<Release>,
    pub advisories: Vec<GhAdvisory>,
    /// Both architectures' programs.
    pub programs: Vec<GoProgram>,
}

/// An OSV query: the Go module ("stdlib" for the standard library) and
/// version (as OSV's Go ecosystem takes them).
pub type OsvQuery = (String, String);

/// What OSV answered for each query.
pub type OsvAnswers = BTreeMap<OsvQuery, Vec<OsvVuln>>;

/// One advisory that affects a pin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub artifact: String,
    pub id: String,
    pub aliases: BTreeSet<String>,
    pub severity: String,
    /// Where, by what: "runc 1.5.2", "github.com/x/y v1.2.3", "Go
    /// standard library go1.26.11".
    pub affects: BTreeMap<String, Affect>,
    pub fixed: String,
    pub summary: String,
    pub url: String,
    /// The program itself (its own advisory, or its main module's), not a
    /// module it links or the Go standard library.
    pub own: bool,
}

/// What an advisory reaches through one module or the program itself.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Affect {
    /// The Go packages the advisory names ("net/http").
    pub packages: BTreeSet<String>,
    /// The artifact's programs that link it; None for all of them.
    pub programs: Option<BTreeSet<String>>,
}

impl Finding {
    /// affects_text: each place the advisory reaches, as the report says
    /// it: "Go standard library go1.26.8 [net/http] in cni/bridge".
    pub fn affects_text(&self) -> Vec<String> {
        self.affects
            .iter()
            .map(|(what, a)| {
                let mut s = what.clone();
                if !a.packages.is_empty() {
                    let p: Vec<&str> = a.packages.iter().map(String::as_str).collect();
                    let _ = write!(s, " [{}]", p.join(", "));
                }
                if let Some(progs) = &a.programs {
                    let p: Vec<&str> = progs.iter().map(String::as_str).collect();
                    let _ = write!(s, " in {}", p.join(", "));
                }
                s
            })
            .collect()
    }
}

fn plain(what: String) -> BTreeMap<String, Affect> {
    [(what, Affect::default())].into()
}

/// A pin's row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub name: String,
    pub pinned: String,
    /// None when no stable release could be found.
    pub latest: Option<String>,
    pub update: bool,
    pub vulnerable: bool,
}

/// The report.
#[derive(Debug, Clone, Default)]
pub struct Report {
    pub rows: Vec<Row>,
    pub findings: Vec<Finding>,
    /// Advisories whose range could not be read and that name no fixed
    /// version: listed for a person, not counted.
    pub unread: Vec<Finding>,
}

/// repo_of: "owner/repo" of a GitHub release download URL.
pub fn repo_of(url: &str) -> Option<String> {
    let rest = url.strip_prefix("https://github.com/")?;
    let mut parts = rest.splitn(4, '/');
    let (owner, repo, kind) = (parts.next()?, parts.next()?, parts.next()?);
    let ok = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'))
    };
    (kind == "releases" && ok(owner) && ok(repo) && repo != "." && repo != "..")
        .then(|| format!("{owner}/{repo}"))
}

/// latest_stable: the newest release that is neither a draft nor a
/// pre-release (flagged, or by its version), by version, not by date.
pub fn latest_stable(releases: &[Release]) -> Option<(Version, String)> {
    releases
        .iter()
        .filter(|r| !r.draft && !r.prerelease)
        .filter_map(|r| {
            let v = Version::parse(&r.tag_name)?;
            v.is_stable().then(|| {
                let shown = r
                    .tag_name
                    .strip_prefix('v')
                    .unwrap_or(&r.tag_name)
                    .to_string();
                (v, shown)
            })
        })
        .max_by(|a, b| a.0.cmp(&b.0))
}

/// osv_queries: what to ask OSV about an artifact's Go programs, each
/// query with the programs it covers. Modules built from the program's
/// own repository ("(devel)") are asked at the main module's version,
/// and that at the pin's when it is "(devel)" too.
pub fn osv_queries(pin: &PinInput) -> BTreeMap<OsvQuery, BTreeSet<String>> {
    let mut out: BTreeMap<OsvQuery, BTreeSet<String>> = BTreeMap::new();
    for p in &pin.programs {
        let main_version = if p.info.main.version.is_empty() || p.info.main.version == "(devel)" {
            format!("v{}", pin.version.trim_start_matches('v'))
        } else {
            p.info.main.version.clone()
        };
        let mut add = |path: &str, version: &str| {
            if path.is_empty() || version.is_empty() {
                return;
            }
            out.entry((path.to_string(), version.to_string()))
                .or_default()
                .insert(p.name.clone());
        };
        add(&p.info.main.path, &main_version);
        for d in &p.info.deps {
            let v = if d.version == "(devel)" {
                main_version.as_str()
            } else {
                d.version.as_str()
            };
            add(&d.path, v);
        }
        if let Some(go) = p.info.go.strip_prefix("go") {
            add("stdlib", go);
        }
    }
    out
}

fn severity_of(v: &OsvVuln) -> String {
    if let Some(s) = v
        .database_specific
        .as_ref()
        .and_then(|d| d.get("severity"))
        .and_then(Value::as_str)
    {
        return s.to_ascii_lowercase();
    }
    match v.severity.first() {
        Some(s) if !s.score.is_empty() => format!("{} {}", s.kind, s.score),
        _ => "unrated".into(),
    }
}

/// The Go packages an OSV record names for a module ("crypto/x509").
fn osv_packages(v: &OsvVuln, module: &str) -> Vec<String> {
    let mut out = BTreeSet::new();
    for a in &v.affected {
        if a.package.as_ref().is_none_or(|p| p.name != module) {
            continue;
        }
        let imports = a
            .ecosystem_specific
            .as_ref()
            .and_then(|e| e.get("imports"))
            .and_then(Value::as_array);
        for i in imports.into_iter().flatten() {
            if let Some(p) = i.get("path").and_then(Value::as_str) {
                out.insert(p.to_string());
            }
        }
    }
    out.into_iter().collect()
}

fn osv_fixed_version(v: &OsvVuln, module: &str, version: &str) -> String {
    let Some(at) = Version::parse(version) else {
        return String::new();
    };
    for a in &v.affected {
        if a.package.as_ref().is_none_or(|p| p.name != module) {
            continue;
        }
        for r in &a.ranges {
            if r.kind != "SEMVER" && r.kind != "ECOSYSTEM" {
                continue;
            }
            let events: Vec<Event> = r
                .events
                .iter()
                .flat_map(|m| {
                    m.iter().filter_map(|(k, x)| match k.as_str() {
                        "introduced" => Some(Event::Introduced(x.clone())),
                        "fixed" => Some(Event::Fixed(x.clone())),
                        "last_affected" => Some(Event::LastAffected(x.clone())),
                        _ => None,
                    })
                })
                .collect();
            if let Some(f) = version::osv_fixed(&at, &events) {
                return f;
            }
        }
    }
    String::new()
}

/// The Go module path's repository: "github.com/owner/repo", or the
/// first two elements elsewhere ("go.etcd.io/etcd").
fn repo_root(path: &str) -> String {
    let n = if path.starts_with("github.com/") {
        3
    } else {
        2
    };
    path.split('/').take(n).collect::<Vec<_>>().join("/")
}

/// What one entry of a GitHub advisory is checked against: the pinned
/// version, or for a Go module of another repository that the artifact's
/// programs link, that module at each version they link (with a label).
/// Empty when the entry names a Go module the programs do not link.
fn gh_targets(
    pin: &PinInput,
    pinned: &Version,
    ecosystem: &str,
    package: &str,
) -> Vec<(Version, Option<String>)> {
    if !ecosystem.eq_ignore_ascii_case("go") || package.is_empty() || pin.programs.is_empty() {
        return vec![(pinned.clone(), None)];
    }
    let root = repo_root(package);
    if pin
        .programs
        .iter()
        .any(|p| repo_root(&p.info.main.path) == root)
    {
        return vec![(pinned.clone(), None)];
    }
    let mut linked: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for p in &pin.programs {
        for d in p.info.deps.iter().filter(|d| d.path == package) {
            linked
                .entry(d.version.clone())
                .or_default()
                .insert(p.name.clone());
        }
    }
    linked
        .into_iter()
        .filter_map(|(v, progs)| {
            let parsed = Version::parse(&v)?;
            let progs: Vec<&str> = progs.iter().map(String::as_str).collect();
            Some((
                parsed,
                Some(format!("{package} {v} in {}", progs.join(", "))),
            ))
        })
        .collect()
}

/// A GitHub advisory's verdict on a pin.
enum Verdict {
    /// Where (None: the program itself) and the fixed versions.
    Affected {
        at: Option<String>,
        fixed: String,
    },
    NotAffected,
    Unread {
        ranges: Vec<String>,
    },
}

fn gh_verdict(a: &GhAdvisory, pin: &PinInput, pinned: &Version) -> Verdict {
    let mut unread = Vec::new();
    let mut read_any = false;
    for v in a.vulnerabilities.iter().flatten() {
        let range = v.vulnerable_version_range.clone().unwrap_or_default();
        let patched = v.patched_versions.clone().unwrap_or_default();
        let (eco, name) = v
            .package
            .as_ref()
            .map(|p| {
                (
                    p.ecosystem.clone().unwrap_or_default(),
                    p.name.clone().unwrap_or_default(),
                )
            })
            .unwrap_or_default();
        for (at, label) in gh_targets(pin, pinned, &eco, &name) {
            match version::in_range(&at, &range) {
                // A range with no upper bound that names its fix
                // (">= 1.29", patched 1.30.1): the fix ends it.
                Some(true) if Version::parse(&patched).is_some_and(|p| at >= p) => read_any = true,
                Some(true) => {
                    return Verdict::Affected {
                        at: label,
                        fixed: patched,
                    };
                }
                Some(false) => read_any = true,
                // A range that cannot be read but names one fixed version:
                // affected when older than the fix.
                None => match Version::parse(&patched) {
                    Some(p) if at < p => {
                        return Verdict::Affected {
                            at: label,
                            fixed: patched,
                        };
                    }
                    Some(_) => read_any = true,
                    None => unread.push(range.clone()),
                },
            }
        }
    }
    if unread.is_empty() || read_any {
        Verdict::NotAffected
    } else {
        Verdict::Unread { ranges: unread }
    }
}

/// merge adds f to found, or folds it into the finding that names the
/// same advisory (by ID or alias: OSV holds one advisory as a GO- and a
/// GHSA- record).
fn merge(found: &mut Vec<Finding>, f: Finding) {
    let same = found.iter_mut().find(|g| {
        g.names(&f.id) || f.aliases.iter().any(|a| g.names(a)) || f.aliases.contains(&g.id)
    });
    let Some(g) = same else {
        found.push(f);
        return;
    };
    g.aliases
        .extend(f.aliases.into_iter().filter(|a| !a.is_empty()));
    g.aliases.insert(f.id);
    let id = g.id.clone();
    g.aliases.remove(&id);
    for (what, a) in f.affects {
        match g.affects.get_mut(&what) {
            None => {
                g.affects.insert(what, a);
            }
            Some(b) => {
                b.packages.extend(a.packages);
                b.programs = match (b.programs.take(), a.programs) {
                    (Some(mut x), Some(y)) => {
                        x.extend(y);
                        Some(x)
                    }
                    _ => None,
                };
            }
        }
    }
    for x in f.fixed.split("; ").filter(|x| !x.is_empty()) {
        if !g.fixed.split("; ").any(|y| y == x) {
            if !g.fixed.is_empty() {
                g.fixed.push_str("; ");
            }
            g.fixed.push_str(x);
        }
    }
    if g.severity == "unrated" {
        g.severity = f.severity;
    }
    if g.summary.is_empty() {
        g.summary = f.summary;
    }
    g.own |= f.own;
}

/// Most severe first.
fn severity_rank(s: &str) -> u8 {
    match s.to_ascii_lowercase().as_str() {
        "critical" => 0,
        "high" => 1,
        "moderate" | "medium" => 2,
        "low" => 3,
        _ => 4,
    }
}

impl Finding {
    /// Whether the finding is the advisory id, under its ID or an alias.
    fn names(&self, id: &str) -> bool {
        self.id == id || self.aliases.contains(id)
    }
}

impl Report {
    /// build: the report from what was collected (no network).
    pub fn build(pins: &[PinInput], osv: &OsvAnswers) -> Report {
        let mut report = Report::default();
        for pin in pins {
            let pinned = Version::parse(&pin.version);
            let latest = latest_stable(&pin.releases);
            let update = match (&pinned, &latest) {
                (Some(p), Some((l, _))) => l > p,
                _ => false,
            };
            let all_programs: BTreeSet<&str> =
                pin.programs.iter().map(|p| p.name.as_str()).collect();
            let main_modules: BTreeSet<&str> = pin
                .programs
                .iter()
                .map(|p| p.info.main.path.as_str())
                .collect();
            let mut found: Vec<Finding> = Vec::new();
            for ((module, ver), programs) in osv_queries(pin) {
                for v in osv
                    .get(&(module.clone(), ver.clone()))
                    .into_iter()
                    .flatten()
                {
                    let own = main_modules.contains(module.as_str());
                    let what = if module == "stdlib" {
                        format!("Go standard library go{ver}")
                    } else {
                        format!("{module} {ver}")
                    };
                    let affect = Affect {
                        packages: if own {
                            BTreeSet::new()
                        } else {
                            osv_packages(v, &module).into_iter().collect()
                        },
                        // Named only when some of the artifact's Go
                        // programs are not affected.
                        programs: (programs.len() < all_programs.len()).then(|| programs.clone()),
                    };
                    let fixed = osv_fixed_version(v, &module, &ver);
                    let fixed = match (module.as_str(), fixed.is_empty()) {
                        (_, true) => String::new(),
                        ("stdlib", false) => format!("Go {fixed}"),
                        _ if own => fixed,
                        (_, false) => format!("{module} {fixed}"),
                    };
                    merge(
                        &mut found,
                        Finding {
                            artifact: pin.name.clone(),
                            id: v.id.clone(),
                            aliases: v.aliases.iter().filter(|a| **a != v.id).cloned().collect(),
                            severity: severity_of(v),
                            affects: [(what, affect)].into(),
                            fixed,
                            summary: v.summary.clone().unwrap_or_default(),
                            url: format!("https://osv.dev/vulnerability/{}", v.id),
                            own,
                        },
                    );
                }
            }
            if let Some(pinned) = &pinned {
                for a in pin.advisories.iter().filter(|a| a.withdrawn_at.is_none()) {
                    let mut finding = Finding {
                        artifact: pin.name.clone(),
                        id: a.ghsa_id.clone(),
                        aliases: a.cve_id.iter().cloned().collect(),
                        severity: a.severity.clone().unwrap_or_else(|| "unrated".into()),
                        affects: plain(format!("{} {}", pin.name, pin.version)),
                        fixed: String::new(),
                        summary: a.summary.clone(),
                        url: a.html_url.clone().unwrap_or_else(|| {
                            format!("https://github.com/advisories/{}", a.ghsa_id)
                        }),
                        own: true,
                    };
                    // Already found through OSV: GitHub's severity when
                    // OSV gives none, nothing else.
                    if let Some(f) = found.iter_mut().find(|f| f.names(&a.ghsa_id)) {
                        if f.severity == "unrated" {
                            f.severity = finding.severity;
                        }
                        continue;
                    }
                    match gh_verdict(a, pin, pinned) {
                        Verdict::Affected { at, fixed } => {
                            if let Some(at) = at {
                                finding.affects = plain(at);
                                finding.own = false;
                            }
                            finding.fixed = fixed;
                            merge(&mut found, finding);
                        }
                        Verdict::NotAffected => {}
                        Verdict::Unread { ranges } => {
                            finding.affects =
                                plain(format!("{} (range {:?})", pin.name, ranges.join("; ")));
                            report.unread.push(finding);
                        }
                    }
                }
            }
            found.sort_by(|a, b| {
                (!a.own, severity_rank(&a.severity), &a.id).cmp(&(
                    !b.own,
                    severity_rank(&b.severity),
                    &b.id,
                ))
            });
            report.rows.push(Row {
                name: pin.name.clone(),
                pinned: pin.version.clone(),
                latest: latest.map(|(_, s)| s),
                update,
                vulnerable: !found.is_empty(),
            });
            report.findings.extend(found);
        }
        report
    }

    /// exit_code: EXIT_VULNERABLE, EXIT_UPDATES, or EXIT_CURRENT.
    pub fn exit_code(&self) -> u8 {
        if !self.findings.is_empty() {
            EXIT_VULNERABLE
        } else if self.rows.iter().any(|r| r.update) {
            EXIT_UPDATES
        } else {
            EXIT_CURRENT
        }
    }

    /// render: the report as Markdown.
    pub fn render(&self) -> String {
        let mut s = String::new();
        s.push_str("# Runtime pack updates\n\n");
        s.push_str(
            "The programs `pack/lock.json` pins, against their projects' latest stable \
             releases and the advisories known for the pinned versions \
             (`armada-pack outdated`).\n\n",
        );
        s.push_str("| Program | Pinned | Latest | Status |\n| --- | --- | --- | --- |\n");
        for r in &self.rows {
            let mut status = Vec::new();
            if r.vulnerable {
                status.push("**vulnerable**");
            }
            match (&r.latest, r.update) {
                (None, _) => status.push("latest release unknown"),
                (Some(_), true) => status.push("update available"),
                (Some(_), false) if !r.vulnerable => status.push("current"),
                _ => {}
            }
            let _ = writeln!(
                s,
                "| {} | {} | {} | {} |",
                cell(&r.name),
                cell(&r.pinned),
                cell(r.latest.as_deref().unwrap_or("?")),
                status.join(", ")
            );
        }
        let (own, linked): (Vec<&Finding>, Vec<&Finding>) =
            self.findings.iter().partition(|f| f.own);
        s.push_str("\n## Advisories in the pinned programs\n\n");
        findings_table(&mut s, &own);
        s.push_str(
            "\n## Advisories in what the Go programs were built with\n\n\
             The Go modules they link and the Go standard library, from their build \
             information.\n\n",
        );
        findings_table(&mut s, &linked);
        if !self.unread.is_empty() {
            s.push_str(
                "\n<details><summary>Advisories whose version ranges could not be read \
                 (check by hand)</summary>\n\n",
            );
            for f in &self.unread {
                let _ = writeln!(
                    s,
                    "- {}: {} ({})",
                    advisory_cell(f),
                    cell(&f.summary),
                    cell(&f.affects_text().join("; "))
                );
            }
            s.push_str("\n</details>\n");
        }
        s.push_str(
            "\nGitHub's security advisories of each program's repository are checked for \
             every program; the Go programs (runc, the CNI plugins, etcd) also through OSV, \
             for their own module, every module their build information names, and the Go \
             standard library they were built with. An advisory in a module or in the \
             standard library may not reach code the program runs: read it before acting. \
             A fix in a module or in Go reaches the pack with an upstream release built \
             with it.\n",
        );
        s
    }
}

fn findings_table(s: &mut String, findings: &[&Finding]) {
    if findings.is_empty() {
        s.push_str("None known.\n");
        return;
    }
    s.push_str(
        "| Advisory | Severity | Program | Affects | Fixed in | Summary |\n\
         | --- | --- | --- | --- | --- | --- |\n",
    );
    for f in findings {
        let _ = writeln!(
            s,
            "| {} | {} | {} | {} | {} | {} |",
            advisory_cell(f),
            cell(&f.severity),
            cell(&f.artifact),
            cell(&f.affects_text().join("; ")),
            cell(if f.fixed.is_empty() { "?" } else { &f.fixed }),
            cell(&f.summary),
        );
    }
}

fn advisory_cell(f: &Finding) -> String {
    let mut s = format!("[{}]({})", cell(&f.id), f.url);
    let other: Vec<&str> = f
        .aliases
        .iter()
        .filter(|a| ["CVE-", "GHSA-", "GO-"].iter().any(|p| a.starts_with(p)))
        .map(String::as_str)
        .collect();
    if !other.is_empty() {
        let _ = write!(s, " ({})", cell(&other.join(", ")));
    }
    s
}

/// cell: text safe in a Markdown table cell.
fn cell(s: &str) -> String {
    s.replace(['\r', '\n'], " ")
        .replace('|', "\\|")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// The programs of an artifact for one architecture, by their names in
/// the pack (main.rs's artifact_files).
pub type Files<'a> = dyn Fn(&Artifact, &str) -> Result<BTreeMap<String, Vec<u8>>, String> + 'a;

/// collect: every artifact's releases, advisories, and Go programs.
pub fn collect(lock: &Lock, files: &Files, token: Option<&str>) -> Result<Vec<PinInput>, String> {
    let mut out = Vec::new();
    for a in &lock.artifacts {
        let repo = repo_of(&a.url);
        let (releases, advisories) = match &repo {
            Some(r) => (releases(r, token)?, advisories(r, token)?),
            None => (Vec::new(), Vec::new()),
        };
        let mut programs = Vec::new();
        for arch in ARCHES {
            for (name, b) in files(a, arch)? {
                let info = gomod::build_info(&b).map_err(|e| format!("{name} ({arch}): {e}"))?;
                if let Some(info) = info {
                    programs.push(GoProgram { name, info });
                }
            }
        }
        out.push(PinInput {
            name: a.name.clone(),
            version: a.version.clone(),
            repo,
            releases,
            advisories,
            programs,
        });
    }
    Ok(out)
}

fn releases(repo: &str, token: Option<&str>) -> Result<Vec<Release>, String> {
    http::request(
        &format!("{GITHUB_API}/repos/{repo}/releases?per_page=100"),
        Body::None,
        &GITHUB_HEADERS,
        token,
    )
}

fn advisories(repo: &str, token: Option<&str>) -> Result<Vec<GhAdvisory>, String> {
    let mut out = Vec::new();
    for page in 1..=10 {
        let got: Vec<GhAdvisory> = http::request(
            &format!(
                "{GITHUB_API}/repos/{repo}/security-advisories?state=published&per_page=100&page={page}"
            ),
            Body::None,
            &GITHUB_HEADERS,
            token,
        )?;
        let n = got.len();
        out.extend(got);
        if n < 100 {
            break;
        }
    }
    Ok(out)
}

#[derive(Deserialize)]
struct BatchAnswer {
    #[serde(default)]
    results: Vec<BatchResult>,
}

#[derive(Deserialize, Default)]
struct BatchResult {
    #[serde(default)]
    vulns: Vec<IdOnly>,
    #[serde(default)]
    next_page_token: Option<String>,
}

#[derive(Deserialize)]
struct IdOnly {
    id: String,
}

fn osv_query_json(q: &OsvQuery, page: Option<&str>) -> Value {
    let mut v = serde_json::json!({
        "package": {"name": q.0, "ecosystem": "Go"},
        "version": q.1,
    });
    if let Some(p) = page {
        v["page_token"] = Value::from(p);
    }
    v
}

/// osv: OSV's records for every query (querybatch for the IDs, then each
/// record once).
pub fn osv(queries: &BTreeSet<OsvQuery>) -> Result<OsvAnswers, String> {
    let queries: Vec<&OsvQuery> = queries.iter().collect();
    let mut ids: BTreeMap<OsvQuery, BTreeSet<String>> = BTreeMap::new();
    for chunk in queries.chunks(500) {
        let body = serde_json::json!({
            "queries": chunk.iter().map(|q| osv_query_json(q, None)).collect::<Vec<_>>(),
        })
        .to_string();
        let ans: BatchAnswer = http::request(
            &format!("{OSV_API}/querybatch"),
            Body::Json(&body),
            &[],
            None,
        )?;
        if ans.results.len() != chunk.len() {
            return Err(format!(
                "OSV answered {} results for {} queries",
                ans.results.len(),
                chunk.len()
            ));
        }
        for (q, mut r) in chunk.iter().zip(ans.results) {
            let set = ids.entry((*q).clone()).or_default();
            set.extend(r.vulns.drain(..).map(|v| v.id));
            let mut pages = 0;
            while let Some(token) = r.next_page_token.take().filter(|t| !t.is_empty()) {
                pages += 1;
                if pages > 20 {
                    return Err(format!("OSV: too many pages for {}@{}", q.0, q.1));
                }
                let body = osv_query_json(q, Some(&token)).to_string();
                r = http::request(&format!("{OSV_API}/query"), Body::Json(&body), &[], None)?;
                set.extend(r.vulns.drain(..).map(|v| v.id));
            }
        }
    }
    let mut records: BTreeMap<String, OsvVuln> = BTreeMap::new();
    for id in ids.values().flatten() {
        if records.contains_key(id) {
            continue;
        }
        if !id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.' | b':'))
        {
            return Err(format!("OSV: unexpected ID {id:?}"));
        }
        let v: OsvVuln = http::request(&format!("{OSV_API}/vulns/{id}"), Body::None, &[], None)?;
        records.insert(id.clone(), v);
    }
    Ok(ids
        .into_iter()
        .map(|(q, set)| {
            let vulns = set
                .iter()
                .filter_map(|id| records.get(id).cloned())
                .collect();
            (q, vulns)
        })
        .collect())
}

#[cfg(test)]
mod tests {
    //! The fixtures in testdata/outdated are answers GitHub's and OSV's
    //! APIs gave (2026-11-26), trimmed to the fields the report reads.
    use super::*;
    use crate::gomod::Dep;

    fn fixture<T: serde::de::DeserializeOwned>(name: &str) -> T {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("testdata/outdated")
            .join(name);
        serde_json::from_slice(&std::fs::read(&p).unwrap())
            .unwrap_or_else(|e| panic!("{}: {e}", p.display()))
    }

    fn dep(path: &str, version: &str) -> Dep {
        Dep {
            path: path.into(),
            version: version.into(),
            sum: String::new(),
        }
    }

    /// runc at version, built with go (as runc 1.5.2 was: go1.26.8).
    fn runc(version: &str, go: &str) -> PinInput {
        PinInput {
            name: "runc".into(),
            version: version.into(),
            repo: Some("opencontainers/runc".into()),
            releases: fixture("runc-releases.json"),
            advisories: fixture("runc-advisories.json"),
            programs: vec![GoProgram {
                name: "runc".into(),
                info: BuildInfo {
                    go: go.into(),
                    main: dep("github.com/opencontainers/runc", &format!("v{version}")),
                    deps: vec![
                        dep("github.com/moby/sys/user", "v0.4.0"),
                        dep("github.com/opencontainers/selinux", "v1.13.1"),
                    ],
                },
            }],
        }
    }

    fn crun(version: &str) -> PinInput {
        PinInput {
            name: "crun".into(),
            version: version.into(),
            repo: Some("containers/crun".into()),
            releases: fixture("crun-releases.json"),
            advisories: fixture("crun-advisories.json"),
            programs: Vec::new(),
        }
    }

    fn osv_answers() -> OsvAnswers {
        let stdlib: OsvVuln = fixture("osv-GO-2026-6859.json");
        let user_go: OsvVuln = fixture("osv-GO-2026-6686.json");
        let user_ghsa: OsvVuln = fixture("osv-GHSA-mjcv-p78q-w5fw.json");
        [
            (("stdlib".to_string(), "1.26.8".to_string()), vec![stdlib]),
            (
                ("github.com/moby/sys/user".to_string(), "v0.4.0".to_string()),
                vec![user_ghsa, user_go],
            ),
        ]
        .into()
    }

    #[test]
    fn repos_from_urls() {
        assert_eq!(
            repo_of("https://github.com/opencontainers/runc/releases/download/v1.5.2/runc.{arch}"),
            Some("opencontainers/runc".into())
        );
        assert_eq!(
            repo_of("https://raw.githubusercontent.com/containers/crun/1.31/flake.nix"),
            None
        );
        assert_eq!(repo_of("https://github.com/a/b/archive/x.tar.gz"), None);
        assert_eq!(repo_of("https://github.com/a/../releases/x"), None);
    }

    #[test]
    fn latest_skips_drafts_and_prereleases() {
        let r: Vec<Release> = fixture("runc-releases.json");
        assert_eq!(latest_stable(&r).map(|x| x.1), Some("1.5.3".into()));
        let r: Vec<Release> = fixture("crun-releases.json");
        assert_eq!(latest_stable(&r).map(|x| x.1), Some("1.31".into()));
        let only_pre = vec![
            Release {
                tag_name: "v1.6.0-rc.2".into(),
                draft: false,
                prerelease: false,
            },
            Release {
                tag_name: "v9.0.0".into(),
                draft: true,
                prerelease: false,
            },
            Release {
                tag_name: "v8.0.0".into(),
                draft: false,
                prerelease: true,
            },
        ];
        assert_eq!(latest_stable(&only_pre), None);
    }

    #[test]
    fn queries_cover_modules_and_stdlib() {
        let mut pin = runc("1.5.2", "go1.26.8");
        pin.programs[0].info.main.version = "(devel)".into();
        pin.programs[0]
            .info
            .deps
            .push(dep("github.com/opencontainers/runc/libct", "(devel)"));
        let q = osv_queries(&pin);
        let keys: Vec<(&str, &str)> = q.keys().map(|(a, b)| (a.as_str(), b.as_str())).collect();
        assert_eq!(
            keys,
            [
                ("github.com/moby/sys/user", "v0.4.0"),
                ("github.com/opencontainers/runc", "v1.5.2"),
                ("github.com/opencontainers/runc/libct", "v1.5.2"),
                ("github.com/opencontainers/selinux", "v1.13.1"),
                ("stdlib", "1.26.8"),
            ]
        );
    }

    #[test]
    fn vulnerable_pins_exit_2() {
        let r = Report::build(&[runc("1.5.2", "go1.26.8"), crun("1.31")], &osv_answers());
        assert_eq!(r.exit_code(), EXIT_VULNERABLE);
        let ids: Vec<(&str, bool)> = r.findings.iter().map(|f| (f.id.as_str(), f.own)).collect();
        // runc's own advisory first; the GO- and GHSA- records of one
        // advisory in a module are one finding; GHSA-cgrx-mc8f-2prm names
        // opencontainers/selinux <= 1.12.0, and runc links 1.13.1.
        assert_eq!(
            ids,
            [
                ("GHSA-g2c3-j8g3-7gpw", true),
                ("GHSA-mjcv-p78q-w5fw", false),
                ("GO-2026-6859", false),
            ]
        );
        let own = &r.findings[0];
        assert_eq!(
            (own.severity.as_str(), own.fixed.as_str()),
            ("high", "1.5.3")
        );
        let user = &r.findings[1];
        assert_eq!(user.severity, "moderate");
        assert!(user.aliases.contains("GO-2026-6686"));
        assert_eq!(user.fixed, "github.com/moby/sys/user 0.4.1");
        let go = &r.findings[2];
        assert_eq!(go.fixed, "Go 1.26.11");
        assert_eq!(
            go.affects_text()[0],
            "Go standard library go1.26.8 [net/http]"
        );
        assert!(r.rows[0].vulnerable && r.rows[0].update);
        // crun 1.31 is past every crun advisory, also GHSA-5f8q-v9f3-rhvj
        // (">= 1.29" with 1.30.1 patched).
        assert!(!r.rows[1].vulnerable && !r.rows[1].update);
        assert!(r.unread.is_empty());
    }

    #[test]
    fn an_older_crun_is_vulnerable() {
        let r = Report::build(&[crun("1.30")], &OsvAnswers::new());
        assert_eq!(r.exit_code(), EXIT_VULNERABLE);
        let ids: Vec<&str> = r.findings.iter().map(|f| f.id.as_str()).collect();
        assert_eq!(
            ids,
            [
                "GHSA-2mxx-58qc-p466",
                "GHSA-5f8q-v9f3-rhvj",
                "GHSA-jj7h-4c3m-j6wf"
            ]
        );
    }

    #[test]
    fn updates_only_exit_1() {
        let mut pin = runc("1.5.3", "go1.26.11");
        pin.programs[0].info.deps.clear();
        pin.releases.push(Release {
            tag_name: "v1.5.4".into(),
            draft: false,
            prerelease: false,
        });
        let r = Report::build(&[pin, crun("1.31")], &osv_answers());
        assert_eq!(r.exit_code(), EXIT_UPDATES, "{:?}", r.findings);
        assert_eq!(r.rows[0].latest.as_deref(), Some("1.5.4"));
    }

    #[test]
    fn current_and_clean_exit_0() {
        let mut pin = runc("1.5.3", "go1.26.11");
        pin.programs[0].info.deps.clear();
        let r = Report::build(&[pin, crun("1.31")], &osv_answers());
        assert_eq!(r.exit_code(), EXIT_CURRENT);
        let text = r.render();
        assert!(
            text.contains("| runc | 1.5.3 | 1.5.3 | current |"),
            "{text}"
        );
        assert_eq!(text.matches("None known.").count(), 2);
    }

    #[test]
    fn unreadable_ranges_are_listed_not_counted() {
        let mut c = crun("1.31");
        c.advisories = vec![GhAdvisory {
            ghsa_id: "GHSA-xxxx-yyyy-zzzz".into(),
            cve_id: None,
            severity: Some("low".into()),
            summary: "a | b\nc".into(),
            html_url: None,
            withdrawn_at: None,
            vulnerabilities: Some(vec![GhVulnerability {
                package: None,
                vulnerable_version_range: Some("libcrun only".into()),
                patched_versions: None,
            }]),
        }];
        let r = Report::build(&[c], &OsvAnswers::new());
        assert_eq!(r.exit_code(), EXIT_CURRENT);
        assert_eq!(r.unread.len(), 1);
        let text = r.render();
        assert!(text.contains("a \\| b c"), "{text}");
        assert!(text.contains("could not be read"));
    }

    #[test]
    fn one_advisory_in_two_records_is_one_finding() {
        let affect = |packages: &[&str], programs: Option<&[&str]>| Affect {
            packages: packages.iter().map(|p| p.to_string()).collect(),
            programs: programs.map(|p| p.iter().map(|p| p.to_string()).collect()),
        };
        let finding = |id: &str, alias: &str, a: Affect| Finding {
            artifact: "etcd".into(),
            id: id.into(),
            aliases: [alias.to_string()].into(),
            severity: "unrated".into(),
            affects: [("m v1.0.0".to_string(), a)].into(),
            fixed: "m 1.0.1".into(),
            summary: String::new(),
            url: String::new(),
            own: false,
        };
        let mut found = Vec::new();
        merge(
            &mut found,
            finding("GHSA-a", "GO-b", affect(&[], Some(&["etcd"]))),
        );
        merge(
            &mut found,
            finding("GO-b", "GHSA-a", affect(&["m/p"], Some(&["etcdutl"]))),
        );
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].affects_text(), ["m v1.0.0 [m/p] in etcd, etcdutl"]);
        assert_eq!(found[0].fixed, "m 1.0.1");
        assert_eq!(found[0].aliases, ["GO-b".to_string()].into());
        merge(&mut found, finding("GO-b", "", affect(&[], None)));
        assert_eq!(found[0].affects_text(), ["m v1.0.0 [m/p]"]);
    }

    #[test]
    fn withdrawn_advisories_are_left_out() {
        let mut pin = runc("1.5.2", "go1.26.11");
        pin.programs[0].info.deps.clear();
        for a in &mut pin.advisories {
            a.withdrawn_at = Some("2026-11-20T00:00:00Z".into());
        }
        let r = Report::build(&[pin], &OsvAnswers::new());
        assert_eq!(r.exit_code(), EXIT_UPDATES);
    }

    #[test]
    fn renders_the_report() {
        let r = Report::build(&[runc("1.5.2", "go1.26.8"), crun("1.31")], &osv_answers());
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/outdated/report.md");
        if std::env::var_os("ARMADA_PACK_UPDATE").is_some() {
            std::fs::write(&path, r.render()).unwrap();
        }
        assert_eq!(r.render(), std::fs::read_to_string(&path).unwrap());
    }
}
