//! armada-pack: builds the runtime pack and what releases carry with it
//! from the pins in pack/lock.json (lib.rs). Run from the repository's
//! root (`make runtime-bundle`, `make runtime-licenses`, `make proto`,
//! scripts/etcd-cache.sh):
//!
//!     armada-pack bundle --arch amd64 --logger F --shim F --dns F --node F [--out F]
//!     armada-pack extract --arch amd64 --artifact etcd --out DIR
//!     armada-pack licenses --out DIR
//!     armada-pack sources --out DIR
//!     armada-pack etcd-api --out DIR
//!     armada-pack outdated

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use armada_pack::lock::{ARCHES, Artifact, LOCK_PATH, Lock};
use armada_pack::{elf, fetch, gomod, outdated, pack, untar};

const USAGE: &str = "usage:
  armada-pack bundle --arch amd64|arm64 --logger FILE --shim FILE --dns FILE --node FILE [--out FILE]
  armada-pack extract --arch amd64|arm64 --artifact NAME --out DIR
  armada-pack licenses --out DIR
  armada-pack sources --out DIR
  armada-pack etcd-api --out DIR
  armada-pack outdated   (exit 0: current, 1: updates, 2: a pin is vulnerable, 3: the check failed)
flags of every command: --lock FILE (default pack/lock.json), --cache DIR (default .cache)";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("outdated") {
        return match Flags::parse(&args[1..], &[]).and_then(|f| check_outdated(&f)) {
            Ok(code) => ExitCode::from(code),
            Err(e) => {
                eprintln!("armada-pack: {e}");
                ExitCode::from(outdated::EXIT_ERROR)
            }
        };
    }
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("armada-pack: {e}");
            ExitCode::FAILURE
        }
    }
}

struct Flags(BTreeMap<String, String>);

impl Flags {
    fn parse(args: &[String], known: &[&str]) -> Result<Flags, String> {
        let mut m = BTreeMap::new();
        let mut it = args.iter();
        while let Some(a) = it.next() {
            let name = a
                .strip_prefix("--")
                .or_else(|| a.strip_prefix('-'))
                .ok_or_else(|| format!("unexpected argument {a:?}\n{USAGE}"))?;
            let (name, value) = match name.split_once('=') {
                Some((n, v)) => (n.to_string(), v.to_string()),
                None => (
                    name.to_string(),
                    it.next()
                        .ok_or_else(|| format!("flag needs an argument: -{name}"))?
                        .clone(),
                ),
            };
            if !known.contains(&name.as_str()) && name != "lock" && name != "cache" {
                return Err(format!("flag provided but not defined: -{name}\n{USAGE}"));
            }
            m.insert(name, value);
        }
        Ok(Flags(m))
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.0
            .get(name)
            .map(String::as_str)
            .filter(|v| !v.is_empty())
    }

    fn need(&self, name: &str, hint: &str) -> Result<&str, String> {
        self.get(name)
            .ok_or_else(|| format!("--{name} is required{hint}"))
    }

    fn lock(&self) -> Result<Lock, String> {
        Lock::load(Path::new(self.get("lock").unwrap_or(LOCK_PATH)))
    }

    fn cache(&self) -> PathBuf {
        PathBuf::from(self.get("cache").unwrap_or(".cache"))
    }

    fn arch(&self) -> Result<&str, String> {
        let a = self.need("arch", "")?;
        if !ARCHES.contains(&a) {
            return Err(format!("unsupported architecture {a:?}"));
        }
        Ok(a)
    }
}

fn run(args: &[String]) -> Result<(), String> {
    let Some((cmd, rest)) = args.split_first() else {
        return Err(USAGE.into());
    };
    match cmd.as_str() {
        "bundle" => bundle(&Flags::parse(
            rest,
            &["arch", "out", "logger", "shim", "dns", "node"],
        )?),
        "extract" => extract(&Flags::parse(rest, &["arch", "artifact", "out"])?),
        "licenses" => licenses(&Flags::parse(rest, &["out"])?),
        "sources" => sources(&Flags::parse(rest, &["out"])?),
        "etcd-api" => etcd_api(&Flags::parse(rest, &["out"])?),
        "-h" | "--help" | "help" => {
            println!("{USAGE}");
            Ok(())
        }
        c => Err(format!("unknown command {c:?}\n{USAGE}")),
    }
}

/// outdated: the pins against their latest releases and the advisories
/// known for them, as a Markdown report on stdout; the exit code says
/// what it found (outdated::EXIT_*). GITHUB_TOKEN, when set, is used for
/// GitHub's API (a higher rate limit); OSV's API needs none.
fn check_outdated(f: &Flags) -> Result<u8, String> {
    let lock = f.lock()?;
    let cache = f.cache();
    let token = std::env::var("GITHUB_TOKEN").ok().filter(|t| !t.is_empty());
    let files = |a: &Artifact, arch: &str| artifact_files(a, arch, &cache);
    let pins = outdated::collect(&lock, &files, token.as_deref())?;
    let queries = pins
        .iter()
        .flat_map(|p| outdated::osv_queries(p).into_keys())
        .collect();
    let osv = outdated::osv(&queries)?;
    let report = outdated::Report::build(&pins, &osv);
    print!("{}", report.render());
    let code = report.exit_code();
    eprintln!(
        "armada-pack outdated: {} pins, {} with a newer release, {} advisories affecting them (exit {code})",
        report.rows.len(),
        report.rows.iter().filter(|r| r.update).count(),
        report.findings.len()
    );
    Ok(code)
}

/// files: an artifact's files for arch, by their names in the pack.
fn artifact_files(
    a: &Artifact,
    arch: &str,
    cache: &Path,
) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let want = a
        .sha256
        .get(arch)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("{}: no checksum for {arch}", a.name))?;
    let b = fetch::fetch(&a.url_for(arch), want, &cache.join("runtime"))
        .map_err(|e| format!("{}: {e}", a.name))?;
    if a.files.is_empty() {
        return Ok([(a.name.clone(), b)].into());
    }
    untar::members(&b, &a.files_for(arch), fetch::MAX_DOWNLOAD)
        .map_err(|e| format!("{}: {e}", a.name))
}

/// bundle: Go's mkbundle. Armada's own programs first (each checked to be
/// an ELF program for arch), then every pinned artifact.
fn bundle(f: &Flags) -> Result<(), String> {
    let arch = f.arch()?;
    let lock = f.lock()?;
    let cache = f.cache();
    let out = f
        .get("out")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(format!("build/pack/linux_{arch}.pack")));
    let mut files = BTreeMap::new();
    let mut versions = BTreeMap::new();
    for (flag, name, make) in [
        ("logger", "armada-log", "make logger"),
        ("shim", "armada-shim", "make shim"),
        ("dns", "armada-dns", "make dns"),
        ("node", "armada-node", "make node"),
    ] {
        let path = f.need(flag, &format!(": build it with {make}"))?;
        let b = std::fs::read(path).map_err(|e| format!("{flag}: {path}: {e}"))?;
        elf::check(&b, arch).map_err(|e| format!("{flag} {path}: {e}"))?;
        files.insert(name.to_string(), b);
        versions.insert(name.to_string(), "source".to_string());
    }
    for a in &lock.artifacts {
        let got = artifact_files(a, arch, &cache)?;
        versions.insert(a.name.clone(), a.version.clone());
        files.extend(got);
    }
    if files.len() > pack::MAX_PACK_FILES {
        return Err(format!(
            "{} files, a pack holds at most {}",
            files.len(),
            pack::MAX_PACK_FILES
        ));
    }
    for (n, b) in &files {
        if b.len() as u64 > pack::MAX_FILE_SIZE {
            return Err(format!("{n}: larger than {} bytes", pack::MAX_FILE_SIZE));
        }
    }
    let p = pack::pack(arch, &versions, &files)?;
    if let Some(dir) = out.parent()
        && !dir.as_os_str().is_empty()
    {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    std::fs::write(&out, &p).map_err(|e| format!("{}: {e}", out.display()))?;
    println!(
        "{}: {} files, {:.1} MB, sha256 {}",
        out.display(),
        files.len(),
        p.len() as f64 / (1 << 20) as f64,
        &fetch::sum_hex(&p)[..16]
    );
    Ok(())
}

/// extract: one artifact's files for arch into a directory, executable.
fn extract(f: &Flags) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let arch = f.arch()?;
    let lock = f.lock()?;
    let name = f.need("artifact", "")?;
    let a = lock
        .artifact(name)
        .ok_or_else(|| format!("{LOCK_PATH} pins no {name}"))?;
    let out = PathBuf::from(f.need("out", "")?);
    for (n, b) in artifact_files(a, arch, &f.cache())? {
        let to = out.join(&n);
        if let Some(p) = to.parent() {
            std::fs::create_dir_all(p).map_err(|e| format!("{}: {e}", p.display()))?;
        }
        let tmp = to.with_extension("part");
        std::fs::write(&tmp, &b).map_err(|e| format!("{}: {e}", tmp.display()))?;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("{}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, &to).map_err(|e| format!("{}: {e}", to.display()))?;
    }
    println!("{name} {} for {arch} in {}", a.version, out.display());
    Ok(())
}

/// licenses: the license files of every Go module the programs of the
/// artifacts marked moduleLicenses link, for both architectures, into
/// DIR/<module>@<version>/, with MODULES.txt listing each module and the
/// programs that link it. Each module zip is checked against the h1 hash
/// the program records; modules of the program's own repository
/// ("(devel)") are covered by its row in THIRD_PARTY_NOTICES.md.
fn licenses(f: &Flags) -> Result<(), String> {
    let lock = f.lock()?;
    let cache = f.cache();
    let out = PathBuf::from(f.need("out", "")?);
    let mut modules: BTreeMap<(String, String), (String, BTreeSet<String>)> = BTreeMap::new();
    for a in lock.artifacts.iter().filter(|a| a.module_licenses) {
        for arch in ARCHES {
            for (name, b) in artifact_files(a, arch, &cache)? {
                let deps = gomod::deps(&b)
                    .map_err(|e| format!("{name}: {e}"))?
                    .ok_or_else(|| format!("{name} ({arch}) is not a Go program"))?;
                for d in deps {
                    if d.version == "(devel)" {
                        continue;
                    }
                    if d.sum.is_empty() {
                        return Err(format!(
                            "{name} records no h1 hash for {}@{}",
                            d.path, d.version
                        ));
                    }
                    let e = modules
                        .entry((d.path.clone(), d.version.clone()))
                        .or_insert_with(|| (d.sum.clone(), BTreeSet::new()));
                    if e.0 != d.sum {
                        return Err(format!(
                            "{}@{}: two hashes ({} and {})",
                            d.path, d.version, e.0, d.sum
                        ));
                    }
                    e.1.insert(name.clone());
                }
            }
        }
    }
    let _ = std::fs::remove_dir_all(&out);
    let mut index = String::new();
    let mut missing = Vec::new();
    for ((path, version), (sum, programs)) in &modules {
        let z = gomod::module_zip(path, version, sum, &cache.join("gomod"))?;
        let found = gomod::license_files(&z, path, version);
        if found.is_empty() {
            missing.push(format!("{path}@{version}"));
            continue;
        }
        let dir = out.join(format!("{path}@{version}"));
        std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        for (n, b) in found {
            std::fs::write(dir.join(&n), b).map_err(|e| format!("{}/{n}: {e}", dir.display()))?;
        }
        let programs: Vec<&str> = programs.iter().map(String::as_str).collect();
        index.push_str(&format!("{path} {version} ({})\n", programs.join(", ")));
    }
    if !missing.is_empty() {
        return Err(format!(
            "no license file at the root of {}",
            missing.join(", ")
        ));
    }
    std::fs::write(out.join("MODULES.txt"), index).map_err(|e| e.to_string())?;
    let programs = source_licenses(&lock, &cache, &out)?;
    println!(
        "{}: license files of {} Go modules, and license texts from the sources of {programs} pinned programs",
        out.display(),
        modules.len()
    );
    Ok(())
}

/// The license files the sources of the artifacts that ship them name
/// (crun's, ADR 0056), each source checked against its pin, into
/// DIR/<name>@<version>/; how many artifacts had any.
fn source_licenses(lock: &Lock, cache: &Path, out: &Path) -> Result<usize, String> {
    let mut n = 0;
    for a in &lock.artifacts {
        let mut found = 0;
        for src in a.sources.iter().filter(|s| !s.licenses.is_empty()) {
            let b = fetch::fetch(&src.url, &src.sha256, &cache.join("sources"))
                .map_err(|e| format!("{} source {}: {e}", a.name, src.file))?;
            let files = untar::members(&b, &src.licenses, fetch::MAX_DOWNLOAD)
                .map_err(|e| format!("{} source {}: {e}", a.name, src.file))?;
            let dir = out.join(a.license_dir());
            std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
            for (name, body) in files {
                pack::check_name(&name)?;
                std::fs::write(dir.join(&name), body)
                    .map_err(|e| format!("{}/{name}: {e}", dir.display()))?;
                found += 1;
            }
        }
        if found > 0 {
            n += 1;
        }
    }
    Ok(n)
}

/// sources: the complete corresponding source of every artifact that
/// names one (crun's, ADR 0056: its release tarball and the build files
/// its static programs are built with), each file checked against its
/// pin, into DIR/<name>-<version>/, with SOURCES.txt naming each file,
/// where it came from, and its SHA-256. Release archives carry them.
fn sources(f: &Flags) -> Result<(), String> {
    let lock = f.lock()?;
    let cache = f.cache();
    let out = PathBuf::from(f.need("out", "")?);
    let _ = std::fs::remove_dir_all(&out);
    std::fs::create_dir_all(&out).map_err(|e| format!("{}: {e}", out.display()))?;
    let mut index = String::new();
    let mut files = 0;
    for a in &lock.artifacts {
        for src in &a.sources {
            pack::check_name(&src.file).map_err(|e| format!("{}: {e}", a.name))?;
            let b = fetch::fetch(&src.url, &src.sha256, &cache.join("sources"))
                .map_err(|e| format!("{} source {}: {e}", a.name, src.file))?;
            let rel = format!("{}/{}", a.source_dir(), src.file);
            let to = out.join(&rel);
            if let Some(p) = to.parent() {
                std::fs::create_dir_all(p).map_err(|e| format!("{}: {e}", p.display()))?;
            }
            std::fs::write(&to, &b).map_err(|e| format!("{}: {e}", to.display()))?;
            index.push_str(&format!("{rel} {} {}\n", src.sha256, src.url));
            files += 1;
        }
    }
    std::fs::write(out.join("SOURCES.txt"), index).map_err(|e| e.to_string())?;
    println!("{}: {files} source files", out.display());
    Ok(())
}

/// etcd-api: etcd's API module at the pinned etcd's version, checked
/// against its pinned h1 hash, under DIR; prints its directory.
fn etcd_api(f: &Flags) -> Result<(), String> {
    let lock = f.lock()?;
    let a = lock
        .artifacts
        .iter()
        .find(|a| a.api_module.is_some())
        .ok_or_else(|| format!("{LOCK_PATH} pins no apiModule"))?;
    let m = a.api_module.as_ref().expect("api module");
    let version = format!("v{}", a.version);
    let z = gomod::module_zip(&m.path, &version, &m.h1, &f.cache().join("gomod"))?;
    let out = PathBuf::from(f.need("out", "")?);
    let dir = out.join(format!("{}@{version}", m.path));
    let _ = std::fs::remove_dir_all(&dir);
    let dir = gomod::extract(&z, &m.path, &version, &out)?;
    println!("{}", dir.display());
    Ok(())
}
