//! armadad upgrade: this machine moved to a newer release (ADR 0030):
//! the release downloaded, its signature (when cosign is installed) and
//! checksum verified, armada and armadad and the systemd units installed,
//! and every active unit restarted in order: armada-runtime, armada-etcd,
//! armada-server, armada-agent. Older releases are refused.

use std::fs;
use std::io::{BufRead, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use armada_client::cli::{Ctx, Error, Result};
use armada_client::release;

use crate::{hooks, systemd};

const DEFAULT_DOWNLOAD_BASE: &str = "https://github.com/ryanbekhen/armada/releases/download";
const OIDC_ISSUER: &str = "https://token.actions.githubusercontent.com";
const MAX_DOWNLOAD: u64 = 512 << 20;
const INSTALLED_BINARY: &str = "/usr/local/bin/armadad";

/// needrestart's settings.
pub const NEEDRESTART_DIR: &str = "/etc/needrestart/conf.d";
pub const NEEDRESTART_FILE: &str = "armada.conf";
pub const NEEDRESTART_CONF: &str = "# Written by Armada: needrestart lists Armada's services but never restarts\n# them; armadad upgrade restarts what it upgrades.\n$nrconf{override_rc}{qr(^armada-)} = 0;\n";

/// The setting written into dir when needrestart is
/// installed and the file differs; whether it wrote.
pub fn write_needrestart(dir: &Path) -> std::result::Result<bool, String> {
    if !fs::metadata(dir).is_ok_and(|m| m.is_dir()) {
        return Ok(false);
    }
    let p = dir.join(NEEDRESTART_FILE);
    if fs::read(&p).is_ok_and(|b| b == NEEDRESTART_CONF.as_bytes()) {
        return Ok(false);
    }
    let tmp = dir.join(format!("{NEEDRESTART_FILE}.new"));
    write_file(&tmp, NEEDRESTART_CONF.as_bytes(), 0o644)?;
    if let Err(e) = fs::rename(&tmp, &p) {
        let _ = fs::remove_file(&tmp);
        return Err(format!(
            "rename {} {}: {}",
            tmp.display(),
            p.display(),
            armada_fsutil::errno_text(&e)
        ));
    }
    Ok(true)
}

/// b written to p, created with perm or truncated.
fn write_file(p: &Path, b: &[u8], perm: u32) -> std::result::Result<(), String> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(perm)
        .open(p)
        .map_err(|e| format!("open {}: {}", p.display(), armada_fsutil::errno_text(&e)))?;
    f.write_all(b)
        .map_err(|e| format!("write {}: {}", p.display(), armada_fsutil::errno_text(&e)))
}

/// What upgrade does to the machine.
struct Upgrader<'a> {
    base: String,
    bin_dir: PathBuf,
    unit_dir: Option<PathBuf>,
    needrestart: Option<PathBuf>,
    cosign: Option<PathBuf>,
    require_sig: bool,
    restart: bool,
    goarch: &'static str,
    out: &'a mut dyn Write,
    warn: &'a mut dyn Write,
}

fn goarch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        a => a,
    }
}

fn look_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let dir = if dir.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            dir
        };
        let p = dir.join(name);
        if fs::metadata(&p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0) {
            return Some(p);
        }
    }
    None
}

fn euid() -> u32 {
    if let Some(v) = hooks::get("EUID").and_then(|v| v.parse().ok()) {
        return v;
    }
    // SAFETY: geteuid cannot fail.
    unsafe { libc::geteuid() }
}

pub fn run(ctx: &mut Ctx<'_>, _: &[String]) -> Result {
    if euid() != 0 {
        return Err(Error::Msg("run it as root: sudo armadad upgrade".into()));
    }
    let bin_dir = match hooks::get("BIN_DIR") {
        Some(d) => PathBuf::from(d),
        None => {
            let exe = std::env::current_exe().map_err(|e| e.to_string())?;
            let exe = fs::canonicalize(&exe).map_err(|e| {
                format!("lstat {}: {}", exe.display(), armada_fsutil::errno_text(&e))
            })?;
            exe.parent().map(Path::to_path_buf).unwrap_or_default()
        }
    };
    let mut target = ctx.str("version");
    let require_sig = ctx.bool("require-signature")
        || std::env::var("ARMADA_REQUIRE_SIGNATURE").is_ok_and(|v| v == "1");
    let restart = !ctx.bool("no-restart");
    let mut base = std::env::var("ARMADA_DOWNLOAD_BASE").unwrap_or_default();
    if base.is_empty() {
        base = DEFAULT_DOWNLOAD_BASE.to_string();
    }
    let unit_dir = hooks::get("UNIT_DIR").unwrap_or_else(|| "/etc/systemd/system".into());
    let needrestart = hooks::get("NEEDRESTART_DIR").unwrap_or_else(|| NEEDRESTART_DIR.into());
    let current = hooks::get("VERSION")
        .unwrap_or_else(|| armada_client::commands::version::get().version.to_string());
    let mut u = Upgrader {
        base,
        bin_dir,
        unit_dir: (!unit_dir.is_empty()).then(|| PathBuf::from(unit_dir)),
        needrestart: (!needrestart.is_empty()).then(|| PathBuf::from(needrestart)),
        cosign: look_path("cosign"),
        require_sig,
        restart,
        goarch: goarch(),
        out: ctx.out,
        warn: ctx.err,
    };
    if target.is_empty() {
        u.step("Looking for the latest release ... ");
        match release::latest() {
            Ok(t) => target = t,
            Err(e) => {
                u.step("failed\n");
                return Err(Error::Msg(format!("{e}; pass --version")));
            }
        }
        u.step(&format!("{target}\n"));
    }
    u.run(&current, &target).map_err(Error::Msg)
}

/// The time since start, to a tenth of a second (`1.2s`).
fn since(start: Instant) -> String {
    let ns = start.elapsed().as_nanos() as i64;
    let unit = 100_000_000;
    let r = ns % unit;
    let rounded = if r + r < unit { ns - r } else { ns + unit - r };
    armada_spec::go::format_duration(rounded)
}

fn size_string(n: u64) -> String {
    if n >= 1 << 20 {
        format!("{:.1} MiB", n as f64 / (1u64 << 20) as f64)
    } else {
        format!("{:.1} KiB", n as f64 / 1024.0)
    }
}

impl Upgrader<'_> {
    /// stepf.
    fn step(&mut self, s: &str) {
        let _ = self.out.write_all(s.as_bytes());
        let _ = self.out.flush();
    }

    fn run(&mut self, current: &str, target: &str) -> std::result::Result<(), String> {
        if !release::is_release(target) {
            return Err(format!(
                "invalid version {} (want vX.Y.Z)",
                armada_spec::go::quote(target)
            ));
        }
        if target == current {
            self.step(&format!("Already at {current}.\n"));
            return Ok(());
        }
        if release::newer(current, target) {
            return Err(format!(
                "{target} is older than this {current}; going back takes the backup from before the upgrade (docs/operations.md#rolling-back-an-upgrade)"
            ));
        }
        self.step(&format!(
            "Upgrading this machine from {current} to {target}\n"
        ));
        let tmp = crate::pack::temp_dir(&std::env::temp_dir(), "armada-upgrade-")?;
        let result = self.install(current, target, &tmp);
        let _ = fs::remove_dir_all(&tmp);
        result
    }

    fn install(
        &mut self,
        current: &str,
        target: &str,
        tmp: &Path,
    ) -> std::result::Result<(), String> {
        let archive = format!(
            "armada_{}_linux_{}.tar.gz",
            target.trim_start_matches('v'),
            self.goarch
        );
        for name in [archive.as_str(), "checksums.txt"] {
            self.fetch(target, name, &tmp.join(name))?;
        }
        self.verify_signature(target, tmp)?;
        if let Err(e) = verify_checksum(&tmp.join("checksums.txt"), &tmp.join(&archive), &archive) {
            self.step("  checksum   FAILED\n");
            return Err(e);
        }
        self.step("  checksum   OK (SHA-256 matches checksums.txt)\n");
        let files = extract_release(&tmp.join(&archive), &tmp.join("x"))?;
        for bin in ["armadad", "armada"] {
            if !files.iter().any(|(k, _)| k == bin) {
                return Err(format!("the release has no {bin}"));
            }
        }
        self.install_binaries(&files)?;
        self.install_units(&files)?;
        self.write_needrestart();
        let mut msg = format!("Upgraded to {target} (from {current})");
        if self.restart {
            if systemd::unit_active("armada-runtime") {
                self.restart_unit("armada-runtime", " (containers keep running)")
                    .map_err(|e| {
                        format!("installed {target}, but restarting armada-runtime failed: {e}")
                    })?;
                msg.push_str("; restarted armada-runtime");
            }
            // The member first, so the server reaches the etcd this armadad
            // carries; then the server, then the node's agent.
            for unit in ["armada-etcd", "armada-server", "armada-agent"] {
                if !systemd::unit_active(unit) {
                    continue;
                }
                self.restart_unit(unit, "").map_err(|e| {
                    format!("installed {target}, but restarting {unit} failed: {e}")
                })?;
                msg.push_str(&format!("; restarted {unit}"));
            }
        } else {
            self.step("  restart    skipped (--no-restart): restart armada-runtime and armada-server or armada-agent yourself\n");
        }
        self.step(&format!("{msg}.\n"));
        Ok(())
    }

    fn fetch(&mut self, tag: &str, name: &str, dst: &Path) -> std::result::Result<(), String> {
        self.step(&format!("  download   {name} ... "));
        let start = Instant::now();
        match self.download(tag, name, dst) {
            Ok(n) => {
                self.step(&format!("{} in {}\n", size_string(n), since(start)));
                Ok(())
            }
            Err(e) => {
                self.step("failed\n");
                Err(e)
            }
        }
    }

    fn download(&mut self, tag: &str, name: &str, dst: &Path) -> std::result::Result<u64, String> {
        let src = format!("{}/{tag}/{name}", self.base);
        let scheme = src.split_once("://").map(|(s, _)| s.to_ascii_lowercase());
        let mut f = fs::OpenOptions::new();
        f.write(true).create_new(true).mode(0o600);
        let open = |f: &mut fs::OpenOptions| {
            f.open(dst)
                .map_err(|e| format!("open {}: {}", dst.display(), armada_fsutil::errno_text(&e)))
        };
        let n = match scheme.as_deref() {
            Some("file") => {
                let path = file_url_path(&src);
                let mut body = fs::File::open(&path).map_err(|e| {
                    format!(
                        "download {name}: open {path}: {}",
                        armada_fsutil::errno_text(&e)
                    )
                })?;
                let mut out = open(&mut f)?;
                std::io::copy(&mut (&mut body).take(MAX_DOWNLOAD + 1), &mut out)
                    .map_err(|e| format!("download {name}: {e}"))?
            }
            Some("https") => {
                let mut out = open(&mut f)?;
                crate::download::https_get(
                    &src,
                    &mut out,
                    MAX_DOWNLOAD + 1,
                    Duration::from_secs(600),
                )
                .map_err(|e| format!("download {name}: {e}"))?
            }
            _ => {
                return Err(format!(
                    "download base {}: want https:// or file://",
                    armada_spec::go::quote(&self.base)
                ));
            }
        };
        if n > MAX_DOWNLOAD {
            return Err(format!("download {name}: too large"));
        }
        Ok(n)
    }

    fn verify_signature(&mut self, tag: &str, dir: &Path) -> std::result::Result<(), String> {
        let Some(cosign) = self.cosign.clone() else {
            if self.require_sig {
                return Err("cosign is not installed and a signature is required".to_string());
            }
            let _ = writeln!(
                self.warn,
                "warning: cosign not found: checking the checksum only"
            );
            self.step("  signature  not checked: cosign is not installed\n");
            return Ok(());
        };
        let bundle = dir.join("checksums.txt.sigstore.json");
        self.fetch(tag, "checksums.txt.sigstore.json", &bundle)?;
        let identity = format!(
            "https://github.com/{}/.github/workflows/release.yml@refs/tags/{tag}",
            release::REPO
        );
        let out = std::process::Command::new(&cosign)
            .arg("verify-blob")
            .arg("--bundle")
            .arg(&bundle)
            .args(["--certificate-identity", &identity])
            .args(["--certificate-oidc-issuer", OIDC_ISSUER])
            .arg(dir.join("checksums.txt"))
            .stdin(std::process::Stdio::null())
            .output();
        let failed = match out {
            Ok(o) if o.status.success() => None,
            Ok(o) => {
                let mut t = o.stdout;
                t.extend_from_slice(&o.stderr);
                Some(String::from_utf8_lossy(&t).trim().to_string())
            }
            Err(_) => Some(String::new()),
        };
        if let Some(text) = failed {
            self.step("  signature  FAILED\n");
            return Err(format!(
                "signature verification of checksums.txt FAILED; not installing: {text}"
            ));
        }
        self.step(&format!(
            "  signature  verified with cosign (release workflow of {}, tag {tag})\n",
            release::REPO
        ));
        Ok(())
    }

    /// Everything is verified: armada, then armadad. Each is its own file;
    /// the rename replaces a link an earlier release left as armada.
    fn install_binaries(&mut self, files: &[(String, PathBuf)]) -> std::result::Result<(), String> {
        for bin in ["armada", "armadad"] {
            let Some((_, src)) = files.iter().find(|(n, _)| n == bin) else {
                return Err(format!("the release has no {bin}"));
            };
            let dst = self.bin_dir.join(bin);
            install_file(src, &dst, 0o755, None)?;
            self.step(&format!("  install    {}\n", dst.display()));
        }
        Ok(())
    }

    /// needrestart told to leave Armada's services alone; a failure warns.
    fn write_needrestart(&mut self) {
        if let Some(dir) = self.needrestart.clone()
            && let Err(e) = write_needrestart(&dir)
        {
            let _ = writeln!(
                self.warn,
                "warning: needrestart may restart Armada's services after package upgrades: {e}"
            );
        }
    }

    fn install_units(&mut self, files: &[(String, PathBuf)]) -> std::result::Result<(), String> {
        let Some(unit_dir) = self.unit_dir.clone() else {
            return Ok(());
        };
        if !fs::metadata(&unit_dir).is_ok_and(|m| m.is_dir()) {
            return Ok(());
        }
        let mut units = Vec::new();
        let armadad = self.bin_dir.join("armadad").to_string_lossy().into_owned();
        for (key, src) in files {
            if !key.ends_with(".service") {
                continue;
            }
            let edit = |b: Vec<u8>| -> Vec<u8> {
                String::from_utf8_lossy(&b)
                    .replace(INSTALLED_BINARY, &armadad)
                    .into_bytes()
            };
            install_file(src, &unit_dir.join(key), 0o644, Some(&edit))?;
            units.push(key.clone());
        }
        if units.is_empty() {
            return Ok(());
        }
        systemd::systemctl(&["daemon-reload"])?;
        units.sort();
        self.step(&format!(
            "  install    systemd units {} (daemon reloaded)\n",
            units.join(", ")
        ));
        Ok(())
    }

    fn restart_unit(&mut self, unit: &str, note: &str) -> std::result::Result<(), String> {
        self.step(&format!("  restart    {unit}{note} ... "));
        let start = Instant::now();
        if let Err(e) = systemd::systemctl(&["restart", unit]) {
            self.step("failed\n");
            return Err(e);
        }
        if !systemd::unit_active(unit) {
            self.step("not running\n");
            return Err(format!(
                "{unit} is not running after the restart; see journalctl -u {unit}"
            ));
        }
        self.step(&format!("running again after {}\n", since(start)));
        Ok(())
    }
}

/// The path of a file:// URL, as url.Parse gives it.
fn file_url_path(u: &str) -> String {
    let rest = &u[u.find("://").map_or(0, |i| i + 3)..];
    let path = match rest.find('/') {
        Some(i) => &rest[i..],
        None => "",
    };
    let path = path.split(['?', '#']).next().unwrap_or("");
    percent_decode(path)
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16)
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn verify_checksum(sums: &Path, file: &Path, name: &str) -> std::result::Result<(), String> {
    let f = fs::File::open(sums)
        .map_err(|e| format!("open {}: {}", sums.display(), armada_fsutil::errno_text(&e)))?;
    let mut want = String::new();
    for line in std::io::BufReader::new(f).lines() {
        let line = line.map_err(|e| e.to_string())?;
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() == 2 && fields[1].trim_start_matches('*') == name {
            want = fields[0].to_string();
        }
    }
    if want.is_empty() {
        return Err(format!("{name} is not listed in checksums.txt"));
    }
    let mut a = fs::File::open(file)
        .map_err(|e| format!("open {}: {}", file.display(), armada_fsutil::errno_text(&e)))?;
    if crate::pack::sha256_reader(&mut a).map_err(|e| e.to_string())? != want.to_lowercase() {
        return Err(format!("checksum mismatch for {name}; not installing"));
    }
    Ok(())
}

/// The binaries and the systemd units, by name.
fn extract_release(
    archive: &Path,
    dir: &Path,
) -> std::result::Result<Vec<(String, PathBuf)>, String> {
    let mut f = fs::File::open(archive).map_err(|e| {
        format!(
            "open {}: {}",
            archive.display(),
            armada_fsutil::errno_text(&e)
        )
    })?;
    // The gzip header is read first.
    let mut head = Vec::new();
    (&mut f)
        .take(10)
        .read_to_end(&mut head)
        .map_err(|e| format!("release archive: {e}"))?;
    if let Some(e) = gzip_header_error(&head) {
        return Err(format!("release archive: {e}"));
    }
    let gz = flate2::read::MultiGzDecoder::new(std::io::BufReader::new(
        std::io::Cursor::new(head).chain(f),
    ));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(dir)
        .map_err(|e| format!("mkdir {}: {}", dir.display(), armada_fsutil::errno_text(&e)))?;
    use std::os::unix::fs::DirBuilderExt;
    let mut tr = crate::tar::Reader::new(gz);
    let mut files: Vec<(String, PathBuf)> = Vec::new();
    loop {
        let h = match tr.next_entry() {
            Ok(Some(h)) => h,
            Ok(None) => break,
            Err(e) => return Err(format!("release archive: {e}")),
        };
        let name = crate::gopath::clean(&h.name);
        let name = name.strip_prefix("./").unwrap_or(&name).to_string();
        let key = if !h.is_regular() {
            continue;
        } else if name == "armadad" || name == "armada" {
            name.clone()
        } else if let Some(rest) = name.strip_prefix("deploy/systemd/")
            && name.starts_with("deploy/systemd/armada-")
            && name.ends_with(".service")
            && !rest.contains('/')
        {
            rest.to_string()
        } else {
            continue;
        };
        if h.size > MAX_DOWNLOAD {
            return Err(format!("release archive: {name} is too large"));
        }
        let dst = dir.join(&key);
        let mut out = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&dst)
            .map_err(|e| format!("open {}: {}", dst.display(), armada_fsutil::errno_text(&e)))?;
        std::io::copy(&mut tr.data().take(h.size), &mut out).map_err(|e| e.to_string())?;
        files.push((key, dst));
    }
    Ok(files)
}

/// What gzip.NewReader says about a header it cannot read.
pub fn gzip_header_error(head: &[u8]) -> Option<&'static str> {
    if head.len() < 10 {
        return Some("unexpected EOF");
    }
    if head[0] != 0x1f || head[1] != 0x8b || head[2] != 8 {
        return Some("gzip: invalid header");
    }
    None
}

/// dst replaced with src (changed by edit) atomically.
fn install_file(
    src: &Path,
    dst: &Path,
    mode: u32,
    edit: Option<&dyn Fn(Vec<u8>) -> Vec<u8>>,
) -> std::result::Result<(), String> {
    let mut b = fs::read(src)
        .map_err(|e| format!("open {}: {}", src.display(), armada_fsutil::errno_text(&e)))?;
    if let Some(edit) = edit {
        b = edit(b);
    }
    let tmp = PathBuf::from(format!("{}.new", dst.display()));
    write_file(&tmp, &b, mode)?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))
        .map_err(|e| format!("chmod {}: {}", tmp.display(), armada_fsutil::errno_text(&e)))?;
    fs::rename(&tmp, dst).map_err(|e| {
        format!(
            "rename {} {}: {}",
            tmp.display(),
            dst.display(),
            armada_fsutil::errno_text(&e)
        )
    })
}
