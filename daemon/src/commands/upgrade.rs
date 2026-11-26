//! armadad upgrade: this machine moved to a release (Go's upgrade.go,
//! ADR 0030), with what ADR 0055 adds for server machines that run etcd
//! and the agent as units of their own:
//!
//! - On a server machine (armada-server enabled), the units the server
//!   wants are enabled when they are not yet (armada-etcd and
//!   armada-agent, new after the last Go release).
//! - Every active unit is restarted, in order: armada-runtime,
//!   armada-etcd, armada-server, armada-agent (Go's upgrader restarted the
//!   first of armada-server and armada-agent, since its server ran the
//!   agent).
//! - The one older release it installs is the last Go release
//!   (`LAST_GO_RELEASE`), as a rollback: armada-server (a leader hands
//!   over), armada-agent, and armada-etcd stopped, the units that release
//!   does not have disabled and removed (and armada-agent disabled on a
//!   server machine, whose Go server runs the agent itself), the release
//!   installed, and its service started. Every other older release is
//!   refused as before.

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

/// The last release of Go's armadad (ADR 0055): the one older release
/// `armadad upgrade --version` installs, rolling this machine back.
pub const LAST_GO_RELEASE: &str = "v0.1.0-alpha.42";
/// Where `systemctl enable` links the units (their WantedBy).
const WANTS_DIR: &str = "multi-user.target.wants";
/// The units a server machine runs beside armada-server, which wants them.
const BESIDE_SERVER: [&str; 2] = ["armada-etcd", "armada-agent"];

/// Whether unit is enabled in the unit directory (its WantedBy link).
fn enabled(unit_dir: &Path, unit: &str) -> bool {
    fs::symlink_metadata(unit_dir.join(WANTS_DIR).join(format!("{unit}.service"))).is_ok()
}

/// needrestart's settings (Go's needrestart.go).
pub const NEEDRESTART_DIR: &str = "/etc/needrestart/conf.d";
pub const NEEDRESTART_FILE: &str = "armada.conf";
pub const NEEDRESTART_CONF: &str = "# Written by Armada: needrestart lists Armada's services but never restarts\n# them; armadad upgrade restarts what it upgrades.\n$nrconf{override_rc}{qr(^armada-)} = 0;\n";

/// writeNeedrestart: the setting written into dir when needrestart is
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

/// os.WriteFile(name, b, perm).
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

/// exec.LookPath.
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

/// time.Duration.Round(100ms).String().
fn since(start: Instant) -> String {
    let ns = start.elapsed().as_nanos() as i64;
    let unit = 100_000_000;
    let r = ns % unit;
    let rounded = if r + r < unit { ns - r } else { ns + unit - r };
    armada_spec::go::format_duration(rounded)
}

/// sizeString.
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
        let rollback = release::newer(current, target);
        if rollback && target != LAST_GO_RELEASE {
            return Err(format!(
                "{target} is older than this {current}; going back takes the backup from before the upgrade (docs/operations.md#rolling-back-an-upgrade)"
            ));
        }
        if rollback {
            self.step(&format!(
                "Rolling this machine back from {current} to {target}, the last release before armadad moved to Rust\n"
            ));
        } else {
            self.step(&format!(
                "Upgrading this machine from {current} to {target}\n"
            ));
        }
        let tmp = crate::pack::temp_dir(&std::env::temp_dir(), "armada-upgrade-")?;
        let result = self.install(current, target, &tmp, rollback);
        let _ = fs::remove_dir_all(&tmp);
        result
    }

    fn install(
        &mut self,
        current: &str,
        target: &str,
        tmp: &Path,
        rollback: bool,
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
        if rollback {
            return self.roll_back(current, target, &files);
        }
        self.install_binaries(&files)?;
        self.install_units(&files)?;
        self.enable_beside_server()?;
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
            // carries; then the server, then the node's agent (ADR 0055).
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

    /// The unit directory, when the machine has one.
    fn units(&self) -> Option<PathBuf> {
        self.unit_dir
            .clone()
            .filter(|d| fs::metadata(d).is_ok_and(|m| m.is_dir()))
    }

    /// On a server machine (armada-server enabled), enables the units it
    /// wants that are not enabled yet: after the first upgrade from the
    /// last Go release, armada-etcd and armada-agent. armada-server wants
    /// them either way; enabling them says so to `systemctl list-unit-files`
    /// and keeps them when someone disables the server for a while.
    fn enable_beside_server(&mut self) -> std::result::Result<(), String> {
        let Some(dir) = self.units() else {
            return Ok(());
        };
        if !enabled(&dir, "armada-server") {
            return Ok(());
        }
        let new: Vec<&str> = BESIDE_SERVER
            .into_iter()
            .filter(|u| dir.join(format!("{u}.service")).is_file() && !enabled(&dir, u))
            .collect();
        if new.is_empty() {
            return Ok(());
        }
        let mut args = vec!["enable"];
        args.extend(&new);
        systemd::systemctl(&args)?;
        self.step(&format!(
            "  enable     {} (run beside armada-server on this server machine)\n",
            new.join(", ")
        ));
        Ok(())
    }

    /// The rollback to the last Go release (ADR 0055, "Rolling back"): the
    /// release is downloaded and verified; this machine's services stop,
    /// the units that release does not have go, and it is installed and
    /// started. Go's server embeds the same etcd member on the same data
    /// directory, and Go's agent adopts the containers.
    fn roll_back(
        &mut self,
        current: &str,
        target: &str,
        files: &[(String, PathBuf)],
    ) -> std::result::Result<(), String> {
        let dir = self.units();
        let server = dir.as_deref().is_some_and(|d| enabled(d, "armada-server"))
            || systemd::unit_active("armada-server");
        let agent = dir.as_deref().is_some_and(|d| enabled(d, "armada-agent"))
            || systemd::unit_active("armada-agent");
        let mut msg = format!("Rolled back to {target} (from {current})");
        // A leader resigns when its server stops, so another server leads
        // before the agent and the member stop.
        let mut stopped = Vec::new();
        for (unit, note) in [
            ("armada-server", " (a leader hands over)"),
            ("armada-agent", " (containers keep running)"),
            ("armada-etcd", ""),
        ] {
            if !systemd::unit_active(unit) {
                continue;
            }
            self.stop_unit(unit, note)?;
            stopped.push(unit);
        }
        if !stopped.is_empty() {
            msg.push_str(&format!("; stopped {}", stopped.join(", ")));
        }
        if let Some(dir) = &dir {
            let has = |unit: &str| files.iter().any(|(n, _)| *n == format!("{unit}.service"));
            // Go's server runs this machine's agent itself: two agents
            // would take turns on the data directory's lock.
            if server && has("armada-agent") && enabled(dir, "armada-agent") {
                systemd::systemctl(&["disable", "armada-agent"])?;
                self.step(&format!(
                    "  disable    armada-agent ({target}'s armada-server runs this machine's agent)\n"
                ));
                msg.push_str("; disabled armada-agent");
            }
            let mut gone = Vec::new();
            for unit in installed_units(dir)? {
                if has(&unit) {
                    continue;
                }
                systemd::systemctl(&["disable", &unit])?;
                let p = dir.join(format!("{unit}.service"));
                fs::remove_file(&p).map_err(|e| {
                    format!("remove {}: {}", p.display(), armada_fsutil::errno_text(&e))
                })?;
                self.step(&format!(
                    "  remove     {} ({target} has no such unit)\n",
                    p.display()
                ));
                gone.push(format!("{unit}.service"));
            }
            if !gone.is_empty() {
                msg.push_str(&format!("; removed {}", gone.join(", ")));
                if !files.iter().any(|(n, _)| n.ends_with(".service")) {
                    systemd::systemctl(&["daemon-reload"])?;
                }
            }
        }
        self.install_binaries(files)?;
        self.install_units(files)?;
        self.write_needrestart();
        let service = if server {
            "armada-server"
        } else if agent {
            "armada-agent"
        } else {
            ""
        };
        if !self.restart {
            if !service.is_empty() {
                self.step(&format!(
                    "  start      skipped (--no-restart): start {service} yourself\n"
                ));
            }
            self.step(&format!("{msg}.\n"));
            return Ok(());
        }
        if systemd::unit_active("armada-runtime") {
            self.restart_unit("armada-runtime", " (containers keep running)")
                .map_err(|e| {
                    format!("installed {target}, but restarting armada-runtime failed: {e}")
                })?;
            msg.push_str("; restarted armada-runtime");
        }
        if !service.is_empty() {
            self.start_unit(service)
                .map_err(|e| format!("installed {target}, but starting {service} failed: {e}"))?;
            msg.push_str(&format!("; started {service}"));
        }
        self.step(&format!("{msg}.\n"));
        Ok(())
    }

    fn stop_unit(&mut self, unit: &str, note: &str) -> std::result::Result<(), String> {
        self.step(&format!("  stop       {unit}{note} ... "));
        let start = Instant::now();
        if let Err(e) = systemd::systemctl(&["stop", unit]) {
            self.step("failed\n");
            return Err(e);
        }
        self.step(&format!("stopped after {}\n", since(start)));
        Ok(())
    }

    fn start_unit(&mut self, unit: &str) -> std::result::Result<(), String> {
        self.step(&format!("  start      {unit} ... "));
        let start = Instant::now();
        if let Err(e) = systemd::systemctl(&["start", unit]) {
            self.step("failed\n");
            return Err(e);
        }
        if !systemd::unit_active(unit) {
            self.step("not running\n");
            return Err(format!(
                "{unit} is not running after the start; see journalctl -u {unit}"
            ));
        }
        self.step(&format!("running after {}\n", since(start)));
        Ok(())
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

/// Armada's units in the unit directory (`armada-*.service` files), by
/// name, sorted.
fn installed_units(dir: &Path) -> std::result::Result<Vec<String>, String> {
    let entries = fs::read_dir(dir)
        .map_err(|e| format!("open {}: {}", dir.display(), armada_fsutil::errno_text(&e)))?;
    let mut out = Vec::new();
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let Some(unit) = name
            .strip_suffix(".service")
            .filter(|u| u.starts_with("armada-"))
        else {
            continue;
        };
        if e.file_type().is_ok_and(|t| t.is_file()) {
            out.push(unit.to_string());
        }
    }
    out.sort();
    Ok(out)
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

/// verifyChecksum.
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

/// extractRelease: the binaries and the systemd units, by name.
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
    // gzip.NewReader reads the header first.
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

/// installFile: dst replaced with src (changed by edit) atomically.
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
