//! armadad backup, backup list, and restore: an archive of the control
//! plane, the control plane's
//! backups in its bucket (ADR 0051), and a restore from either.

use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::Arc;

use armada_client::cli::tabwriter::TabWriter;
use armada_client::cli::{Ctx, Error, Result};
use armada_node::volbackup::repo::Repo;
use armada_node::volbackup::s3::Bucket;
use armada_node::volbackup::target;

use crate::backup::{self, Member, Restorer};
use crate::manifest::Manifest;
use crate::{etcdmember, netutil, state};

fn msg(s: impl Into<String>) -> Error {
    Error::Msg(s.into())
}

pub fn run(ctx: &mut Ctx<'_>, _: &[String]) -> Result {
    let data_dir = ctx.str("data-dir");
    let output = ctx.str("output");
    let mut file = match output.as_str() {
        "" => return Err(msg("pass -o FILE, or -o - to write to stdout")),
        "-" => {
            if armada_client::commands::is_terminal(1) {
                return Err(msg(
                    "refusing to write a binary archive with private keys to a terminal; redirect stdout",
                ));
            }
            None
        }
        // Never overwrite: an older backup may be the only good one.
        o => Some(
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(o)
                .map_err(|e| msg(format!("open {o}: {}", armada_fsutil::errno_text(&e))))?,
        ),
    };
    let remove = |output: &str| {
        if output != "-" {
            let _ = std::fs::remove_file(output);
        }
    };
    let staged = ctx.block_on(async {
        let st = state::state_client(&data_dir).await?;
        backup::prepare(&data_dir, &st.client).await
    });
    let staged = match staged {
        Ok(s) => s,
        Err(e) => {
            remove(&output);
            return Err(msg(e));
        }
    };
    let res = match file.as_mut() {
        Some(f) => backup::create(&staged, f),
        None => backup::create(&staged, &mut *ctx.out),
    };
    if let Err(e) = res {
        remove(&output);
        return Err(msg(e));
    }
    if let Some(f) = &file {
        f.sync_all()
            .map_err(|e| msg(format!("sync {output}: {}", armada_fsutil::errno_text(&e))))?;
    }
    let m = &staged.m;
    let _ = writeln!(
        ctx.err,
        "Backup written ({} files, schema v{}, master key {}, CA {}).",
        m.files.as_ref().map_or(0, |f| f.len()),
        m.schema,
        m.master_key_id,
        m.ca_fingerprint
    );
    let _ = writeln!(
        ctx.err,
        "It contains the CA key and the master key: store it encrypted."
    );
    Ok(())
}

/// A URL or key in a file (mode 0600) or "-" for stdin.
fn read_secret_file(ctx: &mut Ctx<'_>, flag: &str, arg: &str) -> Result<Vec<u8>> {
    let b = if arg == "-" {
        let mut b = Vec::new();
        (&mut *ctx.stdin)
            .take(64 << 10)
            .read_to_end(&mut b)
            .map_err(|e| msg(format!("{flag}: {e}")))?;
        b
    } else {
        armada_fsutil::read_private_file(Path::new(arg)).map_err(|e| msg(format!("{flag}: {e}")))?
    };
    Ok(armada_node::textutil::trim_space(&b).to_vec())
}

fn open_repo(ctx: &mut Ctx<'_>) -> Result<Repo> {
    let (url_file, key_file) = (ctx.str("backup-url"), ctx.str("backup-key"));
    if url_file.is_empty() || key_file.is_empty() {
        return Err(msg("give both --backup-url FILE and --backup-key FILE"));
    }
    if url_file == "-" && key_file == "-" {
        return Err(msg(
            "only one of --backup-url and --backup-key can read stdin",
        ));
    }
    let raw = read_secret_file(ctx, "--backup-url", &url_file)?;
    let key = read_secret_file(ctx, "--backup-key", &key_file)?;
    // The errors never hold the URL.
    let t = target::parse(&String::from_utf8_lossy(&raw)).map_err(msg)?;
    let root = format!("{}_control-plane/", t.prefix);
    let bucket: Arc<Bucket> = Bucket::new(t, None).map_err(msg)?;
    Repo::open(&bucket, &root, &key).map_err(msg)
}

/// A UTC time as a JSON string (RFC 3339 with nanoseconds).
fn time_json(t: &armada_node::volbackup::gotime::Instant) -> String {
    t.rfc3339_nano()
}

pub fn list(ctx: &mut Ctx<'_>, _: &[String]) -> Result {
    let o = ctx.str("output");
    if !o.is_empty() && o != "json" {
        return Err(msg(format!("-o {o}: only json is known")));
    }
    let mut repo = open_repo(ctx)?;
    let snaps = repo.snapshots().map_err(msg)?;
    let mut rows = Vec::new();
    for (id, _) in &snaps {
        let info = repo
            .info(id)
            .map_err(|e| msg(format!("read backup {id}: {e}")))?;
        rows.push(info);
    }
    if o == "json" {
        if rows.is_empty() {
            ctx.print("[]\n");
            return Ok(());
        }
        let items: Vec<String> = rows
            .iter()
            .map(|r| {
                format!(
                    "  {{\n    \"id\": {},\n    \"time\": \"{}\",\n    \"server\": {},\n    \"files\": {},\n    \"bytes\": {}\n  }}",
                    armada_client::config::json_string(&r.id),
                    time_json(&r.time),
                    armada_client::config::json_string(&r.node),
                    r.files,
                    r.bytes
                )
            })
            .collect();
        ctx.print(&format!("[\n{}\n]\n", items.join(",\n")));
        return Ok(());
    }
    if rows.is_empty() {
        ctx.print("No backups yet.\n");
        return Ok(());
    }
    let mut tw = TabWriter::new(0, 2);
    tw.write("ID\tTAKEN\tSERVER\tSIZE\n");
    let local = armada_spec::gotime::load_location("Local")
        .unwrap_or_else(armada_spec::gotime::Location::utc);
    for r in &rows {
        let nanos = r.time.nanos();
        let c = armada_spec::gotime::Time {
            unix: nanos.div_euclid(1_000_000_000) as i64,
            nsec: nanos.rem_euclid(1_000_000_000) as i64,
            loc: local.clone(),
        }
        .civil();
        tw.write(&format!(
            "{}\t{:04}-{:02}-{:02} {:02}:{:02}:{:02}\t{}\t{} bytes\n",
            r.id, c.year, c.month, c.day, c.hour, c.minute, c.second, r.node, r.bytes
        ));
    }
    let s = tw.finish();
    ctx.print(&s);
    Ok(())
}

pub fn restore(ctx: &mut Ctx<'_>, args: &[String]) -> Result {
    let data_dir = ctx.str("data-dir");
    let from_bucket = ctx.changed("backup-url") || ctx.changed("backup-key");
    if from_bucket && !args.is_empty() {
        return Err(msg(
            "give an archive or --backup-url and --backup-key, not both",
        ));
    }
    if !from_bucket && args.is_empty() {
        return Err(msg(
            "give the archive to restore (- for stdin), or --backup-url FILE --backup-key FILE",
        ));
    }
    if !from_bucket && ctx.changed("snapshot") {
        return Err(msg("--snapshot needs --backup-url and --backup-key"));
    }
    let mc = etcdmember::member_config(&data_dir);
    let member = Member {
        addr: mc.addr,
        peer_port: mc.peer_port,
    };
    let failed = |e: String| msg(format!("restore failed, nothing was changed: {e}"));
    let m: Manifest = if from_bucket {
        let mut repo = open_repo(ctx)?;
        let mut id = ctx.str("snapshot");
        if id.is_empty() || id == "latest" {
            let snaps = repo.snapshots().map_err(msg)?;
            id = match snaps.last() {
                Some((id, _)) => id.clone(),
                None => {
                    return Err(msg(
                        "the bucket holds no backup of the control plane at that URL",
                    ));
                }
            };
        }
        let m = restore_snapshot(ctx, &mut repo, &id, &data_dir, member).map_err(failed)?;
        ctx.print(&format!("Restored backup {id}.\n"));
        m
    } else {
        let mut f;
        let (rt, stdin, _) = ctx.split();
        let r: &mut dyn Read = if args[0] == "-" {
            stdin
        } else {
            f = std::fs::File::open(&args[0]).map_err(|e| {
                msg(format!(
                    "open {}: {}",
                    args[0],
                    armada_fsutil::errno_text(&e)
                ))
            })?;
            &mut f
        };
        rt.block_on(backup::restore_archive(r, &data_dir, member))
            .map_err(failed)?
    };
    armada_fsutil::check_private(Path::new(&data_dir)).map_err(|e| msg(e.to_string()))?;
    print_restored(ctx, &m, &data_dir);
    Ok(())
}

/// RestoreSnapshot: snapshot id of the repository, checked as an archive.
fn restore_snapshot(
    ctx: &mut Ctx<'_>,
    repo: &mut Repo,
    id: &str,
    data_dir: &str,
    member: Member,
) -> std::result::Result<Manifest, String> {
    let mut rs = Restorer::new(data_dir)?;
    repo.restore_entries(
        id,
        &mut |e, content| match (e.path.as_str(), e.typ.as_str()) {
            (".", "d") => Ok(()),
            (_, "f") => {
                let mut none = std::io::empty();
                let r: &mut dyn Read = match content {
                    Some(c) => c,
                    None => &mut none,
                };
                rs.add(&e.path, e.size, r)
            }
            _ => Err(format!(
                "unexpected entry {} in backup: only regular files are allowed",
                armada_spec::go::quote(&e.path)
            )),
        },
    )?;
    ctx.block_on(rs.finish(member))
}

fn print_restored(ctx: &mut Ctx<'_>, m: &Manifest, data_dir: &str) {
    let mut s = format!(
        "Restored backup from {} (Armada {}, schema v{}) into {data_dir}.\n\n",
        m.created.minute_zone(),
        m.armada_version,
        m.schema
    );
    s.push_str(&format!(
        "  control plane: {}\n  master key:    {}\n  CA SHA-256:    {}\n\n",
        m.listen, m.master_key_id, m.ca_fingerprint
    ));
    if let Some((a, _)) = armada_client::config::parse_addr_port(&m.listen) {
        let ip = netutil::to_std(&a);
        if !netutil::host_has_ip(&ip) {
            s.push_str(&format!(
                "WARNING: {ip} is not assigned to this host. Nodes and certificates use that\naddress: give this host that private IP before starting the server.\n\n"
            ));
        }
    }
    s.push_str(&format!(
        "Next: systemctl start armada-server (or armadad server --data-dir {data_dir}).\n"
    ));
    s.push_str(
        "Changes made after the backup are gone: nodes that joined since must join again,\n",
    );
    s.push_str("and apps, secrets, or nodes changed since must be redeployed or removed again.\n");
    s.push_str(
        "Users and services are as of the backup: those created since are refused (create\n",
    );
    s.push_str(
        "them again), and roles, deletions, or certificate replacements made since are undone\n",
    );
    s.push_str("(make them again; a deleted user's certificates are valid again until then).\n");
    if m.schema < 14 {
        s.push_str(
            "\nWARNING: this backup predates user records of schema v14. A user created after it\n",
        );
        s.push_str("and missing from it would be a cluster-admin: delete each one at once with\n");
        s.push_str("`armada user delete NAME --yes`, then create it again.\n");
    }
    ctx.print(&s);
}
