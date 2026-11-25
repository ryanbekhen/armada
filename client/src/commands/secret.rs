//! armada secret (Go's secret.go): keys and values the apps of a space
//! share; values are never shown and never taken as arguments.

use std::collections::HashMap;
use std::io::{IsTerminal, Read};

use armada_proto::armada::v1::{
    DeleteSecretRequest, ListSecretsRequest, ListSpaceSecretsRequest, ListSpaceSecretsResponse,
    ListSpacesRequest, SetSecretRequest,
};
use armada_spec as spec;
use armada_spec::go;

use super::app::{WaitFlags, wait_flags, wait_rollout};
use super::deploy::{path_error, scan_lines};
use super::{Output, choice_list, date_time, output_flag, print_json, rpc_err};
use crate::cli::flags::Flag;
use crate::cli::tabwriter::TabWriter;
use crate::cli::{ArgError, Args, Ctx, Error, Node, Result, Tree};
use crate::rpc;
use crate::rpc::Admin;

/// secrets.MaxSize.
const MAX_SIZE: usize = 64 << 10;
const MAX_ENV_KEY: usize = 256;
const MAX_SECRET_FILE: usize = 16 << 20;

pub fn add(t: &mut Tree) -> usize {
    let n = t.add(
        0,
        Node::new("secret", "Keys and values the apps of a space share (values are write-only)")
            .aliases(&["secrets"])
            .long("A secret is a named set of keys in a space; every app and job of the space\ncan use its keys (SECRET/KEY in a spec, or envFrom). The secret named after\nan app is that app's own: a spec's secretRef with no secret names its keys.\n\nValues are encrypted at rest, only decrypted for the nodes that run a replica\nthat uses them, never shown again, and never accepted as command-line\narguments, which would leak into shell history.")
            .example("  armada secret create db --from-env-file db.env\n  armada secret set db PASSWORD < password.txt\n  armada secret list\n  armada secret show db")
            .noun(),
    );
    t.add(
        n,
        Node::new(
            "list",
            "List the secrets of the space (names and key counts only)",
        )
        .aliases(&["ls"])
        .example("  armada secret list\n  armada secret list -A")
        .args(Args::No)
        .flag(output_flag(false))
        .run(list),
    );
    t.add(
        n,
        Node::new(
            "show SECRET",
            "List a secret's keys, their versions, and the revisions that use them",
        )
        .example("  armada secret show db")
        .args(Args::Exact(1))
        .flag(output_flag(false))
        .run(show),
    );
    let mut create = Node::new("create SECRET --from-env-file FILE", "Create a secret with a key for each KEY=VALUE line of a file")
        .long("Create a secret with a key for each KEY=VALUE line of a file (- reads stdin),\nkeeping the keys as written. Blank lines and lines starting with # are\nskipped; a value is everything after the first =, kept exactly, quotes\nincluded. It refuses a secret that exists: change one with armada secret set.")
        .example("  armada secret create db --from-env-file db.env\n  # then in a spec:\n  #   envFrom:\n  #     - secret: db\n  #   env:\n  #     - name: DATABASE_URL\n  #       secretRef: db/DATABASE_URL")
        .args(Args::Exact(1))
        .flag(Flag::string("from-env-file", None, "", "KEY=VALUE lines, one key each (- reads stdin)"))
        .run(create);
    create.required = vec!["from-env-file"];
    t.add(n, create);
    let mut set_flags = vec![
        Flag::string(
            "from-file",
            None,
            "",
            "read the value from this file instead of stdin",
        ),
        Flag::string(
            "from-env-file",
            None,
            "",
            "set a key for each KEY=VALUE line of this file (- reads stdin)",
        ),
        Flag::bool(
            "no-rollout",
            None,
            false,
            "store the value without rolling out the apps that use it",
        ),
        Flag::bool("allow-empty", None, false, "allow an empty value"),
    ];
    set_flags.extend(wait_flags());
    t.add(
        n,
        Node::new("set SECRET KEY | SECRET --from-env-file FILE", "Set a key from stdin, a hidden prompt, or --from-file; or many from --from-env-file")
            .long("Set a key of a secret from stdin, a hidden prompt, or --from-file, creating\nthe secret if it does not exist.\n\nFrom stdin, one trailing newline is removed (as added by echo); --from-file\nstores the file's bytes exactly. Every app whose current revision uses the\nkey rolls out with the new value (see --no-rollout).\n\n--from-env-file sets a key for each KEY=VALUE line, keeping the keys as\nwritten; nothing rolls out, so apps get the values with their next deploy.")
            .example("  armada secret set db PASSWORD < password.txt\n  printf %s \"$TOKEN\" | armada secret set api API_TOKEN\n  armada secret set tls key --from-file key.pem\n  armada secret set db --from-env-file db.env")
            .args(Args::Custom(set_args))
            .flags(set_flags)
            .run(set),
    );
    t.add(
        n,
        Node::new(
            "unset SECRET KEY",
            "Delete every version of a key no app uses",
        )
        .example("  armada secret unset db OLD_PASSWORD")
        .args(Args::Exact(2))
        .run(unset),
    );
    t.add(
        n,
        Node::new(
            "delete SECRET --yes",
            "Delete a secret with every key, once no app uses it",
        )
        .aliases(&["rm"])
        .example("  armada secret delete old-db --yes")
        .args(Args::Exact(1))
        .flag(Flag::bool("yes", None, false, "confirm deleting every key"))
        .run(delete),
    );
    n
}

/// secretID: the ID of the secret named name, its name checked.
fn secret_id(ctx: &Ctx<'_>, name: &str) -> Result<String> {
    let id = ctx.app_id(name).map_err(Error::Msg)?;
    let (_, short) = spec::validate::split_app_id(&id).unwrap_or_default();
    spec::validate::validate_secret_name(&short).map_err(Error::Msg)?;
    Ok(id)
}

fn set_args(ctx: &Ctx<'_>, args: &[String]) -> std::result::Result<(), ArgError> {
    if !ctx.str("from-env-file").is_empty() {
        if args.len() != 1 {
            return Err(ArgError::Own(
                "--from-env-file takes the secret only: armada secret set SECRET --from-env-file FILE"
                    .to_string(),
            ));
        }
        return Ok(());
    }
    if args.len() != 2 {
        return Err(ArgError::Cobra(format!(
            "accepts 2 arg(s), received {}",
            args.len()
        )));
    }
    Ok(())
}

fn set(ctx: &mut Ctx<'_>, args: &[String]) -> Result {
    let secret = secret_id(ctx, &args[0])?;
    let from_env = ctx.str("from-env-file");
    let from_file = ctx.str("from-file");
    if !from_env.is_empty() {
        if !from_file.is_empty() {
            return Err("--from-file and --from-env-file: use one".into());
        }
        return set_from_env_file(ctx, &secret, &from_env, false);
    }
    let key = args[1].clone();
    spec::validate::validate_secret_key(&key).map_err(Error::Msg)?;
    let value = read_secret_value(ctx, &from_file)?;
    if value.is_empty() && !ctx.bool("allow-empty") {
        return Err("the secret value is empty (pass --allow-empty if that is intended)".into());
    }
    let mut admin = ctx.admin()?;
    let req = SetSecretRequest {
        app: secret.clone(),
        name: key.clone(),
        value,
        rollout: !ctx.bool("no-rollout"),
    };
    let resp = rpc!(ctx, admin, set_secret, req).map_err(rpc_err)?;
    let mut revs = resp.revisions.clone();
    if revs.is_empty() && !resp.revision.is_empty() {
        revs = vec![resp.revision.clone()];
    }
    if revs.is_empty() {
        ctx.print(&format!(
            "Set secret {key} of {secret} (version {}).\n",
            resp.version
        ));
        return Ok(());
    }
    ctx.print(&format!(
        "Set secret {key} of {secret} (version {}); rolling out {}.\n",
        resp.version,
        revs.join(", ")
    ));
    let w = WaitFlags::of(ctx);
    if !w.wait {
        return Ok(());
    }
    for rev in revs {
        let app = match rev.rfind("--r") {
            Some(i) => rev[..i].to_string(),
            None => rev.clone(),
        };
        wait_rollout(ctx, &mut admin, &app, &rev, w.timeout)?;
    }
    Ok(())
}

fn create(ctx: &mut Ctx<'_>, args: &[String]) -> Result {
    let secret = secret_id(ctx, &args[0])?;
    let file = ctx.str("from-env-file");
    set_from_env_file(ctx, &secret, &file, true)
}

/// setFromEnvFile: a key of secret for each line of file.
fn set_from_env_file(ctx: &mut Ctx<'_>, secret: &str, file: &str, create: bool) -> Result {
    let entries = read_secret_file(ctx, file)?;
    let mut admin = ctx.admin()?;
    if create {
        let req = ListSecretsRequest {
            app: secret.to_string(),
        };
        let resp = rpc!(ctx, admin, list_secrets, req).map_err(rpc_err)?;
        if !resp.secrets.is_empty() {
            return Err(Error::Msg(format!(
                "secret {secret} exists; change its keys with armada secret set {secret} KEY, or --from-env-file"
            )));
        }
    }
    set_keys(ctx, &mut admin, secret, entries)
}

fn read_secret_file(ctx: &mut Ctx<'_>, file: &str) -> Result<Vec<(String, Vec<u8>)>> {
    let mut data = Vec::new();
    let limit = (MAX_SECRET_FILE + 1) as u64;
    if file == "-" {
        let _ = ctx.stdin.take(limit).read_to_end(&mut data);
    } else {
        let f = std::fs::File::open(file).map_err(|e| Error::Msg(path_error("open", file, &e)))?;
        let _ = f.take(limit).read_to_end(&mut data);
    }
    let entries = parse_secret_file(&data).map_err(|e| Error::Msg(format!("{file}: {e}")))?;
    if entries.is_empty() {
        return Err(Error::Msg(format!("{file} has no KEY=VALUE lines")));
    }
    Ok(entries)
}

/// parseSecretFile: KEY=VALUE lines, keys as written; errors name a line
/// by number and never quote it.
fn parse_secret_file(b: &[u8]) -> std::result::Result<Vec<(String, Vec<u8>)>, String> {
    let max_line = MAX_SIZE + MAX_ENV_KEY + 2;
    let mut out = Vec::new();
    let mut by_name: HashMap<String, usize> = HashMap::new();
    let mut total = 0;
    for (i, line) in scan_lines(b).into_iter().enumerate() {
        let n = i + 1;
        if line.len() > max_line {
            return Err(format!("a line is larger than {MAX_SIZE} bytes"));
        }
        total += line.len() + 1;
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let t = trim_bytes(line);
        if t.is_empty() || t[0] == b'#' {
            continue;
        }
        let Some(eq) = line.iter().position(|&c| c == b'=') else {
            return Err(bad_line(n));
        };
        let key = String::from_utf8_lossy(&line[..eq]).to_string();
        if spec::validate::validate_secret_key(&key).is_err() {
            return Err(bad_line(n));
        }
        if let Some(first) = by_name.get(&key) {
            return Err(format!(
                "line {n}: key {key} was already set on line {first}"
            ));
        }
        by_name.insert(key.clone(), n);
        out.push((key, line[eq + 1..].to_vec()));
    }
    if total > MAX_SECRET_FILE {
        return Err(format!("the file is larger than {MAX_SECRET_FILE} bytes"));
    }
    Ok(out)
}

fn bad_line(n: usize) -> String {
    format!(
        "line {n}: want KEY=VALUE, KEY a variable name or lowercase letters, digits, and hyphens"
    )
}

/// bytes.TrimSpace for what matters here: ASCII white space.
fn trim_bytes(b: &[u8]) -> &[u8] {
    let s = b
        .iter()
        .position(|c| !c.is_ascii_whitespace())
        .unwrap_or(b.len());
    let e = b
        .iter()
        .rposition(|c| !c.is_ascii_whitespace())
        .map_or(s, |e| e + 1);
    &b[s..e]
}

/// setKeys: each key without a rollout, stopping at the first failure.
fn set_keys(
    ctx: &mut Ctx<'_>,
    admin: &mut Admin,
    secret: &str,
    entries: Vec<(String, Vec<u8>)>,
) -> Result {
    let total = entries.len();
    for (i, (name, value)) in entries.into_iter().enumerate() {
        let req = SetSecretRequest {
            app: secret.to_string(),
            name: name.clone(),
            value,
            rollout: false,
        };
        let resp = rpc!(ctx, admin, set_secret, req).map_err(|s| {
            Error::Msg(format!(
                "secret {name} ({i} of {total} set before it): {}",
                crate::rpc::rpc_error(&s)
            ))
        })?;
        ctx.print(&format!("{name} (version {})\n", resp.version));
    }
    ctx.print(&format!(
        "Set {total} keys of {secret}; running replicas get them with each app's next deploy.\n"
    ));
    Ok(())
}

/// ReadSecretValue: a file, a hidden prompt, or piped stdin.
fn read_secret_value(ctx: &mut Ctx<'_>, from_file: &str) -> Result<Vec<u8>> {
    if !from_file.is_empty() {
        let f = std::fs::File::open(from_file)
            .map_err(|e| Error::Msg(path_error("open", from_file, &e)))?;
        return read_limited(f);
    }
    if std::io::stdin().is_terminal() {
        let _ = ctx.err.write_all(b"Value (input hidden): ");
        let b = read_password();
        let _ = ctx.err.write_all(b"\n");
        return b.map_err(Error::Msg);
    }
    let mut b = read_limited(&mut *ctx.stdin)?;
    if b.last() == Some(&b'\n') {
        b.pop();
    }
    if b.last() == Some(&b'\r') {
        b.pop();
    }
    Ok(b)
}

fn read_limited(r: impl Read) -> Result<Vec<u8>> {
    let mut b = Vec::new();
    r.take(MAX_SIZE as u64 + 1)
        .read_to_end(&mut b)
        .map_err(|e| Error::Msg(e.to_string()))?;
    if b.len() > MAX_SIZE {
        return Err(Error::Msg(format!(
            "the secret is larger than {MAX_SIZE} bytes"
        )));
    }
    Ok(b)
}

/// term.ReadPassword on stdin: echo off until a new line.
fn read_password() -> std::result::Result<Vec<u8>, String> {
    let fd = libc::STDIN_FILENO;
    // SAFETY: termios is plain data filled by tcgetattr before use.
    let mut old: libc::termios = unsafe { std::mem::zeroed() };
    // SAFETY: fd is stdin, old a valid pointer.
    if unsafe { libc::tcgetattr(fd, &mut old) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let mut new = old;
    new.c_lflag &= !libc::ECHO;
    new.c_lflag |= libc::ICANON | libc::ISIG;
    new.c_iflag |= libc::ICRNL;
    // SAFETY: as above.
    unsafe { libc::tcsetattr(fd, libc::TCSANOW, &new) };
    let mut ret = Vec::new();
    let mut stdin = std::io::stdin();
    let mut buf = [0u8; 1];
    let result = loop {
        match stdin.read(&mut buf) {
            Ok(0) => {
                if ret.is_empty() {
                    break Err("EOF".to_string());
                }
                break Ok(ret);
            }
            Ok(_) => match buf[0] {
                8 => {
                    ret.pop();
                }
                b'\n' => break Ok(ret),
                c => ret.push(c),
            },
            Err(e) => break Err(e.to_string()),
        }
    };
    // SAFETY: restores the settings read above.
    unsafe { libc::tcsetattr(fd, libc::TCSANOW, &old) };
    result
}

fn list(ctx: &mut Ctx<'_>, _: &[String]) -> Result {
    let o = Output::of(ctx, false);
    o.check()?;
    let mut admin = ctx.admin()?;
    let mut spaces = vec![ctx.scope()];
    if ctx.g.all_spaces {
        let resp = rpc!(ctx, admin, list_spaces, ListSpacesRequest {}).map_err(rpc_err)?;
        spaces = resp.spaces.into_iter().map(|p| p.name).collect();
    }
    let mut all = ListSpaceSecretsResponse::default();
    let mut in_space = Vec::new();
    for p in spaces {
        let req = ListSpaceSecretsRequest { space: p.clone() };
        let resp = rpc!(ctx, admin, list_space_secrets, req).map_err(rpc_err)?;
        for sec in resp.secrets {
            all.secrets.push(sec);
            in_space.push(p.clone());
        }
    }
    if o.json() {
        return print_json(ctx, &all);
    }
    let mut tw = TabWriter::new(0, 2);
    let mut head = "NAME\tKEYS\tUPDATED\tBY\tUSED BY".to_string();
    if ctx.g.all_spaces {
        head = format!("SPACE\t{head}");
    }
    tw.write(&format!("{head}\n"));
    for (i, sec) in all.secrets.iter().enumerate() {
        if ctx.g.all_spaces {
            tw.write(&format!("{}\t", in_space[i]));
        }
        let used = if sec.used_by.is_empty() {
            "-".to_string()
        } else {
            sec.used_by.join(",")
        };
        tw.write(&format!(
            "{}\t{}\t{}\t{}\t{used}\n",
            sec.name,
            sec.keys,
            date_time(sec.updated_at.as_ref()),
            sec.updated_by
        ));
    }
    let out = tw.finish();
    ctx.print(&out);
    Ok(())
}

fn show(ctx: &mut Ctx<'_>, args: &[String]) -> Result {
    let o = Output::of(ctx, false);
    o.check()?;
    let secret = secret_id(ctx, &args[0])?;
    let mut admin = ctx.admin()?;
    let req = ListSecretsRequest {
        app: secret.clone(),
    };
    let resp = rpc!(ctx, admin, list_secrets, req).map_err(rpc_err)?;
    if o.json() {
        return print_json(ctx, &resp);
    }
    if resp.secrets.is_empty() {
        return Err(no_secret(ctx, &mut admin, &secret));
    }
    let mut tw = TabWriter::new(0, 2);
    tw.write("KEY\tVERSION\tUPDATED\tBY\tUSED BY\n");
    for s in &resp.secrets {
        tw.write(&format!(
            "{}\t{}\t{}\t{}\t{}\n",
            s.name,
            s.version,
            date_time(s.updated_at.as_ref()),
            s.updated_by,
            used_by(&secret, &s.used_by)
        ));
    }
    let out = tw.finish();
    ctx.print(&out);
    Ok(())
}

fn unset(ctx: &mut Ctx<'_>, args: &[String]) -> Result {
    let secret = secret_id(ctx, &args[0])?;
    let key = args[1].clone();
    spec::validate::validate_secret_key(&key).map_err(Error::Msg)?;
    let mut admin = ctx.admin()?;
    let req = DeleteSecretRequest {
        app: secret.clone(),
        name: key.clone(),
        ..Default::default()
    };
    rpc!(ctx, admin, delete_secret, req).map_err(rpc_err)?;
    ctx.print(&format!("Deleted secret {key} of {secret}.\n"));
    Ok(())
}

fn delete(ctx: &mut Ctx<'_>, args: &[String]) -> Result {
    let secret = secret_id(ctx, &args[0])?;
    if !ctx.bool("yes") {
        return Err(Error::Msg(format!(
            "this deletes every key of secret {secret}; pass --yes to confirm"
        )));
    }
    let mut admin = ctx.admin()?;
    let req = DeleteSecretRequest {
        app: secret.clone(),
        whole: true,
        ..Default::default()
    };
    rpc!(ctx, admin, delete_secret, req).map_err(rpc_err)?;
    ctx.print(&format!("Deleted secret {secret}.\n"));
    Ok(())
}

/// usedBy: the revisions that use a key, app by app.
fn used_by(secret: &str, revisions: &[String]) -> String {
    if revisions.is_empty() {
        return "-".to_string();
    }
    let mut apps: Vec<String> = Vec::new();
    let mut by_app: HashMap<String, Vec<String>> = HashMap::new();
    for r in revisions {
        let app = match r.rfind("--r") {
            Some(i) if i > 0 => r[..i].to_string(),
            _ => r.clone(),
        };
        if !by_app.contains_key(&app) {
            apps.push(app.clone());
        }
        by_app.entry(app).or_default().push(r.clone());
    }
    let parts: Vec<String> = apps
        .iter()
        .map(|app| {
            let runs = revision_runs(app, &by_app[app]);
            if app != secret {
                format!("{app}:{runs}")
            } else {
                runs
            }
        })
        .collect();
    parts.join(",")
}

/// revisionRuns: r11-r20 for consecutive revisions.
fn revision_runs(app: &str, revisions: &[String]) -> String {
    if revisions.is_empty() {
        return "-".to_string();
    }
    let prefix = format!("{app}--r");
    let mut nums = Vec::new();
    for r in revisions {
        let n = r.strip_prefix(&prefix).and_then(|s| go::atoi(s).ok());
        match n {
            Some(n) if n >= 1 => nums.push(n),
            _ => return revisions.join(","),
        }
    }
    nums.sort();
    nums.dedup();
    let mut parts = Vec::new();
    let mut i = 0;
    while i < nums.len() {
        let mut j = i;
        while j + 1 < nums.len() && nums[j + 1] == nums[j] + 1 {
            j += 1;
        }
        if j == i {
            parts.push(format!("r{}", nums[i]));
        } else if j == i + 1 {
            parts.push(format!("r{}", nums[i]));
            parts.push(format!("r{}", nums[j]));
        } else {
            parts.push(format!("r{}-r{}", nums[i], nums[j]));
        }
        i = j + 1;
    }
    parts.join(",")
}

/// noSecret: a secret with no keys, and the secrets its space has.
fn no_secret(ctx: &mut Ctx<'_>, admin: &mut Admin, secret: &str) -> Error {
    let (space, name) = spec::validate::split_app_id(secret).unwrap_or_default();
    let req = ListSpaceSecretsRequest {
        space: space.clone(),
    };
    let list = rpc!(ctx, admin, list_space_secrets, req);
    match list {
        Ok(l) if !l.secrets.is_empty() => {
            let names: Vec<String> = l.secrets.into_iter().map(|s| s.name).collect();
            Error::Msg(format!(
                "space {space} has no secret {}; its secrets: {}",
                go::quote(&name),
                choice_list(&names)
            ))
        }
        _ => Error::Msg(format!(
            "space {space} has no secret {}; create one with armada secret create {name} --from-env-file FILE",
            go::quote(&name)
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runs() {
        let revs: Vec<String> = (11..=20).rev().map(|n| format!("api--r{n}")).collect();
        assert_eq!(revision_runs("api", &revs), "r11-r20");
        assert_eq!(
            used_by(
                "api",
                &["api--r1".into(), "api--r2".into(), "worker--r3".into()]
            ),
            "r1,r2,worker:r3"
        );
    }

    #[test]
    fn env_files() {
        let e = parse_secret_file(b"# c\n\nA=1\nb-c=x=y\r\n").unwrap();
        assert_eq!(
            e,
            vec![("A".into(), b"1".to_vec()), ("b-c".into(), b"x=y".to_vec())]
        );
        assert!(
            parse_secret_file(b"A=1\nA=2\n")
                .unwrap_err()
                .contains("line 2")
        );
        assert!(
            parse_secret_file(b"bad line\n")
                .unwrap_err()
                .starts_with("line 1")
        );
    }
}
