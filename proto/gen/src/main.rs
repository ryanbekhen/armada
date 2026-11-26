//! Writes armada-proto's generated code (`make proto`), so that building the
//! workspace never needs protoc:
//!
//!   armada-proto-gen ROOT [ETCD_API_DIR]
//!
//! ROOT is the repository. With ETCD_API_DIR (go.etcd.io/etcd/api/v3 at the
//! pinned etcd's version, named `<path>@<version>`, which `armada-pack
//! etcd-api` writes: `make proto-rust`), the etcd protos under proto/vendor are first
//! written again from it (`vendor_etcd`). protoc comes from $PROTOC or the
//! PATH, as prost-build finds it.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args.len() > 2 {
        eprintln!("usage: armada-proto-gen ROOT [ETCD_API_DIR]");
        return ExitCode::from(2);
    }
    let root = PathBuf::from(&args[0]);
    if let Some(etcd) = args.get(1)
        && let Err(e) = vendor_etcd(Path::new(etcd), &root.join("proto/vendor"))
    {
        eprintln!("armada-proto-gen: vendoring etcd's protos: {e}");
        return ExitCode::FAILURE;
    }
    if let Err(e) = generate(&root) {
        eprintln!("armada-proto-gen: {e}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

fn generate(root: &Path) -> io::Result<()> {
    let out = root.join("proto/src/gen");
    fs::create_dir_all(&out)?;
    for entry in fs::read_dir(&out)? {
        let path = entry?.path();
        if path.extension().is_some_and(|e| e == "rs") {
            fs::remove_file(path)?;
        }
    }
    let descriptors = out.join("armada.v1.bin");

    // Armada's protocol: messages, clients, and servers. Timestamps are
    // armada-proto's own (src/timestamp.rs), whose JSON is protojson's. Maps are BTreeMaps,
    // so the binary encoding writes their entries sorted by key, as Go's
    // deterministic encoding does (the replica spec hash), and their
    // protobuf JSON comes out in protojson's order.
    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .build_transport(false)
        .emit_rerun_if_changed(false)
        .extern_path(
            ".google.protobuf.Timestamp",
            "crate::google::protobuf::Timestamp",
        )
        .btree_map(".")
        .out_dir(&out)
        .file_descriptor_set_path(&descriptors)
        .compile_protos(
            &[root.join("api/armada/v1/armada.proto")],
            &[root.join("api")],
        )?;
    let set = fs::read(&descriptors)?;
    fs::remove_file(&descriptors)?;
    pbjson_build::Builder::new()
        .register_descriptors(&set)
        .map_err(io::Error::other)?
        .extern_path(
            ".google.protobuf.Timestamp",
            "crate::google::protobuf::Timestamp",
        )
        .btree_map(["."])
        .out_dir(&out)
        .build(&[".armada.v1"])
        .map_err(io::Error::other)?;

    // etcd's API, the client side only.
    tonic_prost_build::configure()
        .build_client(true)
        .build_server(false)
        .build_transport(false)
        .emit_rerun_if_changed(false)
        .out_dir(&out)
        .compile_protos(
            &[root.join("proto/vendor/etcd/api/etcdserverpb/rpc.proto")],
            &[root.join("proto/vendor")],
        )?;
    Ok(())
}

/// The services of etcd's rpc.proto Armada uses (ADR 0055): the others and
/// their messages are left out.
const ETCD_SERVICES: [&str; 5] = ["KV", "Watch", "Lease", "Cluster", "Maintenance"];

/// Writes the etcd protos Armada generates from: mvccpb/kv.proto as etcd
/// has it, and etcdserverpb/rpc.proto with only ETCD_SERVICES and without
/// the options that need other protos (the HTTP gateway's, OpenAPI's, and
/// etcd's version annotations), which change nothing on the wire. Every
/// message, field, and number kept is etcd's.
fn vendor_etcd(api: &Path, dst: &Path) -> io::Result<()> {
    let version = api
        .file_name()
        .and_then(|n| n.to_str())
        .and_then(|n| n.split_once('@'))
        .map(|(_, v)| v.to_string())
        .ok_or_else(|| io::Error::other(format!("{}: no @version in the name", api.display())))?;
    let header = format!(
        "// From go.etcd.io/etcd/api/v3 {version}, under the Apache License 2.0\n\
         // (proto/vendor/etcd/LICENSE), written by `make proto` (proto/gen):\n\
         // {{}}.\n"
    );
    let etcd = dst.join("etcd");
    fs::create_dir_all(etcd.join("api/mvccpb"))?;
    fs::create_dir_all(etcd.join("api/etcdserverpb"))?;
    // Written, never copied: the module cache's files are read-only.
    fs::write(etcd.join("LICENSE"), fs::read(api.join("LICENSE"))?)?;
    let kv = fs::read_to_string(api.join("mvccpb/kv.proto"))?;
    fs::write(
        etcd.join("api/mvccpb/kv.proto"),
        header.replace("{}", "unchanged") + &kv,
    )?;
    let rpc = fs::read_to_string(api.join("etcdserverpb/rpc.proto"))?;
    fs::write(
        etcd.join("api/etcdserverpb/rpc.proto"),
        header.replace(
            "{}",
            "only the services Armada uses, without the options of other protos",
        ) + &trim_rpc(&rpc)?,
    )
}

fn trim_rpc(src: &str) -> io::Result<String> {
    let lines: Vec<&str> = src.lines().collect();
    let mut kept: Vec<String> = Vec::new();
    // Comments and blank lines wait for what follows them, so the comment
    // of a block left out goes with it.
    let mut pending: Vec<String> = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        let t = line.trim();
        if t.starts_with("//") || t.is_empty() {
            if t == "// for grpc-gateway" {
                i += 1;
                continue;
            }
            pending.push(line.to_string());
            i += 1;
            continue;
        }
        if t.starts_with("import ") {
            let ours = t.contains("etcd/api/mvccpb/");
            if ours {
                kept.append(&mut pending);
                kept.push(line.to_string());
            } else {
                pending.clear();
            }
            i += 1;
            continue;
        }
        if t.starts_with("option (") {
            i = skip_statement(&lines, i);
            pending.retain(|l| !l.trim().is_empty());
            continue;
        }
        let drop = if let Some(name) = t.strip_prefix("service ") {
            let name = name.trim_end_matches('{').trim();
            !ETCD_SERVICES.contains(&name)
        } else if let Some(name) = t.strip_prefix("message ") {
            name.starts_with("Auth")
        } else {
            false
        };
        if drop {
            pending.clear();
            i = skip_block(&lines, i)?;
            continue;
        }
        kept.append(&mut pending);
        kept.push(strip_field_options(line));
        i += 1;
    }
    kept.append(&mut pending);
    let mut out = kept.join("\n");
    out.push('\n');
    // Options removed from an rpc leave `{\n  }`; keep it as one line.
    while out.contains("{\n  }") {
        out = out.replace("{\n  }", "{}");
    }
    if out.contains("authpb") || out.contains("versionpb") || out.contains("google.api") {
        return Err(io::Error::other(
            "rpc.proto still names a proto that is not vendored",
        ));
    }
    Ok(out)
}

/// The index after an option statement, which may span lines in braces.
fn skip_statement(lines: &[&str], start: usize) -> usize {
    let mut depth = 0i32;
    let mut i = start;
    while i < lines.len() {
        depth += braces(lines[i]);
        i += 1;
        if depth <= 0 && lines[i - 1].trim_end().ends_with(';') {
            break;
        }
    }
    i
}

/// The index after a block that opens on `start`.
fn skip_block(lines: &[&str], start: usize) -> io::Result<usize> {
    let mut depth = 0i32;
    let mut i = start;
    while i < lines.len() {
        depth += braces(lines[i]);
        i += 1;
        if depth == 0 && lines[i - 1].contains('}') {
            return Ok(i);
        }
    }
    Err(io::Error::other(format!(
        "a block at line {} never ends",
        start + 1
    )))
}

fn braces(line: &str) -> i32 {
    let code = line.split("//").next().unwrap_or("");
    code.matches('{').count() as i32 - code.matches('}').count() as i32
}

/// A field or enum value without its `[(versionpb.…)]` option.
fn strip_field_options(line: &str) -> String {
    match line.find(" [(versionpb.") {
        Some(at) => match line[at..].find(']') {
            Some(end) => format!("{}{}", &line[..at], &line[at + end + 1..]),
            None => line.to_string(),
        },
        None => line.to_string(),
    }
}
