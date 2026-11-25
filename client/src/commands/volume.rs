//! armada volume and armada snapshot (Go's volume.go).

use std::io::{Read, Write};

use armada_proto::armada::v1::{
    BackupVolumeRequest, CreateVolumeSnapshotRequest, ListVolumeSnapshotsRequest,
    ListVolumesRequest, RemoveVolumeRequest, RestoreVolumeMessage, RestoreVolumeSnapshotRequest,
    RestoreVolumeStart, restore_volume_message,
};

use super::{
    Output, date_time, disk_bytes, human_duration, is_terminal, now_nanos, output_flag, path_error,
    print_json, rpc_err, since,
};
use crate::cli::flags::Flag;
use crate::cli::tabwriter::TabWriter;
use crate::cli::{Args, Ctx, Error, Node, Result, Tree};
use crate::rpc;

/// volumeChunk: the most archive data one restore message carries.
const VOLUME_CHUNK: usize = 64 << 10;

pub fn add_volume(t: &mut Tree) -> usize {
    let n = t.add(
        0,
        Node::new("volume", "List, back up, restore, and delete persistent volumes")
            .aliases(&["volumes"])
            .long("Volumes keep an app's data on the node that runs its replica (ADR 0023). They are\ncreated with the app's first replica, stay on that node, and are kept until deleted\nwith `armada volume delete`. `armadad backup` does not include their contents: back\nthem up with `armada volume backup`, or to a bucket on a schedule (volumes[].backup,\nADR 0041) with `armada snapshot` to list them and take one now.")
            .noun(),
    );
    t.add(
        n,
        Node::new("list [APP]", "List volumes, their node, and how much they hold")
            .aliases(&["ls"])
            .args(Args::Max(1))
            .example("  armada volume list           # every volume of the space\n  armada volume list db        # one app's")
            .flag(output_flag(false))
            .run(list),
    );
    t.add(
        n,
        Node::new("backup APP VOLUME -o FILE", "Copy a volume's contents into a gzipped tar archive")
            .long("Copies a volume's contents from its node into a gzipped tar archive. The copy is\ntaken while the app runs; files it writes meanwhile may be copied half-written.\nWith --stop the app's replica is stopped for the backup and started again\nafterwards, for a consistent copy at the cost of downtime. For databases,\nprefer their own dump tool (armada app exec APP -- pg_dump ...) or --stop.\n\nThe archive holds the app's data as it is: store it as carefully as the app's\nown data.")
            .args(Args::Exact(2))
            .example("  armada volume backup db data -o data.tar.gz          # while the app runs\n  armada volume backup db data -o data.tar.gz --stop   # with the app paused, for a consistent copy")
            .flag(Flag::string("output", Some('o'), "", "archive to create (never overwritten), or - for stdout"))
            .flag(Flag::bool("stop", None, false, "stop the app's replica during the backup"))
            .run(backup),
    );
    t.add(
        n,
        Node::new("restore APP VOLUME FILE | --snapshot ID|latest", "Replace a volume's contents with a backup")
            .long("Replaces a volume's contents with an archive from armada volume backup (FILE, or\n- for stdin), or with a backup from the volume's bucket (--snapshot, see\narmada snapshot list). The app's replica is stopped while the backup is\nwritten and started again afterwards; a broken backup leaves the volume as it was.\n\nWith --node the volume is restored onto that node and bound to it, and the app\nfollows. This is how an app comes back when the node holding its volume is lost\nfor good; it is refused while that node is still connected.")
            .args(Args::Range(2, 3))
            .example("  armada volume restore db data data.tar.gz          # from an archive\n  armada volume restore db data --snapshot latest    # from the volume's bucket\n  armada volume restore db data --snapshot latest --node node2   # onto another node")
            .flag(Flag::string("node", None, "", "restore onto this node and bind the volume to it (when its node is lost)"))
            .flag(Flag::string("snapshot", None, "", "restore this backup from the volume's bucket (an ID, or latest)"))
            .run(restore),
    );
    t.add(
        n,
        Node::new("delete APP VOLUME --yes", "Delete a volume and its data")
            .aliases(&["rm"])
            .long("Delete a volume and its data on its node. The app must no longer mount it: update it\nwithout the volume first. This cannot be undone; back the volume up first if in doubt.")
            .args(Args::Exact(2))
            .example("  armada volume delete db data --yes")
            .flag(Flag::bool("yes", None, false, "confirm deleting the data"))
            .run(delete),
    );
    n
}

pub fn add_snapshot(t: &mut Tree) -> usize {
    let n = t.add(
        0,
        Node::new("snapshot", "List a volume's backups in its bucket, or take one now")
            .aliases(&["snapshots"])
            .long("Volumes whose spec has backup (volumes[].backup, ADR 0041) are backed up to a bucket\non a schedule. These commands list those backups and take one now; restore one with\n`armada volume restore APP VOLUME --snapshot ID|latest`.")
            .noun(),
    );
    t.add(
        n,
        Node::new("list APP VOLUME", "List a volume's backups, oldest first")
            .aliases(&["ls"])
            .args(Args::Exact(2))
            .example("  armada snapshot list db data")
            .flag(output_flag(false))
            .run(snapshot_list),
    );
    t.add(
        n,
        Node::new("create APP VOLUME", "Back a volume up to its bucket now")
            .args(Args::Exact(2))
            .example("  armada snapshot create db data   # a backup to its bucket now")
            .flag(output_flag(false))
            .run(snapshot_create),
    );
    n
}

fn list(ctx: &mut Ctx<'_>, args: &[String]) -> Result {
    let mut args = args.to_vec();
    ctx.qualify(&mut args)?;
    let o = Output::of(ctx, false);
    o.check()?;
    let mut admin = ctx.admin()?;
    let req = ListVolumesRequest {
        app: args.first().cloned().unwrap_or_default(),
    };
    let mut resp = rpc!(ctx, admin, list_volumes, req).map_err(rpc_err)?;
    resp.volumes.retain(|v| ctx.listed(&v.app));
    if o.json() {
        return print_json(ctx, &resp);
    }
    let now = now_nanos();
    let mut tw = TabWriter::new(0, 2);
    tw.write("APP\tVOLUME\tNODE\tPATH\tUSED\tLAST BACKUP\tBACKUPS\tAGE\n");
    let zero = super::unix_ts(0);
    for v in &resp.volumes {
        let path = if v.in_use {
            v.path.clone()
        } else {
            "(not mounted)".to_string()
        };
        let used = if v.used_bytes >= 0 {
            disk_bytes(v.used_bytes)
        } else {
            "-".to_string()
        };
        let (mut last, mut backups) = ("-".to_string(), "-".to_string());
        if v.backup {
            last = "never".to_string();
            if let Some(t) = &v.last_backup_at {
                last = format!("{} ago", human_duration(since(t, now)));
                backups = format!(
                    "{} ({})",
                    v.backup_snapshots,
                    disk_bytes(v.backup_stored_bytes)
                );
            }
            if v.backup_failed_at.is_some() {
                last.push_str(", failing");
            }
        }
        let age = human_duration(since(v.created_at.as_ref().unwrap_or(&zero), now));
        tw.write(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            v.app, v.name, v.node, path, used, last, backups, age
        ));
    }
    let out = tw.finish();
    ctx.print(&out);
    Ok(())
}

fn delete(ctx: &mut Ctx<'_>, args: &[String]) -> Result {
    let mut args = args.to_vec();
    ctx.qualify(&mut args)?;
    if !ctx.bool("yes") {
        return Err(Error::Msg(format!(
            "this deletes the data of volume {} of {}; pass --yes to confirm",
            args[1], args[0]
        )));
    }
    let mut admin = ctx.admin()?;
    let req = RemoveVolumeRequest {
        app: args[0].clone(),
        name: args[1].clone(),
    };
    rpc!(ctx, admin, remove_volume, req).map_err(rpc_err)?;
    ctx.print(&format!("Deleted volume {} of {}.\n", args[1], args[0]));
    Ok(())
}

fn backup(ctx: &mut Ctx<'_>, args: &[String]) -> Result {
    let mut args = args.to_vec();
    ctx.qualify(&mut args)?;
    let output = ctx.str("output");
    let mut file: Option<std::fs::File> = None;
    match output.as_str() {
        "" => return Err("pass -o FILE, or -o - to write to stdout".into()),
        "-" => {
            if is_terminal(1) {
                return Err(
                    "refusing to write a binary archive to a terminal; redirect stdout".into(),
                );
            }
        }
        _ => {
            use std::os::unix::fs::OpenOptionsExt;
            let f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&output)
                .map_err(|e| Error::Msg(path_error("open", &output, &e)))?;
            file = Some(f);
        }
    }
    let to_file = file.is_some();
    let fail = |e: Error| -> Error {
        if to_file {
            let _ = std::fs::remove_file(&output);
        }
        e
    };
    let mut admin = ctx.admin().map_err(fail)?;
    let req = BackupVolumeRequest {
        app: args[0].clone(),
        name: args[1].clone(),
        stop: ctx.bool("stop"),
    };
    let mut stream = rpc!(ctx, admin, backup_volume, req)
        .map_err(rpc_err)
        .map_err(fail)?;
    let mut n: i64 = 0;
    loop {
        let m = match ctx.block_on(stream.message()) {
            Ok(Some(m)) => m,
            Ok(None) => return Err(fail("EOF".into())),
            Err(s) => return Err(fail(rpc_err(s))),
        };
        let res = match &mut file {
            Some(f) => f.write_all(&m.data),
            None => ctx.out.write_all(&m.data),
        };
        if let Err(e) = res {
            let what = if to_file {
                output.as_str()
            } else {
                "/dev/stdout"
            };
            return Err(fail(Error::Msg(path_error("write", what, &e))));
        }
        n += m.data.len() as i64;
        if m.done {
            break;
        }
    }
    if let Some(f) = &file
        && let Err(e) = f.sync_all()
    {
        return Err(fail(Error::Msg(path_error("sync", &output, &e))));
    }
    let _ = writeln!(
        ctx.err,
        "Backed up volume {} of {} ({} compressed).",
        args[1],
        args[0],
        disk_bytes(n)
    );
    Ok(())
}

fn restore(ctx: &mut Ctx<'_>, args: &[String]) -> Result {
    let mut args = args.to_vec();
    ctx.qualify(&mut args[..2])?;
    let snapshot = ctx.str("snapshot");
    let node = ctx.str("node");
    if snapshot.is_empty() == (args.len() != 3) {
        return Err("give an archive FILE or --snapshot ID|latest".into());
    }
    if !snapshot.is_empty() {
        let mut admin = ctx.admin()?;
        let req = RestoreVolumeSnapshotRequest {
            app: args[0].clone(),
            name: args[1].clone(),
            snapshot: snapshot.clone(),
            node,
        };
        let resp = rpc!(ctx, admin, restore_volume_snapshot, req).map_err(rpc_err)?;
        ctx.print(&format!(
            "Restored volume {} of {} on {} from backup {snapshot}.\n",
            args[1], args[0], resp.node
        ));
        return Ok(());
    }
    let mut file = None;
    if args[2] != "-" {
        let f = std::fs::File::open(&args[2])
            .map_err(|e| Error::Msg(path_error("open", &args[2], &e)))?;
        file = Some(f);
    }
    let mut admin = ctx.admin()?;
    let (tx, rx) = tokio::sync::mpsc::channel::<RestoreVolumeMessage>(4);
    let keep = tx.clone();
    let start = RestoreVolumeMessage {
        msg: Some(restore_volume_message::Msg::Start(RestoreVolumeStart {
            app: args[0].clone(),
            name: args[1].clone(),
            node,
        })),
    };
    let name = if file.is_some() {
        args[2].clone()
    } else {
        "/dev/stdin".to_string()
    };
    let (rt, stdin, _) = ctx.split();
    let source: &mut dyn Read = match &mut file {
        Some(f) => f,
        None => stdin,
    };
    // The archive is read between sends, on the runtime's one thread: the
    // call runs while a send waits.
    let feed = async move {
        if tx.send(start).await.is_err() {
            return Ok(());
        }
        let mut buf = vec![0u8; VOLUME_CHUNK];
        loop {
            match source.read(&mut buf) {
                Ok(0) => return Ok(()),
                Ok(k) => {
                    let m = RestoreVolumeMessage {
                        msg: Some(restore_volume_message::Msg::Data(buf[..k].to_vec())),
                    };
                    if tx.send(m).await.is_err() {
                        // The server's error comes with the answer.
                        return Ok(());
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(path_error("read", &name, &e)),
            }
        }
    };
    let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
    let call = admin.call(move |mut c| async move { c.restore_volume(stream).await });
    let res = rt.block_on(async {
        let mut call = std::pin::pin!(call);
        let mut feed = std::pin::pin!(feed);
        // The stream ends only once the archive was read whole: a read
        // error leaves it open, so the server never takes a cut archive
        // for a whole one (Go's command returns, cancelling the call).
        let mut keep = Some(keep);
        let mut fed = false;
        loop {
            tokio::select! {
                r = &mut call => return Ok(r),
                f = &mut feed, if !fed => match f {
                    Ok(()) => {
                        fed = true;
                        keep = None;
                    }
                    Err(e) => {
                        std::mem::forget(keep.take());
                        return Err(e);
                    }
                },
            }
        }
    });
    let resp = res.map_err(Error::Msg)?.map_err(rpc_err)?;
    ctx.print(&format!(
        "Restored volume {} of {} on {}.\n",
        args[1], args[0], resp.node
    ));
    Ok(())
}

fn snapshot_list(ctx: &mut Ctx<'_>, args: &[String]) -> Result {
    let mut args = args.to_vec();
    ctx.qualify(&mut args)?;
    let o = Output::of(ctx, false);
    o.check()?;
    let mut admin = ctx.admin()?;
    let req = ListVolumeSnapshotsRequest {
        app: args[0].clone(),
        name: args[1].clone(),
    };
    let resp = rpc!(ctx, admin, list_volume_snapshots, req).map_err(rpc_err)?;
    if o.json() {
        return print_json(ctx, &resp);
    }
    let now = now_nanos();
    let zero = super::unix_ts(0);
    let mut tw = TabWriter::new(0, 2);
    tw.write("ID\tTIME\tAGE\n");
    for s in &resp.snapshots {
        let t = s.time.as_ref().unwrap_or(&zero);
        tw.write(&format!(
            "{}\t{}\t{}\n",
            s.id,
            date_time(Some(t)),
            human_duration(since(t, now))
        ));
    }
    let out = tw.finish();
    ctx.print(&out);
    Ok(())
}

fn snapshot_create(ctx: &mut Ctx<'_>, args: &[String]) -> Result {
    let mut args = args.to_vec();
    ctx.qualify(&mut args)?;
    let o = Output::of(ctx, false);
    o.check()?;
    let mut admin = ctx.admin()?;
    let req = CreateVolumeSnapshotRequest {
        app: args[0].clone(),
        name: args[1].clone(),
    };
    let resp = rpc!(ctx, admin, create_volume_snapshot, req).map_err(rpc_err)?;
    if o.json() {
        return print_json(ctx, &resp);
    }
    let s = resp.snapshot.clone().unwrap_or_default();
    ctx.print(&format!(
        "Backed up volume {} of {} as {}: {} files, {}, {} new; the bucket holds {} backups in {}.\n",
        args[1],
        args[0],
        s.id,
        s.files,
        disk_bytes(s.bytes),
        disk_bytes(resp.new_bytes),
        resp.snapshots,
        disk_bytes(resp.stored_bytes)
    ));
    Ok(())
}
