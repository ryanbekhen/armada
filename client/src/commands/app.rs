//! armada app and armada revision.

use std::time::Duration as StdDuration;

use armada_proto::armada::v1::{
    AppStatus, AppSummary, Autoscale, GetAppSpecRequest, ListAppsRequest, ListAppsResponse,
    ListRevisionsRequest, ListRevisionsResponse, RemoveAppRequest, ReplicaStatus,
    RestartAppRequest, RevisionInfo, RollbackRequest, SetTrafficRequest, StatusRequest,
    TrafficTarget,
};
use armada_spec as spec;
use armada_spec::go;

use super::deploy::{app_target, check_kind, run_deploy};
use super::{
    OUTPUT_YAML, Output, ago, dash, date_time, day_clock, now_nanos, output_flag, print_json,
    round_second, rpc_err, since,
};
use crate::cli::flags::Flag;
use crate::cli::tabwriter::TabWriter;
use crate::cli::{Args, Ctx, Error, Node, Result, Tree};
use crate::rpc;
use crate::rpc::{Admin, printable};

const ROLLOUT_PROGRESSING: &str = "progressing";
const ROLLOUT_FAILED: &str = "failed";

pub fn add_app(t: &mut Tree) -> usize {
    let app = t.add(
        0,
        Node::new("app", "Deploy, inspect, and roll back apps")
            .aliases(&["apps"])
            .long("Apps are long-running containers with replicas, rolling updates, and\ningress. Deploy one from flags or a spec file; `armada app show NAME -o yaml`\nprints the spec it runs, ready for `armada app deploy --file` on any cluster.")
            .noun(),
    );
    let (flags, exclusive) = super::deploy::flags(false);
    let mut deploy = Node::new("deploy APP [flags] | --file FILE", "Create or change an app from flags or a spec file")
        .long("Create an app, or change one as a new revision rolled out like every change.\n\nWith flags, only what they name changes in the spec the app runs, and the\ndeploy is refused when another change landed since that spec was read; a new\napp needs --image. With --file (- for stdin), the file replaces the whole\nspec. --new refuses an app that exists; --diff prints what would change and\nchanges nothing. Flags cover what is changed often; the rest of the spec\n(custom probes, routes, secret files, volumes, init containers, sidecars,\nplacement, traffic splitting) is written in a file.")
        .example("  armada app deploy hello --image traefik/whoami:v1.10 --port 80 --ingress external --min 2\n  armada app deploy web --image ghcr.io/acme/web:1.4.3 --wait\n  armada app deploy web --env LOG_LEVEL=debug --remove-env DEBUG\n  armada app deploy --file web.yaml --var TAG=1.4.2 --diff")
        .args(Args::Max(1))
        .flags(flags)
        .run(|ctx, args| run_deploy(ctx, args, false));
    deploy.exclusive = exclusive;
    t.add(app, deploy);
    t.add(
        app,
        Node::new("list", "List apps")
            .aliases(&["ls"])
            .args(Args::No)
            .example("  armada app list            # the apps of the space\n  armada app list -A         # of every space\n  armada app list -o json")
            .flag(output_flag(false))
            .run(list),
    );
    t.add(
        app,
        Node::new("show APP", "Show an app: its revision, replicas, and URLs")
            .long("Show an app: its revision, image, replicas, and URLs. -o yaml prints the spec\nit runs as a file holds it, ready for create --file or update --file.")
            .args(Args::Exact(1))
            .example("  armada app show api             # revision, replicas, URLs\n  armada app show api -o yaml     # the spec it runs, for app deploy --file")
            .flag(output_flag(true))
            .run(show),
    );
    t.add(
        app,
        Node::new("restart APP", "Replace every replica of an app, with the latest secret values")
            .long("Make a new revision of the app's spec with the latest value of every\nsecret it uses, and roll it out like any change: replicas are replaced\none at a time, so the app keeps serving. This is how an app picks up a\nsecret changed with `armada secret set`, or starts afresh.\n\nJobs start every run with the latest values, and apps that split\ntraffic between revisions take a new revision from `armada app deploy`.")
            .example("  armada app restart api          # new revision, rolled out\n  armada app restart api --wait   # and wait until it serves")
            .args(Args::Exact(1))
            .flags(wait_flags())
            .run(restart),
    );
    t.add(
        app,
        Node::new("rollback APP [--to REVISION]", "Roll an app back to an earlier revision")
            .long("Roll an app back to an earlier revision with a rolling update.\n\nWithout --to, a rollout in progress is cancelled; otherwise the app\nreturns to the revision before the active one. Revisions keep their\npinned image digest, so a rollback runs exactly the image that ran before.\nREVISION is a full name (web--r3) or its number (r3).")
            .example("  armada app rollback api              # to the revision before the active one\n  armada app rollback api --to r11     # to one revision (armada revision list api)\n  armada app rollback api --wait       # and wait until it serves")
            .args(Args::Exact(1))
            .flag(Flag::string("to", None, "", "the revision to return to (default: the one before the active one)"))
            .flags(wait_flags())
            .run(rollback),
    );
    t.add(
        app,
        Node::new("traffic APP REVISION=WEIGHT...", "Split an app's requests between revisions until the next update")
            .long("Split the requests of an app in multiple revision mode (revisions.mode:\nmultiple) between its revisions until its next update. Weights are\npercent and add up to 100; a revision left out stops serving, and one\nwith weight 0 is reached only through its label. Labels stay as the\nspec set them. REVISION is a full name (web--r3) or its number (r3).")
            .example("  armada app traffic web web--r3=90 web--r4=10\n  armada app traffic web r4=100")
            .args(Args::Min(2))
            .run(traffic),
    );
    t.add(app, super::streams::logs_node(false));
    t.add(app, super::streams::exec_node());
    t.add(app, super::streams::app_top_node());
    t.add(app, super::streams::events_node(false));
    t.add(
        app,
        Node::new("delete APP --yes", "Stop an app's replicas and delete it with its revisions and secrets")
            .aliases(&["rm"])
            .long("Stops serving the app, drains its replicas, and deletes it with its revisions\nand secrets. This cannot be undone. Its volumes and their data stay until\n`armada volume delete`, and creating the same name again finds them.")
            .example("  armada app delete api --yes   # drain its replicas, then delete it")
            .args(Args::Exact(1))
            .flag(Flag::bool("yes", None, false, "confirm deleting the app"))
            .run(delete),
    );
    app
}

pub fn add_revision(t: &mut Tree) -> usize {
    let n = t.add(
        0,
        Node::new("revision", "List and show an app's revisions")
            .aliases(&["revisions"])
            .noun(),
    );
    t.add(
        n,
        Node::new("list APP", "List an app's revisions")
            .aliases(&["ls"])
            .args(Args::Exact(1))
            .example("  armada revision list api")
            .flag(output_flag(false))
            .run(revision_list),
    );
    t.add(
        n,
        Node::new("show REVISION", "Show one revision of an app")
            .long("Show one revision of an app. REVISION is its full name, such as web--r3.")
            .args(Args::Exact(1))
            .example("  armada revision show api--r12          # image digest, platforms, secret versions\n  armada revision show api--r12 -o json")
            .flag(output_flag(false))
            .run(revision_show),
    );
    n
}

/// --wait and --timeout of a command that starts a rollout.
pub fn wait_flags() -> Vec<Flag> {
    vec![
        Flag::bool(
            "wait",
            None,
            false,
            "wait until the rollout completes; fail if it is aborted",
        ),
        Flag::duration("timeout", None, 15 * go::MINUTE, "how long --wait waits"),
    ]
}

pub struct WaitFlags {
    pub wait: bool,
    pub timeout: i64,
}

impl WaitFlags {
    pub fn of(ctx: &Ctx<'_>) -> WaitFlags {
        WaitFlags {
            wait: ctx.bool("wait"),
            timeout: ctx.duration("timeout"),
        }
    }
}

/// How often --wait checks.
pub const WAIT_POLL: StdDuration = StdDuration::from_secs(1);

/// serving: replicas that take traffic.
fn serving(a: &AppStatus) -> i64 {
    a.replicas.iter().filter(|r| r.ready && !r.draining).count() as i64
}

/// Until revision serves, or fails, or another replaces it.
pub fn wait_rollout(
    ctx: &mut Ctx<'_>,
    admin: &mut Admin,
    app: &str,
    revision: &str,
    timeout: i64,
) -> Result {
    let deadline = std::time::Instant::now() + StdDuration::from_nanos(timeout.max(0) as u64);
    let timed_out = || {
        Error::Msg(format!(
            "timed out after {} waiting for {revision}; the rollout continues on the server",
            go::format_duration(timeout)
        ))
    };
    let mut last = String::new();
    loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            return Err(timed_out());
        }
        let req = StatusRequest {
            app: app.to_string(),
            ..Default::default()
        };
        let resp = ctx.block_on(async {
            tokio::time::timeout(
                left,
                admin.call(move |mut c| async move { c.status(req).await }),
            )
            .await
        });
        let resp = match resp {
            Err(_) => return Err(timed_out()),
            Ok(Err(s)) => return Err(rpc_err(s)),
            Ok(Ok(r)) => r,
        };
        let Some(a) = resp.apps.first() else {
            return Err(Error::Msg(format!("app {app} not found")));
        };
        let mut desired = i64::from(a.desired_replicas);
        if !a.traffic.is_empty() && a.active_revision == revision {
            desired = -1;
            for t in &a.traffic {
                if t.revision == revision {
                    desired = i64::from(t.replicas);
                }
            }
            if desired < 0 {
                ctx.print(&format!(
                    "{revision} takes no traffic; traffic: {}\n",
                    traffic_summary(&a.traffic)
                ));
                return Ok(());
            }
        }
        let ready = a
            .replicas
            .iter()
            .filter(|r| r.revision == revision && r.ready && !r.draining)
            .count() as i64;
        if a.active_revision == revision && a.rollout_state.is_empty() && ready >= desired {
            ctx.print(&format!("{revision} is live ({ready}/{desired} ready)\n"));
            return Ok(());
        }
        if a.target_revision != revision {
            if a.rollout_state == ROLLOUT_FAILED {
                return Err(Error::Msg(format!(
                    "rollout of {revision} failed: {}; {} stays active",
                    a.rollout_message, a.active_revision
                )));
            }
            return Err(Error::Msg(format!(
                "rollout of {revision} was replaced by {}",
                a.target_revision
            )));
        }
        let line = format!("{revision}: {ready}/{desired} ready");
        if line != last {
            ctx.print(&format!("{line}\n"));
            last = line;
        }
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left < WAIT_POLL {
            std::thread::sleep(left);
            return Err(timed_out());
        }
        std::thread::sleep(WAIT_POLL);
    }
}

/// "web--r3 90%, web--r4 10% (canary)".
pub fn traffic_summary(traffic: &[TrafficTarget]) -> String {
    traffic
        .iter()
        .map(|t| {
            let mut p = format!("{} {}%", t.revision, t.weight);
            if !t.label.is_empty() {
                p.push_str(&format!(" ({})", t.label));
            }
            p
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Every page.
pub fn list_apps(
    ctx: &mut Ctx<'_>,
    admin: &mut Admin,
    mut req: ListAppsRequest,
) -> Result<Vec<AppSummary>> {
    let mut apps = Vec::new();
    loop {
        let r = req.clone();
        let resp = rpc!(ctx, admin, list_apps, r).map_err(rpc_err)?;
        apps.extend(resp.apps);
        if resp.next_page_token.is_empty() || resp.next_page_token == req.page_token {
            return Ok(apps);
        }
        req = ListAppsRequest {
            space: req.space,
            all_spaces: req.all_spaces,
            page_size: req.page_size,
            page_token: resp.next_page_token,
        };
    }
}

fn list(ctx: &mut Ctx<'_>, _: &[String]) -> Result {
    let o = Output::of(ctx, false);
    o.check()?;
    let mut admin = ctx.admin()?;
    let req = ListAppsRequest {
        space: ctx.g.space.clone(),
        all_spaces: ctx.g.all_spaces,
        ..Default::default()
    };
    let apps = list_apps(ctx, &mut admin, req)?;
    if o.json() {
        return print_json(
            ctx,
            &ListAppsResponse {
                apps,
                next_page_token: String::new(),
            },
        );
    }
    let spaces = ctx.g.all_spaces;
    let mut tw = TabWriter::new(0, 2);
    let mut head = "NAME\tREADY\tSTATE\tREVISION\tIMAGE\tURL".to_string();
    if spaces {
        head = format!("SPACE\t{head}");
    }
    tw.write(&format!("{head}\n"));
    for a in &apps {
        let (p, name) =
            spec::validate::split_app_id(&a.name).unwrap_or((String::new(), a.name.clone()));
        let mut rev = dash(&a.revision);
        let mut image = a.image.clone();
        if !a.target_revision.is_empty() {
            rev = format!("{rev} → {}", a.target_revision);
            if !a.target_image.is_empty() {
                image = a.target_image.clone();
            }
        }
        let mut line = format!(
            "{name}\t{}/{}\t{}\t{rev}\t{image}\t{}",
            a.ready,
            a.desired,
            dash(&a.state),
            dash(&a.url)
        );
        if spaces {
            line = format!("{p}\t{line}");
        }
        tw.write(&format!("{line}\n"));
    }
    let out = tw.finish();
    ctx.print(&out);
    Ok(())
}

fn show(ctx: &mut Ctx<'_>, args: &[String]) -> Result {
    let mut args = args.to_vec();
    ctx.qualify(&mut args)?;
    let o = Output::of(ctx, true);
    o.check()?;
    let mut admin = ctx.admin()?;
    if o.format == OUTPUT_YAML {
        return print_spec(ctx, &mut admin, &args[0], false);
    }
    let req = StatusRequest {
        app: args[0].clone(),
        ..Default::default()
    };
    let resp = rpc!(ctx, admin, status, req).map_err(rpc_err)?;
    let Some(a) = resp.apps.into_iter().next() else {
        return Err(Error::Msg(format!("app {} not found", args[0])));
    };
    if o.json() {
        return print_json(ctx, &a);
    }
    let text = print_app(&a);
    ctx.print(&text);
    Ok(())
}

/// The spec an app or job runs, exactly as GetAppSpec returns
/// it.
pub fn print_spec(ctx: &mut Ctx<'_>, admin: &mut Admin, id: &str, job: bool) -> Result {
    let req = GetAppSpecRequest {
        app: id.to_string(),
    };
    let resp = rpc!(ctx, admin, get_app_spec, req).map_err(rpc_err)?;
    let (p, _) = app_target(id);
    if let Ok(sp) = spec::parse_in(&resp.spec, &p) {
        check_kind(&sp, job, "show")?;
    }
    let _ = ctx.out.write_all(&resp.spec);
    Ok(())
}

/// restarts: "3 (12m ago)".
fn restarts(r: &ReplicaStatus, now: i128) -> String {
    let mut n = r.restarts.to_string();
    if let Some(t) = &r.last_restart_at
        && r.restarts > 0
    {
        n.push_str(&format!(
            " ({} ago)",
            go::format_duration(round_second(since(t, now)))
        ));
    }
    n
}

/// "2-10 replicas, http 34/50, cpu 61%/70%: steady".
fn autoscale_note(a: &Autoscale) -> String {
    let mut parts = vec![format!("{}-{} replicas", a.min, a.max)];
    for r in &a.rules {
        match r.r#type.as_str() {
            "schedule" => {
                match &r.until {
                    Some(t) => parts.push(format!("schedule {} until {}", r.target, day_clock(t))),
                    None => parts.push(format!("schedule {} (closed)", r.target)),
                }
                continue;
            }
            "queue" | "redis" | "rabbitmq" => {
                let cur = if r.measured {
                    r.current.to_string()
                } else {
                    "-".to_string()
                };
                parts.push(format!("{} {cur}/{} per replica", r.r#type, r.target));
                continue;
            }
            _ => {}
        }
        let unit = if r.r#type != "http" { "%" } else { "" };
        let cur = if r.measured {
            format!("{}{unit}", r.current)
        } else {
            "-".to_string()
        };
        parts.push(format!("{} {cur}/{}{unit}", r.r#type, r.target));
    }
    let mut note = parts.join(", ");
    if !a.message.is_empty() {
        note.push_str(&format!(": {}", printable(&a.message)));
    }
    note
}

/// replicaState.
pub fn replica_state(r: &ReplicaStatus) -> String {
    if r.draining {
        return "draining".to_string();
    }
    if r.state == "running" && !r.ready {
        return "running (not ready)".to_string();
    }
    r.state.clone()
}

/// printApp.
fn print_app(a: &AppStatus) -> String {
    let now = now_nanos();
    let mut tw = TabWriter::new(0, 2);
    let field = |tw: &mut TabWriter, k: &str, v: &str| tw.write(&format!("{k}:\t{v}\n"));
    field(&mut tw, "Name", &a.name);
    field(&mut tw, "Revision", &dash(&a.active_revision));
    field(&mut tw, "Image", &a.image);
    field(
        &mut tw,
        "Ready",
        &format!("{}/{}", serving(a), a.desired_replicas),
    );
    field(&mut tw, "Ingress", &dash(&a.ingress));
    for (key, rules) in [("Allowed from", &a.ip_allow), ("Denied from", &a.ip_deny)] {
        for (i, r) in rules.iter().enumerate() {
            let k = if i > 0 {
                String::new()
            } else {
                format!("{key}:")
            };
            let mut line = printable(&r.range);
            let mut note = r.name.clone();
            if !r.description.is_empty() {
                let joined = format!("{note}: {}", r.description);
                note = joined.strip_prefix(": ").unwrap_or(&joined).to_string();
            }
            if !note.is_empty() {
                line.push_str(&format!("  {}", printable(&note)));
            }
            tw.write(&format!("{k}\t{line}\n"));
        }
    }
    match a.rollout_state.as_str() {
        ROLLOUT_PROGRESSING => field(
            &mut tw,
            "Rollout",
            &format!(
                "rolling out {}; {} serves until it is ready",
                a.target_revision, a.active_revision
            ),
        ),
        ROLLOUT_FAILED => {
            let mut stays = format!("{} stays active", a.active_revision);
            let (ready, want) = (serving(a), i64::from(a.desired_replicas));
            if ready < want {
                stays.push_str(&format!(
                    ", but only {ready}/{want} of its replicas are ready"
                ));
            }
            field(
                &mut tw,
                "Rollout",
                &format!("failed: {}; {stays}", printable(&a.rollout_message)),
            );
        }
        _ => {}
    }
    if !a.placement_message.is_empty() {
        field(&mut tw, "Placement", &printable(&a.placement_message));
    }
    if let Some(as_) = &a.autoscale {
        field(&mut tw, "Autoscale", &autoscale_note(as_));
        if as_.last_scaled_at.is_some() {
            field(
                &mut tw,
                "Last scaled",
                &ago(as_.last_scaled_at.as_ref(), now),
            );
        }
    }
    if !a.traffic.is_empty() {
        field(&mut tw, "Traffic", &traffic_summary(&a.traffic));
    }
    for (i, u) in a.urls.iter().enumerate() {
        let k = if i > 0 { "" } else { "URLs:" };
        tw.write(&format!("{k}\t{u}\n"));
    }
    for t in &a.traffic {
        for u in &t.urls {
            tw.write(&format!("\t{u} ({})\n", t.revision));
        }
    }
    if !a.replicas.is_empty() {
        tw.write("\nREPLICA\tREVISION\tNODE\tSTATE\tRESTARTS\tADDRESS\tMESSAGE\n");
        for r in &a.replicas {
            tw.write(&format!(
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
                r.id,
                r.revision,
                r.node_id,
                replica_state(r),
                restarts(r, now),
                dash(&r.address),
                dash(&printable(&r.message))
            ));
        }
    }
    tw.finish()
}

/// r3 becomes APP--r3; full names pass.
fn revision_name(app: &str, rev: &str) -> String {
    if rev.starts_with('r') && !rev.contains("--") {
        return format!("{app}--{rev}");
    }
    rev.to_string()
}

fn rollback(ctx: &mut Ctx<'_>, args: &[String]) -> Result {
    let mut args = args.to_vec();
    ctx.qualify(&mut args)?;
    let mut req = RollbackRequest {
        app: args[0].clone(),
        ..Default::default()
    };
    let to = ctx.str("to");
    if !to.is_empty() {
        req.revision = revision_name(&args[0], &to);
    }
    let mut admin = ctx.admin()?;
    let resp = rpc!(ctx, admin, rollback, req).map_err(rpc_err)?;
    ctx.print(&format!("Rolling {} back to {}.\n", args[0], resp.revision));
    let w = WaitFlags::of(ctx);
    if !w.wait {
        return Ok(());
    }
    wait_rollout(ctx, &mut admin, &args[0], &resp.revision, w.timeout)
}

fn restart(ctx: &mut Ctx<'_>, args: &[String]) -> Result {
    let mut args = args.to_vec();
    ctx.qualify(&mut args)?;
    let mut admin = ctx.admin()?;
    let req = RestartAppRequest {
        app: args[0].clone(),
    };
    let resp = rpc!(ctx, admin, restart_app, req).map_err(rpc_err)?;
    ctx.print(&format!("Restarting {} as {}.\n", args[0], resp.revision));
    let w = WaitFlags::of(ctx);
    if !w.wait {
        return Ok(());
    }
    wait_rollout(ctx, &mut admin, &args[0], &resp.revision, w.timeout)
}

fn traffic(ctx: &mut Ctx<'_>, args: &[String]) -> Result {
    let mut args = args.to_vec();
    ctx.qualify(&mut args)?;
    let app = args[0].clone();
    let mut req = SetTrafficRequest {
        app: app.clone(),
        ..Default::default()
    };
    for a in &args[1..] {
        let parsed = a.split_once('=').and_then(|(rev, w)| {
            let n = go::atoi(w).ok()?;
            (0..=100).contains(&n).then(|| (rev.to_string(), n))
        });
        let Some((rev, n)) = parsed else {
            return Err(Error::Msg(format!(
                "{}: want REVISION=WEIGHT with a weight from 0 to 100",
                go::quote(a)
            )));
        };
        req.traffic.push(TrafficTarget {
            revision: revision_name(&app, &rev),
            weight: n as i32,
            ..Default::default()
        });
    }
    let mut admin = ctx.admin()?;
    let resp = rpc!(ctx, admin, set_traffic, req).map_err(rpc_err)?;
    ctx.print(&format!(
        "Traffic of {app}: {}.\n",
        traffic_summary(&resp.traffic)
    ));
    Ok(())
}

fn delete(ctx: &mut Ctx<'_>, args: &[String]) -> Result {
    let mut args = args.to_vec();
    ctx.qualify(&mut args)?;
    if !ctx.bool("yes") {
        return Err(Error::Msg(format!(
            "this deletes app {} with its revisions and secrets; pass --yes to confirm",
            args[0]
        )));
    }
    let mut admin = ctx.admin()?;
    let req = RemoveAppRequest {
        app: args[0].clone(),
    };
    rpc!(ctx, admin, remove_app, req).map_err(rpc_err)?;
    ctx.print(&format!(
        "Deleting {}: it is gone once its replicas have drained.\n",
        args[0]
    ));
    Ok(())
}

fn list_revisions(ctx: &mut Ctx<'_>, app: &str) -> Result<ListRevisionsResponse> {
    let mut admin = ctx.admin()?;
    let req = ListRevisionsRequest {
        app: app.to_string(),
    };
    rpc!(ctx, admin, list_revisions, req).map_err(rpc_err)
}

fn revision_status(r: &RevisionInfo) -> &'static str {
    match (r.active, r.target) {
        (true, true) => "active",
        (true, false) => "active (rolling out another)",
        (false, true) => "rolling out",
        _ => "-",
    }
}

fn revision_list(ctx: &mut Ctx<'_>, args: &[String]) -> Result {
    let mut args = args.to_vec();
    ctx.qualify(&mut args)?;
    let o = Output::of(ctx, false);
    o.check()?;
    let resp = list_revisions(ctx, &args[0])?;
    if o.json() {
        return print_json(ctx, &resp);
    }
    let mut tw = TabWriter::new(0, 2);
    tw.write("REVISION\tSTATUS\tCREATED\tIMAGE\tPLATFORMS\tDIGEST\n");
    for r in &resp.revisions {
        tw.write(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\n",
            r.name,
            revision_status(r),
            date_time(r.created_at.as_ref()),
            r.image,
            dash(&r.platforms.join(",")),
            dash(&r.image_digest)
        ));
    }
    let out = tw.finish();
    ctx.print(&out);
    Ok(())
}

fn revision_show(ctx: &mut Ctx<'_>, args: &[String]) -> Result {
    let o = Output::of(ctx, false);
    o.check()?;
    let i = match args[0].rfind("--") {
        Some(i) if i > 0 => i,
        _ => {
            return Err(Error::Msg(format!(
                "{}: want a revision name such as web--r3",
                go::quote(&args[0])
            )));
        }
    };
    let app = ctx.app_id(&args[0][..i]).map_err(Error::Msg)?;
    let name = format!("{app}{}", &args[0][i..]);
    let resp = list_revisions(ctx, &app)?;
    for r in &resp.revisions {
        if r.name != name {
            continue;
        }
        if o.json() {
            return print_json(ctx, r);
        }
        let mut tw = TabWriter::new(0, 2);
        tw.write(&format!(
            "Revision:\t{}\nStatus:\t{}\nCreated:\t{}\nImage:\t{}\nDigest:\t{}\nPlatforms:\t{}\n",
            r.name,
            revision_status(r),
            date_time(r.created_at.as_ref()),
            r.image,
            dash(&r.image_digest),
            dash(&r.platforms.join(","))
        ));
        let out = tw.finish();
        ctx.print(&out);
        return Ok(());
    }
    Err(Error::Msg(format!("revision {name} not found")))
}
