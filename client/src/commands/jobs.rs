//! armada job and armada run.

use std::time::{Duration as StdDuration, Instant};

use armada_proto::armada::v1::{
    CancelJobRequest, DeleteJobRequest, JobInfo, JobRunInfo, JobTaskInfo, JobTrigger,
    ListJobRunsRequest, ListJobsRequest, ListJobsResponse, RunJobRequest,
};
use armada_spec as spec;
use armada_spec::go;
use tonic::Code;

use super::app::{WAIT_POLL, print_spec};
use super::deploy::run_deploy;
use super::{
    OUTPUT_YAML, Output, ago, dash, date_time, human_duration, now_nanos, output_flag, print_json,
    rpc_err, since, until,
};
use crate::cli::flags::Flag;
use crate::cli::tabwriter::TabWriter;
use crate::cli::{Args, Ctx, Error, Node, Result, Tree};
use crate::rpc;
use crate::rpc::{Admin, printable};

pub fn add_job(t: &mut Tree) -> usize {
    let job = t.add(
        0,
        Node::new("job", "Deploy, start, and inspect jobs")
            .aliases(&["jobs"])
            .long("Jobs run a container to completion, on demand (`armada job start`), on a\nschedule, or from a queue. Deploy one from flags or a spec file (kind: job).")
            .noun(),
    );
    let (flags, _) = super::deploy::flags(true);
    t.add(
        job,
        Node::new("deploy JOB [flags] | --file FILE", "Create or change a job from flags or a spec file")
            .long("Create a job, or change one; new runs use the new revision. With flags, only\nwhat they name changes, and the deploy is refused when another change landed\nsince the spec was read; a new job needs --image. With --file (kind: job, -\nfor stdin), the file replaces the whole spec. --new refuses a job that\nexists; --diff prints what would change and changes nothing.")
            .example("  armada job deploy migrate --image ghcr.io/acme/api:1.4 --command ./migrate --secret-env DATABASE_URL=database-url\n  armada job deploy report --image ghcr.io/acme/report:2 --schedule \"0 3 * * *\" --time-zone Asia/Jakarta\n  armada job deploy --file migrate.yaml --diff")
            .args(Args::Max(1))
            .flags(flags)
            .run(|ctx, args| run_deploy(ctx, args, true)),
    );
    t.add(
        job,
        Node::new("list", "List jobs with their schedule and latest run")
            .aliases(&["ls"])
            .args(Args::No)
            .example("  armada job list\n  armada job list -o json")
            .flag(output_flag(false))
            .run(list),
    );
    t.add(
        job,
        Node::new("show JOB", "Show a job: its schedule, revision, and latest run")
            .long("Show a job: its schedule, revision, and latest run. -o yaml prints the spec\nit runs as a file holds it, ready for create --file or update --file.")
            .args(Args::Exact(1))
            .example("  armada job show migrate     # schedule, revision, latest run")
            .flag(output_flag(true))
            .run(show),
    );
    t.add(
        job,
        Node::new("start JOB", "Start a run of a job now")
            .long("Start a run of a job now. `armada run list JOB` lists its runs.\n\nWith --wait the command ends when the run does and fails unless the run\nsucceeded, so a script can stop on a failed step such as a migration. A\nrun still going after --timeout keeps going; cancel it with `armada job cancel`.")
            .example("  armada job start migrate --wait --timeout 5m\n  armada run list migrate")
            .args(Args::Exact(1))
            .flag(Flag::bool("wait", None, false, "wait until the run ends; fail unless it succeeded"))
            .flag(Flag::duration("timeout", None, 15 * go::MINUTE, "how long --wait waits"))
            .run(start),
    );
    t.add(job, super::streams::logs_node(true));
    t.add(
        job,
        Node::new("cancel JOB", "Stop a job's pending and running runs")
            .args(Args::Exact(1))
            .example("  armada job cancel migrate   # stop its pending and running runs")
            .run(cancel),
    );
    t.add(
        job,
        Node::new("delete JOB", "Delete a job, stopping its runs and removing their records and logs")
            .aliases(&["rm"])
            .long("Delete a job, stopping its runs and removing their records and logs. Its secrets are kept;\ndelete them with `armada secret delete`.")
            .args(Args::Exact(1))
            .example("  armada job delete migrate")
            .run(delete),
    );
    job
}

pub fn add_run(t: &mut Tree) -> usize {
    let n = t.add(
        0,
        Node::new("run", "List and show a job's runs")
            .aliases(&["runs"])
            .long("A run is one start of a job: now with `armada job start`, on its schedule, or\nfrom its queue. A run with tasks has one attempt per task.")
            .noun(),
    );
    t.add(
        n,
        Node::new("list JOB", "List a job's runs, newest first")
            .aliases(&["ls"])
            .long("List a job's runs, newest first. Finished runs beyond the job's history (5 by default)\nare removed; their logs are kept for 24 hours.")
            .args(Args::Exact(1))
            .example("  armada run list migrate")
            .flag(output_flag(false))
            .run(run_list),
    );
    t.add(
        n,
        Node::new("show JOB RUN", "Show a run of a job, with its tasks")
            .args(Args::Exact(2))
            .example("  armada run show migrate 12   # one run, with its tasks")
            .flag(output_flag(false))
            .run(run_show),
    );
    n
}

fn start(ctx: &mut Ctx<'_>, args: &[String]) -> Result {
    let mut args = args.to_vec();
    ctx.qualify(&mut args)?;
    let mut admin = ctx.admin()?;
    let req = RunJobRequest {
        job: args[0].clone(),
    };
    let resp = rpc!(ctx, admin, run_job, req).map_err(rpc_err)?;
    ctx.print(&format!("Started run {} of {}.\n", resp.run, args[0]));
    if !ctx.bool("wait") {
        return Ok(());
    }
    let timeout = ctx.duration("timeout");
    wait_job_run(ctx, &mut admin, &args[0], resp.run, timeout)
}

/// Until the run ends; an error unless it succeeded.
fn wait_job_run(ctx: &mut Ctx<'_>, admin: &mut Admin, job: &str, run: i64, timeout: i64) -> Result {
    let deadline = Instant::now() + StdDuration::from_nanos(timeout.max(0) as u64);
    let timed_out = || {
        Error::Msg(format!(
            "run {run} of {job} did not end within {}; it keeps going (`armada job cancel {job}` stops it)",
            go::format_duration(timeout)
        ))
    };
    let mut next = Instant::now();
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(timed_out());
        }
        let req = ListJobRunsRequest {
            job: job.to_string(),
        };
        let resp = ctx.block_on(async {
            tokio::time::timeout(
                left,
                admin.call(move |mut c| async move { c.list_job_runs(req).await }),
            )
            .await
        });
        match resp {
            Ok(Ok(resp)) => {
                let Some(r) = resp.runs.iter().find(|r| r.run == run) else {
                    return Err(Error::Msg(format!(
                        "run {run} of {job} is gone; it left the job's history before it could be read"
                    )));
                };
                if let Some(res) = job_run_result(r) {
                    if res.is_ok() {
                        ctx.print(&format!("Run {run} of {job} succeeded.\n"));
                    }
                    return res;
                }
            }
            Ok(Err(s)) if s.code() != Code::Unavailable && !Instant::now().ge(&deadline) => {
                return Err(rpc_err(s));
            }
            _ => {}
        }
        next += WAIT_POLL;
        let now = Instant::now();
        if next <= now {
            next = now + WAIT_POLL;
        }
        if next >= deadline {
            std::thread::sleep(deadline.saturating_duration_since(Instant::now()));
            return Err(timed_out());
        }
        std::thread::sleep(next - now);
    }
}

/// None while the run goes on.
fn job_run_result(r: &JobRunInfo) -> Option<Result> {
    match r.state.as_str() {
        "pending" | "running" => return None,
        "succeeded" => return Some(Ok(())),
        _ => {}
    }
    let mut why = r.state.clone();
    if r.exit_code != 0 {
        why.push_str(&format!(" with exit code {}", r.exit_code));
    }
    let m = printable(&r.message);
    if !m.is_empty() {
        why.push_str(&format!(": {m}"));
    }
    Some(Err(Error::Msg(format!(
        "run {} of {} {why}; see `armada job logs {} --run {}`",
        r.run, r.job, r.job, r.run
    ))))
}

fn list_jobs(ctx: &mut Ctx<'_>) -> Result<ListJobsResponse> {
    let mut admin = ctx.admin()?;
    rpc!(ctx, admin, list_jobs, ListJobsRequest {}).map_err(rpc_err)
}

fn job_schedule(j: &JobInfo) -> String {
    if let Some(tr) = &j.trigger {
        return format!("queue ({} {})", tr.r#type, tr.name);
    }
    if j.schedule.is_empty() {
        return "-".to_string();
    }
    if !j.time_zone.is_empty() {
        return format!("{} ({})", j.schedule, j.time_zone);
    }
    j.schedule.clone()
}

fn list(ctx: &mut Ctx<'_>, _: &[String]) -> Result {
    let o = Output::of(ctx, false);
    o.check()?;
    let mut resp = list_jobs(ctx)?;
    resp.jobs.retain(|j| ctx.listed(&j.name));
    if o.json() {
        return print_json(ctx, &resp);
    }
    let now = now_nanos();
    let all = ctx.g.all_spaces;
    let mut tw = TabWriter::new(0, 2);
    let mut head = "NAME\tSCHEDULE\tLAST RUN\tSTATE\tFINISHED\tNEXT RUN".to_string();
    if all {
        head = format!("SPACE\t{head}");
    }
    tw.write(&format!("{head}\n"));
    for j in &resp.jobs {
        let (mut last, mut state, mut finished) =
            ("-".to_string(), "-".to_string(), "-".to_string());
        if let Some(r) = &j.last_run {
            last = r.run.to_string();
            state = r.state.clone();
            finished = ago(r.finished_at.as_ref(), now);
        }
        let mut next = "-".to_string();
        if let Some(n) = &j.next_run {
            next = format!("in {}", human_duration(until(n, now)));
        } else if let Some(tr) = &j.trigger
            && tr.measured
        {
            next = format!("{} waiting", tr.length);
        }
        let (p, name) = spec::validate::split_app_id(&j.name).unwrap_or_default();
        let mut line = format!(
            "{name}\t{}\t{last}\t{state}\t{finished}\t{next}",
            job_schedule(j)
        );
        if all {
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
    if o.format == OUTPUT_YAML {
        let mut admin = ctx.admin()?;
        return print_spec(ctx, &mut admin, &args[0], true);
    }
    let resp = list_jobs(ctx)?;
    let Some(j) = resp.jobs.iter().find(|j| j.name == args[0]) else {
        return Err(Error::Msg(format!("job {} not found", args[0])));
    };
    if o.json() {
        return print_json(ctx, j);
    }
    let now = now_nanos();
    let mut next = "-".to_string();
    if let Some(n) = &j.next_run {
        next = format!(
            "{} (in {})",
            date_time(Some(n)),
            human_duration(until(n, now))
        );
    }
    let mut last = "-".to_string();
    if let Some(r) = &j.last_run {
        last = format!("{}, {}", r.run, r.state);
        if r.finished_at.is_some() {
            last.push_str(&format!(", finished {}", ago(r.finished_at.as_ref(), now)));
        }
    }
    let mut tw = TabWriter::new(0, 2);
    if let Some(tr) = &j.trigger {
        tw.write(&format!(
            "Name:\t{}\nRevision:\t{}\nImage:\t{}\nTrigger:\t{}\nQueue:\t{}\nLast run:\t{last}\nActive runs:\t{}\n",
            j.name,
            dash(&j.revision),
            j.image,
            trigger_line(tr),
            queue_line(tr, now),
            j.active
        ));
    } else {
        tw.write(&format!(
            "Name:\t{}\nRevision:\t{}\nImage:\t{}\nSchedule:\t{}\nNext run:\t{next}\nLast run:\t{last}\nActive runs:\t{}\n",
            j.name,
            dash(&j.revision),
            j.image,
            job_schedule(j),
            j.active
        ));
    }
    let out = tw.finish();
    ctx.print(&out);
    Ok(())
}

fn run_list(ctx: &mut Ctx<'_>, args: &[String]) -> Result {
    let mut args = args.to_vec();
    ctx.qualify(&mut args)?;
    let o = Output::of(ctx, false);
    o.check()?;
    let mut admin = ctx.admin()?;
    let req = ListJobRunsRequest {
        job: args[0].clone(),
    };
    let resp = rpc!(ctx, admin, list_job_runs, req).map_err(rpc_err)?;
    if o.json() {
        return print_json(ctx, &resp);
    }
    let text = print_runs(&resp.runs, now_nanos());
    ctx.print(&text);
    Ok(())
}

fn print_runs(runs: &[JobRunInfo], now: i128) -> String {
    let mut tw = TabWriter::new(0, 2);
    tw.write("RUN\tSTATE\tTRIGGER\tATTEMPTS\tNODE\tSTARTED\tDURATION\tEXIT\tMESSAGE\n");
    for r in runs {
        let mut dur = "-".to_string();
        if let Some(s) = &r.started_at {
            let d = match &r.finished_at {
                Some(f) => {
                    let end = i128::from(f.seconds) * 1_000_000_000 + i128::from(f.nanos);
                    since(s, end)
                }
                None => since(s, now),
            };
            dur = human_duration(d);
        }
        let exit = if r.state == "succeeded" || r.exit_code != 0 {
            r.exit_code.to_string()
        } else {
            "-".to_string()
        };
        let mut msg = printable(&r.message);
        let t = tasks_done(r);
        if !t.is_empty() {
            let joined = format!("{t}; {msg}");
            msg = joined.strip_suffix("; ").unwrap_or(&joined).to_string();
        }
        if msg.is_empty() {
            msg = "-".to_string();
        }
        tw.write(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{dur}\t{exit}\t{msg}\n",
            r.run,
            r.state,
            r.trigger,
            r.attempts,
            dash(&r.node),
            ago(r.started_at.as_ref(), now)
        ));
    }
    tw.finish()
}

/// "3/10 tasks".
fn tasks_done(r: &JobRunInfo) -> String {
    if r.tasks.is_empty() {
        return String::new();
    }
    let n = r.tasks.iter().filter(|t| t.state == "succeeded").count();
    format!("{n}/{} tasks", r.tasks.len())
}

fn run_show(ctx: &mut Ctx<'_>, args: &[String]) -> Result {
    let mut args = args.to_vec();
    ctx.qualify(&mut args[..1])?;
    let o = Output::of(ctx, false);
    o.check()?;
    let seq = match go::parse_int(&args[1]) {
        Ok(n) if n >= 1 => n,
        _ => {
            return Err(Error::Msg(format!(
                "run must be a number such as 3, not {}",
                go::quote(&args[1])
            )));
        }
    };
    let mut admin = ctx.admin()?;
    let req = ListJobRunsRequest {
        job: args[0].clone(),
    };
    let resp = rpc!(ctx, admin, list_job_runs, req).map_err(rpc_err)?;
    for r in &resp.runs {
        if r.run != seq {
            continue;
        }
        if o.json() {
            return print_json(ctx, r);
        }
        let text = print_runs(std::slice::from_ref(r), now_nanos());
        ctx.print(&text);
        if r.tasks.is_empty() {
            return Ok(());
        }
        ctx.print("\n");
        let text = print_tasks(&r.tasks);
        ctx.print(&text);
        return Ok(());
    }
    Err(Error::Msg(format!(
        "run {seq} of {} not found (finished runs beyond the job's history are removed)",
        args[0]
    )))
}

fn print_tasks(tasks: &[JobTaskInfo]) -> String {
    let mut tw = TabWriter::new(0, 2);
    tw.write("TASK\tSTATE\tATTEMPTS\tNODE\tEXIT\tMESSAGE\n");
    for t in tasks {
        let exit = if t.state == "succeeded" || t.exit_code != 0 {
            t.exit_code.to_string()
        } else {
            "-".to_string()
        };
        tw.write(&format!(
            "{}\t{}\t{}\t{}\t{exit}\t{}\n",
            t.index,
            t.state,
            t.attempts,
            dash(&t.node),
            dash(&printable(&t.message))
        ));
    }
    tw.finish()
}

fn cancel(ctx: &mut Ctx<'_>, args: &[String]) -> Result {
    let mut args = args.to_vec();
    ctx.qualify(&mut args)?;
    let mut admin = ctx.admin()?;
    let req = CancelJobRequest {
        job: args[0].clone(),
    };
    let resp = rpc!(ctx, admin, cancel_job, req).map_err(rpc_err)?;
    if resp.runs.is_empty() {
        ctx.print(&format!("{} has no active runs.\n", args[0]));
        return Ok(());
    }
    for r in resp.runs {
        ctx.print(&format!("Cancelled run {r} of {}.\n", args[0]));
    }
    Ok(())
}

fn delete(ctx: &mut Ctx<'_>, args: &[String]) -> Result {
    let mut args = args.to_vec();
    ctx.qualify(&mut args)?;
    let mut admin = ctx.admin()?;
    let req = DeleteJobRequest {
        job: args[0].clone(),
    };
    rpc!(ctx, admin, delete_job, req).map_err(rpc_err)?;
    ctx.print(&format!("Deleted job {}.\n", args[0]));
    Ok(())
}

/// a job's queue trigger.
fn trigger_line(tr: &JobTrigger) -> String {
    let what = if tr.r#type == spec::SCALE_RABBITMQ {
        "queue"
    } else {
        "list"
    };
    format!(
        "{} {what} {}, {} per run, at most {} at once, read every {}",
        tr.r#type,
        tr.name,
        tr.per_run,
        tr.parallelism,
        human_duration(tr.polling_interval_seconds.saturating_mul(go::SECOND))
    )
}

/// What was last read of a job's queue.
fn queue_line(tr: &JobTrigger, now: i128) -> String {
    if tr.node.is_empty() {
        return "not read: no node can (see armada cluster events)".to_string();
    }
    if !tr.measured {
        return format!("not read yet, from {}", tr.node);
    }
    format!(
        "{} waiting, read {} from {}",
        tr.length,
        ago(tr.measured_at.as_ref(), now),
        tr.node
    )
}
