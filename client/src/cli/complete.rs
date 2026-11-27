//! Shell completion: the scripts cobra v1.10.2 generates for armada (bash,
//! zsh, fish, powershell; Apache-2.0, kept as cobra writes them), the
//! hidden `__complete` command those scripts call (cobra's
//! getCompletions), and the names Tab completes from the cluster (ADR
//! 0052).

use armada_proto::armada::v1::{
    ListAlertChannelsRequest, ListAppsRequest, ListDomainsRequest, ListJobRunsRequest,
    ListJobsRequest, ListMetricsCredentialsRequest, ListPrincipalsRequest, ListRevisionsRequest,
    ListRolesRequest, ListSecretsRequest, ListSpaceSecretsRequest, ListSpacesRequest,
    ListVolumesRequest, ReplicaStatus, StatusRequest,
};
use armada_spec as spec;

use super::flags::{Flag, FlagSet, Value};
use super::{Ctx, Result, Special, Tree, arg_words};
use crate::rpc::Admin;

/// One shell's completion command.
pub struct Shell {
    pub name: &'static str,
    pub long: &'static str,
    script: &'static str,
}

pub const SHELLS: [Shell; 4] = [
    Shell {
        name: "bash",
        long: "Generate the autocompletion script for the bash shell.

This script depends on the 'bash-completion' package.
If it is not installed already, you can install it via your OS's package manager.

To load completions in your current shell session:

\tsource <(armada completion bash)

To load completions for every new session, execute once:

#### Linux:

\tarmada completion bash > /etc/bash_completion.d/armada

#### macOS:

\tarmada completion bash > $(brew --prefix)/etc/bash_completion.d/armada

You will need to start a new shell for this setup to take effect.
",
        script: include_str!("completion/bash.txt"),
    },
    Shell {
        name: "zsh",
        long: "Generate the autocompletion script for the zsh shell.

If shell completion is not already enabled in your environment you will need
to enable it.  You can execute the following once:

\techo \"autoload -U compinit; compinit\" >> ~/.zshrc

To load completions in your current shell session:

\tsource <(armada completion zsh)

To load completions for every new session, execute once:

#### Linux:

\tarmada completion zsh > \"${fpath[1]}/_armada\"

#### macOS:

\tarmada completion zsh > $(brew --prefix)/share/zsh/site-functions/_armada

You will need to start a new shell for this setup to take effect.
",
        script: include_str!("completion/zsh.txt"),
    },
    Shell {
        name: "fish",
        long: "Generate the autocompletion script for the fish shell.

To load completions in your current shell session:

\tarmada completion fish | source

To load completions for every new session, execute once:

\tarmada completion fish > ~/.config/fish/completions/armada.fish

You will need to start a new shell for this setup to take effect.
",
        script: include_str!("completion/fish.txt"),
    },
    Shell {
        name: "powershell",
        long: "Generate the autocompletion script for powershell.

To load completions in your current shell session:

\tarmada completion powershell | Out-String | Invoke-Expression

To load completions for every new session, add the output of the above command
to your powershell profile.
",
        script: include_str!("completion/powershell.txt"),
    },
];

/// A text cobra writes for armada as it writes it for another program
/// (armadad): the name, and the environment variables made of it.
pub fn for_program(text: &str, program: &str) -> String {
    if program == "armada" {
        return text.to_string();
    }
    let upper = program.to_uppercase().replace('-', "_");
    // Each script's first line pads the name to 36 columns.
    let mut text = text.to_string();
    let mut heads = Vec::new();
    for shell in [
        "bash completion V2",
        "zsh completion",
        "fish completion",
        "powershell completion",
    ] {
        let head = format!("# {shell} for {:<36} -*- shell-script -*-", "armada");
        if text.contains(&head) {
            text = text.replace(&head, "\u{0}");
            heads.push(format!("# {shell} for {program:<36} -*- shell-script -*-"));
        }
    }
    let mut text = text
        .replace("armada", program)
        .replace("ARMADA_", &format!("{upper}_"));
    for own in heads {
        text = text.replacen('\u{0}', &own, 1);
    }
    text
}

/// The run of `armada completion SHELL`.
pub fn script(ctx: &mut Ctx<'_>, _: &[String]) -> Result {
    let name = ctx.tree.node(ctx.cmd).name().to_string();
    let shell = SHELLS.iter().find(|s| s.name == name).expect("a shell");
    let script = for_program(shell.script, ctx.tree.program());
    let text = if ctx.bool("no-descriptions") {
        script.replacen(" __complete ", " __completeNoDesc ", 1)
    } else {
        script
    };
    ctx.print(&text);
    Ok(())
}

const ERROR: i32 = 1;
const NO_SPACE: i32 = 2;
const NO_FILE_COMP: i32 = 4;
const DEFAULT: i32 = 0;

fn directive_string(d: i32) -> String {
    let mut v = Vec::new();
    for (bit, name) in [
        (ERROR, "ShellCompDirectiveError"),
        (NO_SPACE, "ShellCompDirectiveNoSpace"),
        (NO_FILE_COMP, "ShellCompDirectiveNoFileComp"),
        (8, "ShellCompDirectiveFilterFileExt"),
        (16, "ShellCompDirectiveFilterDirs"),
        (32, "ShellCompDirectiveKeepOrder"),
    ] {
        if d & bit != 0 {
            v.push(name);
        }
    }
    if v.is_empty() {
        v.push("ShellCompDirectiveDefault");
    }
    v.join(", ")
}

/// What one Tab press asks the cluster for.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Apps,
    Jobs,
    Runs,
    Secrets,
    Keys,
    Revisions,
    RevisionIds,
    Weights,
    Spaces,
    Replicas,
    Containers,
    Volumes,
    Nodes,
    Roles,
    Users,
    Services,
    Alerts,
    Metrics,
    Domains,
}

/// placeholderKind.
fn placeholder_kind(noun: &str, verb: &str, word: &str) -> Option<Kind> {
    Some(match word {
        "APP" => Kind::Apps,
        "JOB" => Kind::Jobs,
        "RUN" => Kind::Runs,
        "SECRET" if verb == "create" => return None,
        "SECRET" => Kind::Secrets,
        "KEY" => Kind::Keys,
        "REVISION" if noun == "revision" => Kind::RevisionIds,
        "REVISION" => Kind::Revisions,
        "REVISION=WEIGHT" => Kind::Weights,
        "SPACE" => Kind::Spaces,
        "NODE" => Kind::Nodes,
        "ROLE" => Kind::Roles,
        "VOLUME" => Kind::Volumes,
        "DOMAIN" => Kind::Domains,
        "NAME" if verb == "create" => return None,
        "NAME" => match noun {
            "space" => Kind::Spaces,
            "user" => Kind::Users,
            "service" => Kind::Services,
            "alert" => Kind::Alerts,
            "metrics" => Kind::Metrics,
            _ => return None,
        },
        _ => return None,
    })
}

/// The completer of each placeholder of a runnable leaf.
fn arg_kinds(tree: &Tree, i: usize) -> Option<Vec<Option<Kind>>> {
    let n = tree.node(i);
    if !n.runnable() || tree.has_sub(i) || n.special != Special::None {
        return None;
    }
    let noun = n
        .parent
        .map(|p| tree.node(p).name().to_string())
        .unwrap_or_default();
    let kinds: Vec<Option<Kind>> = arg_words(n)
        .iter()
        .map(|w| placeholder_kind(&noun, n.name(), w.trim_matches(['[', ']', '.'])))
        .collect();
    if kinds.iter().all(|k| k.is_none()) {
        return None;
    }
    Some(kinds)
}

/// The flags of command i that name something.
fn flag_kind(tree: &Tree, i: usize, flag: &Flag) -> Option<Kind> {
    if flag.inherited {
        // Registered before the parents' flags were merged: never found.
        return None;
    }
    let parent = tree.node(i).parent.map(|p| tree.node(p).name());
    match flag.name.as_str() {
        "space" => Some(Kind::Spaces),
        "node" => Some(Kind::Nodes),
        "role" => Some(Kind::Roles),
        "user" => Some(Kind::Users),
        "service" => Some(Kind::Services),
        "replica" if parent == Some("app") => Some(Kind::Replicas),
        "container" if parent == Some("app") => Some(Kind::Containers),
        "to" if parent == Some("app") => Some(Kind::Revisions),
        "run" if parent == Some("job") => Some(Kind::Runs),
        _ => None,
    }
}

/// The run of `armada __complete ARGS... TO_COMPLETE`.
pub fn run(ctx: &mut Ctx<'_>, args: &[String]) {
    let no_desc = ctx_called_no_desc(ctx, args);
    let (comps, directive, err) = completions(ctx, args);
    if let Some(e) = err {
        let _ = writeln!(ctx.err, "[Debug] [Error] {e}");
    }
    for c in comps {
        let mut c = c.as_str();
        if no_desc {
            c = c.split('\t').next().unwrap_or("");
        }
        let c = c.split('\n').next().unwrap_or("").trim();
        ctx.print(&format!("{c}\n"));
    }
    ctx.print(&format!(":{directive}\n"));
    let _ = writeln!(
        ctx.err,
        "Completion ended with directive: {}",
        directive_string(directive)
    );
}

fn ctx_called_no_desc(ctx: &Ctx<'_>, _args: &[String]) -> bool {
    if CALLED_NO_DESC.with(|c| c.get()) {
        return true;
    }
    let own = for_program("ARMADA_COMPLETION_DESCRIPTIONS", ctx.tree.program());
    for k in [own.as_str(), "COBRA_COMPLETION_DESCRIPTIONS"] {
        if let Ok(v) = std::env::var(k)
            && !v.is_empty()
        {
            return super::flags::parse_bool(&v) == Some(false);
        }
    }
    false
}

thread_local! {
    /// Whether the run was `__completeNoDesc`.
    pub static CALLED_NO_DESC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// getCompletions.
fn completions(ctx: &mut Ctx<'_>, args: &[String]) -> (Vec<String>, i32, Option<String>) {
    let tree = ctx.tree;
    let to_complete = args.last().cloned().unwrap_or_default();
    let trimmed = &args[..args.len().saturating_sub(1)];
    let (fin, final_args, err) = tree.find(trimmed);
    if err.is_some() {
        return (
            Vec::new(),
            DEFAULT,
            Some(format!(
                "unable to find a command for arguments: [{}]",
                trimmed.join(" ")
            )),
        );
    }
    let node = tree.node(fin);
    let mut fs = tree.flag_set(fin, true);
    let (flag, final_args, to_complete, flag_err) = check_flag_completion(
        &fs,
        node.name(),
        node.disable_flag_parsing,
        &final_args,
        &to_complete,
    );
    let mut flag_completion = true;
    let mut probe = fs.clone();
    let mut with_dash = final_args.clone();
    with_dash.push("--".to_string());
    let _ = probe.parse(&with_dash);
    let new_count = probe.args.len();
    let mut parsed = fs.clone();
    if let Err(e) = parsed.parse(&final_args) {
        let text = match e {
            super::flags::ParseError::Help => "pflag: help requested".to_string(),
            super::flags::ParseError::Text(t) => t,
        };
        return (
            Vec::new(),
            DEFAULT,
            Some(format!(
                "Error while parsing flags from args [{}]: {text}",
                final_args.join(" ")
            )),
        );
    }
    fs = parsed;
    // The parse sets the root's persistent flags, as cobra's does through
    // the variables they point to.
    ctx.g = super::globals_from(&fs);
    if new_count > fs.args.len() {
        flag_completion = false;
    }
    if let Some(e) = flag_err
        && (!e.1 || flag_completion)
    {
        return (Vec::new(), DEFAULT, Some(e.0));
    }
    if !node.disable_flag_parsing && fs.changed("help") {
        return (Vec::new(), NO_FILE_COMP, None);
    }
    let final_args: Vec<String> = if node.disable_flag_parsing {
        final_args
    } else {
        fs.args.clone()
    };
    // a set flag of an exclusive group
    // hides the others.
    let mut hidden: Vec<String> = Vec::new();
    for g in &node.exclusive {
        if g.iter().any(|n| fs.changed(n)) {
            for n in g {
                if !fs.changed(n) {
                    hidden.push(n.to_string());
                }
            }
        }
    }
    let name_completions = |f: &Flag, to: &str| -> Vec<String> {
        if f.hidden || hidden.contains(&f.name) {
            return Vec::new();
        }
        let mut out = Vec::new();
        let long = format!("--{}", f.name);
        if long.starts_with(to) {
            out.push(format!("{long}\t{}", f.usage));
        }
        if let Some(c) = f.shorthand {
            let short = format!("-{c}");
            if short.starts_with(to) {
                out.push(format!("{short}\t{}", f.usage));
            }
        }
        out
    };
    let ordered: Vec<&Flag> = {
        let mut inh: Vec<&Flag> = fs.sorted().into_iter().filter(|f| f.inherited).collect();
        inh.extend(fs.sorted().into_iter().filter(|f| !f.inherited));
        inh
    };
    let required = |to: &str| -> Vec<String> {
        ordered
            .iter()
            .filter(|f| f.required && !f.changed)
            .flat_map(|f| name_completions(f, to))
            .collect()
    };
    let mut comps: Vec<String> = Vec::new();
    let mut directive;
    if flag.is_none()
        && to_complete.starts_with('-')
        && !to_complete.contains('=')
        && flag_completion
    {
        comps = required(&to_complete);
        if comps.is_empty() {
            for f in &ordered {
                let multiple = matches!(f.value, Value::StrArray(_) | Value::StrSlice(_));
                if !f.changed || multiple {
                    comps.extend(name_completions(f, &to_complete));
                }
            }
        }
        directive = NO_FILE_COMP;
        if comps.len() == 1 && comps[0].ends_with('=') {
            directive = NO_SPACE;
        }
        if !node.disable_flag_parsing {
            return (comps, directive, None);
        }
    } else {
        directive = DEFAULT;
        if flag.is_none() {
            let local_changed = fs.flags.iter().any(|f| {
                !f.inherited && f.changed && !node.persistent.iter().any(|p| p.name == f.name)
            });
            if final_args.is_empty() && !local_changed {
                for c in tree.children(fin) {
                    if tree.available(c) || tree.node(c).special == Special::Help {
                        let n = tree.node(c);
                        if n.name().starts_with(to_complete.as_str()) {
                            comps.push(format!("{}\t{}", n.name(), n.short));
                        }
                        directive = NO_FILE_COMP;
                    }
                }
            }
            comps.extend(required(&to_complete));
        }
    }
    // The completion function of the flag, or of the command's arguments.
    if let Some(f) = &flag
        && flag_completion
    {
        if let Some(kind) = flag_kind(tree, fin, f) {
            let (c, d) = complete(ctx, kind, &final_args, &to_complete);
            comps.extend(c);
            directive = d;
        }
        return (comps, directive, None);
    }
    match node.special {
        Special::Help => {
            let (c, d) = help_completions(tree, &final_args, &to_complete);
            comps.extend(c);
            directive = d;
        }
        Special::Completion => directive = NO_FILE_COMP,
        _ => {
            if let Some(kinds) = arg_kinds(tree, fin) {
                let (c, d) = complete_args(ctx, fin, &kinds, &final_args, &to_complete);
                comps.extend(c);
                directive = d;
            }
        }
    }
    (comps, directive, None)
}

/// The help command's ValidArgsFunction.
fn help_completions(tree: &Tree, args: &[String], to: &str) -> (Vec<String>, i32) {
    let (cmd, _, err) = tree.find(args);
    if err.is_some() {
        return (Vec::new(), NO_FILE_COMP);
    }
    let mut out = Vec::new();
    for c in tree.children(cmd) {
        let n = tree.node(c);
        if (tree.available(c) || n.special == Special::Help) && n.name().starts_with(to) {
            out.push(format!("{}\t{}", n.name(), n.short));
        }
    }
    (out, NO_FILE_COMP)
}

/// The flag whose value is being completed, the
/// arguments without it, and the text to complete. The error's bool says
/// whether it is cobra's flagCompError.
#[allow(clippy::type_complexity)]
fn check_flag_completion(
    fs: &FlagSet,
    cmd: &str,
    disable: bool,
    args: &[String],
    last: &str,
) -> (Option<Flag>, Vec<String>, String, Option<(String, bool)>) {
    if disable {
        return (None, args.to_vec(), last.to_string(), None);
    }
    let mut flag_name = String::new();
    let mut trimmed = args.to_vec();
    let mut with_equal = false;
    let mut last_arg = last.to_string();
    if last.starts_with('-') {
        if let Some(i) = last.find('=') {
            flag_name = if last[..i].starts_with("--") {
                last[2..i].to_string()
            } else {
                last[i.saturating_sub(1)..i].to_string()
            };
            last_arg = last[i + 1..].to_string();
            with_equal = true;
        } else {
            return (None, args.to_vec(), last.to_string(), None);
        }
    }
    if flag_name.is_empty()
        && let Some(prev) = args.last()
        && is_flag_arg(prev)
        && !prev.contains('=')
    {
        flag_name = if let Some(n) = prev.strip_prefix("--") {
            n.to_string()
        } else {
            prev[prev.len() - 1..].to_string()
        };
        trimmed = args[..args.len() - 1].to_vec();
    }
    if flag_name.is_empty() {
        return (None, trimmed, last_arg, None);
    }
    let found = if flag_name.chars().count() == 1 {
        fs.shorthand(flag_name.chars().next().expect("one"))
            .cloned()
    } else {
        fs.lookup(&flag_name).cloned()
    };
    let Some(f) = found else {
        return (
            None,
            args.to_vec(),
            last.to_string(),
            Some((
                format!("Subcommand '{cmd}' does not support flag '{flag_name}'"),
                true,
            )),
        );
    };
    if !with_equal && !f.no_opt_def_val().is_empty() {
        return (None, args.to_vec(), last_arg, None);
    }
    (Some(f), trimmed, last_arg, None)
}

fn is_flag_arg(a: &str) -> bool {
    let b = a.as_bytes();
    (b.len() >= 3 && &b[..2] == b"--") || (b.len() >= 2 && b[0] == b'-' && b[1] != b'-')
}

/// completeArgs.
fn complete_args(
    ctx: &mut Ctx<'_>,
    cmd: usize,
    kinds: &[Option<Kind>],
    args: &[String],
    to: &str,
) -> (Vec<String>, i32) {
    let mut i = args.len();
    if i >= kinds.len() {
        let words = arg_words(ctx.tree.node(cmd));
        let variadic = words
            .last()
            .is_some_and(|w| w.trim_matches(['[', ']']).ends_with("..."));
        if !variadic {
            return (Vec::new(), NO_FILE_COMP);
        }
        i = kinds.len() - 1;
    }
    match kinds[i] {
        None => (Vec::new(), DEFAULT),
        Some(k) => complete(ctx, k, args, to),
    }
}

/// complete: the names kind takes that start with to.
fn complete(ctx: &mut Ctx<'_>, kind: Kind, args: &[String], to: &str) -> (Vec<String>, i32) {
    let mut directive = NO_FILE_COMP;
    if crate::commands::resolve_space(ctx).is_err() {
        return (Vec::new(), directive);
    }
    let Ok(mut admin) = ctx.admin() else {
        return (Vec::new(), directive);
    };
    let g = ctx_globals(ctx);
    let names = ctx.block_on(async {
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            names(g, &mut admin, kind, args),
        )
        .await
        .unwrap_or_default()
    });
    let mut out: Vec<String> = names.into_iter().filter(|n| n.starts_with(to)).collect();
    out.sort();
    out.dedup();
    if out.first().is_some_and(|n| n.ends_with('=')) {
        directive |= NO_SPACE;
    }
    (out, directive)
}

/// What the names of one Tab press need from the command.
#[derive(Clone)]
struct G {
    space: String,
    all: bool,
}

fn ctx_globals(ctx: &Ctx<'_>) -> G {
    G {
        space: ctx.g.space.clone(),
        all: ctx.g.all_spaces,
    }
}

impl G {
    fn scope(&self) -> String {
        if self.space.is_empty() {
            spec::validate::DEFAULT_SPACE.to_string()
        } else {
            self.space.clone()
        }
    }

    /// id: the ID of name in the space, "" when it is not one.
    fn id(&self, name: &str) -> String {
        if name.contains('.') {
            let Some((p, _)) = spec::validate::split_app_id(name) else {
                return String::new();
            };
            if !self.space.is_empty() && self.space != p {
                return String::new();
            }
            return name.to_string();
        }
        spec::validate::app_id(&self.space, name)
    }

    /// name: how an ID is typed in the space.
    fn name(&self, id: &str) -> String {
        match spec::validate::split_app_id(id) {
            Some((space, name)) if space == self.scope() => name,
            _ => id.to_string(),
        }
    }

    fn listed(&self, id: &str) -> bool {
        self.all || spec::validate::split_app_id(id).is_some_and(|(p, _)| p == self.scope())
    }
}

async fn apps(g: &G, admin: &mut Admin) -> Vec<String> {
    let mut out = Vec::new();
    let mut token = String::new();
    for _ in 0..20 {
        let req = ListAppsRequest {
            space: g.scope(),
            page_token: token.clone(),
            ..Default::default()
        };
        let Ok(resp) = admin
            .call(|mut c| async move { c.list_apps(req).await })
            .await
        else {
            return out;
        };
        for a in resp.apps {
            out.push(g.name(&spec::validate::app_id(&a.space, &a.name)));
        }
        token = resp.next_page_token;
        if token.is_empty() {
            break;
        }
    }
    out
}

async fn revisions(admin: &mut Admin, id: &str) -> Vec<String> {
    if id.is_empty() {
        return Vec::new();
    }
    let req = ListRevisionsRequest {
        app: id.to_string(),
    };
    let Ok(resp) = admin
        .call(|mut c| async move { c.list_revisions(req).await })
        .await
    else {
        return Vec::new();
    };
    resp.revisions
        .iter()
        .map(|r| crate::commands::replica::short_revision(&r.name).to_string())
        .collect()
}

async fn names(g: G, admin: &mut Admin, kind: Kind, args: &[String]) -> Vec<String> {
    match kind {
        Kind::Apps => apps(&g, admin).await,
        Kind::Jobs => {
            let Ok(resp) = admin
                .call(|mut c| async move { c.list_jobs(ListJobsRequest {}).await })
                .await
            else {
                return Vec::new();
            };
            resp.jobs
                .iter()
                .filter(|j| g.listed(&j.name))
                .map(|j| g.name(&j.name))
                .collect()
        }
        Kind::Runs => {
            let Some(a) = args.first() else {
                return Vec::new();
            };
            let req = ListJobRunsRequest { job: g.id(a) };
            let Ok(resp) = admin
                .call(|mut c| async move { c.list_job_runs(req).await })
                .await
            else {
                return Vec::new();
            };
            resp.runs.iter().map(|r| r.run.to_string()).collect()
        }
        Kind::Secrets => {
            let req = ListSpaceSecretsRequest { space: g.scope() };
            let Ok(resp) = admin
                .call(|mut c| async move { c.list_space_secrets(req).await })
                .await
            else {
                return Vec::new();
            };
            resp.secrets.into_iter().map(|s| s.name).collect()
        }
        Kind::Keys => {
            let Some(a) = args.first() else {
                return Vec::new();
            };
            let id = g.id(a);
            if id.is_empty() {
                return Vec::new();
            }
            let (_, short) = spec::validate::split_app_id(&id).unwrap_or_default();
            if spec::validate::validate_secret_name(&short).is_err() {
                return Vec::new();
            }
            let req = ListSecretsRequest { app: id };
            let Ok(resp) = admin
                .call(|mut c| async move { c.list_secrets(req).await })
                .await
            else {
                return Vec::new();
            };
            resp.secrets.into_iter().map(|s| s.name).collect()
        }
        Kind::Revisions => {
            let Some(a) = args.first() else {
                return Vec::new();
            };
            revisions(admin, &g.id(a)).await
        }
        Kind::RevisionIds => {
            let mut out = Vec::new();
            for app in apps(&g, admin).await {
                for r in revisions(admin, &g.id(&app)).await {
                    out.push(format!("{app}--{r}"));
                }
            }
            out
        }
        Kind::Weights => {
            let Some(a) = args.first() else {
                return Vec::new();
            };
            revisions(admin, &g.id(a))
                .await
                .into_iter()
                .map(|r| format!("{r}="))
                .collect()
        }
        Kind::Spaces => {
            let Ok(resp) = admin
                .call(|mut c| async move { c.list_spaces(ListSpacesRequest {}).await })
                .await
            else {
                return Vec::new();
            };
            resp.spaces.into_iter().map(|s| s.name).collect()
        }
        Kind::Replicas => replicas(&g, admin, args)
            .await
            .iter()
            .map(|r| crate::commands::replica::short_replica(&r.id).to_string())
            .collect(),
        Kind::Containers => {
            let mut out = Vec::new();
            for r in replicas(&g, admin, args).await {
                out.extend(r.containers);
                out.extend(r.init_containers);
            }
            out
        }
        Kind::Volumes => {
            let Some(a) = args.first() else {
                return Vec::new();
            };
            let req = ListVolumesRequest { app: g.id(a) };
            let Ok(resp) = admin
                .call(|mut c| async move { c.list_volumes(req).await })
                .await
            else {
                return Vec::new();
            };
            resp.volumes.into_iter().map(|v| v.name).collect()
        }
        Kind::Nodes => {
            let req = StatusRequest {
                nodes_only: true,
                ..Default::default()
            };
            let Ok(resp) = admin.call(|mut c| async move { c.status(req).await }).await else {
                return Vec::new();
            };
            resp.nodes.into_iter().map(|n| n.id).collect()
        }
        Kind::Roles => {
            let Ok(resp) = admin
                .call(|mut c| async move { c.list_roles(ListRolesRequest::default()).await })
                .await
            else {
                return Vec::new();
            };
            resp.roles.into_iter().map(|r| r.name).collect()
        }
        Kind::Users | Kind::Services => {
            let kind = if kind == Kind::Users {
                "user"
            } else {
                "service"
            };
            let req = ListPrincipalsRequest {
                kind: kind.to_string(),
            };
            let Ok(resp) = admin
                .call(|mut c| async move { c.list_principals(req).await })
                .await
            else {
                return Vec::new();
            };
            resp.principals
                .into_iter()
                .filter(|p| !p.removed)
                .map(|p| p.name)
                .collect()
        }
        Kind::Alerts => {
            let Ok(resp) = admin
                .call(|mut c| async move {
                    c.list_alert_channels(ListAlertChannelsRequest::default())
                        .await
                })
                .await
            else {
                return Vec::new();
            };
            resp.channels.into_iter().map(|a| a.name).collect()
        }
        Kind::Metrics => {
            let Ok(resp) = admin
                .call(|mut c| async move {
                    c.list_metrics_credentials(ListMetricsCredentialsRequest::default())
                        .await
                })
                .await
            else {
                return Vec::new();
            };
            resp.credentials.into_iter().map(|m| m.name).collect()
        }
        Kind::Domains => {
            let Ok(resp) = admin
                .call(|mut c| async move { c.list_domains(ListDomainsRequest::default()).await })
                .await
            else {
                return Vec::new();
            };
            resp.domains.into_iter().map(|d| d.name).collect()
        }
    }
}

/// replicas: the replicas of the app in args[0].
async fn replicas(g: &G, admin: &mut Admin, args: &[String]) -> Vec<ReplicaStatus> {
    let Some(a) = args.first() else {
        return Vec::new();
    };
    let id = g.id(a);
    if id.is_empty() {
        return Vec::new();
    }
    let req = StatusRequest {
        app: id,
        ..Default::default()
    };
    let Ok(resp) = admin.call(|mut c| async move { c.status(req).await }).await else {
        return Vec::new();
    };
    if resp.apps.len() != 1 {
        return Vec::new();
    }
    resp.apps
        .into_iter()
        .next()
        .map(|a| a.replicas)
        .unwrap_or_default()
}
