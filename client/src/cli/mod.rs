//! The command tree, run as spf13/cobra v1.10.2 runs commands: finding the
//! command in the arguments, flags, argument checks and the errors
//! `explain` makes of them, help (`write_help`), suggestions, nouns that
//! refuse unknown verbs, the
//! `help` command, and the hidden `completion` and `__complete` commands.

pub mod clidoc;
pub mod complete;
pub mod flags;
pub mod tabwriter;

use std::io::{Read, Write};

use flags::{Flag, FlagSet, ParseError, Value};

/// What a command's run returns when it fails.
#[derive(Debug)]
pub enum Error {
    /// Printed as "Error: TEXT", exit code 1.
    Msg(String),
    /// Exit with this code and print nothing (armada app exec).
    Exit(i32),
}

impl<T: Into<String>> From<T> for Error {
    fn from(s: T) -> Error {
        Error::Msg(s.into())
    }
}

pub type Result<T = ()> = std::result::Result<T, Error>;

/// A command's run.
pub type Run = fn(&mut Ctx<'_>, &[String]) -> Result;

/// What a custom argument check found.
pub enum ArgError {
    /// One of cobra's own texts, which explain replaces.
    Cobra(String),
    /// A text of Armada's own, kept.
    Own(String),
}

/// A command's argument check (cobra.PositionalArgs).
#[derive(Clone, Copy)]
pub enum Args {
    /// None set: legacyArgs.
    Legacy,
    No,
    Exact(usize),
    Min(usize),
    Max(usize),
    /// cobra.RangeArgs.
    Range(usize, usize),
    Custom(fn(&Ctx<'_>, &[String]) -> std::result::Result<(), ArgError>),
}

/// Which built-in command a node is.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Special {
    None,
    Help,
    Completion,
    Complete,
}

/// One command.
pub struct Node {
    pub use_: String,
    pub aliases: Vec<String>,
    pub short: String,
    pub long: String,
    pub example: String,
    pub hidden: bool,
    pub group: String,
    pub args: Args,
    /// The arguments' errors go through explain (commands with Args when
    /// Run walked the tree).
    pub explain: bool,
    pub run: Option<Run>,
    /// A noun: refuses verbs it lacks (refuseUnknownCommands).
    pub noun: bool,
    pub flags: Vec<Flag>,
    pub persistent: Vec<Flag>,
    pub disable_flags_in_use_line: bool,
    pub disable_flag_parsing: bool,
    pub required: Vec<&'static str>,
    pub exclusive: Vec<Vec<&'static str>>,
    pub special: Special,
    /// FParseErrWhitelist.UnknownFlags: flags it does not know are
    /// skipped (armadad etcd, which systemd passes the server's flags).
    pub unknown_flags: bool,
    pub parent: Option<usize>,
    pub children: Vec<usize>,
    pub removed: bool,
}

impl Node {
    pub fn new(use_: &str, short: &str) -> Node {
        Node {
            use_: use_.to_string(),
            aliases: Vec::new(),
            short: short.to_string(),
            long: String::new(),
            example: String::new(),
            hidden: false,
            group: String::new(),
            args: Args::Legacy,
            explain: true,
            run: None,
            noun: false,
            flags: Vec::new(),
            persistent: Vec::new(),
            disable_flags_in_use_line: false,
            disable_flag_parsing: false,
            required: Vec::new(),
            exclusive: Vec::new(),
            special: Special::None,
            unknown_flags: false,
            parent: None,
            children: Vec::new(),
            removed: false,
        }
    }

    pub fn aliases(mut self, a: &[&str]) -> Node {
        self.aliases = a.iter().map(|s| s.to_string()).collect();
        self
    }

    pub fn long(mut self, s: &str) -> Node {
        self.long = s.to_string();
        self
    }

    pub fn example(mut self, s: &str) -> Node {
        self.example = s.to_string();
        self
    }

    pub fn args(mut self, a: Args) -> Node {
        self.args = a;
        self
    }

    pub fn run(mut self, r: Run) -> Node {
        self.run = Some(r);
        self
    }

    pub fn flag(mut self, f: Flag) -> Node {
        self.flags.push(f);
        self
    }

    pub fn flags(mut self, fs: Vec<Flag>) -> Node {
        self.flags.extend(fs);
        self
    }

    pub fn noun(mut self) -> Node {
        self.noun = true;
        self
    }

    /// Cobra's Name: the first word of Use.
    pub fn name(&self) -> &str {
        self.use_.split(' ').next().unwrap_or("")
    }

    fn runnable(&self) -> bool {
        self.run.is_some() || self.noun || matches!(self.special, Special::Help | Special::Complete)
    }
}

/// The root's groups of nouns (ADR 0052).
pub struct Group {
    pub id: &'static str,
    pub title: &'static str,
}

/// The whole tree.
pub struct Tree {
    pub nodes: Vec<Node>,
    pub groups: Vec<Group>,
    /// What to type for a verb a noun has not got, by
    /// "NOUN VERB" (the client's; armadad has none).
    pub verb_hints: fn(&str) -> Option<&'static str>,
}

impl Tree {
    pub fn new(root: Node) -> Tree {
        Tree {
            nodes: vec![root],
            groups: Vec::new(),
            verb_hints: |_| None,
        }
    }

    /// The program's name: the root's (armada, or armadad).
    pub fn program(&self) -> &str {
        self.nodes[0].name()
    }

    /// AddCommand.
    pub fn add(&mut self, parent: usize, mut n: Node) -> usize {
        n.parent = Some(parent);
        let i = self.nodes.len();
        self.nodes.push(n);
        self.nodes[parent].children.push(i);
        i
    }

    pub fn node(&self, i: usize) -> &Node {
        &self.nodes[i]
    }

    /// Commands(): the children, sorted by name.
    pub fn children(&self, i: usize) -> Vec<usize> {
        let mut v: Vec<usize> = self.nodes[i]
            .children
            .iter()
            .copied()
            .filter(|&c| !self.nodes[c].removed)
            .collect();
        v.sort_by(|&a, &b| self.nodes[a].name().cmp(self.nodes[b].name()));
        v
    }

    fn has_sub(&self, i: usize) -> bool {
        self.nodes[i]
            .children
            .iter()
            .any(|&c| !self.nodes[c].removed)
    }

    /// CommandPath.
    pub fn path(&self, i: usize) -> String {
        match self.nodes[i].parent {
            Some(p) => format!("{} {}", self.path(p), self.nodes[i].name()),
            None => self.nodes[i].name().to_string(),
        }
    }

    /// The help command of the root.
    fn is_help_command(&self, i: usize) -> bool {
        self.nodes[i].special == Special::Help
    }

    /// IsAvailableCommand.
    pub fn available(&self, i: usize) -> bool {
        let n = &self.nodes[i];
        if n.hidden || n.removed || self.is_help_command(i) {
            return false;
        }
        n.runnable() || self.has_available_sub(i)
    }

    /// HasAvailableSubCommands.
    pub fn has_available_sub(&self, i: usize) -> bool {
        self.nodes[i].children.iter().any(|&c| self.available(c))
    }

    /// The flags of command i: its own, its persistent ones, its parents'
    /// persistent ones (inherited), and with help, cobra's help flag.
    pub fn flag_set(&self, i: usize, help: bool) -> FlagSet {
        let mut flags: Vec<Flag> = self.nodes[i].flags.clone();
        flags.extend(self.nodes[i].persistent.iter().cloned());
        let mut p = self.nodes[i].parent;
        while let Some(pi) = p {
            for f in &self.nodes[pi].persistent {
                if !flags.iter().any(|g| g.name == f.name) {
                    let mut f = f.clone();
                    f.inherited = true;
                    flags.push(f);
                }
            }
            p = self.nodes[pi].parent;
        }
        if help && !flags.iter().any(|f| f.name == "help") {
            let mut h = Flag::bool(
                "help",
                Some('h'),
                false,
                &format!("help for {}", self.nodes[i].name()),
            );
            h.help = true;
            flags.push(h);
        }
        for f in &mut flags {
            for g in &self.nodes[i].exclusive {
                if g.contains(&f.name.as_str()) {
                    f.exclusive.push(g.join(" "));
                }
            }
            if self.nodes[i].required.contains(&f.name.as_str()) {
                f.required = true;
            }
        }
        let mut fs = FlagSet::new(flags);
        fs.ignore_unknown = self.nodes[i].unknown_flags;
        fs
    }

    /// UseLine.
    pub fn use_line(&self, i: usize) -> String {
        let n = &self.nodes[i];
        let mut line = match n.parent {
            Some(p) => format!("{} {}", self.path(p), n.use_),
            None => n.use_.clone(),
        };
        if !n.disable_flags_in_use_line && !line.contains("[flags]") {
            line.push_str(" [flags]");
        }
        line
    }

    fn find_next(&self, i: usize, next: &str) -> Option<usize> {
        self.nodes[i].children.iter().copied().find(|&c| {
            let n = &self.nodes[c];
            !n.removed && (n.name() == next || n.aliases.iter().any(|a| a == next))
        })
    }

    /// stripFlags, with the flags cobra knows of while finding the command
    /// (its help flag is added only when a command runs).
    fn strip_flags(&self, args: &[String], i: usize) -> Vec<String> {
        let fs = self.flag_set(i, false);
        let no_opt = |name: &str| {
            fs.lookup(name)
                .is_some_and(|f| !f.no_opt_def_val().is_empty())
        };
        let short_no_opt = |name: &str| {
            name.chars()
                .next()
                .and_then(|c| fs.shorthand(c))
                .is_some_and(|f| !f.no_opt_def_val().is_empty())
        };
        let mut commands = Vec::new();
        let mut k = 0;
        while k < args.len() {
            let s = &args[k];
            k += 1;
            if s == "--" {
                break;
            }
            let long_with_value = s.starts_with("--") && !s.contains('=') && !no_opt(&s[2..]);
            let short_with_value =
                s.starts_with('-') && !s.contains('=') && s.len() == 2 && !short_no_opt(&s[1..]);
            if long_with_value || short_with_value {
                if args.len() - k <= 1 {
                    break;
                }
                k += 1;
                continue;
            }
            if !s.is_empty() && !s.starts_with('-') {
                commands.push(s.clone());
            }
        }
        commands
    }

    /// argsMinusFirstX.
    fn args_minus_first_x(&self, args: &[String], i: usize, x: &str) -> Vec<String> {
        let fs = self.flag_set(i, false);
        let no_opt = |name: &str| {
            fs.lookup(name)
                .is_some_and(|f| !f.no_opt_def_val().is_empty())
        };
        let short_no_opt = |name: &str| {
            name.chars()
                .next()
                .and_then(|c| fs.shorthand(c))
                .is_some_and(|f| !f.no_opt_def_val().is_empty())
        };
        let mut pos = 0;
        while pos < args.len() {
            let s = &args[pos];
            if s == "--" {
                break;
            }
            let long_with_value = s.starts_with("--") && !s.contains('=') && !no_opt(&s[2..]);
            let short_with_value =
                s.starts_with('-') && !s.contains('=') && s.len() == 2 && !short_no_opt(&s[1..]);
            if long_with_value || short_with_value {
                pos += 2;
                continue;
            }
            if !s.starts_with('-') && s == x {
                let mut out = args[..pos].to_vec();
                out.extend_from_slice(&args[pos + 1..]);
                return out;
            }
            pos += 1;
        }
        args.to_vec()
    }

    /// Find: the command the arguments name, the arguments left, and
    /// legacyArgs' error for a command without an argument check.
    pub fn find(&self, args: &[String]) -> (usize, Vec<String>, Option<String>) {
        let mut c = 0;
        let mut a = args.to_vec();
        loop {
            let wo = self.strip_flags(&a, c);
            let Some(next) = wo.first() else { break };
            let Some(cmd) = self.find_next(c, next) else {
                break;
            };
            a = self.args_minus_first_x(&a, c, next);
            c = cmd;
        }
        let mut err = None;
        if matches!(self.nodes[c].args, Args::Legacy) && self.has_sub(c) {
            let stripped = self.strip_flags(&a, c);
            if self.nodes[c].parent.is_none()
                && let Some(first) = stripped.first()
            {
                err = Some(format!(
                    "unknown command {} for {}{}",
                    quote(first),
                    quote(&self.path(c)),
                    self.find_suggestions(c, first)
                ));
            }
        }
        (c, a, err)
    }

    /// SuggestionsFor, with cobra's minimum distance: 2 at the root (set by
    /// findSuggestions), 0 for nouns (never set).
    pub fn suggestions_for(&self, i: usize, typed: &str, distance: usize) -> Vec<String> {
        let mut out = Vec::new();
        for c in self.children(i) {
            if !self.available(c) {
                continue;
            }
            let name = self.nodes[c].name();
            if ld(typed, name) <= distance || name.to_lowercase().starts_with(&typed.to_lowercase())
            {
                out.push(name.to_string());
            }
        }
        out
    }

    fn find_suggestions(&self, i: usize, arg: &str) -> String {
        let s = self.suggestions_for(i, arg, 2);
        if s.is_empty() {
            return String::new();
        }
        let mut out = "\n\nDid you mean this?\n".to_string();
        for n in s {
            out.push_str(&format!("\t{n}\n"));
        }
        out
    }
}

/// Levenshtein distance over bytes, ignoring case (cobra's ld).
fn ld(s: &str, t: &str) -> usize {
    let s = s.to_lowercase().into_bytes();
    let t = t.to_lowercase().into_bytes();
    let mut d = vec![vec![0usize; t.len() + 1]; s.len() + 1];
    for (i, row) in d.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, cell) in d[0].iter_mut().enumerate() {
        *cell = j;
    }
    for j in 1..=t.len() {
        for i in 1..=s.len() {
            if s[i - 1] == t[j - 1] {
                d[i][j] = d[i - 1][j - 1];
            } else {
                let min = d[i - 1][j].min(d[i][j - 1]).min(d[i - 1][j - 1]);
                d[i][j] = min + 1;
            }
        }
    }
    d[s.len()][t.len()]
}

/// %q.
pub fn quote(s: &str) -> String {
    armada_spec::go::quote(s)
}

/// The persistent flags of the root, shared by every command.
#[derive(Clone, Debug, Default)]
pub struct Globals {
    pub config_path: String,
    /// --space, else ARMADA_SPACE, else the client config's; empty is the
    /// default space.
    pub space: String,
    pub all_spaces: bool,
}

/// What a running command has: the tree, its flags, the streams.
pub struct Ctx<'a> {
    pub tree: &'a Tree,
    pub cmd: usize,
    pub flags: FlagSet,
    pub g: Globals,
    pub out: &'a mut dyn Write,
    pub err: &'a mut dyn Write,
    pub stdin: &'a mut dyn Read,
    /// The runtime calls to the control plane run on.
    rt: tokio::runtime::Runtime,
}

impl<'a> Ctx<'a> {
    pub fn str(&self, name: &str) -> String {
        match self.flags.lookup(name).map(|f| &f.value) {
            Some(Value::Str(s)) => s.clone(),
            _ => String::new(),
        }
    }

    pub fn bool(&self, name: &str) -> bool {
        matches!(
            self.flags.lookup(name).map(|f| &f.value),
            Some(Value::Bool(true))
        )
    }

    pub fn int(&self, name: &str) -> i64 {
        match self.flags.lookup(name).map(|f| &f.value) {
            Some(Value::Int(n) | Value::Int64(n)) => *n,
            _ => 0,
        }
    }

    pub fn duration(&self, name: &str) -> i64 {
        match self.flags.lookup(name).map(|f| &f.value) {
            Some(Value::Duration(d)) => *d,
            _ => 0,
        }
    }

    pub fn strs(&self, name: &str) -> Vec<String> {
        match self.flags.lookup(name).map(|f| &f.value) {
            Some(Value::StrArray(v) | Value::StrSlice(v)) => v.clone(),
            _ => Vec::new(),
        }
    }

    pub fn changed(&self, name: &str) -> bool {
        self.flags.changed(name)
    }

    /// CommandPath of the running command.
    pub fn path(&self) -> String {
        self.tree.path(self.cmd)
    }

    /// Runs a future to its end on the command's runtime.
    pub fn block_on<F: std::future::Future>(&mut self, f: F) -> F::Output {
        self.rt.block_on(f)
    }

    /// The runtime, entered while a channel is made (tonic spawns its
    /// worker on it).
    pub fn runtime(&self) -> &tokio::runtime::Runtime {
        &self.rt
    }

    /// The runtime with the command's stdin and stdout, for a call that
    /// streams one while the runtime runs it.
    pub fn split(&mut self) -> (&tokio::runtime::Runtime, &mut dyn Read, &mut dyn Write) {
        (&self.rt, &mut *self.stdin, &mut *self.out)
    }

    /// Writes to stdout, ignoring errors.
    pub fn print(&mut self, s: &str) {
        let _ = self.out.write_all(s.as_bytes());
    }

    /// The command's help, to stdout (cobra's Help with Armada's help func).
    pub fn help(&mut self) {
        let h = write_help(self.tree, self.cmd, &self.flags, true);
        self.print(&h);
    }
}

/// The arguments' check, with cobra's texts.
fn check_args(ctx: &Ctx<'_>, args: &[String]) -> std::result::Result<(), ArgError> {
    let tree = ctx.tree;
    let n = tree.node(ctx.cmd);
    let len = args.len();
    match n.args {
        Args::Legacy => {
            if tree.has_sub(ctx.cmd) && n.parent.is_none() && len > 0 {
                return Err(ArgError::Cobra(format!(
                    "unknown command {} for {}{}",
                    quote(&args[0]),
                    quote(&tree.path(ctx.cmd)),
                    tree.find_suggestions(ctx.cmd, &args[0])
                )));
            }
            Ok(())
        }
        Args::No if len > 0 => Err(ArgError::Cobra(format!(
            "unknown command {} for {}",
            quote(&args[0]),
            quote(&tree.path(ctx.cmd))
        ))),
        Args::Exact(k) if len != k => Err(ArgError::Cobra(format!(
            "accepts {k} arg(s), received {len}"
        ))),
        Args::Min(k) if len < k => Err(ArgError::Cobra(format!(
            "requires at least {k} arg(s), only received {len}"
        ))),
        Args::Max(k) if len > k => Err(ArgError::Cobra(format!(
            "accepts at most {k} arg(s), received {len}"
        ))),
        Args::Range(a, b) if len < a || len > b => Err(ArgError::Cobra(format!(
            "accepts between {a} and {b} arg(s), received {len}"
        ))),
        Args::Custom(f) => f(ctx, args),
        _ => Ok(()),
    }
}

/// The placeholders at the start of a Use line (argWords).
pub fn arg_words(n: &Node) -> Vec<String> {
    let mut words = Vec::new();
    for f in n.use_.split_whitespace().skip(1) {
        if !is_arg_word(f) {
            break;
        }
        words.push(f.to_string());
    }
    words
}

/// `^\[?[A-Z][A-Za-z0-9_=|.]*\]?$`.
fn is_arg_word(f: &str) -> bool {
    let b = f.as_bytes();
    let mut i = 0;
    if b.first() == Some(&b'[') {
        i = 1;
    }
    let mut end = b.len();
    if end > i && b[end - 1] == b']' {
        end -= 1;
    }
    if i >= end || !b[i].is_ascii_uppercase() {
        // A lone "]" may also close: try with the bracket as a body byte.
        return false;
    }
    b[i + 1..end]
        .iter()
        .all(|&c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'=' | b'|' | b'.'))
}

/// Which arguments are missing, or how many are too many.
pub fn arg_error(tree: &Tree, i: usize, args: &[String]) -> String {
    let words = arg_words(tree.node(i));
    let mut required = Vec::new();
    let mut variadic = false;
    for w in &words {
        if w.ends_with("...") || w.ends_with("...]") {
            variadic = true;
        }
        if !w.starts_with('[') {
            required.push(w.clone());
        }
    }
    let msg = if args.len() < required.len() {
        format!("missing {}", required[args.len()..].join(" "))
    } else if words.is_empty() {
        format!("{} takes no arguments, got {}", tree.path(i), args.len())
    } else if !variadic && args.len() > words.len() {
        format!(
            "too many arguments: expected {}, got {}",
            words.join(" "),
            args.len()
        )
    } else {
        format!("wrong number of arguments ({})", args.len())
    };
    format!(
        "{msg}\nUsage: {}\nRun '{} --help' for more",
        tree.use_line(i),
        tree.path(i)
    )
}

/// a verb with its arguments.
fn verb_line(n: &Node) -> String {
    format!("{} {}", n.name(), arg_words(n).join(" "))
        .trim()
        .to_string()
}

/// Usage, examples, with describe the description, then verbs
/// and flags.
pub fn write_help(tree: &Tree, i: usize, fs: &FlagSet, describe: bool) -> String {
    let n = tree.node(i);
    let mut w = String::from("Usage:");
    let subs = tree.has_available_sub(i);
    if n.runnable() && !subs {
        w.push_str(&format!("\n  {}", tree.use_line(i)));
    }
    if subs {
        w.push_str(&format!("\n  {} [command]", tree.path(i)));
    }
    if !n.aliases.is_empty() {
        let mut all = vec![n.name().to_string()];
        all.extend(n.aliases.iter().cloned());
        w.push_str(&format!("\n\nAliases:\n  {}", all.join(", ")));
    }
    if !n.example.is_empty() {
        w.push_str(&format!("\n\nExamples:\n{}", n.example));
    }
    if describe {
        let d = if n.long.is_empty() { &n.short } else { &n.long };
        let d = d.trim();
        if !d.is_empty() {
            w.push_str(&format!("\n\n{d}"));
        }
    }
    if subs && n.parent.is_none() && !tree.groups.is_empty() {
        let all = tree.children(i);
        let width = all
            .iter()
            .map(|&c| tree.node(c).name().len())
            .max()
            .unwrap_or(0);
        for g in &tree.groups {
            w.push_str(&format!("\n\n{}", g.title));
            for &c in &all {
                let cn = tree.node(c);
                if cn.group == g.id && (tree.available(c) || cn.name() == "help") {
                    w.push_str(&format!("\n  {:<width$}  {}", cn.name(), cn.short));
                }
            }
        }
    } else if subs {
        w.push_str("\n\nAvailable Commands:");
        let list: Vec<usize> = tree
            .children(i)
            .into_iter()
            .filter(|&c| tree.available(c) || tree.node(c).name() == "help")
            .collect();
        let width = list
            .iter()
            .map(|&c| verb_line(tree.node(c)).len())
            .max()
            .unwrap_or(0);
        for c in list {
            w.push_str(&format!(
                "\n  {:<width$}  {}",
                verb_line(tree.node(c)),
                tree.node(c).short
            ));
        }
    }
    let local = fs.usages(|f| !f.inherited);
    if !local.is_empty() {
        w.push_str(&format!(
            "\n\nFlags:\n{}",
            local.trim_end_matches([' ', '\n'])
        ));
    }
    let inherited = fs.usages(|f| f.inherited);
    if !inherited.is_empty() {
        w.push_str(&format!(
            "\n\nGlobal Flags:\n{}",
            inherited.trim_end_matches([' ', '\n'])
        ));
    }
    if subs {
        w.push_str(&format!(
            "\n\nUse \"{} [command] --help\" for more information about a command.",
            tree.path(i)
        ));
    }
    w.push('\n');
    w
}

/// What is set up before a command runs: the root's persistent pre-run.
pub type PreRun = fn(&mut Ctx<'_>) -> Result;

/// Runs the tree with args and returns the exit code.
pub fn run(
    tree: &mut Tree,
    args: &[String],
    pre_run: PreRun,
    stdin: &mut dyn Read,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    add_builtins(tree, args);
    let (cmd, rest, find_err) = tree.find(args);
    if let Some(e) = find_err {
        let _ = writeln!(err, "Error: {e}");
        return 1;
    }
    let tree: &Tree = tree;
    let mut ctx = Ctx {
        tree,
        cmd,
        flags: tree.flag_set(cmd, true),
        g: Globals::default(),
        out,
        err,
        stdin,
        rt: tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a tokio runtime"),
    };
    match execute(&mut ctx, &rest, pre_run) {
        Ok(()) => 0,
        Err(Error::Exit(code)) => code,
        Err(Error::Msg(m)) => {
            let _ = writeln!(ctx.err, "Error: {m}");
            1
        }
    }
}

fn execute(ctx: &mut Ctx<'_>, args: &[String], pre_run: PreRun) -> Result {
    let tree = ctx.tree;
    let n = tree.node(ctx.cmd);
    let argv: Vec<String> = if n.disable_flag_parsing {
        args.to_vec()
    } else {
        match ctx.flags.parse(args) {
            Ok(()) => ctx.flags.args.clone(),
            Err(ParseError::Help) => {
                ctx.help();
                return Ok(());
            }
            Err(ParseError::Text(t)) => {
                return Err(Error::Msg(format!(
                    "{t}\nRun '{} --help' for its flags",
                    tree.path(ctx.cmd)
                )));
            }
        }
    };
    ctx.g = globals_from(&ctx.flags);
    if ctx.bool("help") && !n.disable_flag_parsing {
        ctx.help();
        return Ok(());
    }
    if !n.runnable() {
        ctx.help();
        return Ok(());
    }
    if let Err(e) = check_args(ctx, &argv) {
        return Err(Error::Msg(match e {
            ArgError::Own(t) => t,
            ArgError::Cobra(_) if n.explain && !matches!(n.args, Args::Legacy) => {
                arg_error(tree, ctx.cmd, &argv)
            }
            ArgError::Cobra(t) => t,
        }));
    }
    pre_run(ctx)?;
    if !n.disable_flag_parsing {
        let missing: Vec<String> = ctx
            .flags
            .sorted()
            .into_iter()
            .filter(|f| f.required && !f.changed)
            .map(|f| f.name.clone())
            .collect();
        if !missing.is_empty() {
            return Err(Error::Msg(format!(
                "required flag(s) \"{}\" not set",
                missing.join("\", \"")
            )));
        }
        let mut groups: Vec<String> = n.exclusive.iter().map(|g| g.join(" ")).collect();
        groups.sort();
        for g in groups {
            let mut set: Vec<&str> = g
                .split(' ')
                .filter(|name| ctx.flags.changed(name))
                .collect();
            if set.len() > 1 {
                set.sort();
                return Err(Error::Msg(format!(
                    "if any flags in the group [{g}] are set none of the others can be; [{}] were all set",
                    set.join(" ")
                )));
            }
        }
    }
    if n.noun {
        return refuse_unknown(ctx, &argv);
    }
    match n.special {
        Special::Help => {
            help_command(ctx, &argv);
            Ok(())
        }
        Special::Complete => {
            complete::run(ctx, &argv);
            Ok(())
        }
        _ => (n.run.expect("runnable"))(ctx, &argv),
    }
}

pub(crate) fn globals_from(fs: &FlagSet) -> Globals {
    let s = |name: &str| match fs.lookup(name).map(|f| &f.value) {
        Some(Value::Str(v)) => v.clone(),
        _ => String::new(),
    };
    // A command's own --space of another kind (alert's list of spaces)
    // hides the root's, which keeps its default.
    let space = match fs.lookup("space").map(|f| &f.value) {
        Some(Value::Str(v)) => v.clone(),
        _ => std::env::var("ARMADA_SPACE").unwrap_or_default(),
    };
    Globals {
        config_path: s("config"),
        space,
        all_spaces: matches!(
            fs.lookup("all-spaces").map(|f| &f.value),
            Some(Value::Bool(true))
        ),
    }
}

/// refuseUnknownCommands' run of a noun.
fn refuse_unknown(ctx: &mut Ctx<'_>, args: &[String]) -> Result {
    if args.is_empty() {
        ctx.help();
        return Ok(());
    }
    let tree = ctx.tree;
    let path = tree.path(ctx.cmd);
    let mut msg = format!("unknown command {} for {}", quote(&args[0]), quote(&path));
    let s = tree.suggestions_for(ctx.cmd, &args[0], 0);
    if !s.is_empty() {
        msg.push_str(&format!("; did you mean {}?", s.join(" or ")));
    }
    msg = format!("{msg} (see {path} --help)");
    let key = format!("{} {}", tree.node(ctx.cmd).name(), args[0]);
    if let Some(hint) = (tree.verb_hints)(&key) {
        msg.push('\n');
        msg.push_str(hint);
    }
    Err(Error::Msg(msg))
}

/// %#q of a []string: each in back quotes where it can be.
fn backquote_list(args: &[String]) -> String {
    let parts: Vec<String> = args
        .iter()
        .map(|a| {
            let can = a.chars().all(|c| {
                c != '`' && c != '\u{feff}' && (c == '\t' || armada_spec::go::is_print(c))
            });
            if can { format!("`{a}`") } else { quote(a) }
        })
        .collect();
    format!("[{}]", parts.join(" "))
}

/// The help command.
fn help_command(ctx: &mut Ctx<'_>, args: &[String]) {
    let tree = ctx.tree;
    let (cmd, _, err) = tree.find(args);
    if err.is_some() {
        ctx.print(&format!("Unknown help topic {}\n", backquote_list(args)));
        // The root never ran, so cobra has not given it its help flag.
        let fs = tree.flag_set(0, false);
        let h = write_help(tree, 0, &fs, false);
        ctx.print(&h);
        return;
    }
    let fs = tree.flag_set(cmd, true);
    let h = write_help(tree, cmd, &fs, true);
    ctx.print(&h);
}

/// The help command, the hidden completion command, and __complete when it
/// runs, as ExecuteC adds them.
fn add_builtins(tree: &mut Tree, args: &[String]) {
    let name = tree.program().to_string();
    let mut help = Node::new("help [command]", "Help about any command").long(&format!(
        "Help provides help for any command in the application.\nSimply type {name} help [path to command] for full details."
    ));
    help.special = Special::Help;
    help.explain = false;
    help.group = "monitoring".to_string();
    tree.add(0, help);

    let mut comp = Node::new("__complete [command-line]", "Request shell completion choices for the specified command-line")
        .aliases(&["__completeNoDesc"])
        .long("__complete is a special command that is used by the shell completion logic\nto request completion choices for the specified command-line.")
        .args(Args::Min(1));
    comp.special = Special::Complete;
    comp.hidden = true;
    comp.disable_flag_parsing = true;
    comp.disable_flags_in_use_line = true;
    comp.explain = false;
    let ci = tree.add(0, comp);
    let (found, _, err) = tree.find(args);
    if err.is_some() || found != ci {
        tree.nodes[ci].removed = true;
    }

    let mut completion = Node::new(
        "completion",
        "Generate the autocompletion script for the specified shell",
    )
    .long(&format!(
        "Generate the autocompletion script for {name} for the specified shell.
See each sub-command's help for details on how to use the generated script.
"
    ))
    .args(Args::No);
    completion.hidden = true;
    completion.explain = false;
    completion.special = Special::Completion;
    let c = tree.add(0, completion);
    for shell in complete::SHELLS {
        let mut n = Node::new(
            shell.name,
            &format!("Generate the autocompletion script for {}", shell.name),
        )
        .long(&complete::for_program(shell.long, &name))
        .args(Args::No)
        .run(complete::script)
        .flag(Flag::bool(
            "no-descriptions",
            None,
            false,
            "disable completion descriptions",
        ));
        n.explain = false;
        n.disable_flags_in_use_line = shell.name == "bash";
        n.special = Special::Completion;
        tree.add(c, n);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levenshtein() {
        assert_eq!(ld("ap", "app"), 1);
        assert_eq!(ld("APP", "app"), 0);
        assert_eq!(ld("secert", "secret"), 2);
    }

    #[test]
    fn arg_word_rule() {
        for w in ["APP", "[APP]", "REVISION=WEIGHT...", "IP|none", "[KEY...]"] {
            assert!(is_arg_word(w), "{w}");
        }
        for w in ["[flags]", "|", "--file", "app"] {
            assert!(!is_arg_word(w), "{w}");
        }
    }
}
