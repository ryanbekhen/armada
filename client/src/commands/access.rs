//! armada user, service, role (Go's rbac.go), metrics (metrics.go), and
//! alert (alerts.go).

use armada_pki as pki;
use armada_proto::armada::v1::{
    AlertChannel, AlertChannelRequest, AssignmentRequest, CreateServiceRequest, CreateUserRequest,
    DeleteAlertChannelRequest, DeletePrincipalRequest, IssueMetricsCertificateRequest,
    IssueMetricsCertificateResponse, IssuePrincipalCertificateRequest, LabelAllowance,
    ListAlertChannelsRequest, ListMetricsCredentialsRequest, ListPrincipalsRequest,
    ListPrincipalsResponse, ListRolesRequest, ListRolesResponse, ListServersRequest,
    RenewOwnCertificateRequest, RevokeMetricsCredentialsRequest, RoleAssignment, RoleInfo,
    TestAlertChannelRequest, UpdatePrincipalRequest,
};
use armada_spec::go;

use super::{
    Output, ago, dash, date_only, go_time, now_nanos, output_flag, path_error, print_json,
    read_token_arg, rpc_err,
};
use crate::cli::flags::Flag;
use crate::cli::tabwriter::TabWriter;
use crate::cli::{Args, Ctx, Error, Node, Result, Tree};
use crate::rpc;
use crate::rpc::Admin;

const KIND_USER: &str = "user";
const KIND_SERVICE: &str = "service";

const SSH_USAGE: &str = "reach the servers through this SSH host ([user@]host or a ~/.ssh/config alias): `ssh -W` to their private addresses, mTLS inside";
const ROLE_USAGE: &str =
    "a first role: viewer, deployer, admin (with --space), space-creator, or cluster-admin";
const ALLOW_LABEL_USAGE: &str =
    "a node label KEY=VALUE its apps' placement may require (repeat for more)";

pub fn add_user(t: &mut Tree) -> usize {
    add_principal(t, KIND_USER)
}

pub fn add_service(t: &mut Tree) -> usize {
    add_principal(t, KIND_SERVICE)
}

/// newPrincipalCommand.
fn add_principal(t: &mut Tree, kind: &'static str) -> usize {
    let service = kind == KIND_SERVICE;
    let noun = if service {
        Node::new(
            "service",
            "Programs such as a CI system, each with a certificate of their own",
        )
        .aliases(&["services"])
        .long("Services are programs such as a CI system. Each has certificates of its own\nand holds roles like a user; `armada role list` shows the roles and who\nholds them.")
    } else {
        Node::new("user", "People, each with a certificate of their own")
            .aliases(&["users"])
            .long("Users are people. Each has a certificate of their own and holds roles:\nviewer, deployer, or admin in a space (viewer also over the whole cluster),\nspace-creator, or cluster-admin. Only cluster-admin manages access;\n`armada role list` shows the roles and who holds them.")
    };
    let n = t.add(0, noun.noun());

    // create
    let mut create = if service {
        Node::new("create NAME [--role ROLE [--space P]] [--allow-label KEY=VALUE]...", "Create a service")
            .long("Create a service, a tool that uses the API, with a first role (in --space\nfor viewer, deployer, and admin). Give it a client config with\n`armada service credentials`, and more roles with\n`armada role grant`.")
            .example("  armada service create ci --role deployer --space shop\n  armada service create portal --role space-creator")
            .run(|ctx, args| create(ctx, args, KIND_SERVICE))
    } else {
        Node::new("create NAME -o FILE [--role ROLE [--space P]] [--allow-label KEY=VALUE]...", "Create a user with a certificate of their own")
            .long("Create a user and write their client config to FILE: a certificate under\ntheir own name (one year) for a key made here. Give them FILE privately; they\nkeep it as ~/.armada/config, mode 0600. --role gives a first role (in\n--space for viewer, deployer, and admin); give more with\n`armada role grant`. A user with no role can only renew.")
            .example("  armada user create ana -o ana.config --role deployer --space shop\n  armada user create ops -o ops.config --role cluster-admin\n  armada user create ops -o ops.config --role cluster-admin --ssh ops@bastion.example.com")
            .run(|ctx, args| create(ctx, args, KIND_USER))
            .flag(Flag::string("output", Some('o'), "", "client config file to create"))
            .flag(Flag::string("ssh", None, "", SSH_USAGE))
    };
    create = create
        .args(Args::Exact(1))
        .flag(Flag::string("role", None, "", ROLE_USAGE))
        .flag(Flag::string_array("allow-label", None, ALLOW_LABEL_USAGE));
    t.add(n, create);

    // list
    let list_short = format!("List {kind}s and their roles");
    t.add(
        n,
        Node::new("list", &list_short)
            .aliases(&["ls"])
            .args(Args::No)
            .example(if service {
                "  armada service list"
            } else {
                "  armada user list"
            })
            .flag(output_flag(false))
            .run(if service {
                |ctx, args| list(ctx, args, KIND_SERVICE)
            } else {
                |ctx, args| list(ctx, args, KIND_USER)
            }),
    );

    // show
    let show_short = format!("Show a {kind}'s roles and allowed node labels");
    t.add(
        n,
        Node::new("show NAME", &show_short)
            .args(Args::Exact(1))
            .example(if service {
                "  armada service show ci"
            } else {
                "  armada user show alice"
            })
            .flag(output_flag(false))
            .run(if service {
                |ctx, args| show(ctx, args, KIND_SERVICE)
            } else {
                |ctx, args| show(ctx, args, KIND_USER)
            }),
    );

    // credentials
    let creds = if service {
        Node::new("credentials NAME -o FILE", "Write a client config for a service")
            .long("Make a key here and a certificate for service NAME (90 days), and write a\nclient config to FILE (mode 0600). The tool uses it with `armada --config\nFILE`, or the API with its PEM fields, and renews it with\n`armada service renew --config FILE`. Its other certificates stay valid\nuntil it renews or is deleted.")
            .example("  armada service credentials ci -o ci.config   # another certificate; the others keep working")
            .run(|ctx, args| credentials(ctx, args, KIND_SERVICE))
    } else {
        Node::new("credentials NAME -o FILE", "Write a new client config for a user, revoking their older certificates")
            .long("Make a key here and a new certificate for user NAME (one year), and write\ntheir client config to FILE. Certificates the user was given before stop\nworking: use it when a key is lost or leaked.")
            .example("  armada user credentials alice -o alice.config     # a new certificate; older ones stop working\n  armada user credentials alice -o alice.config --ssh bastion.example.com")
            .run(|ctx, args| credentials(ctx, args, KIND_USER))
    };
    t.add(
        n,
        creds
            .args(Args::Exact(1))
            .flag(Flag::string(
                "output",
                Some('o'),
                "",
                "client config file to create",
            ))
            .flag(Flag::string("ssh", None, "", SSH_USAGE)),
    );

    // renew
    let renew = if service {
        Node::new("renew --config FILE", "Renew the certificate of a service's client config")
            .long("Run by the tool with its own client config (--config or ARMADA_CONFIG): get\na new 90-day certificate for a new key and rewrite the file. Every other\ncertificate of the service is revoked; the one in the file is replaced.")
            .example("  armada service renew --config ci.config")
            .run(|ctx, args| renew(ctx, args, KIND_SERVICE))
    } else {
        Node::new("renew", "Renew the user certificate in your client config")
            .long("Get a new one-year certificate for a new key, under the same name, and\nrewrite the client config (--config, default ~/.armada/config, else\n/etc/armada/admin.config, which needs sudo). Run it before the current\ncertificate expires: an expired one cannot renew. `armadad doctor` warns 30\ndays ahead. The old certificate stays valid until it expires. For one that\nhas expired, run `armadad user renew` as root on a server.")
            .example("  armada user renew    # before the certificate in your config expires")
            .run(|ctx, args| renew(ctx, args, KIND_USER))
    };
    t.add(n, renew.args(Args::No));

    // update
    let update_short = format!("Replace the node labels a {kind}'s apps may require");
    let update_long = format!(
        "Replace the node label values the apps a {kind} deploys may name in\nplacement.require (armada.* labels are always allowed): restricted nodes\ncan be kept for some spaces. Roles change with `armada role grant` and `armada role revoke`."
    );
    t.add(
        n,
        Node::new("update NAME (--allow-label KEY=VALUE... | --clear-labels)", &update_short)
            .long(&update_long)
            .args(Args::Exact(1))
            .example(if service {
                "  armada service update ci --allow-label team=web\n  armada service update ci --clear-labels"
            } else {
                "  armada user update alice --allow-label team=web\n  armada user update alice --clear-labels"
            })
            .flag(Flag::string_array("allow-label", None, ALLOW_LABEL_USAGE))
            .flag(Flag::bool("clear-labels", None, false, "allow no node labels"))
            .run(if service {
                |ctx, args| update(ctx, args, KIND_SERVICE)
            } else {
                |ctx, args| update(ctx, args, KIND_USER)
            }),
    );

    // delete
    let delete_short = format!("Delete a {kind} and revoke every certificate of it");
    let delete_long = format!(
        "Revoke every certificate of the {kind}, at once and on every server, and\ntake its roles back. You cannot delete yourself."
    );
    t.add(
        n,
        Node::new("delete NAME --yes", &delete_short)
            .aliases(&["rm"])
            .long(&delete_long)
            .args(Args::Exact(1))
            .example(if service {
                "  armada service delete ci --yes"
            } else {
                "  armada user delete alice --yes"
            })
            .flag(Flag::bool("yes", None, false, "confirm deleting"))
            .run(if service {
                |ctx, args| delete(ctx, args, KIND_SERVICE)
            } else {
                |ctx, args| delete(ctx, args, KIND_USER)
            }),
    );
    n
}

/// roleFlags.assignment: --space only when given on the command line.
fn assignment(ctx: &Ctx<'_>, role: &str) -> RoleAssignment {
    let mut a = RoleAssignment {
        role: role.to_string(),
        space: String::new(),
    };
    if ctx.flags.lookup("space").is_some_and(|f| f.changed) {
        a.space = ctx.g.space.clone();
    }
    a
}

/// labelFlags.allowances.
fn allowances(values: &[String]) -> Result<Vec<LabelAllowance>> {
    let mut out: Vec<LabelAllowance> = Vec::new();
    for s in values {
        let (k, v) = s.split_once('=').unwrap_or(("", ""));
        if !s.contains('=') || k.is_empty() || v.is_empty() {
            return Err(Error::Msg(format!(
                "--allow-label {}: want KEY=VALUE",
                go::quote(s)
            )));
        }
        match out.iter_mut().find(|l| l.key == k) {
            Some(l) => l.values.push(v.to_string()),
            None => out.push(LabelAllowance {
                key: k.to_string(),
                values: vec![v.to_string()],
            }),
        }
    }
    Ok(out)
}

/// newFile: refuses to overwrite a file, which may hold another key.
fn new_file(path: &str) -> Result {
    if path.is_empty() {
        return Err("give the file to write with -o".into());
    }
    match std::fs::symlink_metadata(path) {
        Ok(_) => Err(Error::Msg(format!(
            "{path} already exists; choose another file"
        ))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::Msg(path_error("lstat", path, &e))),
    }
}

/// writeCredentials: a client config for key and the issued certificate.
fn write_credentials(
    ctx: &mut Ctx<'_>,
    admin: &mut Admin,
    out: &str,
    who: &str,
    ssh: &str,
    key_pem: &[u8],
    resp: &IssueMetricsCertificateResponse,
) -> Result {
    let cc = crate::config::load(&ctx.g.config_path).map_err(Error::Msg)?;
    let mut servers = cc.servers;
    if !ssh.is_empty() {
        let list =
            rpc!(ctx, admin, list_servers, ListServersRequest::default()).map_err(rpc_err)?;
        servers = super::node::server_addrs(&list);
        if servers.is_empty() {
            return Err("the cluster lists no server addresses".into());
        }
    }
    let c = crate::config::Config {
        servers,
        ssh: ssh.to_string(),
        ca: String::from_utf8_lossy(&resp.ca_cert).into_owned(),
        cert: String::from_utf8_lossy(&resp.cert).into_owned(),
        key: String::from_utf8_lossy(key_pem).into_owned(),
        ..Default::default()
    };
    c.save_file(out).map_err(Error::Msg)?;
    ctx.print(&format!(
        "Wrote {out} for {who} (valid until {}); it holds a private key, hand it over privately.\n",
        date_only(&go_time(resp.expires_at.as_ref(), false))
    ));
    Ok(())
}

fn create(ctx: &mut Ctx<'_>, args: &[String], kind: &str) -> Result {
    let name = args[0].clone();
    let (out, ssh) = (ctx.str("output"), ctx.str("ssh"));
    if !ssh.is_empty() {
        crate::config::check_ssh(&ssh).map_err(Error::Msg)?;
    }
    let allow = allowances(&ctx.strs("allow-label"))?;
    let role = ctx.str("role");
    let mut roles = Vec::new();
    if !role.is_empty() {
        roles.push(assignment(ctx, &role));
    }
    if kind == KIND_USER {
        new_file(&out)?;
        if !pki::valid_name(&name) {
            return Err(Error::Msg(format!(
                "invalid name {}: letters, digits, '.', '_', '-', at most 63",
                go::quote(&name)
            )));
        }
    }
    let mut admin = ctx.admin()?;
    if kind == KIND_SERVICE {
        let req = CreateServiceRequest {
            name: name.clone(),
            roles,
            labels: allow,
        };
        let p = rpc!(ctx, admin, create_service, req).map_err(rpc_err)?;
        ctx.print(&format!(
            "Created service {name} ({}). Give it a client config with `armada service credentials {name} -o FILE`.\n",
            roles_text(&p.roles)
        ));
        return Ok(());
    }
    let (key, csr) = pki::new_csr(&pki::Identity::new(pki::KIND_USER, &name))
        .map_err(|e| Error::Msg(e.to_string()))?;
    let req = CreateUserRequest {
        name: name.clone(),
        csr,
        roles,
        labels: allow,
    };
    let resp = rpc!(ctx, admin, create_user, req).map_err(rpc_err)?;
    write_credentials(
        ctx,
        &mut admin,
        &out,
        &format!("user:{name}"),
        &ssh,
        key.expose(),
        &resp,
    )
}

fn roles_text(roles: &[RoleAssignment]) -> String {
    if roles.is_empty() {
        return "no role".to_string();
    }
    roles
        .iter()
        .map(|r| {
            if r.space.is_empty() {
                r.role.clone()
            } else {
                format!("{} in {}", r.role, r.space)
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn labels_text(ls: &[LabelAllowance]) -> String {
    let out: Vec<String> = ls
        .iter()
        .flat_map(|l| l.values.iter().map(move |v| format!("{}={v}", l.key)))
        .collect();
    dash(&out.join(","))
}

fn list_principals(ctx: &mut Ctx<'_>, kind: &str) -> Result<ListPrincipalsResponse> {
    let mut admin = ctx.admin()?;
    let req = ListPrincipalsRequest {
        kind: kind.to_string(),
    };
    rpc!(ctx, admin, list_principals, req).map_err(rpc_err)
}

fn list(ctx: &mut Ctx<'_>, _: &[String], kind: &str) -> Result {
    let o = Output::of(ctx, false);
    o.check()?;
    let resp = list_principals(ctx, kind)?;
    if o.json() {
        return print_json(ctx, &resp);
    }
    let mut tw = TabWriter::new(0, 2);
    if kind == KIND_SERVICE {
        tw.write("NAME\tROLES\tCERTIFICATES\tEXPIRES\n");
    } else {
        tw.write("NAME\tROLES\tSTATUS\tCREATED BY\n");
    }
    for p in &resp.principals {
        if kind == KIND_SERVICE {
            let exp = p
                .cert_expires_at
                .as_ref()
                .map_or("-".to_string(), |t| date_only(&go_time(Some(t), false)));
            tw.write(&format!(
                "{}\t{}\t{}\t{}\n",
                p.name,
                roles_text(&p.roles),
                p.certificates,
                exp
            ));
            continue;
        }
        let mut st = if p.removed { "deleted" } else { "active" }.to_string();
        if resp.you_kind == kind && p.name == resp.you {
            st.push_str(" (you)");
        }
        tw.write(&format!(
            "{}\t{}\t{}\t{}\n",
            p.name,
            roles_text(&p.roles),
            st,
            dash(&p.created_by)
        ));
    }
    let out = tw.finish();
    ctx.print(&out);
    Ok(())
}

fn show(ctx: &mut Ctx<'_>, args: &[String], kind: &str) -> Result {
    let o = Output::of(ctx, false);
    o.check()?;
    let resp = list_principals(ctx, kind)?;
    let Some(p) = resp.principals.iter().find(|p| p.name == args[0]) else {
        return Err(Error::Msg(format!("{kind} {} not found", args[0])));
    };
    if o.json() {
        return print_json(ctx, p);
    }
    let mut w = format!("{kind}:{}\n", p.name);
    if p.removed {
        w.push_str("  status:       deleted\n");
    }
    w.push_str(&format!("  roles:        {}\n", roles_text(&p.roles)));
    w.push_str(&format!("  node labels:  {}\n", labels_text(&p.labels)));
    if let Some(t) = &p.created_at {
        w.push_str(&format!(
            "  created:      {} by {}\n",
            date_only(&go_time(Some(t), true)),
            dash(&p.created_by)
        ));
    }
    if kind == KIND_SERVICE {
        let exp = p
            .cert_expires_at
            .as_ref()
            .map_or("-".to_string(), |t| date_only(&go_time(Some(t), false)));
        w.push_str(&format!(
            "  certificates: {}, newest until {exp}\n",
            p.certificates
        ));
    }
    ctx.print(&w);
    Ok(())
}

fn credentials(ctx: &mut Ctx<'_>, args: &[String], kind: &str) -> Result {
    let name = args[0].clone();
    let (out, ssh) = (ctx.str("output"), ctx.str("ssh"));
    new_file(&out)?;
    if !ssh.is_empty() {
        crate::config::check_ssh(&ssh).map_err(Error::Msg)?;
    }
    let pk = if kind == KIND_SERVICE {
        pki::KIND_SERVICE
    } else {
        pki::KIND_USER
    };
    let (key, csr) = pki::new_csr(&pki::Identity::new(pk, &name))
        .map_err(|_| Error::Msg(format!("invalid name {}", go::quote(&name))))?;
    let mut admin = ctx.admin()?;
    let req = IssuePrincipalCertificateRequest {
        name: name.clone(),
        csr,
    };
    let resp = if kind == KIND_SERVICE {
        rpc!(ctx, admin, issue_service_certificate, req)
    } else {
        rpc!(ctx, admin, issue_user_certificate, req)
    }
    .map_err(rpc_err)?;
    write_credentials(
        ctx,
        &mut admin,
        &out,
        &format!("{kind}:{name}"),
        &ssh,
        key.expose(),
        &resp,
    )
}

fn renew(ctx: &mut Ctx<'_>, _: &[String], kind: &str) -> Result {
    let path = ctx.g.config_path.clone();
    let mut cc = crate::config::load(&path).map_err(Error::Msg)?;
    let cert =
        pki::parse_cert_pem(cc.cert.as_bytes()).map_err(|e| Error::Msg(format!("{path}: {e}")))?;
    let id = cert.identity().ok().and_then(|id| id.principal());
    let Some(id) = id.filter(|id| id.kind == kind) else {
        return Err(Error::Msg(format!(
            "{path} does not hold a {kind} certificate"
        )));
    };
    let (key, csr) = pki::new_csr(&id).map_err(|e| Error::Msg(e.to_string()))?;
    let mut admin = ctx.admin()?;
    let resp = rpc!(
        ctx,
        admin,
        renew_own_certificate,
        RenewOwnCertificateRequest { csr }
    )
    .map_err(rpc_err)?;
    cc.cert = String::from_utf8_lossy(&resp.cert).into_owned();
    cc.key = String::from_utf8_lossy(key.expose()).into_owned();
    cc.ca = String::from_utf8_lossy(&resp.ca_cert).into_owned();
    cc.save_file(&path).map_err(Error::Msg)?;
    ctx.print(&format!(
        "Renewed {id} (valid until {}).\n",
        date_only(&go_time(resp.expires_at.as_ref(), false))
    ));
    Ok(())
}

fn update(ctx: &mut Ctx<'_>, args: &[String], kind: &str) -> Result {
    let values = ctx.strs("allow-label");
    if ctx.bool("clear-labels") == !values.is_empty() {
        return Err("give --allow-label KEY=VALUE (repeat it) or --clear-labels".into());
    }
    let allow = allowances(&values)?;
    let mut admin = ctx.admin()?;
    let req = UpdatePrincipalRequest {
        kind: kind.to_string(),
        name: args[0].clone(),
        labels: allow,
    };
    let p = rpc!(ctx, admin, update_principal, req).map_err(rpc_err)?;
    ctx.print(&format!(
        "Updated {kind} {}: node labels {}.\n",
        args[0],
        labels_text(&p.labels)
    ));
    Ok(())
}

fn delete(ctx: &mut Ctx<'_>, args: &[String], kind: &str) -> Result {
    if !ctx.bool("yes") {
        return Err(Error::Msg(format!(
            "this revokes every certificate of {kind} {}; pass --yes to confirm",
            args[0]
        )));
    }
    let mut admin = ctx.admin()?;
    let req = DeletePrincipalRequest {
        kind: kind.to_string(),
        name: args[0].clone(),
    };
    rpc!(ctx, admin, delete_principal, req).map_err(rpc_err)?;
    ctx.print(&format!(
        "Deleted {kind} {}; its certificates are refused.\n",
        args[0]
    ));
    Ok(())
}

// ---- role ----

pub fn add_role(t: &mut Tree) -> usize {
    let n = t.add(
        0,
        Node::new("role", "List the roles and who holds them; grant and revoke them")
            .aliases(&["roles"])
            .long("Roles are built in: viewer, deployer, or admin in a space (viewer also over\nthe whole cluster), space-creator, and cluster-admin. Users and services\nhold them; only cluster-admin grants and revokes them.")
            .noun(),
    );
    t.add(
        n,
        Node::new("list", "List the roles, where each may be given, and who holds it")
            .aliases(&["ls"])
            .long("List the roles, where each may be given, and who holds it: a user or\nservice, with the space in parentheses for a role given in one.\n`armada role show ROLE` says what a role allows.")
            .args(Args::No)
            .example("  armada role list    # the roles and who holds each")
            .flag(output_flag(false))
            .run(role_list),
    );
    t.add(
        n,
        Node::new(
            "show ROLE",
            "Show what a role allows and the API methods it reaches",
        )
        .args(Args::Exact(1))
        .example("  armada role show deployer")
        .flag(output_flag(false))
        .run(role_show),
    );
    let who = [
        Flag::string("user", None, "", "the user"),
        Flag::string("service", None, "", "the service"),
    ];
    t.add(
        n,
        Node::new("grant ROLE (--user NAME | --service NAME) [--space SPACE]", "Give a user or service a role")
            .long("Give a role: viewer (in --space, or without it over the whole cluster),\ndeployer or admin (in --space; not in default), space-creator, or\ncluster-admin. It applies to the next call the user or service makes.")
            .example("  armada role grant deployer --user ana --space shop\n  armada role grant viewer --service ci")
            .args(Args::Exact(1))
            .flags(who.to_vec())
            .run(|ctx, args| role_change(ctx, args, true)),
    );
    t.add(
        n,
        Node::new(
            "revoke ROLE (--user NAME | --service NAME) [--space SPACE]",
            "Take a role back from a user or service",
        )
        .long("Take a role back. You cannot take cluster-admin from yourself.")
        .example("  armada role revoke deployer --user ana --space shop")
        .args(Args::Exact(1))
        .flags(who.to_vec())
        .run(|ctx, args| role_change(ctx, args, false)),
    );
    n
}

fn list_roles(ctx: &mut Ctx<'_>) -> Result<ListRolesResponse> {
    let mut admin = ctx.admin()?;
    rpc!(ctx, admin, list_roles, ListRolesRequest::default()).map_err(rpc_err)
}

fn role_scope(r: &RoleInfo) -> &'static str {
    match (r.cluster, r.space) {
        (true, true) => "the cluster, or a space",
        (true, false) => "the cluster",
        _ => "a space",
    }
}

fn role_list(ctx: &mut Ctx<'_>, _: &[String]) -> Result {
    let o = Output::of(ctx, false);
    o.check()?;
    let resp = list_roles(ctx)?;
    if o.json() {
        return print_json(ctx, &resp);
    }
    // Only cluster-admin lists who holds what; others see the roles.
    let mut admin = ctx.admin()?;
    let holders: Option<Vec<(String, Vec<String>)>> = match rpc!(
        ctx,
        admin,
        list_principals,
        ListPrincipalsRequest::default()
    ) {
        Ok(p) => {
            let mut out: Vec<(String, Vec<String>)> = Vec::new();
            for p in &p.principals {
                for r in &p.roles {
                    let mut h = format!("{} {}", p.kind, p.name);
                    if !r.space.is_empty() {
                        h.push_str(&format!(" ({})", r.space));
                    }
                    match out.iter_mut().find(|(k, _)| *k == r.role) {
                        Some((_, v)) => v.push(h),
                        None => out.push((r.role.clone(), vec![h])),
                    }
                }
            }
            Some(out)
        }
        Err(s) if s.code() == tonic::Code::PermissionDenied => None,
        Err(s) => return Err(rpc_err(s)),
    };
    let mut tw = TabWriter::new(0, 2);
    match &holders {
        None => tw.write("ROLE\tGIVEN IN\n"),
        Some(_) => tw.write("ROLE\tGIVEN IN\tHELD BY\n"),
    }
    for r in &resp.roles {
        match &holders {
            None => tw.write(&format!("{}\t{}\n", r.name, role_scope(r))),
            Some(h) => {
                let held = h
                    .iter()
                    .find(|(k, _)| *k == r.name)
                    .map(|(_, v)| v.join(", "))
                    .unwrap_or_default();
                tw.write(&format!("{}\t{}\t{}\n", r.name, role_scope(r), dash(&held)));
            }
        }
    }
    let out = tw.finish();
    ctx.print(&out);
    Ok(())
}

fn role_show(ctx: &mut Ctx<'_>, args: &[String]) -> Result {
    let o = Output::of(ctx, false);
    o.check()?;
    let resp = list_roles(ctx)?;
    let Some(r) = resp.roles.iter().find(|r| r.name == args[0]) else {
        let names: Vec<&str> = resp.roles.iter().map(|r| r.name.as_str()).collect();
        return Err(Error::Msg(format!(
            "unknown role {}; the roles: {}",
            go::quote(&args[0]),
            names.join(", ")
        )));
    };
    if o.json() {
        return print_json(ctx, r);
    }
    ctx.print(&format!(
        "{}\n  given in:  {}\n  allows:    {}\n  methods:   {}\n",
        r.name,
        role_scope(r),
        r.description,
        r.methods.join(", ")
    ));
    Ok(())
}

fn role_change(ctx: &mut Ctx<'_>, args: &[String], grant: bool) -> Result {
    let (user, service) = (ctx.str("user"), ctx.str("service"));
    let (kind, name) = match (user.is_empty(), service.is_empty()) {
        (false, false) => return Err("give --user or --service, not both".into()),
        (false, true) => (KIND_USER, user),
        (true, false) => (KIND_SERVICE, service),
        (true, true) => return Err("give --user NAME or --service NAME".into()),
    };
    let role = assignment(ctx, &args[0]);
    let req = AssignmentRequest {
        kind: kind.to_string(),
        name: name.clone(),
        role: Some(role.clone()),
    };
    let mut admin = ctx.admin()?;
    let (p, verb) = if grant {
        (rpc!(ctx, admin, create_assignment, req), "Gave")
    } else {
        (rpc!(ctx, admin, delete_assignment, req), "Took back")
    };
    let p = p.map_err(rpc_err)?;
    ctx.print(&format!(
        "{verb} {}; {kind} {name} now holds {}.\n",
        roles_text(std::slice::from_ref(&role)),
        roles_text(&p.roles)
    ));
    Ok(())
}

// ---- metrics ----

pub fn add_metrics(t: &mut Tree) -> usize {
    let mut noun = Node::new("metrics", "Credentials for the Prometheus metrics endpoint")
        .long("The leader serves Prometheus metrics on `armadad server --metrics-listen IP:PORT`,\nover TLS, only to metrics (or admin) client certificates.")
        .noun();
    noun.args = Args::No;
    let n = t.add(0, noun);
    t.add(
        n,
        Node::new("credentials NAME", "Create a client certificate that may only scrape metrics")
            .long("Create a key and a client certificate (metrics:NAME) that may only scrape the\nmetrics endpoint, and write ca.pem, cert.pem, and key.pem to a new directory.\nThe key is generated here and never sent to the server. The certificate lasts\na year; armada metrics revoke NAME refuses every certificate of the name.\nKeep the key with the scraper only.")
            .args(Args::Exact(1))
            .example("  armada metrics credentials prometheus                    # ca.pem, cert.pem, key.pem in armada-metrics-prometheus\n  armada metrics credentials prometheus -o /etc/prometheus/armada")
            .flag(Flag::string("output", Some('o'), "", "directory to create for the files (default: armada-metrics-NAME)"))
            .run(metrics_credentials),
    );
    t.add(
        n,
        Node::new("list", "List metrics scrapers with a valid certificate")
            .aliases(&["ls"])
            .long("List the metrics scrapers (metrics:NAME) whose certificates are on record and\nhave not expired. Certificates issued before the cluster recorded them are\nnot listed; they still work until armada metrics revoke NAME.")
            .args(Args::No)
            .example("  armada metrics list")
            .flag(output_flag(false))
            .run(metrics_list),
    );
    t.add(
        n,
        Node::new("revoke NAME --yes", "Refuse every certificate of a metrics scraper")
            .long("Refuse every certificate of metrics:NAME from now on, on every server,\nincluding ones issued before the cluster recorded them. armada metrics\ncredentials NAME issues a new one.")
            .args(Args::Exact(1))
            .example("  armada metrics revoke prometheus --yes")
            .flag(Flag::bool("yes", None, false, "confirm revoking"))
            .run(metrics_revoke),
    );
    n
}

fn metrics_credentials(ctx: &mut Ctx<'_>, args: &[String]) -> Result {
    use std::os::unix::fs::DirBuilderExt;
    let name = args[0].clone();
    if pki::parse_identity(&format!("{}:{name}", pki::KIND_METRICS)).is_err() {
        return Err("invalid name: use letters, digits, '.', '_', and '-' (at most 63)".into());
    }
    let mut dir = ctx.str("output");
    if dir.is_empty() {
        dir = format!("armada-metrics-{name}");
    }
    // A new directory: never overwrite another key.
    if let Err(e) = std::fs::DirBuilder::new().mode(0o700).create(&dir) {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            return Err(Error::Msg(format!(
                "{dir} already exists; choose another --output"
            )));
        }
        return Err(Error::Msg(path_error("mkdir", &dir, &e)));
    }
    let (key, csr) = pki::new_csr(&pki::Identity::new(pki::KIND_METRICS, &name))
        .map_err(|e| Error::Msg(e.to_string()))?;
    let mut admin = match ctx.admin() {
        Ok(a) => a,
        Err(e) => {
            let _ = std::fs::remove_dir(&dir);
            return Err(e);
        }
    };
    let req = IssueMetricsCertificateRequest {
        name: name.clone(),
        csr,
    };
    let resp = match rpc!(ctx, admin, issue_metrics_certificate, req) {
        Ok(r) => r,
        Err(s) => {
            let _ = std::fs::remove_dir(&dir);
            return Err(rpc_err(s));
        }
    };
    for (file, data) in [
        ("ca.pem", resp.ca_cert.as_slice()),
        ("cert.pem", resp.cert.as_slice()),
        ("key.pem", key.expose()),
    ] {
        let p = std::path::Path::new(&dir).join(file);
        armada_fsutil::write_file_atomic(&p, data, 0o600).map_err(|e| Error::Msg(e.to_string()))?;
    }
    ctx.print(&format!(
        "Wrote {dir}/{{ca,cert,key}}.pem for metrics:{name} (valid until {}).\nScrape https://<server private IP>:<port>/metrics with them and server name {}.\n",
        date_only(&go_time(resp.expires_at.as_ref(), false)),
        go::quote(pki::SERVER_NAME)
    ));
    Ok(())
}

fn metrics_list(ctx: &mut Ctx<'_>, _: &[String]) -> Result {
    let o = Output::of(ctx, false);
    o.check()?;
    let mut admin = ctx.admin()?;
    let resp = rpc!(
        ctx,
        admin,
        list_metrics_credentials,
        ListMetricsCredentialsRequest::default()
    )
    .map_err(rpc_err)?;
    if o.json() {
        return print_json(ctx, &resp);
    }
    let mut tw = TabWriter::new(0, 2);
    tw.write("NAME\tCERTIFICATES\tEXPIRES\n");
    for c in &resp.credentials {
        let mut last: Option<(i64, i32)> = None;
        for cert in &c.certificates {
            let t = cert
                .expires_at
                .as_ref()
                .map_or((0, 0), |t| (t.seconds, t.nanos));
            if last.is_none_or(|l| t > l) {
                last = Some(t);
            }
        }
        let exp = match last {
            None => "0001-01-01".to_string(),
            Some((s, n)) => date_only(&go_time(
                Some(&armada_proto::google::protobuf::Timestamp {
                    seconds: s,
                    nanos: n,
                }),
                false,
            )),
        };
        tw.write(&format!("{}\t{}\t{exp}\n", c.name, c.certificates.len()));
    }
    let out = tw.finish();
    ctx.print(&out);
    Ok(())
}

fn metrics_revoke(ctx: &mut Ctx<'_>, args: &[String]) -> Result {
    if !ctx.bool("yes") {
        return Err(Error::Msg(format!(
            "this revokes every certificate of metrics:{}; pass --yes to confirm",
            args[0]
        )));
    }
    let mut admin = ctx.admin()?;
    let req = RevokeMetricsCredentialsRequest {
        name: args[0].clone(),
    };
    rpc!(ctx, admin, revoke_metrics_credentials, req).map_err(rpc_err)?;
    ctx.print(&format!(
        "Revoked metrics:{}; its certificates are refused.\n",
        args[0]
    ));
    Ok(())
}

// ---- alert ----

const ALERT_LONG: &str = "Alerts tell people about events that need them (ADR 0045): a node lost, a
replica out of memory or crashing, a failed rollout, job, certificate, or
backup, and the like. The leader sends a notice to every channel that wants
the event, and a second one when a lasting condition, such as a lost node,
is resolved. Repeats within 10 minutes are not sent again, and a channel gets
at most 20 notices a minute; the rest are summed up in one.

A channel is a JSON webhook, Slack, Discord, Telegram, or email (SMTP). Its
URL, bot token, or password is read from a file or stdin (-), stored
encrypted, and never shown. Only cluster admins manage channels.";

/// alertSecretFlags: a channel's secret; each type uses one.
const ALERT_SECRET_FLAGS: [&str; 3] = ["url", "token", "password"];

pub fn add_alert(t: &mut Tree) -> usize {
    let n = t.add(
        0,
        Node::new(
            "alert",
            "Where notices about events go: Slack, Discord, Telegram, email, or a webhook",
        )
        .aliases(&["alerts"])
        .long(ALERT_LONG)
        .noun(),
    );
    t.add(n, alert_channel_node(true));
    t.add(n, alert_channel_node(false));
    t.add(
        n,
        Node::new("list", "List alert channels and how sending went")
            .aliases(&["ls"])
            .long("List alert channels. SENT and FAILED count notices since the current leader\nstarted; LAST ERROR says why the last notice that failed did.")
            .args(Args::No)
            .example("  armada alert list")
            .flag(output_flag(false))
            .run(alert_list),
    );
    t.add(
        n,
        Node::new("delete NAME", "Delete an alert channel")
            .aliases(&["rm"])
            .args(Args::Exact(1))
            .example("  armada alert delete ops")
            .run(alert_delete),
    );
    t.add(
        n,
        Node::new("test NAME", "Send a test notice to a channel now")
            .long("Send a test notice to a channel and wait for it, so a wrong URL, token,\nchat, or mail server shows at once.")
            .args(Args::Exact(1))
            .example("  armada alert test ops    # send a test notice now")
            .run(alert_test),
    );
    n
}

fn alert_channel_node(create: bool) -> Node {
    let n = if create {
        Node::new("create NAME --type TYPE", "Add an alert channel")
            .long("Add an alert channel. Without --reason it gets the events that need a person;\n--reason names others (--reason all for every event). --space keeps only\nevents of those spaces' apps (events of nodes and certificates have no\nspace and are left out then).\n\n  webhook   --url -      POST of a JSON object per notice\n  slack     --url -      an incoming webhook URL\n  discord   --url -      a channel webhook URL\n  telegram  --token - --chat-id ID   a bot token from @BotFather and the chat\n  email     --smtp-host H:P --from A --to A,B [--smtp-user U --password -]\n\nURLs must be https://, or http:// to a private IP address. Email uses TLS on\nport 465 and STARTTLS on other ports (plain SMTP only to a private IP).")
            .example("  armada alert create ops --type slack --url - < slack-webhook-url\n  armada alert create oncall --type telegram --chat-id -1001234567890 --token - < bot-token\n  armada alert create mail --type email --smtp-host smtp.example.com:587 \\\n    --smtp-user alerts@example.com --password - --from alerts@example.com --to ops@example.com < smtp-password\n  armada alert test ops")
            .flag(Flag::string("type", None, "", "webhook, slack, discord, telegram, or email"))
            .run(|ctx, args| alert_channel(ctx, args, true))
    } else {
        Node::new("update NAME", "Change an alert channel")
            .long("Change only the fields given; the type stays. An empty --space or --reason\nremoves that filter, and --url, --token, or --password replaces the secret.")
            .example("  armada alert update ops --space shop,billing --reason Crashed,OutOfMemory\n  armada alert update ops --reason ''        # back to the default: warnings\n  armada alert update ops --url - < new-webhook-url")
            .run(|ctx, args| alert_channel(ctx, args, false))
    };
    n.args(Args::Exact(1)).flags(vec![
        Flag::string("url", None, "", "file holding the webhook URL (webhook, slack, discord), or - for stdin"),
        Flag::string("token", None, "", "file holding the Telegram bot token, or - for stdin"),
        Flag::string("password", None, "", "file holding the SMTP password, or - for stdin"),
        Flag::string("chat-id", None, "", "Telegram chat: an ID such as -1001234567890, or @channelname"),
        Flag::string("smtp-host", None, "", "mail server as host:port, e.g. smtp.example.com:587"),
        Flag::string("smtp-user", None, "", "user name at the mail server (with --password)"),
        Flag::string("from", None, "", "sender address of the emails"),
        Flag::string_slice("to", None, "recipients, comma separated (at most 10)"),
        Flag::string_slice("space", None, "only events of these spaces' apps, comma separated"),
        Flag::string_slice("reason", None, "only these event reasons, comma separated, or all (default: the ones that need a person)"),
    ])
}

fn alert_channel(ctx: &mut Ctx<'_>, args: &[String], create: bool) -> Result {
    let typ = if create {
        ctx.str("type")
    } else {
        String::new()
    };
    let ch = |n: &str| ctx.changed(n);
    let mut req = AlertChannelRequest {
        channel: Some(AlertChannel {
            name: args[0].clone(),
            r#type: typ.clone(),
            chat_id: ctx.str("chat-id"),
            smtp_host: ctx.str("smtp-host"),
            smtp_user: ctx.str("smtp-user"),
            from: ctx.str("from"),
            to: ctx.strs("to"),
            spaces: ctx.strs("space"),
            reasons: ctx.strs("reason"),
            ..Default::default()
        }),
        set_chat_id: ch("chat-id"),
        set_smtp: ch("smtp-host") || ch("smtp-user"),
        set_from: ch("from"),
        set_to: ch("to"),
        set_spaces: ch("space"),
        set_reasons: ch("reason"),
        ..Default::default()
    };
    for f in ALERT_SECRET_FLAGS {
        if !ctx.changed(f) {
            continue;
        }
        if req.set_secret {
            return Err("give only one of --url, --token, and --password".into());
        }
        // Never from an argument: shell history keeps those.
        let arg = ctx.str(f);
        let v = read_token_arg(ctx, &format!("--{f}"), &arg)?;
        req.set_secret = true;
        req.secret = v;
    }
    let mut admin = ctx.admin()?;
    if create {
        if typ.is_empty() {
            return Err("--type is required: webhook, slack, discord, telegram, or email".into());
        }
        rpc!(ctx, admin, create_alert_channel, req).map_err(rpc_err)?;
        ctx.print(&format!(
            "Created alert channel {}; send a test notice with: armada alert test {}\n",
            args[0], args[0]
        ));
        return Ok(());
    }
    if !req.set_secret
        && !req.set_chat_id
        && !req.set_smtp
        && !req.set_from
        && !req.set_to
        && !req.set_spaces
        && !req.set_reasons
    {
        return Err("nothing to change; see armada alert update --help".into());
    }
    rpc!(ctx, admin, update_alert_channel, req).map_err(rpc_err)?;
    ctx.print(&format!("Updated alert channel {}.\n", args[0]));
    Ok(())
}

fn alert_target(c: &AlertChannel) -> String {
    match c.r#type.as_str() {
        "telegram" => c.chat_id.clone(),
        "email" => c.to.join(","),
        _ => String::new(),
    }
}

fn alert_list(ctx: &mut Ctx<'_>, _: &[String]) -> Result {
    let o = Output::of(ctx, false);
    o.check()?;
    let mut admin = ctx.admin()?;
    let resp = rpc!(
        ctx,
        admin,
        list_alert_channels,
        ListAlertChannelsRequest::default()
    )
    .map_err(rpc_err)?;
    if o.json() {
        return print_json(ctx, &resp);
    }
    let now = now_nanos();
    let mut tw = TabWriter::new(0, 2);
    tw.write("CHANNEL\tTYPE\tTO\tSPACES\tREASONS\tSENT\tFAILED\tLAST SENT\tLAST ERROR\n");
    for c in &resp.channels {
        let mut reasons = c.reasons.join(",");
        if reasons.is_empty() {
            reasons = "warnings".to_string();
        }
        tw.write(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            c.name,
            c.r#type,
            dash(&alert_target(c)),
            dash(&c.spaces.join(",")),
            reasons,
            c.sent,
            c.failed,
            ago(c.last_sent.as_ref(), now),
            dash(&c.last_error)
        ));
    }
    let out = tw.finish();
    ctx.print(&out);
    Ok(())
}

fn alert_delete(ctx: &mut Ctx<'_>, args: &[String]) -> Result {
    let mut admin = ctx.admin()?;
    let req = DeleteAlertChannelRequest {
        name: args[0].clone(),
    };
    rpc!(ctx, admin, delete_alert_channel, req).map_err(rpc_err)?;
    ctx.print(&format!("Deleted alert channel {}.\n", args[0]));
    Ok(())
}

fn alert_test(ctx: &mut Ctx<'_>, args: &[String]) -> Result {
    let mut admin = ctx.admin()?;
    let req = TestAlertChannelRequest {
        name: args[0].clone(),
    };
    rpc!(ctx, admin, test_alert_channel, req).map_err(rpc_err)?;
    ctx.print(&format!("Sent a test notice to {}.\n", args[0]));
    Ok(())
}
