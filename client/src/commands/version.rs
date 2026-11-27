//! armada version: this build and the servers' versions.

use std::collections::BTreeMap;

use armada_proto::armada::v1::ListServersRequest;

use super::{OUTPUT_JSON, OUTPUT_TEXT, output_flag};
use crate::cli::{Args, Ctx, Error, Node, Result, Tree};
use crate::config::json_string;
use crate::{release, rpc};

/// Build information: set at build time through ARMADA_VERSION,
/// ARMADA_COMMIT, and ARMADA_DATE.
pub struct Info {
    pub version: &'static str,
    pub commit: &'static str,
    pub date: &'static str,
    pub toolchain: &'static str,
    pub platform: String,
}

/// This build's information.
pub fn get() -> Info {
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        a => a,
    };
    // The platform names Armada's releases use: macOS is darwin.
    let os = match std::env::consts::OS {
        "macos" => "darwin",
        o => o,
    };
    Info {
        version: option_env!("ARMADA_VERSION").unwrap_or("dev"),
        commit: option_env!("ARMADA_COMMIT").unwrap_or("unknown"),
        date: option_env!("ARMADA_DATE").unwrap_or("unknown"),
        toolchain: env!("ARMADA_RUSTC_VERSION"),
        platform: format!("{os}/{arch}"),
    }
}

impl Info {
    /// The line `armada version` prints for this build.
    pub fn string(&self) -> String {
        format!(
            "armada {} (commit {}, built {}, {}, {})",
            self.version, self.commit, self.date, self.toolchain, self.platform
        )
    }

    /// The JSON, indented by two spaces. The toolchain keeps the key
    /// goVersion, which scripts may read.
    pub fn json(&self) -> String {
        format!(
            "{{\n  \"version\": {},\n  \"commit\": {},\n  \"date\": {},\n  \"goVersion\": {},\n  \"platform\": {}\n}}\n",
            json_string(self.version),
            json_string(self.commit),
            json_string(self.date),
            json_string(self.toolchain),
            json_string(&self.platform)
        )
    }
}

pub fn add(t: &mut Tree) -> usize {
    t.add(
        0,
        Node::new("version", "Print build information and the latest release")
            .args(Args::No)
            .example(
                "  armada version             # this client, the servers, and the latest release\n  armada version -o json",
            )
            .flag(output_flag(false))
            .run(run),
    )
}

fn run(ctx: &mut Ctx<'_>, _: &[String]) -> Result {
    let info = get();
    let output = ctx.str("output");
    match output.as_str() {
        OUTPUT_TEXT => {
            let mut lines = vec![info.string()];
            lines.extend(server_versions(ctx));
            lines.extend(release::latest_line(info.version));
            ctx.print(&format!("{}\n", lines.join("\n")));
            Ok(())
        }
        OUTPUT_JSON => {
            ctx.print(&info.json());
            Ok(())
        }
        other => Err(Error::Msg(format!(
            "unsupported output format {} (want \"text\" or \"json\")",
            armada_spec::go::quote(other)
        ))),
    }
}

/// The control plane's versions, when it is reached.
fn server_versions(ctx: &mut Ctx<'_>) -> Vec<String> {
    let Ok(mut admin) = ctx.admin() else {
        return Vec::new();
    };
    let resp = ctx.block_on(async {
        tokio::time::timeout(
            release::CHECK_TIMEOUT,
            admin.call(|mut c| async move { c.list_servers(ListServersRequest {}).await }),
        )
        .await
    });
    let resp = match resp {
        Err(_) => return vec!["server: unknown (context deadline exceeded)".to_string()],
        Ok(Err(s)) => return vec![format!("server: unknown ({})", rpc::rpc_error(&s))],
        Ok(Ok(r)) => r,
    };
    let mut by_version: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for s in resp.servers {
        let v = if s.version.is_empty() {
            "unknown".to_string()
        } else {
            s.version
        };
        by_version.entry(v).or_default().push(s.name);
    }
    let parts: Vec<String> = by_version
        .into_iter()
        .map(|(v, names)| format!("{v} ({})", names.join(", ")))
        .collect();
    vec![format!("server: {}", parts.join(", "))]
}
