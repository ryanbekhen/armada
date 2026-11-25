//! armadad version: build information and the latest release (Go's
//! cli.NewVersionCommand with nothing more: the client's server line is
//! the client's own).

use armada_client::cli::{Ctx, Error, Result};
use armada_client::commands::version::get;
use armada_client::release;

pub fn run(ctx: &mut Ctx<'_>, _: &[String]) -> Result {
    let info = get();
    match ctx.str("output").as_str() {
        "text" => {
            let mut lines = vec![info.string()];
            lines.extend(release::latest_line(info.version));
            ctx.print(&format!("{}\n", lines.join("\n")));
            Ok(())
        }
        "json" => {
            ctx.print(&info.json());
            Ok(())
        }
        other => Err(Error::Msg(format!(
            "unsupported output format {} (want \"text\" or \"json\")",
            armada_spec::go::quote(other)
        ))),
    }
}
