//! The commands that come later in the second part of ADR 0055's pull
//! request 18 (18b): those that run the server or the agent, set a machine
//! up, or need the container runtime's driver (doctor, runtime reset and
//! migrate, init, join, server join, server, agent). Until then this
//! development build says so and fails.

use armada_client::cli::{Ctx, Error, Result};

pub fn run(ctx: &mut Ctx<'_>, _: &[String]) -> Result {
    Err(Error::Msg(format!(
        "{} is not in this development build of armadad in Rust yet: it comes with ADR 0055's pull request 18b",
        ctx.path()
    )))
}
