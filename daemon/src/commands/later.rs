//! The command that comes later in ADR 0055's pull request 18b: armadad
//! doctor. Until then this development build says so and fails.

use armada_client::cli::{Ctx, Error, Result};

pub fn run(ctx: &mut Ctx<'_>, _: &[String]) -> Result {
    Err(Error::Msg(format!(
        "{} is not in this development build of armadad in Rust yet: it comes with ADR 0055's pull request 18b",
        ctx.path()
    )))
}
