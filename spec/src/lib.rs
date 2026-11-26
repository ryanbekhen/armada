//! Armada's app and job specs (ADR 0055): a port of Go's internal/spec.
//!
//! Specs are parsed strictly from YAML exactly as Go parses them (the YAML
//! library itself is ported, so error texts and line numbers match),
//! defaulted, and validated with Go's messages; they are written back as
//! YAML (`-o yaml`) and as JSON (stored revisions) byte for byte as Go
//! writes them. The cases recorded from Go's tests drive this crate through
//! the `armada-spec-check` program (tests/parity.rs).

pub mod cron;
pub mod decode;
pub mod export;
pub mod go;
mod gotables;
pub mod gotime;
pub mod json;
pub mod spec;
pub mod validate;
pub mod vars;
pub mod yaml;

pub use spec::*;
pub use validate::FieldError;

/// Parse decodes, defaults, and validates an app spec of the default space.
pub fn parse(data: &[u8]) -> Result<App, String> {
    parse_in(data, "")
}

/// ParseIn is Parse for an app of space; empty means the default space.
pub fn parse_in(data: &[u8], space: &str) -> Result<App, String> {
    if data.len() > MAX_SPEC_BYTES {
        return Err(format!("spec is larger than {MAX_SPEC_BYTES} bytes"));
    }
    let mut app = decode::decode_app(data)?;
    if space != validate::DEFAULT_SPACE {
        app.space = space.to_string();
    }
    app.set_defaults();
    app.validate().map_err(|e| validate::join(&e))?;
    Ok(app)
}
