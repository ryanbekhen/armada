//! YAML as go-yaml v3 (go.yaml.in/yaml/v3 v3.0.6) reads and writes it: its
//! reader, scanner, parser, node composer, resolver, emitter, and node
//! encoder, derived from it so specs parse, fail, and print exactly as
//! they always have. The scanner, parser, reader, and emitter are derived
//! from its C (libyaml) derived files, which are under the MIT license; the
//! rest is under the Apache License 2.0 (THIRD_PARTY_NOTICES.md).

pub mod chars;
pub mod compose;
pub mod emitter;
pub mod encode;
pub mod parser;
pub mod reader;
pub mod resolve;
pub mod scanner;
pub mod types;
