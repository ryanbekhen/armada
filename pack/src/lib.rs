//! armada-pack: the runtime pack's build tool (ADR 0011, ADR 0055). It
//! reads the pins in `pack/lock.json`, downloads each upstream artifact
//! over HTTPS (curl), keeps it only when its SHA-256 matches, and writes
//! the pack `armadad` embeds (the bundle feature, daemon/build.rs): a
//! gzipped tar with MANIFEST.json first, then every file by name, as Go's
//! `embedded.Pack` writes it. It also collects the license files of the
//! Go modules the pack's etcd programs link (`licenses`), fetches etcd's
//! API module for `make proto` (`etcd-api`), and extracts one artifact's
//! files (`extract`, scripts/etcd-cache.sh). Never shipped: it runs on the
//! machine that builds a release.

pub mod elf;
pub mod fetch;
pub mod gomod;
pub mod lock;
pub mod pack;
pub mod untar;
