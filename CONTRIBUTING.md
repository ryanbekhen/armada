# Contributing to Armada

Thank you for helping. Bug reports, questions, ideas, documentation fixes,
and code are all welcome.

## Ask, report, suggest

- **Questions and ideas:** open an issue with the *Question* or *Feature request*
  template. Say what you are trying to do, not only what you would change.
- **Bugs:** use the *Bug report* template, with the Armada version (`armada
  version`), the machines' OS and architecture, what you ran, what you
  expected, and what happened. `armadad doctor`, `armada cluster events`,
  and `armada app show APP` usually hold the useful part.
- **Security issues:** never in a public issue. Follow [SECURITY.md](SECURITY.md).

## Build and test

Armada is written in Rust. You need rustup with clang: the toolchain is
pinned in each `rust-toolchain.toml` (the Cargo workspace at the root, and
the standard-library-only programs in `logger/`, `shim/`, and `dns/`), and
ring, under rustls, compiles its C with clang. `cargo-deny`
(`cargo install cargo-deny --locked`) checks the crates, and `protoc` is
needed only to change the API.

```bash
make build         # ./bin/armada (client) and ./bin/armadad (daemon); on macOS the client only
make lint          # cargo fmt --check, and clippy as released and with the test features
make test          # every member's tests (cargo test --workspace)
make replays       # the recorded behaviour under */tests/testdata, replayed (REPLAYS=server ... for some)
make vuln          # cargo deny: crate licenses and RustSec advisories
cargo run --locked -p armada-pack -- outdated  # the runtime pack's pins: newer releases and known advisories
make check         # all of the above, release builds for both targets, and logger/, shim/, dns/, proto/gen
make logger        # armada-log for amd64 and arm64 (cd logger && cargo test for its tests)
make build-bundle  # static Linux armadad with the container runtime embedded, and armada (ARCH=arm64 for arm64)
make docs          # regenerate the CLI reference in docs/cli
make proto         # regenerate proto/src/gen after changing api/armada/v1/armada.proto
make haproxy-check # haproxy -c on rendered configurations (needs docker, podman, or nerdctl)
```

A single test: `cargo test -p armada-spec NAME`. The replays' recordings
(`*/tests/testdata`) are goldens: nothing writes them again, and a change of
behaviour they cover changes them by hand.

[test/e2e](test/e2e/README.md) builds a cluster on real machines and
checks it end to end: rolling updates and failover under load, node loss,
reboots, and every feature's scenario. Releases run all of it.

## Pull requests

- **CI** builds, lints, and tests what a pull request touches: the crates
  it changes and every crate that depends on one, the programs outside the
  workspace it changes, and the packaging when something a release builds
  changes (`scripts/ci-changes.sh` decides). One that changes only
  documents (Markdown, `docs/`, the license, issue templates) only has its
  commit subjects checked.
- **One change per pull request**, small enough to review. Open an issue
  first for anything large.
- **Commit subjects** follow Conventional Commits
  (`feat:`, `fix:`, `docs:`, `security:`, `perf:`, `refactor:`, `test:`,
  ...), written for the people reading the release notes; CI checks them
  (`sh scripts/check-commits.sh origin/main..HEAD`).
- **Documents in the same change.** A change that makes any document stale
  updates it in the same pull request: the guides and references in
  `docs/`, the CLI help, and, for design changes, an
  [architecture decision record](docs/adr/README.md).
- **Tests.** New behaviour comes with tests next to the code. Changes to
  certificates, secrets, the proxy configuration, or API authorization also
  test what must be refused.
- **Licenses of dependencies.** A new crate must be under Apache-2.0,
  MIT, BSD-2-Clause, BSD-3-Clause, ISC, MPL-2.0, CC0-1.0, or Unicode-3.0
  (Unicode data), so Armada stays free for commercial use; `cargo deny
  check licenses` (`deny.toml`) checks it, CI runs it, and
  [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) names every crate
  (armada-pack's tests check it). `logger/`, `shim/`, and `dns/` use the
  Rust standard library only.
  Never add code under the GPL, AGPL, SSPL, BUSL, or a license that limits
  commercial use. A new or upgraded program in the embedded runtime
  (`pack/lock.json`) updates
  [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) in the same change.
- **Security rules.** Armada holds root on every node: never weaken mTLS,
  validate anything that reaches the proxy configuration, keep secrets out
  of logs and arguments, and bind internal services only to private
  addresses. The [threat model](docs/threat-model.md) lists what each
  part defends against.

All code, comments, and documents are in English. By contributing you
agree that your contribution is licensed under the
[Apache License 2.0](LICENSE).
