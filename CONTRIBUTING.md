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

You need Go (the version in `go.mod`), `golangci-lint` v2, `govulncheck`,
and `protoc` (only to change the API).

```bash
make build         # ./bin/armada (client) and ./bin/armadad (daemon)
make test          # unit tests with the race detector
make check         # vet + lint + test + govulncheck: what CI runs
make build-bundle  # a Linux armadad with the container runtime embedded
make docs          # regenerate the CLI reference in docs/cli
make proto         # regenerate api/armada/v1 after changing the .proto
```

A single test: `go test ./internal/spec/... -run TestName`. Golden files of
the proxy configuration: `go test ./internal/proxy/haproxy -update`.

[test/e2e](test/e2e/README.md) builds a cluster on real machines and
checks it end to end: rolling updates and failover under load, node loss,
reboots, and every feature's scenario. Releases run all of it.

## Pull requests

- **CI** builds, lints, and tests every pull request that changes code. One
  that changes only documents (Markdown, `docs/`, the license, issue
  templates) skips those jobs and only has its commit subjects checked.
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
- **Licenses of dependencies.** A new Go module must be under Apache-2.0,
  MIT, BSD-2-Clause, BSD-3-Clause, ISC, MPL-2.0, or CC0-1.0, so Armada
  stays free for commercial use; `make licenses` checks it, and CI runs it.
  Never add code under the GPL, AGPL, SSPL, BUSL, or a license that limits
  commercial use. A new or upgraded program in the embedded runtime
  (`internal/runtime/embedded/lock.go`) updates
  [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) in the same change.
- **Security rules.** Armada holds root on every node: never weaken mTLS,
  validate anything that reaches the proxy configuration, keep secrets out
  of logs and arguments, and bind internal services only to private
  addresses. The [threat model](docs/threat-model.md) lists what each
  part defends against.

All code, comments, and documents are in English. By contributing you
agree that your contribution is licensed under the
[Apache License 2.0](LICENSE).
