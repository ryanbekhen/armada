# Releasing

Releases are built and signed by GitHub Actions; nothing is built or signed
on a maintainer's machine.

## Cutting a release

1. Make sure `main` is green (`make check` locally matches CI), and that
   the runtime pack's pins have no known advisory:
   `cargo run --locked -p armada-pack -- outdated` (below) must not exit
   with 2. Update an affected pin first, or say in the release notes why
   the advisory does not reach Armada.
2. Run the end-to-end test on real machines from the commit you are about to
   tag ([test/e2e](../test/e2e/README.md)); it must pass.
3. Tag and push:

   ```bash
   git tag -s v0.1.0 -m "v0.1.0"
   git push origin v0.1.0
   ```

4. The `release` workflow (`.github/workflows/release.yml`) builds the
   `armada` client for macOS on a macOS runner (`darwin-client.yml`, for
   `darwin/amd64` and `darwin/arm64`), then runs CI's gates again on the
   whole workspace (`make lint test replays vuln programs-check`: formats,
   clippy, the tests, the replays, `cargo deny check advisories
   licenses`, and the programs outside the workspace). GoReleaser (`.goreleaser.yaml`) then runs
   `make runtime-bundle` (armada-log, armada-shim, armada-dns, and
   armada-node built with the pinned Rust toolchain, and the pinned runtime
   programs downloaded and checked; see ADR 0011), builds `armadad` and
   `armada` from Rust with `cargo build --release --locked` for
   `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl` (static
   programs; `armadad` with the `bundle` feature, so it embeds the runtime
   pack; ADR 0055), takes the macOS client the first job built
   (`scripts/release-darwin.sh` checks it is a Mach-O program for its
   architecture), and publishes a **draft** release with:
   - `armada-client_<version>_linux_<arch>.tar.gz` (the `armada` client
     alone, for computers that only manage a cluster, LICENSE, README,
     SECURITY.md, and the license files below),
   - `armada_<version>_linux_<arch>.tar.gz` (`armadad`, `armada`, LICENSE,
     README, SECURITY.md, the license files below, and the systemd units
     in `deploy/systemd/`, which `install.sh` and `armadad upgrade` take),
   - `armada_<version>_darwin_<arch>.tar.gz` (the `armada` client, LICENSE,
     README, SECURITY.md, and the license files below),
   - `checksums.txt` (SHA-256),
   - an SPDX SBOM per archive (syft),
   - `checksums.txt.sigstore.json`, a keyless cosign signature bundle of
     the checksum file, tied to the workflow identity and the tag,
   - GitHub build provenance attestations for the archives and checksums.
   Every archive carries `THIRD_PARTY_NOTICES.md`, `third_party/licenses/`,
   and `licenses/rust/` (each crate's license files, `make rust-licenses`);
   the full Linux archives also `licenses/runtime/` (the license files of
   the Go modules the pack's etcd and etcdutl link, and crun's `COPYING`
   and `COPYING.libcrun` in `crun@<version>/`, `make runtime-licenses`)
   and `source/runtime/` (crun's complete corresponding source: its
   release tarball, the build files of its static programs, and
   `SOURCES.txt` with each file's SHA-256 and address, `make
   runtime-sources`; crun is GPL-2.0, ADR 0056). `armada-pack` (`pack/`)
   builds the runtime pack and collects `licenses/runtime/` and
   `source/runtime/`.
   Both programs print the tag,
   the full commit, and the commit's time in `armada version` and
   `armadad version`: GoReleaser gives cargo `ARMADA_VERSION`,
   `ARMADA_COMMIT`, and `ARMADA_DATE`, which `client/build.rs` reads (the
   macOS job sets the same).
5. Review the draft and publish it.

CI runs only what a change touches (`scripts/ci-changes.sh`, job
`changes`): the crates it changes and every crate that depends on one, the
programs outside the workspace it changes, HAProxy's check when the
renderer or the image changes, and the packaging when something a release
builds changes. Every job runs on GitHub's runners, the Rust jobs keeping
crates and build output in GitHub's cache (keyed by the lock and the
toolchain), and every workflow from an outside contributor waits for the
owner's approval.

CI checks the configuration when something a release builds changes
(`goreleaser check`, job `release-config`), builds the macOS client when
the client changes (job `client-macos`), builds for arm64 only on pushes
to `main`, and on a push to `main` that touches something a release builds
runs the whole packaging without publishing or signing (job
`release-dry-run`: `goreleaser release --snapshot --skip=publish,sign`,
then `scripts/release-contents.sh`, which checks the archives' names,
programs, units, license files, crun's source against its pins, checksums,
and the version string). To do the same on a Linux machine, build the macOS client
on a Mac first, or check the Linux part with a copy of `.goreleaser.yaml`
without the darwin build and archive.

Tags with a pre-release suffix (`v0.1.0-rc.1`) are marked as pre-releases.
What a release may change is in [compatibility.md](compatibility.md): a
release that deprecates or removes something says so in its notes.

## Commit messages and release notes

GoReleaser writes the release notes from the commit subjects since the
previous tag, grouped by their [Conventional Commits](https://www.conventionalcommits.org/)
type, so every commit subject reads `type(scope)!: description`:

| Type | Release notes section |
| --- | --- |
| any type with `!` (`feat!:`, `fix(api)!:`) | Breaking changes |
| `feat` | Features |
| `security` | Security |
| `fix` | Bug fixes |
| `perf` | Performance |
| `docs` | Documentation |
| `deps` (Dependabot's crate updates) | Dependencies |
| `refactor`, `revert`, anything else | Other changes |
| `test`, `ci`, `build`, `chore`, `style` | left out |

The scope is optional, lowercase (`feat(cli): ...`). Pull requests are
merged by rebase, so each commit lands as written; the `commits` CI job
(`scripts/check-commits.sh`) rejects subjects that do not follow the format.
Run it locally with `sh scripts/check-commits.sh origin/main..HEAD`.
Dependabot pull requests are titled `deps: ...` (crates) or
`ci(deps): ...` (actions); squash-merging one uses the title as the commit
subject, so it lands in the right section. Merge commits are left out of
the notes. Every
release also ends with install and verification instructions (the
`release.footer` in `.goreleaser.yaml`).

## Labels, issues, and branch protection

- Labels are defined in `.github/labels.json`; the `labels` workflow
  creates or updates them when the file changes on `main` (or run
  `sh scripts/sync-labels.sh` with an authenticated `gh`). Labels that are
  not listed are left alone.
- Pull requests are labelled automatically: an `area/...` label per changed
  path (`.github/labeler.yml`) and a type label from the title's
  Conventional Commits prefix (`feat:` → `enhancement`, `fix:` → `bug`,
  `!` → `breaking`). Dependabot pull requests get `dependencies`.
- Issues are opened through forms (bug report, feature request, question)
  that apply a type label and `needs-triage`; blank issues are off, and
  security reports are routed to private vulnerability reporting.
- `main` is protected by a repository ruleset: no force pushes or deletion,
  linear history, changes only through pull requests (rebase or squash),
  and the required CI jobs must pass (`lint`, `test`, `vuln`, both `build`
  jobs, `haproxy`, `installer`, `logger`, `release-config`, `commits`). A
  job a change does not need is skipped by its condition, which counts as
  passed, so a required job is never removed from `ci.yml` while the
  ruleset names it: one that no longer runs would block every merge.
  `client-macos` and `release-dry-run` are not required. A new required CI
  job must be added to the ruleset as well.
- Release tags (`v*`) are protected by a second ruleset: only repository
  admins may create, move, or delete them. The `release` workflow also
  refuses a tag whose commit is not on `main`, so only reviewed code is
  built and signed. That check runs from the tagged commit's own workflow
  file, so the tag ruleset is what keeps anyone else from tagging.

## Verifying a release by hand

```bash
VERSION=v0.1.0
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity "https://github.com/ryanbekhen/armada/.github/workflows/release.yml@refs/tags/$VERSION" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
sha256sum --ignore-missing -c checksums.txt
gh attestation verify armada_${VERSION#v}_linux_amd64.tar.gz --repo ryanbekhen/armada
```

`install.sh` performs the first two checks automatically.

## Supply chain rules

- Every GitHub Action is pinned to a full commit SHA; Dependabot proposes
  updates for actions and crates weekly.
- The Rust toolchain is pinned in `rust-toolchain.toml`, and every crate
  in `Cargo.lock` (builds use `--locked`); `cargo deny check advisories`
  checks them against RustSec's advisories on every change of code.
- The HAProxy system image is pinned by digest in the code.
- The bundled runtime binaries (crun, runc, CNI plugins, tini, etcd)
  are pinned by version and SHA-256 in `pack/lock.json`; `make
  runtime-bundle` downloads them over HTTPS only and refuses any checksum
  mismatch. Dependabot and `cargo deny` do not see them, so the
  `pack-updates` workflow (`.github/workflows/pack-updates.yml`, Mondays
  and on demand) runs `armada-pack outdated` and keeps one issue, "Runtime
  pack updates", open while it finds something (label `dependencies`,
  plus `security` when an advisory affects a pin), closing it once
  everything is current. `armada-pack outdated` compares each pin with
  the latest stable release of the GitHub repository its URL names, and
  looks up the advisories known for the pinned version: the repository's
  GitHub security advisories for every program, and OSV for the Go
  programs (runc, the CNI plugins, etcd): their own module, every module
  their build information names, and the Go release they were built with
  (read from the pinned binaries, downloaded and checked as `make
  runtime-bundle` does, never run). It prints a Markdown report and exits
  0 when every pin is current and clean, 1 when only newer releases
  exist, 2 when a known advisory affects a pin, and 3 when the check
  itself failed. It uses `GITHUB_TOKEN` for GitHub's API when set. An
  advisory in a module or in Go may not reach code the program runs:
  read it, and update the pin once upstream releases a build with the
  fix.

## Updating the bundled runtime

1. Pick the new upstream release and read its notes.
2. Download the artifact for both architectures. Where upstream signs it
   (crun, runc, tini: detached GPG signatures), verify the signature
   against the maintainers' published keys; for crun also compare with the
   release's `CHECKSUMS` (crun: the `-disable-systemd` programs, ADR
   0056), for the CNI plugins with the `.sha256` and `.sha512` files on the GitHub
   release, for etcd with its `SHA256SUMS`.
3. Record the version, the URL, and both SHA-256 values in
   `pack/lock.json` (for etcd also the paths inside its archive, and the
   go.sum hash of `go.etcd.io/etcd/api/v3` at the new version as
   `apiModule.h1`, from `https://sum.golang.org/lookup/go.etcd.io/etcd/api/v3@vVERSION`),
   and the version in `THIRD_PARTY_NOTICES.md`'s table: `cargo test -p
   armada-pack` checks the pins and the notices. For crun (GPL, ADR 0056)
   also pin its source in `sources`: the release's source tarball (with
   the paths of `COPYING` and `COPYING.libcrun` in it) and the build files
   of the new tag (`flake.nix`, `flake.lock`, `nix/*.nix`), each by
   SHA-256, and update the libraries its static programs link in
   `THIRD_PARTY_NOTICES.md` (`strings` on the program names their nixpkgs
   store paths; `flake.lock` names the nixpkgs revision); `make
   runtime-sources` collects them. A program under the GPL ships only
   with its complete corresponding source, and only as a process of its
   own (never linked).
4. For etcd, `make runtime-licenses` (the new release's modules into
   `build/licenses-runtime`; it fails on a module without a license file)
   and `make proto-rust` (etcd's protos vendored again from the new API
   module; review the diff of `proto/`).
5. `make build-bundle` (it runs `make runtime-bundle` first), then run the
   end-to-end test on Linux machines ([test/e2e](../test/e2e/README.md):
   every node runs the supervisor runtime through armada-node) and the
   Rust supervisor runtime's conformance test on a node
   (`supervisor::conformance`, see CLAUDE.md) before merging.
- Never use the Let's Encrypt production endpoint in CI.
