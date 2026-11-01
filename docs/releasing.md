# Releasing

Releases are built and signed by GitHub Actions; nothing is built or signed
on a maintainer's machine.

## Cutting a release

1. Make sure `main` is green (`make check` locally matches CI).
2. Tag and push:

   ```bash
   git tag -s v0.1.0 -m "v0.1.0"
   git push origin v0.1.0
   ```

3. The `release` workflow (`.github/workflows/release.yml`) runs vet, the
   race tests, and govulncheck again, then GoReleaser
   (`.goreleaser.yaml`) builds `linux/amd64` and `linux/arm64` with
   `CGO_ENABLED=0` and `-trimpath` (after `make runtime-bundle`, with the
   `bundle` tag, so the binary embeds the container runtime; see ADR 0011),
   and publishes a **draft** release with:
   - `armada_<version>_linux_<arch>.tar.gz` (binary, LICENSE, README,
     SECURITY.md, systemd units),
   - `checksums.txt` (SHA-256),
   - an SPDX SBOM per archive (syft),
   - `checksums.txt.sigstore.json`, a keyless cosign signature bundle of
     the checksum file, tied to the workflow identity and the tag,
   - GitHub build provenance attestations for the archives and checksums.
4. Review the draft and publish it.

Tags with a pre-release suffix (`v0.1.0-rc.1`) are marked as pre-releases.

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
  updates for actions and Go modules weekly.
- The Go toolchain is pinned with `toolchain` in `go.mod`.
- The HAProxy system image is pinned by digest in the code.
- The bundled runtime binaries (containerd, runc, CNI plugins, tini) are
  pinned by version and SHA-256 in `internal/runtime/embedded/lock.go`.
  Before each release, check their advisories: `govulncheck` does not see
  them.

## Updating the bundled runtime

1. Pick the new upstream release and read its notes.
2. Download the artifact for both architectures. Where upstream signs it
   (runc, tini: detached GPG signatures), verify the signature against the
   maintainers' published keys; for containerd and the CNI plugins compare
   with the `.sha256sum` files on the GitHub release.
3. Record the version and both SHA-256 values in `lock.go`.
4. `make runtime-bundle build-bundle`, then run the embedded runtime
   end to end on a Linux node (deploy, rolling update, secret files,
   internal DNS, self-healing) before merging.
- Never use the Let's Encrypt production endpoint in CI.
