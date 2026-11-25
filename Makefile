MODULE   := github.com/ryanbekhen/armada
BIN      := bin/armada
DAEMON   := bin/armadad
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT   ?= $(shell git rev-parse --verify -q HEAD 2>/dev/null || echo unknown)
DATE     ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X $(MODULE)/internal/version.version=$(VERSION) \
	-X $(MODULE)/internal/version.commit=$(COMMIT) \
	-X $(MODULE)/internal/version.date=$(DATE)

export CGO_ENABLED := 0

.PHONY: all build build-bundle logger shim dns node node-test-hooks pki-parity store-parity rust-check runtime-bundle test cover lint fmt vet vuln licenses licenses-save proto docs tidy check clean

all: check build

build:
	go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/armada
	go build -trimpath -ldflags '$(LDFLAGS)' -o $(DAEMON) ./cmd/armadad

# Downloads the pinned containerd, runc, CNI plugins, and tini (ADR 0011),
# checks their SHA-256, and packs them for embedding.
# armada-log (logger/), the log writer every container's shim runs: Rust,
# standard library only, static for both architectures with the linker
# Rust ships (toolchain pinned in logger/rust-toolchain.toml).
LOGGER_OUT = logger/target/$(1)-unknown-linux-musl/release/armada-log
# armada-shim (shim/), which supervises an app's containers without
# containerd (ADR 0046): built the same way.
SHIM_OUT = shim/target/$(1)-unknown-linux-musl/release/armada-shim
# armada-dns (dns/), the node-local resolver of containers (ADR 0053):
# built the same way.
DNS_OUT = dns/target/$(1)-unknown-linux-musl/release/armada-dns
# armada-node (node/), the node agent moving to Rust (ADR 0054): a member
# of the Cargo workspace at the repository's root (ADR 0055), built the same
# way, with crates (cargo deny checks their licenses).
NODE_OUT = target/$(1)-unknown-linux-musl/release/armada-node

logger:
	cd logger && cargo build --release --locked --target x86_64-unknown-linux-musl
	cd logger && cargo build --release --locked --target aarch64-unknown-linux-musl

shim:
	cd shim && cargo build --release --locked --target x86_64-unknown-linux-musl
	cd shim && cargo build --release --locked --target aarch64-unknown-linux-musl

dns:
	cd dns && cargo build --release --locked --target x86_64-unknown-linux-musl
	cd dns && cargo build --release --locked --target aarch64-unknown-linux-musl

node:
	cargo build --release --locked -p armada-node --target x86_64-unknown-linux-musl
	cargo build --release --locked -p armada-node --target aarch64-unknown-linux-musl

# armada-node reading the ARMADA_NODE_TEST_* hooks Go's parity tests set
# (node/src/hooks.rs), built apart from the release binary and never packed.
node-test-hooks:
	cargo build --release --locked -p armada-node --features test-hooks --target x86_64-unknown-linux-musl --target-dir target/test-hooks

# The programs Go's parity tests of the CA, certificates, and secrets run
# (ADR 0055): target/debug/armada-pki-parity (ARMADA_PKI_BIN) and
# target/debug/armada-secrets-parity (ARMADA_SECRETS_BIN). Never part of a
# release.
pki-parity:
	cargo build --locked -p armada-pki -p armada-secrets --features armada-pki/parity,armada-secrets/parity

# The program Go's parity tests of the store run (ADR 0055):
# target/debug/armada-store-parity (ARMADA_STORE_BIN). Never part of a
# release.
store-parity:
	cargo build --locked -p armada-store --features parity

# The Cargo workspace's checks (ADR 0055; CI job logger): format, lints,
# tests, crate licenses, and every member built for both release targets.
# proto/gen, outside it, gets its format and lints checked too; armada-log,
# armada-shim, and armada-dns are checked in their own directories.
rust-check:
	cargo fmt --all --check
	cargo clippy --locked --workspace --all-targets -- -D warnings
	cargo clippy --locked -p armada-node --all-targets --features test-hooks -- -D warnings
	cargo clippy --locked -p armada-pki -p armada-secrets --all-targets --features armada-pki/parity,armada-secrets/parity -- -D warnings
	cargo clippy --locked -p armada-store --all-targets --features parity -- -D warnings
	cargo test --locked --workspace
	cargo deny --locked check licenses
	cargo build --release --locked --workspace --target x86_64-unknown-linux-musl
	cargo build --release --locked --workspace --target aarch64-unknown-linux-musl
	cd proto/gen && cargo fmt --check && cargo clippy --locked --all-targets -- -D warnings

runtime-bundle: logger shim dns node
	go run ./internal/runtime/embedded/mkbundle -arch amd64 -logger $(call LOGGER_OUT,x86_64) -shim $(call SHIM_OUT,x86_64) -dns $(call DNS_OUT,x86_64) -node $(call NODE_OUT,x86_64)
	go run ./internal/runtime/embedded/mkbundle -arch arm64 -logger $(call LOGGER_OUT,aarch64) -shim $(call SHIM_OUT,aarch64) -dns $(call DNS_OUT,aarch64) -node $(call NODE_OUT,aarch64)

# Linux binaries as releases are built: armadad with the runtime bundle
# embedded, and the armada client.
build-bundle: runtime-bundle
	GOOS=linux GOARCH=$(or $(GOARCH),amd64) go build -trimpath -tags bundle -ldflags '$(LDFLAGS)' -o $(DAEMON)-linux-$(or $(GOARCH),amd64) ./cmd/armadad
	GOOS=linux GOARCH=$(or $(GOARCH),amd64) go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)-linux-$(or $(GOARCH),amd64) ./cmd/armada

test:
	CGO_ENABLED=1 go test -race ./...

cover:
	CGO_ENABLED=1 go test -race -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

lint:
	golangci-lint run

fmt:
	golangci-lint fmt

vet:
	go vet ./...

vuln:
	govulncheck ./...

docs: ## regenerate the command line reference in docs/cli
	go test ./internal/clidoc -run TestReferenceIsCurrent -update -count=1

# Go's code next to the protos, then armada-proto's (proto/src/gen, ADR
# 0055) with the generators proto/gen pins (its own Cargo.lock): Armada's
# protocol, and etcd's protos vendored again from the etcd module go.mod
# pins (proto/vendor). The Rust code is checked in, so building it needs no
# protoc.
proto:
	go build -o bin/tools/ google.golang.org/protobuf/cmd/protoc-gen-go google.golang.org/grpc/cmd/protoc-gen-go-grpc
	protoc -I api \
		--plugin=protoc-gen-go=bin/tools/protoc-gen-go \
		--plugin=protoc-gen-go-grpc=bin/tools/protoc-gen-go-grpc \
		--go_out=api --go_opt=paths=source_relative \
		--go-grpc_out=api --go-grpc_opt=paths=source_relative \
		api/armada/v1/*.proto
	cargo run --locked -q --manifest-path proto/gen/Cargo.toml -- . "$$(go list -m -f '{{.Dir}}' go.etcd.io/etcd/api/v3)"

tidy:
	go mod tidy

# Everything CI runs, in one target.
check: vet lint test vuln

clean:
	rm -rf bin coverage.out internal/runtime/embedded/bundle

# Licenses of the Go modules the binaries are built from (THIRD_PARTY_NOTICES.md).
GO_LICENSES = go run github.com/google/go-licenses/v2@v2.0.1
ALLOWED_LICENSES = Apache-2.0,MIT,BSD-2-Clause,BSD-3-Clause,ISC,MPL-2.0,CC0-1.0

licenses: ## fail when a Go module under a license outside ALLOWED_LICENSES is added
	$(GO_LICENSES) check ./cmd/... --allowed_licenses=$(ALLOWED_LICENSES)

licenses-save: ## copy every Go module's license and notice files into build/licenses (release archives)
	rm -rf build/licenses
	$(GO_LICENSES) save ./cmd/... --save_path=build/licenses 2>/dev/null
	sh scripts/rust-licenses.sh build/licenses-rust
