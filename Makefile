BIN      := bin/armada
DAEMON   := bin/armadad
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT   ?= $(shell git rev-parse --verify -q HEAD 2>/dev/null || echo unknown)
# The commit's time in UTC, as GoReleaser's CommitDate: the same tree builds
# the same version string, so cargo builds again only what changed.
DATE     ?= $(shell TZ=UTC git log -1 --format=%cd --date=format-local:%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ)

# `armada version` and `armadad version` (client/build.rs, ADR 0055): read
# by the client crate at compile time.
VERSION_ENV = ARMADA_VERSION=$(VERSION) ARMADA_COMMIT=$(COMMIT) ARMADA_DATE=$(DATE)

# The test programs and hooks of the workspace's members, never part of a
# release: armada-node's and armadad's test hooks (node/src/hooks.rs,
# daemon/src/hooks.rs), the client's clock, and the parity programs the
# replays drive (armada-store-parity, armada-server-parity,
# armada-agent-parity).
TEST_FEATURES = armada-node/test-hooks,$(REPLAY_FEATURES)

# The replays (ADR 0055, item 20): what Go's code did, recorded before the
# Go code was removed, replayed against the Rust code. The recordings under
# each crate's tests/testdata are goldens: nothing writes them again, so a
# change of behaviour changes them by hand. `make replays` runs them all in
# one cargo run, so each crate is built once with one set of features;
# REPLAYS names some (CI runs those a change touches).
REPLAYS ?= store server agent client daemon
REPLAY_FEATURE_store = armada-store/parity
REPLAY_FEATURE_server = armada-server/parity
REPLAY_FEATURE_agent = armada-agent/parity
REPLAY_FEATURE_client = armada-client/test-hooks
REPLAY_FEATURE_daemon = armada-daemon/test-hooks
REPLAY_TESTS_store = replay
REPLAY_TESTS_server = scenarios
REPLAY_TESTS_agent = scenarios
REPLAY_TESTS_client = parity
REPLAY_TESTS_daemon = parity logwriter
empty :=
space := $(empty) $(empty)
comma := ,
REPLAY_FEATURES = $(subst $(space),$(comma),$(foreach r,store server agent client daemon,$(REPLAY_FEATURE_$(r))))

.PHONY: all build build-bundle logger shim dns node node-test-hooks fmt lint test replays store-replay server-scenarios agent-scenarios client-replay daemon-replay haproxy-check deny vuln programs-check rust-check check runtime-bundle runtime-licenses rust-licenses proto proto-rust docs clean

all: check build

# armada and armadad for this machine, without the runtime pack
# (build-bundle embeds it). armadad runs on Linux only, so elsewhere
# (macOS) only the client is built.
LINUX := $(filter Linux,$(shell uname -s))

build:
	$(VERSION_ENV) cargo build --release --locked -p armada-client $(if $(LINUX),-p armada-daemon)
	mkdir -p bin
	cp target/release/armada $(BIN)
	$(if $(LINUX),cp target/release/armadad $(DAEMON))

# armada-pack (pack/, a workspace member that is never shipped) builds the
# runtime pack from the pins in pack/lock.json: it downloads the pinned
# runc, CNI plugins, tini, and etcd (ADR 0046, ADR 0055) over
# HTTPS, keeps each only when its SHA-256 matches, and packs them with
# Armada's own programs below into build/pack/linux_<arch>.pack, which
# daemon/build.rs embeds. Built with the release profile: it compresses
# about 100 MB per pack.
PACK = cargo run --release --locked -q -p armada-pack --
# armada-log (logger/), the log writer every container's shim runs: Rust,
# standard library only, static for both architectures with the linker
# Rust ships (toolchain pinned in logger/rust-toolchain.toml).
LOGGER_OUT = logger/target/$(1)-unknown-linux-musl/release/armada-log
# armada-shim (shim/), which supervises an app's containers (ADR 0046):
# built the same way.
SHIM_OUT = shim/target/$(1)-unknown-linux-musl/release/armada-shim
# armada-dns (dns/), the node-local resolver of containers (ADR 0053):
# built the same way.
DNS_OUT = dns/target/$(1)-unknown-linux-musl/release/armada-dns
# armada-node (node/, ADR 0054): a member of the Cargo workspace at the
# repository's root (ADR 0055), built the same way, with crates (cargo
# deny checks their licenses).
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

# armada-node reading the ARMADA_NODE_TEST_* hooks (node/src/hooks.rs),
# built apart from the release binary and never packed.
node-test-hooks:
	cargo build --release --locked -p armada-node --features test-hooks --target x86_64-unknown-linux-musl --target-dir target/test-hooks

fmt:
	cargo fmt --all

# Lints of the workspace twice: as released (code only a release build
# has, such as the hooks turned off) and with the test features.
lint:
	cargo fmt --all --check
	cargo clippy --locked --workspace --all-targets -- -D warnings
	cargo clippy --locked --workspace --all-targets --features $(TEST_FEATURES) -- -D warnings

# Every member's tests, as released.
test:
	cargo test --locked --workspace

replays:
	sh scripts/etcd-cache.sh
	ARMADA_ETCD_DIR=$(CURDIR)/.cache/etcd cargo test --locked \
		$(foreach r,$(REPLAYS),-p armada-$(r)) \
		--features $(subst $(space),$(comma),$(strip $(foreach r,$(REPLAYS),$(REPLAY_FEATURE_$(r))))) \
		$(addprefix --test ,$(sort $(foreach r,$(REPLAYS),$(REPLAY_TESTS_$(r)))))

# Each replay alone.

# The store's calls, answers, and keyspaces on the pinned etcd, with the
# Rust-only checks of two stores at once.
store-replay:
	sh scripts/etcd-cache.sh
	ARMADA_ETCD_DIR=$(CURDIR)/.cache/etcd cargo test --locked -p armada-store --features armada-store/parity --test replay

# The control plane's scenarios against the Rust server on the pinned etcd.
server-scenarios:
	sh scripts/etcd-cache.sh
	ARMADA_ETCD_DIR=$(CURDIR)/.cache/etcd cargo test --locked -p armada-server --features armada-server/parity --test scenarios

# The agent's scenarios against its parity program with the fakes in Rust.
agent-scenarios:
	cargo test --locked -p armada-agent --features armada-agent/parity --test scenarios

# The client's cases against the Rust armada (its test-hooks build, whose
# clock starts at the recorded time) and a stand-in AdminService.
client-replay:
	cargo test --locked -p armada-client --features armada-client/test-hooks --test parity

# The daemon's cases against the Rust armadad with its test hooks, the
# stand-ins, a stand-in bucket, and the pinned etcd; and what the log
# writer stores (ARMADA_LOG_BIN=armada-log checks armada-log too).
daemon-replay:
	sh scripts/etcd-cache.sh
	ARMADA_ETCD_DIR=$(CURDIR)/.cache/etcd cargo test --locked -p armada-daemon --features armada-daemon/test-hooks --test parity --test logwriter

# haproxy -c on the configurations armada-node renders, with the pinned
# image (needs docker, podman, or nerdctl; CI job haproxy).
haproxy-check:
	sh scripts/haproxy-check.sh

# The crates' licenses (deny.toml) and the advisories of every crate in
# Cargo.lock (RustSec). `cargo install cargo-deny --locked`.
deny:
	cargo deny --locked check licenses

vuln:
	cargo deny --locked check advisories licenses

# armada-log, armada-shim, and armada-dns: each in its own directory with
# its own lock file and toolchain file (standard library only), and the
# generator of `make proto` (proto/gen, its own lock).
programs-check:
	for d in logger shim dns proto/gen; do \
		(cd $$d && cargo fmt --check && cargo clippy --locked --all-targets -- -D warnings && cargo test --locked) || exit 1; \
	done

# Everything CI checks of the workspace, in one target: formats and lints,
# tests, the replays, the crates' licenses and advisories, and every
# member built for both release targets.
rust-check: lint test replays vuln
	cargo build --release --locked --workspace --target x86_64-unknown-linux-musl
	cargo build --release --locked --workspace --target aarch64-unknown-linux-musl

check: rust-check programs-check

runtime-bundle: logger shim dns node
	$(PACK) bundle --arch amd64 --logger $(call LOGGER_OUT,x86_64) --shim $(call SHIM_OUT,x86_64) --dns $(call DNS_OUT,x86_64) --node $(call NODE_OUT,x86_64)
	$(PACK) bundle --arch arm64 --logger $(call LOGGER_OUT,aarch64) --shim $(call SHIM_OUT,aarch64) --dns $(call DNS_OUT,aarch64) --node $(call NODE_OUT,aarch64)

# The license files of every Go module the pack's etcd and etcdutl link
# (their build information names each with its go.sum hash, which every
# module zip from the Go module proxy is checked against) into
# build/licenses-runtime: release archives carry them as licenses/runtime.
runtime-licenses:
	$(PACK) licenses --out build/licenses-runtime

# Every crate's license and notice files into build/licenses-rust (release
# archives: licenses/rust).
rust-licenses:
	sh scripts/rust-licenses.sh build/licenses-rust

# Linux binaries as releases build them (.goreleaser.yaml): static musl
# armadad with the runtime pack embedded (the bundle feature, daemon/build.rs)
# and the armada client, for ARCH (amd64, the default, or arm64).
BUNDLE_ARCH = $(or $(ARCH),amd64)
BUNDLE_TARGET = $(if $(filter arm64,$(BUNDLE_ARCH)),aarch64,x86_64)-unknown-linux-musl

build-bundle: runtime-bundle
	$(VERSION_ENV) cargo build --release --locked -p armada-daemon -p armada-client --features armada-daemon/bundle --target $(BUNDLE_TARGET)
	mkdir -p bin
	cp target/$(BUNDLE_TARGET)/release/armadad $(DAEMON)-linux-$(BUNDLE_ARCH)
	cp target/$(BUNDLE_TARGET)/release/armada $(BIN)-linux-$(BUNDLE_ARCH)

# The command line reference in docs/cli, written from the commands:
# armada's pages by the client's clidoc test, armadad's by the daemon's.
# Without ARMADA_CLIDOC_UPDATE the same tests (cargo test) fail when
# docs/cli is stale.
docs:
	ARMADA_CLIDOC_UPDATE=1 cargo test --locked -p armada-client --test clidoc
	ARMADA_CLIDOC_UPDATE=1 cargo test --locked -p armada-daemon --test clidoc

# armada-proto's code (proto/src/gen, ADR 0055) with the generators
# proto/gen pins (its own Cargo.lock): Armada's protocol
# (api/armada/v1/armada.proto), and etcd's protos vendored again
# (proto/vendor) from etcd's API module at the version the pinned etcd
# links (pack/lock.json, checked against its go.sum hash there; armada-pack
# etcd-api). The code is checked in, so building it needs no protoc.
proto: proto-rust

proto-rust:
	dir=$$($(PACK) etcd-api --out .cache/etcd-api) && \
		cargo run --locked -q --manifest-path proto/gen/Cargo.toml -- . "$$dir"

clean:
	rm -rf bin build/pack
