#!/bin/sh
# Puts the pinned etcd and etcdutl (pack/lock.json) for this machine's
# architecture into .cache/etcd, checked against the pinned SHA-256,
# unless they are there already. The replays of the store, the server, and
# the daemon run them (ADR 0055): `make store-replay`, `server-scenarios`,
# and `daemon-replay` run this first. armada-pack (pack/) downloads and
# checks the release archive, as `make runtime-bundle` does.
set -eu

dir=.cache/etcd
if [ -x "$dir/etcd" ] && [ -x "$dir/etcdutl" ]; then
	exit 0
fi
case "$(uname -m)" in
x86_64) arch=amd64 ;;
aarch64 | arm64) arch=arm64 ;;
*)
	echo "etcd-cache: no pinned etcd for $(uname -m)" >&2
	exit 1
	;;
esac
cargo run --release --locked -q -p armada-pack -- extract --arch "$arch" --artifact etcd --out "$dir"
