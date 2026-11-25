#!/bin/sh
# Puts the pinned etcd and etcdutl (internal/runtime/embedded/lock.go) for
# this machine's architecture into .cache/etcd, checked against the pinned
# SHA-256, unless they are there already. The daemon parity tests hand
# them to the Rust armadad, which runs them where Go's armadad embeds etcd
# (ADR 0055): `make daemon-parity` runs this first.
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
lock=internal/runtime/embedded/lock.go
# The etcd entry of lock.go: its URL, and the SHA-256 for this arch.
url=$(grep -o 'https://github.com/etcd-io/etcd/releases/download/[^"]*' "$lock" | head -n 1)
sum=$(awk '/Name: *"etcd"/ { in_etcd = 1 } in_etcd && /"'"$arch"'":/ { gsub(/[",]/, "", $2); print $2; exit }' "$lock")
version=$(printf '%s\n' "$url" | sed 's|.*/download/\(v[^/]*\)/.*|\1|')
if [ -z "$url" ] || [ -z "$sum" ]; then
	echo "etcd-cache: no etcd pin in $lock" >&2
	exit 1
fi
url=$(printf '%s\n' "$url" | sed "s/{arch}/$arch/")
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -fsSL --retry 3 -o "$tmp/etcd.tar.gz" "$url"
echo "$sum  $tmp/etcd.tar.gz" | sha256sum -c - >/dev/null
tar -xzf "$tmp/etcd.tar.gz" -C "$tmp" "etcd-$version-linux-$arch/etcd" "etcd-$version-linux-$arch/etcdutl"
mkdir -p "$dir"
mv "$tmp/etcd-$version-linux-$arch/etcd" "$tmp/etcd-$version-linux-$arch/etcdutl" "$dir/"
echo "etcd-cache: etcd $version for $arch in $dir"
