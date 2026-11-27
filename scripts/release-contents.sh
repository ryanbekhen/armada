#!/bin/sh
# Checks what GoReleaser wrote into DIST (default dist) against what
# install.sh, armadad upgrade, and people
# read (docs/releasing.md): every archive name, the binaries and files in
# each, checksums.txt, static Linux programs, the runtime pack in armadad,
# crun's source in the full Linux archives (ADR 0056), and the version
# both binaries print. Run it from the repository's root (it reads
# pack/lock.json). CI's release-dry-run job runs it
# after `goreleaser release --snapshot`; run it locally the same way.
set -eu
dist=${1:-dist}
fail() {
	echo "release-contents: $*" >&2
	exit 1
}
[ -f "$dist/checksums.txt" ] || fail "no $dist/checksums.txt"
[ -f "$dist/metadata.json" ] || fail "no $dist/metadata.json"
version=$(jq -r .version "$dist/metadata.json")
tag=$(jq -r .tag "$dist/metadata.json")
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Every archive a release has, each listed in checksums.txt.
for a in \
	"armada_${version}_linux_amd64" "armada_${version}_linux_arm64" \
	"armada-client_${version}_linux_amd64" "armada-client_${version}_linux_arm64" \
	"armada_${version}_darwin_amd64" "armada_${version}_darwin_arm64"; do
	[ -f "$dist/$a.tar.gz" ] || fail "missing $a.tar.gz"
	grep -q "  $a.tar.gz\$" "$dist/checksums.txt" || fail "$a.tar.gz is not in checksums.txt"
	mkdir "$work/$a"
	tar -xzf "$dist/$a.tar.gz" -C "$work/$a"
	for f in armada LICENSE THIRD_PARTY_NOTICES.md README.md SECURITY.md; do
		[ -f "$work/$a/$f" ] || fail "$a: no $f"
	done
	[ -x "$work/$a/armada" ] || fail "$a: armada is not executable"
	[ ! -L "$work/$a/armada" ] || fail "$a: armada is a link"
	for d in third_party/licenses licenses/rust; do
		[ -n "$(ls -A "$work/$a/$d" 2>/dev/null)" ] || fail "$a: $d is empty"
	done
done
(cd "$dist" && sha256sum --ignore-missing -c checksums.txt >/dev/null) || fail "checksums.txt does not match"

for arch in amd64 arm64; do
	full=$work/armada_${version}_linux_$arch
	client=$work/armada-client_${version}_linux_$arch
	# The full archive: both programs, each its own file, and the units.
	[ -x "$full/armadad" ] || fail "linux_$arch: no armadad program"
	[ ! -L "$full/armadad" ] || fail "linux_$arch: armadad is a link"
	for unit in armada-server armada-agent armada-runtime armada-etcd; do
		[ -f "$full/deploy/systemd/$unit.service" ] || fail "linux_$arch: no deploy/systemd/$unit.service"
	done
	# The license files of the Go modules the pack's etcd programs link.
	[ -f "$full/licenses/runtime/MODULES.txt" ] || fail "linux_$arch: no licenses/runtime/MODULES.txt"
	# crun's complete corresponding source and license texts (GPL-2.0,
	# ADR 0056): every file pack/lock.json pins, with its SHA-256.
	src=$full/source/runtime
	[ -f "$src/SOURCES.txt" ] || fail "linux_$arch: no source/runtime/SOURCES.txt"
	crun=$(jq -r '.artifacts[] | select(.name == "crun") | .version' pack/lock.json)
	[ "$(jq '[.artifacts[].sources // [] | length] | add' pack/lock.json)" -eq "$(wc -l <"$src/SOURCES.txt")" ] || fail "linux_$arch: SOURCES.txt does not list every pinned source"
	while read -r rel sum _url; do
		[ -f "$src/$rel" ] || fail "linux_$arch: no source/runtime/$rel"
		[ "$(sha256sum "$src/$rel" | cut -d' ' -f1)" = "$sum" ] || fail "linux_$arch: source/runtime/$rel does not match its pin"
	done <"$src/SOURCES.txt"
	[ -f "$src/crun-$crun/crun-$crun.tar.gz" ] || fail "linux_$arch: no source/runtime/crun-$crun/crun-$crun.tar.gz"
	for f in COPYING COPYING.libcrun; do
		[ -f "$full/licenses/runtime/crun@$crun/$f" ] || fail "linux_$arch: no licenses/runtime/crun@$crun/$f"
	done
	[ ! -e "$client/source" ] || fail "client archive linux_$arch: holds the runtime's source"
	[ ! -e "$client/armadad" ] || fail "client archive linux_$arch: holds armadad"
	[ ! -e "$client/deploy" ] || fail "client archive linux_$arch: holds the units"
	case $arch in
	amd64) machine=x86-64 pack=build/pack/linux_amd64.pack ;;
	arm64) machine=aarch64 pack=build/pack/linux_arm64.pack ;;
	esac
	for b in "$full/armadad" "$full/armada" "$client/armada"; do
		out=$(file -b "$b")
		case $out in
		*"$machine"*static*) ;;
		*) fail "$b: not a static $machine program: $out" ;;
		esac
	done
	# armadad carries the runtime pack (the bundle feature).
	if [ -f "$pack" ]; then
		[ "$(stat -c %s "$full/armadad")" -gt "$(stat -c %s "$pack")" ] || fail "linux_$arch: armadad has no runtime pack"
	fi
done
for arch in amd64 arm64; do
	d=$work/armada_${version}_darwin_$arch
	[ ! -e "$d/armadad" ] || fail "darwin_$arch: holds armadad"
	out=$(file -b "$d/armada")
	case $out in
	Mach-O*) ;;
	*) fail "darwin_$arch: armada is not a Mach-O program: $out" ;;
	esac
done

# The version string, as Go's -X flags set it: the tag and the full commit.
if [ "$(uname -m)" = x86_64 ]; then
	commit=$(jq -r .commit "$dist/metadata.json")
	for b in armada armadad; do
		out=$(ARMADA_NO_UPDATE_CHECK=1 "$work/armada_${version}_linux_amd64/$b" version)
		case $out in
		"armada $tag (commit $commit, built "*", rust"*", linux/amd64)"*) ;;
		*) fail "$b version: $out" ;;
		esac
	done
fi
echo "release-contents: $dist matches the release layout ($tag)"
