#!/bin/sh
# Stands in for cargo in GoReleaser's darwin build of the armada client
# (.goreleaser.yaml, build armada-darwin). The client is built on macOS by
# the darwin-client workflow, whose artifact the release job puts in
# target/<target>/release/armada; GoReleaser runs this script as
# `sh scripts/release-darwin.sh --target=TARGET ...` and then takes
# that file, as it takes cargo's output. The script checks that the file is
# there and is a 64-bit Mach-O program for TARGET, and makes it executable
# (artifacts lose the mode). It builds nothing.
set -eu
target=
for arg in "$@"; do
	case $arg in
	--target=*) target=${arg#--target=} ;;
	esac
done
case $target in
x86_64-apple-darwin) cpu=07000001 ;;
aarch64-apple-darwin) cpu=0c000001 ;;
*)
	echo "release-darwin: unexpected target '$target'" >&2
	exit 1
	;;
esac
bin=target/$target/release/armada
if [ ! -s "$bin" ]; then
	echo "release-darwin: $bin is missing: the darwin-client job builds it on macOS" >&2
	exit 1
fi
# The Mach-O header: magic MH_MAGIC_64 (little-endian), then the CPU type.
head=$(od -An -tx1 -N8 "$bin" | tr -d ' \n')
if [ "$head" != "cffaedfe$cpu" ]; then
	echo "release-darwin: $bin is not a 64-bit Mach-O program for $target" >&2
	exit 1
fi
chmod 0755 "$bin"
