#!/bin/sh
# Copies the license and notice files of every crate the Cargo workspace
# (Cargo.toml: armada-node, armada-proto, armada-spec) uses into
# OUT/<crate>-<version>/, for release archives (licenses/rust). A crate
# published without its license file (pbjson, tonic-prost) gets the one
# from its repository, kept in third_party/licenses/rust/<crate>/.
set -eu
out=${1:?usage: rust-licenses.sh OUT}
rm -rf "$out"
mkdir -p "$out"
cargo metadata --format-version 1 --locked --manifest-path Cargo.toml |
	jq -r '.packages[] | select(.source != null) | "\(.name) \(.version) \(.manifest_path)"' |
	while read -r crate version manifest; do
		name=$crate-$version
		dir=$(dirname "$manifest")
		mkdir -p "$out/$name"
		found=0
		# Names in any case: some crates ship license-mit, for one.
		for f in "$dir"/* "third_party/licenses/rust/$crate"/*; do
			[ -f "$f" ] || continue
			case $(basename "$f" | tr '[:lower:]' '[:upper:]') in
			LICENSE* | LICENCE* | COPYING* | NOTICE* | UNLICENSE*) ;;
			*) continue ;;
			esac
			cp "$f" "$out/$name/"
			found=1
		done
		if [ "$found" = 0 ]; then
			echo "rust-licenses: $name has no license file" >&2
			exit 1
		fi
	done
