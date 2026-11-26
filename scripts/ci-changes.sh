#!/bin/sh
# What a change touches, for CI's jobs to run only what it needs
# (.github/workflows/ci.yml, job changes). Prints key=value lines, which
# CI appends to $GITHUB_OUTPUT:
#
#   code       anything but documents changed
#   crates     the workspace members to lint and test: those changed and
#              every member that depends on one (path dependencies, dev
#              ones included, read from each member's Cargo.toml)
#   packages   the same as cargo's -p arguments
#   features   the test features of those members (parity, test-hooks),
#              which only the members selected may name
#   replays    the replays to run: store, server, agent, client, daemon
#   logger shim dns proto_gen
#              these programs outside the workspace changed
#   clidoc     docs/cli changed (checked by the client's and the daemon's
#              clidoc tests)
#   haproxy    what HAProxy reads changed (the renderer, its recorded
#              cases, the pinned image)
#   installer  install.sh, a shell script, or the units changed
#   release    something a release builds or packs changed
#   macos      the macOS client's build is affected
#
# Usage: ci-changes.sh BASE HEAD. Without both, or when the diff cannot
# be read, everything runs. So does a change to the workspace's manifest,
# lock, toolchain, lints, Makefile, the CI workflow, or this script, and
# a file this script does not know.
set -eu

members=$(sed -n 's/^members = \[\(.*\)\]$/\1/p' Cargo.toml | tr -d '",')

all=false
files=${CI_CHANGES_FILES-} # tests of this script: the changed files
if [ -n "$files" ]; then
	:
elif [ $# -lt 2 ] || [ -z "$1" ] || [ "$1" = 0000000000000000000000000000000000000000 ] ||
	! files=$(git diff --name-only "$1" "$2"); then
	all=true
fi

code=false changed='' logger=false shim=false dns=false proto_gen=false
clidoc=false haproxy=false installer=false release=false macos=false

add() {
	case " $changed " in
	*" $1 "*) ;;
	*) changed="$changed $1" ;;
	esac
}

for f in $files; do
	case "$f" in
	# Documents. THIRD_PARTY_NOTICES.md is read by armada-pack's tests.
	THIRD_PARTY_NOTICES.md) code=true release=true && add pack ;;
	docs/cli/*) code=true clidoc=true ;;
	*.md | docs/* | LICENSE | .github/ISSUE_TEMPLATE/* | .github/labeler.yml | \
		.github/labels.json | .github/dependabot.yml | .github/workflows/labels.yml | \
		.github/workflows/pack-updates.yml) ;;
	# Everything.
	Cargo.toml | Cargo.lock | rust-toolchain.toml | .cargo/* | deny.toml | Makefile | \
		.github/workflows/ci.yml | scripts/ci-changes.sh | scripts/etcd-cache.sh) all=true ;;
	# Outside the workspace.
	proto/gen/*) code=true proto_gen=true ;;
	logger/*) code=true logger=true release=true && add pack ;;
	shim/*) code=true shim=true release=true && add pack ;;
	dns/*) code=true dns=true release=true && add pack ;;
	api/*) code=true proto_gen=true && add proto ;;
	# Packaging and installing.
	.goreleaser.yaml | .github/workflows/release.yml | scripts/release-*.sh | \
		scripts/rust-licenses.sh | third_party/*) code=true release=true ;;
	.github/workflows/darwin-client.yml) code=true release=true macos=true ;;
	deploy/*) code=true release=true installer=true ;;
	scripts/haproxy-check.sh) code=true installer=true haproxy=true ;;
	install.sh | test/*.sh | scripts/*.sh) code=true installer=true ;;
	test/*) ;;
	*)
		dir=${f%%/*}
		case " $members " in
		*" $dir "*)
			code=true
			add "$dir"
			case "$f" in
			node/src/proxy/* | node/tests/render.rs | node/tests/testdata/render.* | \
				agent/src/haproxy/engine.rs) haproxy=true ;;
			esac
			;;
		*) all=true ;;
		esac
		;;
	esac
done
if $all; then
	code=true changed=$members logger=true shim=true dns=true proto_gen=true
	clidoc=true haproxy=true installer=true release=true macos=true
fi

# Every member that depends on a changed one, until nothing is added.
crates=$changed
while :; do
	before=$crates
	for m in $members; do
		case " $crates " in *" $m "*) continue ;; esac
		# shellcheck disable=SC2013 # crate names, one word each
		for d in $(sed -n 's/.*path = "\.\.\/\([a-z]*\)".*/\1/p' "$m/Cargo.toml"); do
			case " $crates " in
			*" $d "*)
				crates="$crates $m"
				break
				;;
			esac
		done
	done
	[ "$crates" = "$before" ] && break
done

packages='' features='' replays=''
for m in $members; do
	case " $crates " in *" $m "*) ;; *) continue ;; esac
	packages="$packages -p armada-$m"
	case $m in
	node | client | daemon) features="$features,armada-$m/test-hooks" ;;
	store | server | agent) features="$features,armada-$m/parity" ;;
	esac
	case $m in
	store | server | agent | client | daemon) replays="$replays $m" ;;
	esac
	release=true
	[ "$m" != client ] || macos=true
done

trim() { echo "$1" | sed 's/^[ ,]*//'; }
echo "code=$code"
echo "crates=$(trim "$crates")"
echo "packages=$(trim "$packages")"
echo "features=$(trim "$features")"
echo "replays=$(trim "$replays")"
echo "logger=$logger"
echo "shim=$shim"
echo "dns=$dns"
echo "proto_gen=$proto_gen"
echo "clidoc=$clidoc"
echo "haproxy=$haproxy"
echo "installer=$installer"
echo "release=$release"
echo "macos=$macos"
