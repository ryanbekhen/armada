#!/bin/sh
# shellcheck disable=SC2016 # fake programs are written with literal $
# Tests install.sh against a fake release served from a local directory.
# Run from the repository root on Linux: sh test/install_test.sh
set -eu

ROOT=$(pwd)
WORK=$(mktemp -d)
trap 'rm -rf -- "$WORK"' EXIT

VERSION=v0.0.1-test
ARCH=amd64
case "$(uname -m)" in aarch64 | arm64) ARCH=arm64 ;; esac
ARCHIVE="armada_${VERSION#v}_linux_${ARCH}.tar.gz"

fail() {
	printf 'FAIL: %s\n' "$*" >&2
	exit 1
}

# make_release DIR: a release with fake binaries and the systemd units.
make_release() {
	rel="$1/$VERSION"
	mkdir -p "$rel" "$1/src/deploy"
	for bin in armada armadad; do
		{
			printf '#!/bin/sh\n'
			printf 'echo "%s $*" >>"${FAKE_LOG:-/dev/null}"\n' "$bin"
			printf '[ "${FAKE_FAIL:-}" != 1 ] || exit 1\n'
			printf 'echo "%s %s (fake)"\n' "$bin" "$VERSION"
		} >"$1/src/$bin"
		chmod 755 "$1/src/$bin"
	done
	cp -R "$ROOT/deploy/systemd" "$1/src/deploy/"
	tar -czf "$rel/$ARCHIVE" -C "$1/src" armada armadad deploy
	(cd "$rel" && sha256sum "$ARCHIVE" >checksums.txt)
}

# install_from DIR NAME [VAR=value...]: runs install.sh into $WORK/NAME.
install_from() {
	dir=$1
	name=$2
	shift 2
	mkdir -p "$WORK/$name/units"
	env ARMADA_VERSION="$VERSION" ARMADA_DOWNLOAD_BASE="file://$dir" \
		ARMADA_PREFIX="$WORK/$name/prefix" ARMADA_SYSTEMD_DIR="$WORK/$name/units" \
		"$@" sh "$ROOT/install.sh" >"$WORK/$name.log" 2>&1
}

# A good release installs the binary and units.
make_release "$WORK/good"
install_from "$WORK/good" good || {
	cat "$WORK/good.log"
	fail "good release was rejected"
}
[ -x "$WORK/good/prefix/bin/armada" ] || fail "client not installed"
[ -x "$WORK/good/prefix/bin/armadad" ] || fail "daemon not installed"
grep -q "Checksum verified" "$WORK/good.log" || fail "checksum not reported"
grep -q "$WORK/good/prefix/bin/armadad server" "$WORK/good/units/armada-server.service" ||
	fail "unit does not point at the installed binary"
grep -q "$WORK/good/prefix/bin/armadad runtime" "$WORK/good/units/armada-runtime.service" ||
	fail "runtime unit not installed"
[ "$(stat -c %a "$WORK/good/prefix/bin/armadad")" = 755 ] || fail "binary mode"

# The client alone: no daemon, no units.
install_from "$WORK/good" client ARMADA_CLIENT_ONLY=1 || {
	cat "$WORK/client.log"
	fail "client-only install failed"
}
[ -x "$WORK/client/prefix/bin/armada" ] || fail "client-only: client not installed"
[ ! -e "$WORK/client/prefix/bin/armadad" ] || fail "client-only: daemon installed"
[ ! -e "$WORK/client/units/armada-server.service" ] || fail "client-only: units installed"

# An archive without the daemon is refused for a full install.
mkdir -p "$WORK/nodaemon/$VERSION" "$WORK/nodaemon/src"
cp "$WORK/good/src/armada" "$WORK/nodaemon/src/"
tar -czf "$WORK/nodaemon/$VERSION/$ARCHIVE" -C "$WORK/nodaemon/src" armada
(cd "$WORK/nodaemon/$VERSION" && sha256sum "$ARCHIVE" >checksums.txt)
if install_from "$WORK/nodaemon" nodaemon; then fail "archive without armadad installed"; fi
grep -q "does not contain the armadad binary" "$WORK/nodaemon.log" || fail "nodaemon: wrong error"

# A tampered archive is refused and nothing is installed.
make_release "$WORK/tampered"
printf 'x' >>"$WORK/tampered/$VERSION/$ARCHIVE"
if install_from "$WORK/tampered" tampered; then fail "tampered archive installed"; fi
grep -q "checksum mismatch" "$WORK/tampered.log" || fail "tampered: wrong error: $(cat "$WORK/tampered.log")"
[ ! -e "$WORK/tampered/prefix/bin/armada" ] || fail "tampered binary left behind"
[ ! -e "$WORK/tampered/prefix/bin/armadad" ] || fail "tampered daemon left behind"

# An archive missing from the checksum file is refused.
make_release "$WORK/unlisted"
: >"$WORK/unlisted/$VERSION/checksums.txt"
if install_from "$WORK/unlisted" unlisted; then fail "unlisted archive installed"; fi
grep -q "not listed" "$WORK/unlisted.log" || fail "unlisted: wrong error"

# Only release tags are accepted as versions.
for bad in 'v1.2' '1.2.3' 'v1.2.3;id' 'v1.2.3/../../x' 'latest-ish'; do
	if install_from "$WORK/good" badver ARMADA_VERSION="$bad"; then fail "version '$bad' accepted"; fi
	grep -q "invalid version" "$WORK/badver.log" || fail "version '$bad': wrong error"
done

# Plain HTTP downloads are not allowed.
if install_from "$WORK/good" http ARMADA_DOWNLOAD_BASE="http://127.0.0.1:1"; then fail "http download allowed"; fi

# Requiring a signature without cosign fails.
if ! command -v cosign >/dev/null 2>&1; then
	if install_from "$WORK/good" nosig ARMADA_REQUIRE_SIGNATURE=1; then fail "installed without a required signature"; fi
	grep -q "cosign is not installed" "$WORK/nosig.log" || fail "nosig: wrong error"
fi

# Setting the machine up: fake root, systemctl, and sudo.
FAKE="$WORK/fakebin"
mkdir -p "$FAKE"
REAL_ID=$(command -v id)
printf '#!/bin/sh\n[ "$*" = -u ] && { echo 0; exit 0; }\nexec %s "$@"\n' "$REAL_ID" >"$FAKE/id"
printf '#!/bin/sh\necho "systemctl $*" >>"$FAKE_LOG"\n' >"$FAKE/systemctl"
printf '#!/bin/sh\nexit 1\n' >"$FAKE/sudo"
chmod 755 "$FAKE/id" "$FAKE/systemctl" "$FAKE/sudo"

# setup NAME [VAR=value...] -- ARGS...: install.sh ARGS as fake root.
setup() {
	name=$1
	shift
	n=0
	for a in "$@"; do
		[ "$a" = -- ] && break
		n=$((n + 1))
	done
	mkdir -p "$WORK/$name/units"
	: >"$WORK/$name.calls"
	vars=""
	while [ "$n" -gt 0 ]; do
		vars="$vars$1
"
		shift
		n=$((n - 1))
	done
	shift
	(
		IFS='
'
		# shellcheck disable=SC2086 # one VAR=value per line
		exec env PATH="$FAKE:$PATH" FAKE_LOG="$WORK/$name.calls" SUDO_USER= \
			ARMADA_VERSION="$VERSION" ARMADA_DOWNLOAD_BASE="file://$WORK/good" \
			ARMADA_PREFIX="$WORK/$name/prefix" ARMADA_SYSTEMD_DIR="$WORK/$name/units" \
			ARMADA_ETC_DIR="$WORK/$name/etc" $vars sh "$ROOT/install.sh" "$@"
	) >"$WORK/$name.log" 2>&1 </dev/null
}

setup init ARMADA_SERVER_FLAGS="--acme-email ops@example.com" -- init --private-ip 10.0.0.2 || {
	cat "$WORK/init.log"
	fail "init failed"
}
grep -q "armadad init --private-ip 10.0.0.2" "$WORK/init.calls" || fail "init: armadad not run"
grep -q "systemctl enable --now armada-server.service" "$WORK/init.calls" || fail "init: server not started"
grep -qx 'ARMADA_SERVER_FLAGS="--acme-email ops@example.com"' "$WORK/init/etc/server.env" || fail "init: server.env"
[ "$(stat -c %a "$WORK/init/etc/server.env")" = 600 ] || fail "init: server.env mode"
grep -q "ready" "$WORK/init.log" || fail "init: did not wait for the control plane"

setup join -- join 10.0.0.2:7444 --ca-hash sha256:ab --token-file /t || fail "join failed"
grep -q "armadad join 10.0.0.2:7444 --ca-hash sha256:ab --token-file /t" "$WORK/join.calls" || fail "join: armadad not run"
grep -q "enable --now armada-agent.service" "$WORK/join.calls" || fail "join: agent not started"
[ ! -e "$WORK/join/etc/server.env" ] || fail "join: wrote server.env"

setup sjoin -- server join 10.0.0.2:7444 --ca-hash sha256:ab || fail "server join failed"
grep -q "armadad server join 10.0.0.2:7444" "$WORK/sjoin.calls" || fail "server join: armadad not run"
grep -q "enable --now armada-server.service" "$WORK/sjoin.calls" || fail "server join: server not started"

# A failed armadad starts nothing.
if setup failed FAKE_FAIL=1 -- init; then fail "failed init reported success"; fi
if grep -q systemctl "$WORK/failed.calls"; then fail "failed init started a unit"; fi

# Unknown commands and unsafe server flags fail before anything is installed.
if setup unknown -- deploy; then fail "unknown command accepted"; fi
grep -q "unknown command" "$WORK/unknown.log" || fail "unknown: wrong error"
[ ! -e "$WORK/unknown/prefix/bin/armadad" ] || fail "unknown: installed anyway"
# shellcheck disable=SC2016 # the $ is the point
if setup flags 'ARMADA_SERVER_FLAGS=--x=$(id)' -- init; then fail "unsafe server flags accepted"; fi
grep -q "must not contain" "$WORK/flags.log" || fail "flags: wrong error"

# Setting up needs root.
if [ "$(id -u)" != 0 ]; then
	mkdir -p "$WORK/user/units"
	if env ARMADA_VERSION="$VERSION" ARMADA_DOWNLOAD_BASE="file://$WORK/good" ARMADA_PREFIX="$WORK/user/prefix" \
		ARMADA_SYSTEMD_DIR="$WORK/user/units" sh "$ROOT/install.sh" init >"$WORK/user.log" 2>&1; then
		fail "init without root accepted"
	fi
	grep -q "needs root" "$WORK/user.log" || fail "user: wrong error"
fi

echo "install.sh: all tests passed"
