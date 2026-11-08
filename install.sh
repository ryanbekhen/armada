#!/bin/sh
# Armada installer: downloads a release, verifies it, and installs armadad
# (the daemon), armada (the client), and the systemd units. On macOS, or with
# ARMADA_CLIENT_ONLY=1, it installs the client only. It never runs anything it
# has not verified.
#
# Install, then set the machine up in the same step:
#
#   curl -fsSL https://raw.githubusercontent.com/ryanbekhen/armada/main/install.sh | sudo sh -s - init
#   curl -fsSL .../install.sh | sudo sh -s - join ADDR --ca-hash sha256:...         (from 'armada token create')
#   curl -fsSL .../install.sh | sudo sh -s - server join ADDR --ca-hash sha256:...  (from 'armada token create --server')
#
# The arguments go to armadad, then the right unit is enabled and started
# (armada-server after init and server join, armada-agent after join). Join
# tokens are read from a hidden prompt on the terminal, or --token-file. Run
# with no arguments to only install (or upgrade) the binaries and units.
#
# Or download it and read it first:
#
#   curl -fsSLO https://raw.githubusercontent.com/ryanbekhen/armada/main/install.sh
#   less install.sh
#   sudo sh install.sh [init | join ... | server join ...]
#
# Environment:
#   ARMADA_VERSION             release tag to install (default: latest)
#   ARMADA_SERVER_FLAGS        with init or server join: written to
#                              /etc/armada/server.env when it does not exist,
#                              e.g. "--acme-email ops@example.com"
#   ARMADA_CLIENT_ONLY=1       install only the armada client (always on macOS)
#   ARMADA_REQUIRE_SIGNATURE=1 fail unless the cosign signature is verified
#   ARMADA_PREFIX              install prefix (default: /usr/local)
#   ARMADA_SYSTEMD_DIR         unit directory (default: /etc/systemd/system;
#                              empty skips the units)
#   ARMADA_DOWNLOAD_BASE       mirror of the release downloads (testing)
#   ARMADA_ETC_DIR             configuration directory (default: /etc/armada; testing)
set -eu

# Everything runs from main, called on the last line, so a download cut short
# by `curl | sh` runs nothing.
main() {

REPO="ryanbekhen/armada"
VERSION="${ARMADA_VERSION:-latest}"
PREFIX="${ARMADA_PREFIX:-/usr/local}"
SYSTEMD_DIR="${ARMADA_SYSTEMD_DIR-/etc/systemd/system}"
REQUIRE_SIG="${ARMADA_REQUIRE_SIGNATURE:-0}"
CLIENT_ONLY="${ARMADA_CLIENT_ONLY:-0}"
ETC_DIR="${ARMADA_ETC_DIR:-/etc/armada}"
OIDC_ISSUER="https://token.actions.githubusercontent.com"

say() { printf '%s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die() {
	printf 'error: %s\n' "$*" >&2
	exit 1
}

need() { command -v "$1" >/dev/null 2>&1 || die "$1 is required"; }

need curl
need tar
need uname

# What to run once installed: the arguments for armadad and the unit to start.
UNIT=""
case "${1:-}" in
"") ;;
init) UNIT=armada-server ;;
join) UNIT=armada-agent ;;
server)
	[ "${2:-}" = join ] || die "usage: install.sh server join ADDR --ca-hash sha256:..."
	UNIT=armada-server
	;;
*) die "unknown command '$1' (want init, join, or server join; none only installs)" ;;
esac
if [ -n "$UNIT" ]; then
	[ "$(id -u)" = 0 ] || die "setting the machine up needs root: pipe into 'sudo sh -s - $*'"
	need systemctl
fi

case "$(uname -s)" in
Linux) OS=linux ;;
Darwin)
	OS=darwin
	CLIENT_ONLY=1
	;;
*) die "Armada runs on Linux; the armada client also on macOS" ;;
esac
case "$(uname -m)" in
x86_64 | amd64) ARCH=amd64 ;;
aarch64 | arm64) ARCH=arm64 ;;
*) die "unsupported architecture $(uname -m)" ;;
esac
[ -z "$UNIT" ] || [ "$CLIENT_ONLY" != 1 ] || die "'$1' sets up a Linux machine; this install is the client only"

if [ "$VERSION" = latest ]; then
	tag() { sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1; }
	VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null | tag || true)
	# releases/latest leaves out pre-releases; while there is no stable
	# release, take the newest published one.
	[ -n "$VERSION" ] ||
		VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases?per_page=1" | tag)
	[ -n "$VERSION" ] || die "could not determine the latest release"
fi
# The version ends up in URLs and file names: accept only a release tag.
printf '%s' "$VERSION" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$' ||
	die "invalid version '$VERSION' (want vX.Y.Z)"

BASE="${ARMADA_DOWNLOAD_BASE:-https://github.com/$REPO/releases/download}/$VERSION"
ARCHIVE="armada_${VERSION#v}_${OS}_${ARCH}.tar.gz"

TMP=$(mktemp -d)
trap 'rm -rf -- "$TMP"' EXIT INT TERM

fetch() { curl -fsSL --proto '=https,file' --retry 3 -o "$TMP/$1" "$BASE/$1"; }

say "Downloading Armada $VERSION ($OS/$ARCH)..."
fetch "$ARCHIVE" || die "download of $ARCHIVE failed"
fetch checksums.txt || die "download of checksums.txt failed"

# 1. Signature: the checksum file must be signed by this repository's release
#    workflow for this exact tag.
if command -v cosign >/dev/null 2>&1; then
	fetch checksums.txt.sigstore.json || die "the release has no signature bundle"
	cosign verify-blob \
		--bundle "$TMP/checksums.txt.sigstore.json" \
		--certificate-identity "https://github.com/$REPO/.github/workflows/release.yml@refs/tags/$VERSION" \
		--certificate-oidc-issuer "$OIDC_ISSUER" \
		"$TMP/checksums.txt" >/dev/null 2>&1 ||
		die "signature verification of checksums.txt FAILED; not installing"
	say "Signature verified (cosign, $REPO release workflow)."
elif [ "$REQUIRE_SIG" = 1 ]; then
	die "cosign is not installed and ARMADA_REQUIRE_SIGNATURE=1"
else
	warn "cosign not found: checking the checksum only. Install cosign to verify the signature."
fi

# 2. Checksum of the archive against the (signed) checksum file.
WANT=$(awk -v f="$ARCHIVE" '$2 == f { print $1 }' "$TMP/checksums.txt")
[ -n "$WANT" ] || die "$ARCHIVE is not listed in checksums.txt"
if command -v sha256sum >/dev/null 2>&1; then
	GOT=$(sha256sum "$TMP/$ARCHIVE" | awk '{ print $1 }')
elif command -v shasum >/dev/null 2>&1; then
	GOT=$(shasum -a 256 "$TMP/$ARCHIVE" | awk '{ print $1 }')
else
	die "sha256sum or shasum is required"
fi
[ "$GOT" = "$WANT" ] || die "checksum mismatch for $ARCHIVE; not installing"
say "Checksum verified."

mkdir -p "$TMP/x"
tar -xzf "$TMP/$ARCHIVE" -C "$TMP/x"
BINS=armada
[ "$CLIENT_ONLY" = 1 ] || BINS="armadad armada"
for bin in $BINS; do
	[ -f "$TMP/x/$bin" ] || die "archive does not contain the $bin binary"
done

mkdir -p "$PREFIX/bin"
for bin in $BINS; do
	install -m 0755 "$TMP/x/$bin" "$PREFIX/bin/$bin.new"
	mv -f "$PREFIX/bin/$bin.new" "$PREFIX/bin/$bin"
	say "Installed $PREFIX/bin/$bin"
done

if [ "$CLIENT_ONLY" = 1 ]; then
	say ""
	say "Next: copy the client config (~/.armada/config) from a server's root user,"
	say "then run 'armada status'. The control plane's private address must be reachable."
	"$PREFIX/bin/armada" version
	return 0
fi

if [ -n "$SYSTEMD_DIR" ] && [ -d "$SYSTEMD_DIR" ]; then
	for unit in armada-server.service armada-agent.service armada-runtime.service; do
		[ -f "$TMP/x/deploy/systemd/$unit" ] || continue
		sed "s#/usr/local/bin/armadad#$PREFIX/bin/armadad#" "$TMP/x/deploy/systemd/$unit" >"$TMP/$unit"
		install -m 0644 "$TMP/$unit" "$SYSTEMD_DIR/$unit"
	done
	if command -v systemctl >/dev/null 2>&1 && [ "$SYSTEMD_DIR" = /etc/systemd/system ]; then
		systemctl daemon-reload
	fi
	say "Installed systemd units in $SYSTEMD_DIR (not started)."
fi

# sudo's secure_path leaves out /usr/local/bin on some distributions (RHEL,
# Oracle Linux, Rocky, Alma), where `sudo armadad` then finds nothing.
if [ "$(id -u)" = 0 ] && command -v sudo >/dev/null 2>&1; then
	found=$(sudo -n sh -c 'command -v armadad' 2>/dev/null || true)
	if [ "$found" != "$PREFIX/bin/armadad" ]; then
		warn "sudo does not find $PREFIX/bin/armadad (its secure_path leaves out $PREFIX/bin): run 'sudo $PREFIX/bin/armadad', use a root shell, or reinstall with ARMADA_PREFIX=/usr."
	fi
fi

if [ -z "$UNIT" ]; then
	say ""
	say "Next, as root (sudo before each command):"
	say "  first node:   sudo armadad init"
	say "                sudo systemctl enable --now armada-server"
	say "  other nodes:  sudo armadad join ...         (from 'armada token create')"
	say "                sudo systemctl enable --now armada-agent"
	say "  more servers: sudo armadad server join ...  (from 'armada token create --server')"
	say "                sudo systemctl enable --now armada-server"
	"$PREFIX/bin/armadad" version
	return 0
fi

setup "$@"
}

# setup runs `armadad ARGS` and starts the unit it needs.
setup() {
	# The admin config init writes belongs to root, whatever HOME sudo kept.
	ROOT_HOME=$(awk -F: '$3 == 0 { print $6; exit }' /etc/passwd)
	ROOT_HOME="${ROOT_HOME:-/root}"

	if [ "$UNIT" = armada-server ] && [ -n "${ARMADA_SERVER_FLAGS:-}" ]; then
		case "$ARMADA_SERVER_FLAGS" in
		*[\"\$\`\\]* | *"
"*) die "ARMADA_SERVER_FLAGS must not contain quotes, \$, backquotes, backslashes, or newlines" ;;
		esac
		if [ -e "$ETC_DIR/server.env" ]; then
			warn "$ETC_DIR/server.env exists; leaving it as it is (ARMADA_SERVER_FLAGS ignored)"
		else
			install -d -m 0700 "$ETC_DIR"
			(umask 077 && printf 'ARMADA_SERVER_FLAGS="%s"\n' "$ARMADA_SERVER_FLAGS" >"$ETC_DIR/server.env")
			say "Wrote $ETC_DIR/server.env."
		fi
	fi

	# The script itself may be arriving on stdin (curl | sh): give armadad the
	# terminal for the token prompt, or nothing.
	say ""
	if (: </dev/tty) 2>/dev/null; then
		HOME="$ROOT_HOME" ARMADA_INSTALLER=1 "$PREFIX/bin/armadad" "$@" </dev/tty || die "armadad $1 failed; nothing was started"
	else
		HOME="$ROOT_HOME" ARMADA_INSTALLER=1 "$PREFIX/bin/armadad" "$@" </dev/null || die "armadad $1 failed (no terminal for the token prompt? pass --token-file)"
	fi

	systemctl enable --now "$UNIT.service"
	say "Started $UNIT."

	[ "$1" = init ] || {
		say "Check it from a machine with the admin config: armada node list"
		return 0
	}

	# Whoever ran sudo administers the cluster: give them the admin config
	# so armada works without root.
	src="$ROOT_HOME/.armada/config"
	user="${SUDO_USER:-}"
	if [ -n "$user" ] && [ "$user" != root ] && [ -f "$src" ]; then
		home=$(awk -F: -v u="$user" '$1 == u { print $6; exit }' /etc/passwd)
		if [ -z "$home" ] || [ ! -d "$home" ]; then
			warn "no home directory for $user; copy $src yourself"
		elif [ -e "$home/.armada/config" ]; then
			warn "$home/.armada/config exists; leaving it as it is"
		else
			group=$(id -gn "$user")
			install -d -m 0700 -o "$user" -g "$group" "$home/.armada"
			install -m 0600 -o "$user" -g "$group" "$src" "$home/.armada/config"
			say "Copied the admin config to $home/.armada/config: armada works for $user without sudo."
		fi
	fi

	printf 'Waiting for the control plane'
	i=0
	until HOME="$ROOT_HOME" "$PREFIX/bin/armada" status >/dev/null 2>&1; do
		i=$((i + 1))
		if [ "$i" -ge 60 ]; then
			say ""
			warn "the control plane is not answering yet: journalctl -u armada-server"
			return 0
		fi
		printf '.'
		sleep 2
	done
	say " ready."
	say ""
	say "Next:"
	say "  armada cluster set --root-domain apps.example.com   (DNS: *.apps.example.com -> your nodes)"
	say "  armada token create                                  (add a node)"
	say "  armada deploy -f app.yaml"
}

main "$@"
