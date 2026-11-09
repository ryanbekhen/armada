#!/bin/sh
# Armada installer: downloads a release, verifies it, and installs armadad
# (the daemon), armada (the client), and the systemd units. On macOS, or with
# ARMADA_CLIENT_ONLY=1, it installs the client only. It never runs anything it
# has not verified.
#
# It only installs (or upgrades): setting the machine up stays with you
# (armadad init, join, or server join, then systemctl enable --now).
#
#   curl -fsSL https://raw.githubusercontent.com/ryanbekhen/armada/main/install.sh | sudo sh
#
# Or download it and read it first:
#
#   curl -fsSLO https://raw.githubusercontent.com/ryanbekhen/armada/main/install.sh
#   less install.sh
#   sudo sh install.sh
#
# Environment:
#   ARMADA_VERSION             release tag to install (default: latest)
#   ARMADA_CLIENT_ONLY=1       install only the armada client (always on macOS)
#   ARMADA_REQUIRE_SIGNATURE=1 fail unless the cosign signature is verified
#   ARMADA_PREFIX              install prefix (default: /usr/local)
#   ARMADA_SYSTEMD_DIR         unit directory (default: /etc/systemd/system;
#                              empty skips the units)
#   ARMADA_DOWNLOAD_BASE       mirror of the release downloads (testing)
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

[ $# -eq 0 ] || die "install.sh only installs and takes no arguments; run 'sudo armadad $*' yourself afterwards"

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
	say "Next: ask an administrator for a client config ('armada admin add NAME -o FILE'),"
	say "keep it as ~/.armada/config (mode 0600), then run 'armada status'."
	say "The control plane's private address must be reachable."
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

# Members of the armada group read the admin config armadad init writes
# (/etc/armada/admin.config), so they use armada without root.
if [ "$(id -u)" = 0 ] && ! grep -q '^armada:' /etc/group; then
	if command -v groupadd >/dev/null 2>&1; then
		groupadd --system armada
	elif command -v addgroup >/dev/null 2>&1; then
		addgroup -S armada
	fi && say "Created the armada group: its members administer the cluster without sudo."
fi

# sudo's secure_path leaves out /usr/local/bin on some distributions (RHEL,
# Oracle Linux, Rocky, Alma), where `sudo armadad` then finds nothing.
if [ "$(id -u)" = 0 ] && command -v sudo >/dev/null 2>&1; then
	found=$(sudo -n sh -c 'command -v armadad' 2>/dev/null || true)
	if [ "$found" != "$PREFIX/bin/armadad" ]; then
		warn "sudo does not find $PREFIX/bin/armadad (its secure_path leaves out $PREFIX/bin): run 'sudo $PREFIX/bin/armadad', use a root shell, or reinstall with ARMADA_PREFIX=/usr."
	fi
fi

say ""
say "Next, as root (sudo before each command):"
say "  first node:   sudo armadad init"
say "                sudo systemctl enable --now armada-server"
say "                sudo usermod -aG armada \$USER   (armada without sudo; log in again)"
say "  other nodes:  sudo armadad join ...         (from 'armada token create')"
say "                sudo systemctl enable --now armada-agent"
say "  more servers: sudo armadad server join ...  (from 'armada token create --server')"
say "                sudo systemctl enable --now armada-server"
"$PREFIX/bin/armadad" version
}

main "$@"
