#!/bin/sh
# haproxy -c on the configurations armada-node renders for the recorded
# named cases (node/tests/render.rs, writes_configs_for_haproxy_check),
# with the HAProxy image Armada pins (agent/src/haproxy/engine.rs), through
# docker, podman, or nerdctl. A development and CI check (job haproxy):
# Armada itself runs no container CLI.
set -eu

cli=
for c in docker podman nerdctl; do
	if command -v "$c" >/dev/null 2>&1; then
		cli=$c
		break
	fi
done
if [ -z "$cli" ]; then
	echo "haproxy-check: no docker, podman, or nerdctl" >&2
	exit 1
fi

image=$(sed -n 's/^ *"\(haproxy:[^"]*@sha256:[0-9a-f]*\)";$/\1/p' agent/src/haproxy/engine.rs)
if [ -z "$image" ]; then
	echo "haproxy-check: no pinned image in agent/src/haproxy/engine.rs" >&2
	exit 1
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/armada-haproxy.XXXXXX")
trap 'rm -rf "$work"' EXIT
ARMADA_HAPROXY_CHECK_DIR=$work/cases cargo test --locked -q -p armada-node --test render writes_configs_for_haproxy_check

# One test certificate as the default and in the certificate directory:
# the check loads both.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
	-subj /CN=armada.test -keyout "$work/key.pem" -out "$work/cert.pem" 2>/dev/null
for d in "$work"/cases/*/; do
	cat "$work/cert.pem" "$work/key.pem" >"$d/default.pem"
	cp "$d/default.pem" "$d/certs/armada.test.pem"
done
# The check runs as root without capabilities: everything readable.
chmod -R a+rX "$work"

# Each configuration is copied to the path it names, in one container.
# shellcheck disable=SC2016 # expanded by the container's shell
"$cli" run --rm --network none --user root -v "$work/cases:/cases:ro" --tmpfs /var/run/haproxy \
	"$image" sh -c '
	fail=0
	for d in /cases/*/; do
		rm -rf /usr/local/etc/haproxy
		mkdir -p /usr/local/etc/haproxy
		cp -R "$d". /usr/local/etc/haproxy/
		name=$(cat "$d/case.txt")
		if ! out=$(haproxy -c -f /usr/local/etc/haproxy/haproxy.cfg 2>&1); then
			echo "FAIL $name: $out"
			fail=1
		elif echo "$out" | grep -q "\[WARNING\]"; then
			echo "WARN $name: $out"
			fail=1
		else
			echo "ok   $name"
		fi
	done
	exit $fail'
