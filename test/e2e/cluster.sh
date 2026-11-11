#!/bin/sh
# End-to-end test of an Armada cluster on real machines (see README.md).
#
#   ARMADA_BIN=bin/armadad E2E_DOMAIN=apps.example.org \
#   E2E_ACME_EMAIL=you@example.org sh test/e2e/cluster.sh hosts
#
# The hosts file lists fresh Linux machines, one per line:
#
#   NAME  SSH-TARGET  PRIVATE-IP  PUBLIC-IP
#
# The first three become control plane servers (only the first if there are
# fewer than three); the others join as nodes. The script installs
# ARMADA_BIN (or ARMADA_BIN_AMD64/ARMADA_BIN_ARM64, by the machine's
# architecture) on every machine, builds the cluster, and runs the scenarios
# one after another, stopping at the first failure. It leaves the machines
# as they are: throw them away afterwards.
set -eu

# Scenarios that run after the cluster is built and the test app serves.
# E2E_ONLY=isolation,rollout runs only those (empty: all); E2E_LIST=1 lists
# them. test/e2e/README.md says which to pick for a change.
SCENARIOS="listeners project-secret conntrack isolation load rollout agent-restart failover node-loss backup placement platforms cpu spread queues reboot"
E2E_ONLY=${E2E_ONLY:-}
if [ "${E2E_LIST:-}" = 1 ]; then
	echo "$SCENARIOS" | tr ' ' '\n'
	exit 0
fi
for _s in $(printf '%s' "$E2E_ONLY" | tr ',' ' '); do
	case " $SCENARIOS " in
	*" $_s "*) ;;
	*)
		echo "e2e: unknown scenario '$_s' in E2E_ONLY (E2E_LIST=1 lists them)" >&2
		exit 2
		;;
	esac
done
want() {
	[ -z "$E2E_ONLY" ] && return 0
	case ",$E2E_ONLY," in
	*",$1,"*) return 0 ;;
	esac
	return 1
}

HOSTS=${1:?usage: cluster.sh HOSTS-FILE}
ARMADA_BIN=${ARMADA_BIN:-}
ARMADA_BIN_AMD64=${ARMADA_BIN_AMD64:-$ARMADA_BIN}
ARMADA_BIN_ARM64=${ARMADA_BIN_ARM64:-$ARMADA_BIN}
if [ -z "$ARMADA_BIN_AMD64$ARMADA_BIN_ARM64" ]; then
	echo "e2e: set ARMADA_BIN (or ARMADA_BIN_AMD64/ARMADA_BIN_ARM64) to Linux armadad binaries with the runtime embedded (make build-bundle; the armada client next to each is installed too)" >&2
	exit 2
fi
: "${E2E_DOMAIN:?set E2E_DOMAIN to a root domain whose wildcard record points at every public IP}"
: "${E2E_ACME_EMAIL:?set E2E_ACME_EMAIL to the ACME account email}"
E2E_ACME_CA=${E2E_ACME_CA:-letsencrypt-staging}
E2E_SSH_OPTS=${E2E_SSH_OPTS:-}
E2E_SUDO=${E2E_SUDO:-}                  # "sudo" when SSH-TARGET is not root
E2E_REBOOT=${E2E_REBOOT:-1}             # 0 skips rebooting every machine at once
E2E_BRIDGE_GW=${E2E_BRIDGE_GW:-} # armada0 address; read from each node if empty
E2E_SERVER_FLAGS=${E2E_SERVER_FLAGS:-}
# A conformance test binary for the last machine's architecture
# (go test -c -tags integration ./internal/runtime/containerd/); empty skips.
E2E_CONFORMANCE=${E2E_CONFORMANCE:-}

case $E2E_ACME_CA in
letsencrypt | *acme-v02.api.letsencrypt.org*)
	echo "e2e: never test against the Let's Encrypt production endpoint" >&2
	exit 2
	;;
esac
for tool in ssh scp curl jq openssl awk; do
	command -v "$tool" >/dev/null || {
		echo "e2e: $tool is required" >&2
		exit 2
	}
done
UNITS=$(cd "$(dirname "$0")/../../deploy/systemd" && pwd)

# client_of BIN names the armada client built next to armadad binary BIN
# (bin/armadad-linux-amd64 -> bin/armada-linux-amd64).
client_of() { printf '%s/%s' "$(dirname "$1")" "$(basename "$1" | sed 's/^armadad/armada/')"; }

# host N COLUMN prints a column of the Nth machine (1 name, 2 SSH target,
# 3 private IP, 4 public IP); index NAME prints the line number of NAME.
host() { awk -v n="$1" -v c="$2" 'NF && $1 !~ /^#/ { if (++i == n) print $c }' "$HOSTS"; }
index() { awk -v name="$1" 'NF && $1 !~ /^#/ { i++; if ($1 == name) print i }' "$HOSTS"; }
N=$(awk 'NF && $1 !~ /^#/' "$HOSTS" | wc -l | tr -d ' ')
[ "$N" -ge 2 ] || {
	echo "e2e: the hosts file needs at least two machines" >&2
	exit 2
}
SERVERS=1
[ "$N" -lt 3 ] || SERVERS=3
PUBLIC_IPS=$(awk 'NF && $1 !~ /^#/ { print $4 }' "$HOSTS" | tr '\n' ' ')
REPLICAS=$N
[ "$REPLICAS" -ge 3 ] || REPLICAS=3
APP=hello
URL_HOST=$APP.$E2E_DOMAIN
V1=traefik/whoami:v1.10
V2=traefik/whoami:v1.11
CLI=1 # the machine the armada CLI runs on
WORK=$(mktemp -d)
LOAD_PID=
STARTED=$(date +%s)

log() { printf '\n==> %s\n' "$*"; }
ok() { printf '    ok: %s\n' "$*"; }
fail() {
	printf '    FAIL: %s\n' "$*" >&2
	exit 1
}
q() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"; }

# on N CMD runs CMD as root on machine N; stdin is passed through.
on() {
	_target=$(host "$1" 2)
	shift
	# shellcheck disable=SC2086 # E2E_SSH_OPTS is a list of options
	# sudo's secure_path may leave out /usr/local/bin, where armada goes.
	ssh $E2E_SSH_OPTS -o BatchMode=yes -o ConnectTimeout=10 "$_target" "$E2E_SUDO sh -c $(q "PATH=/usr/local/bin:\$PATH; $*")"
}
cli() { on "$CLI" "armada $*"; }

# wait_for SECONDS DESCRIPTION CMD... retries CMD until it succeeds.
wait_for() {
	_secs=$1 _desc=$2
	shift 2
	_end=$(($(date +%s) + _secs))
	until "$@" >/dev/null 2>&1; do
		[ "$(date +%s)" -lt "$_end" ] || fail "$_desc (not within ${_secs}s)"
		sleep 3
	done
	ok "$_desc"
}

# status prints every app with its replicas, and the nodes, as one JSON
# object: {"apps": [app show -o json...], "nodes": [...]}.
status() {
	_st_apps=$(cli app list -A -o json | jq -r '.apps[]?.name') || return 1
	_st_json=$(cli node list -o json) || return 1
	for _st_app in $_st_apps; do
		_st_one=$(cli app show "$_st_app" -o json) || return 1
		_st_json="$_st_json
$_st_one"
	done
	printf '%s\n' "$_st_json" | jq -s '{nodes: (.[0].nodes // []), apps: .[1:]}'
}
# serving [IMAGE]: every desired replica of the active revision serves, no
# rollout is in progress, and no other replica is left.
serving() {
	status | jq -e --arg app "$APP" --arg image "${1:-}" '
		.apps[] | select(.name == $app)
		| (.desiredReplicas // 0) as $want
		| [.replicas[]? | select((.draining // false) | not)] as $live
		| ($image == "" or .image == $image)
		  and (.rolloutState // "") == ""
		  and ($live | length) == $want
		  and ([$live[] | select(.state == "running" and (.ready // false))] | length) == $want'
}
# even: the app's replicas are spread over the ready nodes within one.
even() {
	status | jq -e --arg app "$APP" '
		[.nodes[] | select(.state == "ready") | .id] as $ids
		| [.apps[] | select(.name == $app) | .replicas[]? | select((.draining // false) | not)] as $live
		| [$ids[] as $id | [$live[] | select(.nodeId == $id)] | length]
		| (max - min) <= 1'
}
replicas_on() { # replicas_on NODE: live replicas of the app on NODE
	status | jq -r --arg app "$APP" --arg node "$1" \
		'[.apps[] | select(.name == $app) | .replicas[]? | select(.nodeId == $node and ((.draining // false) | not))] | length'
}
none_on() { [ "$(replicas_on "$1")" = 0 ]; }
even_settled() { serving "" && even; }
replica_ids() { # live (not draining) replicas of the app
	status | jq -r --arg app "$APP" '[.apps[] | select(.name == $app) | .replicas[]? | select((.draining // false) | not) | .id] | sort | join(" ")'
}
nodes_ready() { status | jq -e --argjson n "$N" '[.nodes[] | select(.state == "ready")] | length == $n'; }
node_lost() { status | jq -e --arg node "$1" '.nodes[] | select(.id == $node) | .state != "ready"'; }
voting() { [ "$(cli server list 2>/dev/null | grep -c ' voting ')" -ge "$1" ]; }
leader() { cli server list 2>/dev/null | awk '$3 == "leader" { print $1 }'; }
new_leader() { _l=$(leader) && [ -n "$_l" ] && [ "$_l" != "$1" ]; }
reachable() { on "$1" true; }
https_ok() { [ "$(curl -sk -o /dev/null -w '%{http_code}' --max-time 5 --resolve "$URL_HOST:443:$1" "https://$URL_HOST/")" = 200 ]; }
all_https_ok() {
	for _ip in $PUBLIC_IPS; do https_ok "$_ip" || return 1; done
}
cert_ok() {
	for _ip in $PUBLIC_IPS; do
		echo | openssl s_client -connect "$_ip:443" -servername "$URL_HOST" 2>/dev/null |
			openssl x509 -noout -checkhost "$URL_HOST" 2>/dev/null | grep -q 'does match' || return 1
	done
}

# load_start and load_stop send requests round robin to every public IP;
# load_stop fails if any of them did not return 200.
load_start() {
	: >"$WORK/load"
	rm -f "$WORK/load.stop"
	(
		# shellcheck disable=SC2086 # split into one IP per argument
		set -- $PUBLIC_IPS
		while [ ! -f "$WORK/load.stop" ]; do
			for ip in "$@"; do
				# "000" means curl got no response; its exit code and message
				# tell a refused connection from a slow workstation link.
				res=$(curl -sk -o /dev/null -w '%{http_code} curl=%{exitcode} %{errormsg}' --max-time 5 \
					--resolve "$URL_HOST:443:$ip" "https://$URL_HOST/" || true)
				code=${res%% *}
				echo "$code $ip ${res#* } at $(date -u +%H:%M:%S)" >>"$WORK/load"
			done
		done
	) &
	LOAD_PID=$!
}
load_stop() {
	touch "$WORK/load.stop"
	wait "$LOAD_PID" || true
	LOAD_PID=
	_total=$(wc -l <"$WORK/load" | tr -d ' ')
	_bad=$(grep -vc '^200 ' "$WORK/load" || true)
	[ "$_total" -gt 0 ] || fail "$1: no requests sent"
	if [ "$_bad" -gt 0 ]; then
		grep -v '^200 ' "$WORK/load" | sort | uniq -c | sed 's/^/      /' >&2
		fail "$1: $_bad of $_total requests did not return 200"
	fi
	ok "$1: $_total requests, all 200"
}

deploy() { # deploy IMAGE: (re)deploys the test app with IMAGE
	cat <<EOF | cli app update --file - --create-if-missing
name: $APP
image: $1
env:
  - name: E2E_SECRET
    secretRef: e2e-secret
ingress:
  type: external
  port: 80
probes:
  readiness:
    path: /health
scale:
  min: $REPLICAS
EOF
}

# join N server|node creates a join token on the CLI machine and joins
# machine N with it. The token goes through a 0600 file on tmpfs and is
# never printed.
join() {
	if [ "$2" = server ]; then cli server join-token; else cli node join-token; fi >"$WORK/token"
	_tok=$(sed -n 's/^Token (.*shown once): //p' "$WORK/token")
	_cmd=$(sed -n 's/^  sudo \(armadad .*join .*\)$/\1/p' "$WORK/token")
	rm -f "$WORK/token"
	if [ -z "$_tok" ] || [ -z "$_cmd" ]; then fail "armada node join-token printed no token"; fi
	printf '%s\n' "$_tok" | on "$1" 'umask 077; cat > /run/armada/e2e.token'
	_tok=
	if [ "$2" = server ]; then
		_args="--name $(host "$1" 1)" _unit=armada-server
	else
		_args="--node-name $(host "$1" 1)" _unit=armada-agent
	fi
	on "$1" "$_cmd $_args --private-ip $(host "$1" 3) --token-file /run/armada/e2e.token >/dev/null;
		rc=\$?; rm -f /run/armada/e2e.token; [ \$rc -eq 0 ] && systemctl enable --now -q $_unit"
}

cleanup() {
	_rc=$?
	[ -z "$LOAD_PID" ] || kill "$LOAD_PID" 2>/dev/null || true
	if [ "$_rc" -ne 0 ]; then
		printf '\n==> diagnostics (CLI on %s)\n' "$(host "$CLI" 1)" >&2
		cli server list >&2 || true
		cli cluster status >&2 || true
		cli app list -A >&2 || true
		# HAProxy reloads and restarts explain dropped requests.
		_since=$(date -u -r "$STARTED" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date -u -d "@$STARTED" '+%Y-%m-%d %H:%M:%S')
		_i=1
		while [ "$_i" -le "$N" ]; do
			printf '\n    haproxy events on %s (UTC):\n' "$(host "$_i" 1)" >&2
			on "$_i" "journalctl -u armada-agent -u armada-server --utc --since '$_since' -o short-iso --no-pager | grep -i haproxy | tail -n 20" >&2 || true
			_i=$((_i + 1))
		done
	fi
	rm -rf "$WORK"
	exit "$_rc"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

log "install on $N machines"
i=1
while [ "$i" -le "$N" ]; do
	case $(on "$i" 'uname -m') in
	x86_64 | amd64) _bin=$ARMADA_BIN_AMD64 ;;
	aarch64 | arm64) _bin=$ARMADA_BIN_ARM64 ;;
	*) _bin= ;;
	esac
	[ -n "$_bin" ] || fail "no binary for the architecture of $(host "$i" 1)"
	# A copy can stall on a poor link: retry a few times.
	for _f in "$_bin:/tmp/armadad.e2e" "$(client_of "$_bin"):/tmp/armada.e2e"; do
		_try=1
		# shellcheck disable=SC2086
		until scp -q $E2E_SSH_OPTS -o BatchMode=yes -o ServerAliveInterval=10 -o ServerAliveCountMax=3 \
			"${_f%%:*}" "$(host "$i" 2):${_f#*:}"; do
			[ "$_try" -lt 3 ] || fail "copying ${_f%%:*} to $(host "$i" 1)"
			_try=$((_try + 1))
			sleep 5
		done
	done
	for unit in armada-server armada-agent armada-runtime; do
		on "$i" "cat > /etc/systemd/system/$unit.service" <"$UNITS/$unit.service"
	done
	on "$i" 'install -m 0755 /tmp/armadad.e2e /usr/local/bin/armadad && install -m 0755 /tmp/armada.e2e /usr/local/bin/armada &&
		rm /tmp/armadad.e2e /tmp/armada.e2e &&
		systemctl daemon-reload && install -d -m 0700 /etc/armada /run/armada/secrets'
	if ! on "$i" "armadad doctor --private-ip $(host "$i" 3)" >"$WORK/doctor" 2>&1 ||
		grep -q 'FAIL' "$WORK/doctor"; then
		cat "$WORK/doctor" >&2
		fail "armadad doctor on $(host "$i" 1)"
	fi
	ok "$(host "$i" 1): $(on "$i" 'armadad version' | head -1), doctor passes"
	i=$((i + 1))
done

log "create the cluster on $(host 1 1)"
FLAGS="--acme-email $E2E_ACME_EMAIL --acme-ca $E2E_ACME_CA --node-lost-timeout 30s $E2E_SERVER_FLAGS"
i=1
while [ "$i" -le "$SERVERS" ]; do
	on "$i" "umask 077; echo $(q "ARMADA_SERVER_FLAGS=\"$FLAGS\"") > /etc/armada/server.env"
	i=$((i + 1))
done
on 1 "armadad init --node-name $(host 1 1) --private-ip $(host 1 3) >/dev/null && systemctl enable --now -q armada-server"
wait_for 120 "control plane answers" voting 1

i=2
while [ "$i" -le "$N" ]; do
	if [ "$i" -le "$SERVERS" ]; then
		join "$i" server
		wait_for 180 "$(host "$i" 1) joined as a voting control plane member" voting "$i"
	else
		join "$i" node
		ok "$(host "$i" 1) joined as a node"
	fi
	i=$((i + 1))
done
wait_for 180 "all $N nodes ready" nodes_ready

if [ -n "$E2E_CONFORMANCE" ]; then
	log "conformance suite on the embedded runtime of $(host "$N" 1)"
	# shellcheck disable=SC2086
	scp -q $E2E_SSH_OPTS -o BatchMode=yes "$E2E_CONFORMANCE" "$(host "$N" 2):/tmp/conformance.e2e"
	if ! on "$N" "chmod 0755 /tmp/conformance.e2e && ARMADA_BIN=/usr/local/bin/armadad ARMADA_HOST_IP=$(host "$N" 3) \
		ARMADA_SUBNET=\$(sed -n 's/.*\"containerSubnet\": *\"\([^\"]*\)\".*/\1/p' /var/lib/armada/agent.json) \
		/tmp/conformance.e2e -test.run Conformance -test.v; _rc=\$?; rm -f /tmp/conformance.e2e; exit \$_rc" >"$WORK/conformance" 2>&1; then
		cat "$WORK/conformance" >&2
		fail "conformance suite"
	fi
	grep -q -- '--- SKIP' "$WORK/conformance" && grep -- '--- SKIP' "$WORK/conformance" | sed 's/^/    /'
	ok "$(grep -c -- '--- PASS' "$WORK/conformance") checks pass"
fi
if [ "$SERVERS" -gt 1 ]; then
	# server list wrote every server address into the admin config; a copy
	# on machine 2 keeps the CLI usable while machine 1 is down.
	on 1 'cat /etc/armada/admin.config' | on 2 'umask 077; mkdir -p ~root/.armada && cat > ~root/.armada/config'
fi

if want listeners; then
log "only HAProxy faces the public network"
i=1
while [ "$i" -le "$N" ]; do
	# Each node has its own container subnet (ADR 0025).
	_gw=$E2E_BRIDGE_GW
	[ -n "$_gw" ] || _gw=$(on "$i" "ip -4 -o addr show dev armada0 | awk '{ sub(/\\/.*/, \"\", \$4); print \$4; exit }'")
	_bad=$(on "$i" 'ss -H -ltn' | awk -v priv="$(host "$i" 3)" -v gw="$_gw" '{
		addr = $4; port = addr; sub(/.*:/, "", port); sub(/:[^:]*$/, "", addr); sub(/%.*/, "", addr)
		gsub(/[][]/, "", addr)
		if (addr ~ /^127\./ || addr == "::1" || addr == priv || addr == gw) next
		if (port == 22 || port == 80 || port == 443) next
		print $4
	}')
	[ -z "$_bad" ] || fail "$(host "$i" 1) listens publicly on: $(echo "$_bad" | tr '\n' ' ')"
	i=$((i + 1))
done
ok "every other listener is on a private, loopback, or bridge address"

fi
log "deploy $APP ($REPLICAS replicas) with a secret"
SECRET=e2e-$(openssl rand -hex 16)
printf '%s' "$SECRET" | cli secret set "$APP" e2e-secret >/dev/null
cli cluster set --root-domain "$E2E_DOMAIN" >/dev/null
deploy "$V1" >/dev/null
wait_for 300 "$REPLICAS replicas serving $V1" serving "$V1"
wait_for 60 "replicas spread evenly" even
wait_for 300 "certificate for $URL_HOST on every node" cert_ok
wait_for 60 "https://$URL_HOST answers 200 on every public IP" all_https_ok
curl -sk --max-time 5 --resolve "$URL_HOST:443:$(host 1 4)" "https://$URL_HOST/?env=true" | grep -qx "E2E_SECRET=$SECRET" ||
	fail "the secret did not reach the container"
ok "the secret reached the container"

if want project-secret; then
log "a secret of an app in another project"
cli project create e2e-proj >/dev/null
printf '%s' "$SECRET" | cli secret set e2e-app --project e2e-proj e2e-secret --no-rollout >/dev/null
[ "$(cli secret list e2e-app --project e2e-proj | grep -c e2e-secret)" = 1 ] ||
	fail "armada secret list does not show the secret of a project's app"
cli secret delete e2e-app --project e2e-proj e2e-secret >/dev/null
ok "a project's app has secrets"
i=1
while [ "$i" -le "$N" ]; do
	_hits=$(printf '%s\n' "$SECRET" | on "$i" 'journalctl --no-pager -o cat | grep -c -F -f - || true')
	[ "$_hits" = 0 ] || fail "the secret value appears in the journal on $(host "$i" 1)"
	i=$((i + 1))
done
ok "the secret value is in no journal"

fi
if want conntrack; then
log "connection tracking"
# The agent raises the limit once the kernel module is loaded (ADR 0025).
conntrack_raised() {
	i=1
	while [ "$i" -le "$N" ]; do
		# shellcheck disable=SC2016 # expanded on the node
		on "$i" 'want=$(($(sed -n "s/^MemTotal: *\([0-9]*\) kB/\1/p" /proc/meminfo) / 4)); [ "$want" -le 262144 ] || want=262144
			[ "$(cat /proc/sys/net/netfilter/nf_conntrack_max)" -ge "$want" ]' >/dev/null 2>&1 || return 1
		i=$((i + 1))
	done
}
wait_for 60 "every node raised its connection tracking limit" conntrack_raised

fi
if want isolation; then
log "isolation between apps and projects"
# Each replica answers on port 80 and has wget. A check that cannot run at all
# must not pass as blocked, so a blocked request has to show wget's own error.
iso_deploy() { # iso_deploy NAME PROJECT REPLICAS
	printf 'name: %s\nimage: nginx:1-alpine\ningress:\n  type: internal\n  port: 80\nscale:\n  min: %s\n  max: %s\n' "$1" "$3" "$3" |
		on "$CLI" "cat >/root/iso.yaml && armada app update --file /root/iso.yaml --create-if-missing --project $2" >/dev/null
}
iso_ready() { # iso_ready APP-ID COUNT
	status | jq -e --arg app "$1" --argjson n "$2" '
		.apps[] | select(.name == $app)
		| [.replicas[]? | select((.draining // false) | not)] as $live
		| ($live | length) == $n and all($live[]; .state == "running" and (.ready // false))'
}
iso_ips() { # iso_ips APP-ID: the live replicas' container addresses
	status | jq -r --arg app "$1" '.apps[] | select(.name == $app) | .replicas[]? | select((.draining // false) | not) | .address | split(":")[0]'
}
iso_gone() { [ "$(status | jq --arg app "$1" '[.apps[] | select(.name == $app)] | length')" = 0 ]; }
reaches() { cli app exec "$1" -- wget -q -O /dev/null -T 3 "http://$2/" >/dev/null 2>&1; }
blocked() {
	if _out=$(cli app exec "$1" -- wget -q -O /dev/null -T 3 "http://$2/" 2>&1); then return 1; fi
	case $_out in *wget:*) return 0 ;; esac
	return 1
}
iso_matrix() { # iso_matrix WHEN
	for _ip in $(iso_ips web.e2e-proj); do
		wait_for 60 "$1: a replica reaches its own app's $_ip" reaches web.e2e-proj "$_ip"
		wait_for 60 "$1: another app of the project cannot reach $_ip directly" blocked other.e2e-proj "$_ip"
		wait_for 60 "$1: another project cannot reach $_ip" blocked caller.e2e-other "$_ip"
	done
	wait_for 60 "$1: the project reaches web through its internal name" reaches other.e2e-proj web.e2e-proj.internal
	wait_for 60 "$1: another project does not" blocked caller.e2e-other web.e2e-proj.internal
	wait_for 60 "$1: a project's app cannot reach a node's private IP" blocked caller.e2e-other "$(host "$N" 3)"
}
cli project create e2e-other >/dev/null
iso_deploy web e2e-proj 2
iso_deploy other e2e-proj 1
iso_deploy caller e2e-other 1
wait_for 180 "web has 2 replicas ready" iso_ready web.e2e-proj 2
wait_for 180 "other has 1 replica ready" iso_ready other.e2e-proj 1
wait_for 180 "caller has 1 replica ready" iso_ready caller.e2e-other 1
iso_matrix started
wait_for 60 "a replica reaches itself on localhost" reaches web.e2e-proj 127.0.0.1
iso_deploy web e2e-proj 4
wait_for 180 "web has 4 replicas ready" iso_ready web.e2e-proj 4
iso_matrix "scaled up"
iso_deploy gone e2e-proj 1
wait_for 180 "a new app is ready" iso_ready gone.e2e-proj 1
_gone_ip=$(iso_ips gone.e2e-proj | head -n 1)
wait_for 60 "the new app reaches itself" reaches gone.e2e-proj "$_gone_ip"
wait_for 60 "another project cannot reach the new app" blocked caller.e2e-other "$_gone_ip"
cli app delete gone.e2e-proj --yes >/dev/null
wait_for 120 "a removed app is gone" iso_gone gone.e2e-proj
wait_for 60 "a removed app's address stays blocked" blocked caller.e2e-other "$_gone_ip"
iso_matrix "after a removal"
for _app in web.e2e-proj other.e2e-proj caller.e2e-other; do
	cli app delete "$_app" --yes >/dev/null
	wait_for 120 "$_app is gone" iso_gone "$_app"
done
cli project delete e2e-proj >/dev/null
cli project delete e2e-other >/dev/null
ok "both projects are removed"

fi
if want load; then
log "steady load"
# Nothing changes in the cluster: a failure here is the path between this
# machine and the nodes, not Armada.
load_start
sleep 60
load_stop "steady load"

fi
if want rollout; then
log "rolling update under load"
load_start
deploy "$V2" >/dev/null
wait_for 300 "rolled out to $V2" serving "$V2"
load_stop "rolling update"

log "rollback under load"
load_start
cli app rollback "$APP" >/dev/null
wait_for 300 "rolled back to $V1" serving "$V1"
load_stop "rollback"

fi
if want agent-restart; then
log "agent restart adopts running containers"
# A rollout can leave the app unevenly spread for a moment; let rebalancing
# finish so that only the restart could change the replica set.
wait_for 300 "$APP spread evenly before the restart" even_settled
_before=$(replica_ids)
_unit=armada-agent
[ "$N" -gt "$SERVERS" ] || _unit=armada-server
load_start
on "$N" "systemctl restart $_unit"
sleep 10
wait_for 120 "$APP serving after restarting $_unit on $(host "$N" 1)" serving
load_stop "agent restart"
[ "$(replica_ids)" = "$_before" ] || fail "replicas were replaced instead of adopted"
ok "no replica was replaced"

fi
if [ "$SERVERS" -gt 1 ] && want failover; then
	log "leader failover under load"
	_old=$(leader)
	_i=$(index "$_old")
	[ "$_i" != 1 ] || CLI=2
	load_start
	on "$_i" 'systemctl stop armada-server'
	wait_for 60 "a new leader took over from $_old" new_leader "$_old"
	REPLICAS=$((REPLICAS + 1))
	cli app scale "$APP" --replicas "$REPLICAS" >/dev/null
	wait_for 180 "scaled to $REPLICAS through the new leader" serving
	load_stop "leader stop"
	on "$_i" 'systemctl start armada-server'
	wait_for 180 "$_old is back as a voting member" voting "$SERVERS"
	CLI=1

	_old=$(leader)
	_i=$(index "$_old")
	[ "$_i" != 1 ] || CLI=2
	load_start
	# shellcheck disable=SC2016 # expands on the machine
	on "$_i" 'kill -KILL "$(systemctl show -p MainPID --value armada-server)"'
	wait_for 60 "a new leader took over from $_old (SIGKILL)" new_leader "$_old"
	wait_for 180 "$_old restarted and is voting again" voting "$SERVERS"
	load_stop "leader SIGKILL"
	CLI=1
fi

if want node-loss; then
log "node loss and return under load"
_node=$(host "$N" 1)
_unit=armada-agent
[ "$N" -gt "$SERVERS" ] || _unit=armada-server
load_start
on "$N" "systemctl stop $_unit"
wait_for 120 "$_node marked lost" node_lost "$_node"
wait_for 300 "its replicas replaced on the other nodes" none_on "$_node"
wait_for 300 "$APP serving without $_node" serving
on "$N" "systemctl start $_unit"
wait_for 180 "$_node ready again" nodes_ready
wait_for 600 "replicas rebalanced onto $_node" even
wait_for 180 "$APP serving after the rebalance" serving
load_stop "node loss and rebalance"

fi
if want backup; then
log "backup"
on "$CLI" 'armadad backup -o /root/e2e-backup.tar.gz' >/dev/null 2>&1
[ "$(on "$CLI" 'stat -c %a /root/e2e-backup.tar.gz')" = 600 ] || fail "backup file is not 0600"
on "$CLI" 'rm -f /root/e2e-backup.tar.gz'
ok "backup written with mode 0600"

fi
if want placement; then
log "placement: labels and a restricted node under load"
_node=$(host "$N" 1)
# pinned_on NODE: both replicas of the pinned app serve on NODE.
pinned_on() {
	status | jq -e --arg node "$1" '
		[.apps[] | select(.name == "pinned") | .replicas[]? | select((.draining // false) | not)] as $live
		| ($live | length) == 2 and all($live[]; .nodeId == $node and .state == "running" and (.ready // false))'
}
placement_note() { status | jq -e '.apps[] | select(.name == "pinned") | (.placementMessage // "") | test("no ready node matches")'; }
arch_labels() { status | jq -e --argjson n "$N" '[.nodes[] | select((.labels["armada.arch"] // "") != "")] | length == $n'; }
wait_for 30 "every node reports armada.arch" arch_labels
load_start
cli node label "$_node" e2e.role=pinned >/dev/null
cli node restrict "$_node" >/dev/null
wait_for 300 "$APP moved off restricted $_node" none_on "$_node"
wait_for 180 "$APP serving without $_node" serving
load_stop "restricting a node"
cat <<EOF | cli app update --file - --create-if-missing >/dev/null
name: pinned
image: $V1
ingress:
  type: none
scale:
  min: 2
placement:
  require:
    e2e.role: pinned
EOF
wait_for 300 "pinned app runs only on $_node" pinned_on "$_node"
cli node label "$_node" e2e.role- >/dev/null
wait_for 60 "app show explains why pinned has nowhere to go" placement_note
cli node unrestrict "$_node" >/dev/null
wait_for 600 "$APP spread back over every node" even

fi
if want platforms; then
log "image platforms"
# The architectures in the cluster; an image built for one architecture
# only must run on nodes of that architecture, or nowhere.
_archs=$(status | jq -r '[.nodes[].labels["armada.arch"]] | unique | .[]')
_archlist=$(status | jq -r '[.nodes[].labels["armada.arch"]] | unique | join(", ")')
hello_platforms() {
	_line=$(cli app revision list "$APP" | awk 'NR > 1 && $2 == "active"')
	for _a in $_archs; do
		echo "$_line" | grep -q "linux/$_a" || return 1
	done
}
# only_on APP ARCH: two replicas of APP run, each on an ARCH node.
only_on() {
	status | jq -e --arg app "$1" --arg want "$2" '
		(.nodes | map({key: .id, value: .labels["armada.arch"]}) | from_entries) as $archOf
		| [.apps[] | select(.name == $app) | .replicas[]? | select((.draining // false) | not)] as $live
		| ($live | length) == 2 and all($live[]; .state == "running" and $archOf[.nodeId] == $want)'
}
# unplaced APP ARCH: nothing of APP runs and app show names ARCH.
unplaced() {
	status | jq -e --arg app "$1" --arg want "no ready node can run the image, which is built for linux/$2" '
		.apps[] | select(.name == $app)
		| ((.placementMessage // "") | contains($want))
		  and ([.replicas[]? | select((.draining // false) | not) | select(.state == "running")] | length) == 0'
}
wait_for 30 "armada app revision list lists every node architecture ($_archlist) for $APP" hello_platforms
for _a in amd64 arm64; do
	case $_a in
	amd64) _image=amd64/busybox:1.37 ;;
	arm64) _image=arm64v8/busybox:1.37 ;;
	esac
	cat <<EOF | cli app update --file - --create-if-missing >/dev/null
name: only-$_a
image: $_image
command: ["sleep", "3600"]
ingress:
  type: none
scale:
  min: 2
EOF
	if echo "$_archs" | grep -qx "$_a"; then
		wait_for 300 "a linux/$_a image runs only on $_a nodes" only_on "only-$_a" "$_a"
	else
		wait_for 120 "a linux/$_a image runs nowhere and app show says why" unplaced "only-$_a" "$_a"
	fi
done

fi
if want cpu; then
log "CPU reservations"
# A replica without resources.cpu reserves 100m, which gives its container
# a CPU weight below the default of 100.
low_weight() {
	_r=$(status | jq -r --arg app "$APP" '[.apps[] | select(.name == $app) | .replicas[]? | select(.state == "running")][0] | "\(.id) \(.nodeId)"')
	_w=$(on "$(index "${_r#* }")" "cat /sys/fs/cgroup/armada/armada-${_r% *}-*/cpu.weight")
	[ -n "$_w" ] && [ "$_w" -lt 100 ]
}
wait_for 30 "$APP containers get a CPU weight from their reservation" low_weight
cat <<EOF | cli app update --file - --create-if-missing >/dev/null
name: cpu-hog
image: busybox:1.37
command: ["sleep", "3600"]
ingress:
  type: none
resources:
  cpu: "64"
EOF
no_cpu() {
	status | jq -e '.apps[] | select(.name == "cpu-hog")
		| ((.placementMessage // "") | contains("none has 64 of CPU free"))
		  and ([.replicas[]? | select(.state == "running")] | length) == 0'
}
wait_for 60 "an app reserving more CPU than any node has runs nowhere and app show says why" no_cpu

fi
if want spread; then
log "placement: spreading over a label"
# Every node but the last is in zone a, the last alone in zone b: spread by
# zone, half of the replicas go to the last node.
_last=$(host "$N" 1)
i=1
while [ "$i" -le "$N" ]; do
	_zone=a
	[ "$i" -lt "$N" ] || _zone=b
	cli node label "$(host "$i" 1)" "e2e.zone=$_zone" >/dev/null
	i=$((i + 1))
done
cat <<EOF | cli app update --file - --create-if-missing >/dev/null
name: spread
image: busybox:1.37
command: ["sleep", "3600"]
ingress:
  type: none
resources:
  cpu: 10m
  memory: 16Mi
scale:
  min: 4
placement:
  spreadBy: e2e.zone
EOF
# half_on NODE: four replicas run, two of them on NODE.
half_on() {
	status | jq -e --arg node "$1" '
		[.apps[] | select(.name == "spread") | .replicas[]? | select((.draining // false) | not)] as $live
		| ($live | length) == 4 and all($live[]; .state == "running")
		  and ([$live[] | select(.nodeId == $node)] | length) == 2'
}
wait_for 300 "spread by zone: two of four replicas on $_last, alone in its zone" half_on "$_last"

fi
if want queues; then
log "autoscaling on a Redis list, a RabbitMQ queue, a command, and a schedule"
# Each broker runs in its app's own container on 127.0.0.1: only a
# connection made inside the replica's network namespace reaches it.
QPASS=e2e-queue-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')
printf 'redis://:%s@127.0.0.1:6379/0' "$QPASS" | cli secret set e2e-redis redis-url >/dev/null
cat <<EOF | cli app update e2e-redis --file - --create-if-missing >/dev/null
name: e2e-redis
image: redis:7-alpine
command: ["redis-server", "--requirepass", "$QPASS"]
ingress:
  type: none
scale:
  min: 1
  max: 2
  rules:
    - type: redis
      urlSecretRef: redis-url
      list: jobs
      length: 10
EOF
# Guest may only log in from localhost, which the rule's connection is.
printf 'amqp://guest:guest@127.0.0.1:5672/' | cli secret set e2e-rabbit amqp-url >/dev/null
cat <<'EOF' | cli app update e2e-rabbit --file - --create-if-missing >/dev/null
name: e2e-rabbit
image: rabbitmq:3-management-alpine
ingress:
  type: none
resources:
  memory: 512Mi
scale:
  min: 1
  max: 2
  rules:
    - type: rabbitmq
      urlSecretRef: amqp-url
      queue: jobs
      length: 10
EOF
cat <<'EOF' | cli app update e2e-cmdq --file - --create-if-missing >/dev/null
name: e2e-cmdq
image: busybox:1.37
command: ["sleep", "86400"]
ingress:
  type: none
resources:
  memory: 32Mi
scale:
  min: 1
  max: 2
  rules:
    - type: queue
      command: ["sh", "-c", "cat /tmp/queue 2>/dev/null || echo 0"]
      length: 10
    - type: schedule
      schedule: "* * * * *"
      duration: 2m
      replicas: 2
EOF
running() {
	status | jq -e --arg app "$1" '[.apps[] | select(.name == $app) | .replicas[]? | select(.state == "running" and .ready)] | length >= 1' >/dev/null
}
rule() {
	status | jq -e --arg app "$1" --arg type "$2" --argjson n "$3" '.apps[] | select(.name == $app)
		| .desiredReplicas == 2 and ([.autoscale.rules[]? | select(.type == $type and .measured and ((.current // 0) | tonumber) == $n)] | length) == 1' >/dev/null
}
wait_for 240 "e2e-redis runs" running e2e-redis
cli app exec e2e-redis -- redis-cli -a "$QPASS" --no-auth-warning rpush jobs $(seq 1 25) >/dev/null
wait_for 120 "a Redis list of 25 at 10 per replica scales e2e-redis to 2" rule e2e-redis redis 25

wait_for 300 "e2e-rabbit runs" running e2e-rabbit
publish() {
	cli app exec e2e-rabbit -- sh -c "'rabbitmqadmin declare queue name=jobs durable=true >/dev/null && for i in \$(seq 1 25); do rabbitmqadmin publish routing_key=jobs payload=\$i >/dev/null; done'"
}
wait_for 120 "25 messages published to RabbitMQ" publish
wait_for 120 "a RabbitMQ queue of 25 at 10 per replica scales e2e-rabbit to 2" rule e2e-rabbit rabbitmq 25

wait_for 120 "e2e-cmdq runs" running e2e-cmdq
cli app exec e2e-cmdq -- sh -c "'echo 15 > /tmp/queue'" >/dev/null
cmdq() {
	status | jq -e '.apps[] | select(.name == "e2e-cmdq") | .desiredReplicas == 2
		and ([.autoscale.rules[]? | select(.type == "queue" and .measured and ((.current // 0) | tonumber) == 15)] | length) == 1
		and ([.autoscale.rules[]? | select(.type == "schedule" and .until != null)] | length) == 1' >/dev/null
}
wait_for 120 "a command's queue of 15 is read and a schedule window that opens every minute holds e2e-cmdq at 2" cmdq

i=1
while [ "$i" -le "$N" ]; do
	_hits=$(printf '%s\n' "$QPASS" | on "$i" 'journalctl --no-pager -o cat | grep -c -F -f - || true')
	[ "$_hits" = 0 ] || fail "the Redis password appears in the journal on $(host "$i" 1)"
	i=$((i + 1))
done
ok "the Redis password is in no journal"
for a in e2e-redis e2e-rabbit e2e-cmdq; do cli app delete "$a" --yes >/dev/null; done

fi

if [ "$E2E_REBOOT" = 1 ] && want reboot; then
	log "reboot every machine at once"
	i=1
	while [ "$i" -le "$N" ]; do
		on "$i" 'systemctl reboot' >/dev/null 2>&1 || true
		i=$((i + 1))
	done
	sleep 30
	i=1
	while [ "$i" -le "$N" ]; do
		wait_for 600 "$(host "$i" 1) is back" reachable "$i"
		i=$((i + 1))
	done
	wait_for 300 "control plane has $SERVERS voting members" voting "$SERVERS"
	wait_for 300 "all $N nodes ready" nodes_ready
	wait_for 300 "$APP serving" serving
	wait_for 120 "https://$URL_HOST answers 200 on every public IP" all_https_ok
fi

log "passed in $((($(date +%s) - STARTED) / 60)) minutes (scenarios: ${E2E_ONLY:-all})"
