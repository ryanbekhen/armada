#!/bin/sh
# End-to-end test of upgrading a cluster in place, machine by machine (see
# README.md):
#
#   E2E_TO=v0.2.0 E2E_DOMAIN=apps.example.org E2E_ACME_EMAIL=you@example.org \
#   E2E_ETCDCTL=bin/etcdctl sh test/e2e/upgrade.sh hosts
#
# The hosts file lists five fresh Linux machines, one per line, as for
# cluster.sh:
#
#   NAME  SSH-TARGET  PRIVATE-IP  PUBLIC-IP
#
# The first three become control plane servers, the other two nodes. Every
# machine gets the release E2E_FROM (default v0.1.0-alpha.44, the release
# upgrades come from) with install.sh, and the cluster is built on it: the
# wireguard network mode, an app with a volume, a job on a schedule,
# internal HTTP and TCP apps, and a public app with a certificate. Under
# continuous load through the public and the internal addresses, every
# machine is upgraded to E2E_TO with `armadad upgrade`: the standby servers,
# the leader, then the nodes, once no machine has a container runc created
# left (E2E_FROM moves them to crun; E2E_TO carries no runc, ADR 0056).
# The run passes only with every request answered, no container or state
# of runc's on any machine afterwards, no image pulled again, every etcd
# member ID unchanged, and the keyspace unchanged but for what the release
# writes (servers/ records, events, what replica reports change). A release
# that moves the state to armada-kv (ADR 0057) is held from moving it during
# the upgrade (--state-move off); the move scenario then moves it under the
# same load: the state in armada-kv on every server, the keyspace the same,
# etcd's data kept as etcd.moved, and a backup of armada-kv's state.
#
# Releases come from GitHub, or from E2E_RELEASES: a local directory laid
# out as the release downloads (TAG/armada_<version>_linux_<arch>.tar.gz,
# TAG/checksums.txt, ...) holding E2E_FROM and E2E_TO, copied to every
# machine and used through ARMADA_DOWNLOAD_BASE=file://.
set -eu

# Scenarios after the cluster is built on E2E_FROM and its workloads run.
# E2E_ONLY=upgrade runs only that (empty: all; move needs the upgrade, which
# always runs); E2E_LIST=1 lists them.
SCENARIOS="upgrade move"
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

HOSTS=${1:?usage: upgrade.sh HOSTS-FILE}
E2E_FROM=${E2E_FROM:-v0.1.0-alpha.44}
: "${E2E_TO:?set E2E_TO to the release to upgrade to (a tag on GitHub, or one in E2E_RELEASES)}"
: "${E2E_DOMAIN:?set E2E_DOMAIN to a root domain whose wildcard record points at every public IP}"
: "${E2E_ACME_EMAIL:?set E2E_ACME_EMAIL to the ACME account email}"
: "${E2E_ETCDCTL:?set E2E_ETCDCTL to a Linux etcdctl for the architecture of the first machine (from the etcd release archive the runtime pack pins), which reads the keyspace and the member IDs}"
E2E_ACME_CA=${E2E_ACME_CA:-letsencrypt-staging}
E2E_SSH_OPTS=${E2E_SSH_OPTS:-}
E2E_SUDO=${E2E_SUDO:-}
E2E_RELEASES=${E2E_RELEASES:-}

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
[ -f "$E2E_ETCDCTL" ] || {
	echo "e2e: E2E_ETCDCTL names no file" >&2
	exit 2
}
if [ -n "$E2E_RELEASES" ]; then
	for _t in "$E2E_FROM" "$E2E_TO"; do
		[ -f "$E2E_RELEASES/$_t/checksums.txt" ] || {
			echo "e2e: $E2E_RELEASES/$_t has no checksums.txt" >&2
			exit 2
		}
	done
fi
INSTALLER="$(cd "$(dirname "$0")/../.." && pwd)/install.sh"

host() { awk -v n="$1" -v c="$2" 'NF && $1 !~ /^#/ { if (++i == n) print $c }' "$HOSTS"; }
N=$(awk 'NF && $1 !~ /^#/' "$HOSTS" | wc -l | tr -d ' ')
[ "$N" -ge 5 ] || {
	echo "e2e: the hosts file needs five machines: three servers and two nodes" >&2
	exit 2
}
N=5
SERVERS=3
PUBLIC_IPS=$(awk 'NF && $1 !~ /^#/ { if (++i <= 5) print $4 }' "$HOSTS" | tr '\n' ' ')
APP=hello
URL_HOST=$APP.$E2E_DOMAIN
SPACE=e2e-up
CLI=1
WORK=$(mktemp -d)
LOAD_PID=
STARTED=$(date +%s)
BASE_ENV=
if [ -n "$E2E_RELEASES" ]; then BASE_ENV="ARMADA_DOWNLOAD_BASE=file:///root/e2e-releases"; fi

log() { printf '\n==> %s\n' "$*"; }
ok() { printf '    ok: %s\n' "$*"; }
fail() {
	printf '    FAIL: %s\n' "$*" >&2
	exit 1
}
q() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"; }

# on N CMD runs CMD as root on machine N, retrying a dropped SSH connection.
on() {
	_on_n=$1
	shift
	_on_try=1
	while :; do
		_target=$(host "$_on_n" 2)
		# shellcheck disable=SC2086 # E2E_SSH_OPTS is a list of options
		ssh $E2E_SSH_OPTS -o BatchMode=yes -o ConnectTimeout=10 "$_target" "$E2E_SUDO sh -c $(q "PATH=/usr/local/bin:\$PATH; $*")" && return 0
		_on_rc=$?
		if [ "$_on_rc" -ne 255 ] || [ "$_on_try" -ge 4 ]; then
			return "$_on_rc"
		fi
		_on_try=$((_on_try + 1))
		sleep 5
	done
}
cli() { on "$CLI" "armada $*"; }
copy() { # copy FILE N DEST
	_try=1
	# shellcheck disable=SC2086
	until scp -q $E2E_SSH_OPTS -o BatchMode=yes "$1" "$(host "$2" 2):$3"; do
		[ "$_try" -lt 3 ] || fail "copying $1 to $(host "$2" 1)"
		_try=$((_try + 1))
		sleep 5
	done
}

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
ready() { # ready APP-ID COUNT: COUNT replicas, all running and ready
	status | jq -e --arg app "$1" --argjson n "$2" '
		.apps[] | select(.name == $app)
		| [.replicas[]? | select((.draining // false) | not)] as $live
		| ($live | length) == $n and all($live[]; .state == "running" and (.ready // false))'
}
voting() { [ "$(cli server list 2>/dev/null | grep -c ' voting ')" -ge "$1" ]; }
leader() { cli server list 2>/dev/null | awk '$3 == "leader" { print $1 }'; }
nodes_ready() { status | jq -e --argjson n "$N" '[.nodes[] | select(.state == "ready")] | length == $n'; }
index() { awk -v name="$1" 'NF && $1 !~ /^#/ { i++; if ($1 == name) print i }' "$HOSTS"; }
https_ok() { [ "$(curl -sk -o /dev/null -w '%{http_code}' --max-time 5 --resolve "$URL_HOST:443:$1" "https://$URL_HOST/")" = 200 ]; }
all_https_ok() {
	for _ip in $PUBLIC_IPS; do https_ok "$_ip" || return 1; done
}

# The public load: requests round robin over every public IP, each line
# its status code. load_check fails on any but 200.
load_start() {
	: >"$WORK/load"
	rm -f "$WORK/load.stop"
	(
		# shellcheck disable=SC2086 # one IP per argument
		set -- $PUBLIC_IPS
		while [ ! -f "$WORK/load.stop" ]; do
			for ip in "$@"; do
				res=$(curl -sk -o /dev/null -w '%{http_code} curl=%{exitcode} %{errormsg}' --max-time 5 \
					--resolve "$URL_HOST:443:$ip" "https://$URL_HOST/" || true)
				echo "${res%% *} $ip ${res#* } at $(date -u +%H:%M:%S)" >>"$WORK/load"
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
	[ "$_total" -gt 0 ] || fail "$1: no public requests sent"
	if [ "$_bad" -gt 0 ]; then
		grep -v '^200 ' "$WORK/load" | sort | uniq -c | sed 's/^/      /' >&2
		fail "$1: $_bad of $_total public requests did not return 200"
	fi
	ok "$1: $_total public requests, all 200"
}

# The internal load: every replica of the prober app (spread over the machines)
# asks inner over HTTP and tcp-echo over TCP through the node's resolver
# and proxy, over and over, counting answers in /tmp/counts.
prober_counts() { # prober_counts: "OK FAIL" summed over every prober replica
	_ok=0 _bad=0
	for _r in $(status | jq -r --arg app "prober.$SPACE" '.apps[] | select(.name == $app) | .replicas[]?.id'); do
		_c=$(cli app exec "prober.$SPACE" --replica "$_r" -- cat /tmp/counts | tr -d '\r') || return 1
		_ok=$((_ok + ${_c%% *}))
		_bad=$((_bad + ${_c##* }))
	done
	echo "$_ok $_bad"
}
internal_reset() {
	for _r in $(status | jq -r --arg app "prober.$SPACE" '.apps[] | select(.name == $app) | .replicas[]?.id'); do
		cli app exec "prober.$SPACE" --replica "$_r" -- sh -c "$(q 'echo "0 0" > /tmp/counts.reset')" >/dev/null ||
			fail "resetting prober replica $_r"
	done
}
internal_check() {
	_counts=$(prober_counts) || fail "$1: reading the probers' counts"
	[ "${_counts%% *}" -gt 0 ] || fail "$1: no internal request answered"
	if [ "${_counts##* }" != 0 ]; then
		# Each failure's time (UTC) and kind: http (a name or the request) or tcp.
		for _r in $(status | jq -r --arg app "prober.$SPACE" '.apps[] | select(.name == $app) | .replicas[]?.id'); do
			cli app exec "prober.$SPACE" --replica "$_r" -- sh -c 'cat /tmp/fails 2>/dev/null' | sed "s/^/    $_r: /" >&2 || true
		done
		fail "$1: ${_counts##* } internal requests failed (${_counts%% *} answered)"
	fi
	ok "$1: ${_counts%% *} internal HTTP and TCP requests, none failed"
}

# What must not change, written into DIR: armada-node's image records
# (when each was pulled), the etcd member IDs, and the keyspace.
# The store the state is in: etcd's member, or armada-kv's once moved
# (ADR 0057), which serves the same API with the same certificates.
STATE_DIR=/var/lib/armada/etcd
STATE_PORT=2379
etcdctl() {
	_ip=$(host 1 3)
	on 1 "/root/e2e-etcdctl --endpoints https://$_ip:$STATE_PORT --cacert $STATE_DIR/ca.crt --cert $STATE_DIR/member.crt --key $STATE_DIR/member.key $*"
}
snapshot() { # snapshot DIR
	mkdir -p "$1"
	_i=1
	while [ "$_i" -le "$N" ]; do
		on "$_i" 'cat /var/lib/armada/node/images/index.json' | jq -S '.images // {} | map_values(.created)' >"$1/images.$_i" ||
			fail "reading armada-node's image records on $(host "$_i" 1)"
		_i=$((_i + 1))
	done
	etcdctl 'member list -w json' | jq -S '[.members[] | {name, ID}] | sort_by(.name)' >"$1/members" || fail "etcd member list"
	etcdctl 'get --prefix /armada/ -w json' | jq -S '
		[.kvs[]? | {key: (.key | @base64d), value: (.value | @base64d)}]
		| map(.key |= ltrimstr("/armada/"))
		# What the release writes, and what runs on its own while the
		# cluster serves: servers/ records (versions), events, the commit
		# and audit counters, and the job: its record (the fire it last
		# scheduled), its runs, and their attempts.
		# And the records of the state move (ADR 0057).
		| map(select((.key | test("^(servers/|events/|audit/|commit$|auditseq$|meta/state-move|apps/e2e-job\\.e2e-up$|runs/e2e-job\\.e2e-up/|replicas/e2e-job\\.e2e-up-j|placements/e2e-job\\.e2e-up-j)")) | not))
		| map(.value |= (try fromjson catch .))
		# Fields agents and the leader rewrite on their own: when a node
		# was last seen and the version its agent runs, when a replica
		# report arrived, and what a recreated replica changes (one whose
		# container runc created): its container, its address, and when
		# it got ready.
		| map(if (.key | startswith("nodes/")) then .value |= del(.lastSeen, .version)
		      elif (.key | startswith("replicas/")) then .value |= del(.updatedAt, .containerId, .address, .ip, .readySince, .message, .restarts, .lastRestartAt, .lastRestart)
		      else . end)
		| from_entries' >"$1/keyspace" || fail "reading the keyspace"
	[ -s "$1/keyspace" ] || fail "the keyspace read is empty"
}
# unchanged BEFORE AFTER WHEN: every check against the snapshot before.
unchanged() {
	_i=1
	while [ "$_i" -le "$N" ]; do
		jq -e --slurpfile after "$2/images.$_i" 'to_entries | all(.value == $after[0][.key])' "$1/images.$_i" >/dev/null ||
			fail "$3: an image was pulled again on $(host "$_i" 1): $(jq -c . "$1/images.$_i") then $(jq -c . "$2/images.$_i")"
		_i=$((_i + 1))
	done
	ok "$3: no image pulled again"
	if [ "${4:-}" = new-members ]; then
		# A new store: its own member IDs, one per server.
		[ "$(jq length "$2/members")" = "$SERVERS" ] || fail "$3: $(jq -c . "$2/members") are not $SERVERS members"
		ok "$3: $SERVERS members in the new store"
	else
		cmp -s "$1/members" "$2/members" || fail "$3: etcd members changed: $(jq -c . "$1/members") then $(jq -c . "$2/members")"
		ok "$3: every etcd member ID unchanged"
	fi
	if ! cmp -s "$1/keyspace" "$2/keyspace"; then
		jq -r --slurpfile after "$2/keyspace" '
			. as $before | ($before | keys) + ($after[0] | keys) | unique[] as $k
			| select($before[$k] != $after[0][$k])
			| "      \($k)\n        before \($before[$k] | tojson | .[0:400])\n        after  \($after[0][$k] | tojson | .[0:400])"' "$1/keyspace" >&2
		fail "$3: the keyspace changed (keys above)"
	fi
	ok "$3: the keyspace is unchanged but for servers/ and events"
}

# upgrade_machine N TAG: armadad upgrade on machine N; the server list,
# the nodes, and the cluster's workloads come back.
upgrade_machine() {
	_name=$(host "$1" 1)
	on "$1" "$BASE_ENV armadad upgrade --version $2" >"$WORK/upgrade.$1" 2>&1 || {
		cat "$WORK/upgrade.$1" >&2
		fail "armadad upgrade --version $2 on $_name"
	}
	on "$1" "armadad version" | head -n 1 | grep -q "$2" || fail "$_name does not run $2"
	if [ "$1" -le "$SERVERS" ]; then
		wait_for 180 "control plane has $SERVERS voting members" voting "$SERVERS"
	fi
	wait_for 180 "all $N nodes ready" nodes_ready
	ok "$_name runs $2"
}
# units_of N: the Armada units active on machine N.
# shellcheck disable=SC2016 # expanded on the machine
units_of() { on "$1" 'for u in armada-etcd armada-kv armada-server armada-agent; do systemctl is-active --quiet $u && printf "%s " $u; done; true'; }

cleanup() {
	_rc=$?
	[ -z "$LOAD_PID" ] || kill "$LOAD_PID" 2>/dev/null || true
	if [ "$_rc" -ne 0 ]; then
		printf '\n==> diagnostics (CLI on %s)\n' "$(host "$CLI" 1)" >&2
		cli server list >&2 || true
		cli cluster status >&2 || true
		cli app list -A >&2 || true
	fi
	rm -rf "$WORK"
	exit "$_rc"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

log "install $E2E_FROM on $N machines"
if [ -n "$E2E_RELEASES" ]; then
	# shellcheck disable=SC2046 # one tag per argument, each once
	tar -C "$E2E_RELEASES" -cf "$WORK/releases.tar" $(printf '%s\n' "$E2E_FROM" "$E2E_TO" | sort -u)
fi
i=1
while [ "$i" -le "$N" ]; do
	if [ -n "$E2E_RELEASES" ]; then
		copy "$WORK/releases.tar" "$i" /root/e2e-releases.tar
		on "$i" 'rm -rf /root/e2e-releases && mkdir -m 0700 /root/e2e-releases && tar -C /root/e2e-releases -xf /root/e2e-releases.tar && rm /root/e2e-releases.tar'
	fi
	on "$i" "ARMADA_VERSION=$E2E_FROM $BASE_ENV sh -s >/dev/null" <"$INSTALLER" || fail "install.sh $E2E_FROM on $(host "$i" 1)"
	on "$i" 'install -d -m 0700 /etc/armada /run/armada/secrets'
	ok "$(host "$i" 1): $(on "$i" 'armadad version' | head -n 1)"
	i=$((i + 1))
done
case $(on 1 'uname -m') in x86_64 | amd64 | aarch64 | arm64) ;; *) fail "unknown architecture on $(host 1 1)" ;; esac
copy "$E2E_ETCDCTL" 1 /root/e2e-etcdctl
on 1 'chmod 0700 /root/e2e-etcdctl'

log "create the cluster on $E2E_FROM: three servers, two nodes, the wireguard mode"
FLAGS="--acme-email $E2E_ACME_EMAIL --acme-ca $E2E_ACME_CA --node-lost-timeout 30s"
i=1
while [ "$i" -le "$SERVERS" ]; do
	on "$i" "umask 077; echo $(q "ARMADA_SERVER_FLAGS=\"$FLAGS\"") > /etc/armada/server.env"
	i=$((i + 1))
done
on 1 "armadad init --node-name $(host 1 1) --private-ip $(host 1 3) --network wireguard >/dev/null && systemctl enable --now -q armada-server"
wait_for 120 "control plane answers" voting 1
i=2
while [ "$i" -le "$N" ]; do
	if [ "$i" -le "$SERVERS" ]; then cli server join-token; else cli node join-token; fi >"$WORK/token"
	_tok=$(sed -n 's/^Token (.*shown once): //p' "$WORK/token")
	_cmd=$(sed -n 's/^  sudo \(armadad .*join .*\)$/\1/p' "$WORK/token")
	rm -f "$WORK/token"
	if [ -z "$_tok" ] || [ -z "$_cmd" ]; then fail "no join token printed"; fi
	printf '%s\n' "$_tok" | on "$i" 'umask 077; cat > /run/armada/e2e.token'
	_tok=
	if [ "$i" -le "$SERVERS" ]; then
		_args="--name $(host "$i" 1)" _unit=armada-server
	else
		_args="--node-name $(host "$i" 1)" _unit=armada-agent
	fi
	on "$i" "$_cmd $_args --private-ip $(host "$i" 3) --token-file /run/armada/e2e.token >/dev/null;
		rc=\$?; rm -f /run/armada/e2e.token; [ \$rc -eq 0 ] && systemctl enable --now -q $_unit"
	if [ "$i" -le "$SERVERS" ]; then
		wait_for 180 "$(host "$i" 1) joined as a voting server" voting "$i"
	else
		ok "$(host "$i" 1) joined as a node"
	fi
	i=$((i + 1))
done
wait_for 180 "all $N nodes ready" nodes_ready

log "workloads: a public app, internal HTTP and TCP apps, a volume, a job"
cli cluster update --root-domain "$E2E_DOMAIN" >/dev/null
cat <<EOF | cli app deploy --file - >/dev/null
name: $APP
image: traefik/whoami:v1.10
ingress:
  type: external
  port: 80
probes:
  readiness:
    path: /health
scale:
  min: $N
EOF
cli space create "$SPACE" >/dev/null
deploy_in() { # deploy_in: the spec on stdin, into the space
	on "$CLI" "cat >/root/e2e-up.yaml && armada app deploy --file /root/e2e-up.yaml --space $SPACE" >/dev/null
}
deploy_in <<'EOF'
name: inner
image: traefik/whoami:v1.10
ingress:
  type: internal
  port: 80
scale:
  min: 2
EOF
deploy_in <<'EOF'
name: tcp-echo
image: busybox:1.37
command: [nc, -lk, -p, "7000", -e, cat]
ingress:
  type: internal
  protocol: tcp
  port: 7000
  allow: [prober]
scale:
  min: 2
  max: 2
EOF
# The prober counts what inner and tcp-echo answer; a reset file zeroes
# the counts between checks.
deploy_in <<EOF
name: prober
image: busybox:1.37
command:
  - sh
  - -c
  - |
    ok=0 bad=0
    while :; do
      if [ -f /tmp/counts.reset ]; then ok=0 bad=0; rm -f /tmp/counts.reset /tmp/fails; fi
      why=
      wget -q -O /dev/null -T 3 http://inner/ || why=http
      [ -n "\$why" ] || [ "\$(echo hi | nc -w 3 tcp-echo 7000)" = hi ] || why=tcp
      if [ -z "\$why" ]; then
        ok=\$((ok + 1))
      else
        bad=\$((bad + 1))
        echo "\$(date -u +%H:%M:%S) \$why" >> /tmp/fails
      fi
      echo "\$ok \$bad" > /tmp/counts
      sleep 0.2
    done
ingress:
  type: none
scale:
  min: $N
EOF
cli node label "$(host "$N" 1)" e2e-vol=yes >/dev/null
deploy_in <<'EOF'
name: e2e-vol
image: busybox:1.37
command: ["httpd", "-f", "-p", "80", "-h", "/data"]
ingress:
  type: internal
  port: 80
placement:
  require:
    e2e-vol: ["yes"]
volumes:
  - name: data
    path: /data
EOF
on "$CLI" "cat >/root/e2e-job.yaml && armada job deploy e2e-job --file /root/e2e-job.yaml --space $SPACE" >/dev/null <<'EOF'
kind: job
name: e2e-job
image: busybox:1.37
command: ["sh", "-c", "echo ran"]
schedule: "* * * * *"
concurrency: forbid
history: 3
EOF
wait_for 300 "$APP has $N replicas ready" ready "$APP" "$N"
wait_for 300 "inner has 2 replicas ready" ready "inner.$SPACE" 2
wait_for 300 "tcp-echo has 2 replicas ready" ready "tcp-echo.$SPACE" 2
wait_for 300 "prober has $N replicas ready" ready "prober.$SPACE" "$N"
wait_for 300 "e2e-vol runs on $(host "$N" 1)" ready "e2e-vol.$SPACE" 1
printf 'kept across the upgrade' | cli app exec "e2e-vol.$SPACE" -i -- sh -c "$(q 'cat > /data/notes.txt')" ||
	fail "writing into the volume"
wait_for 300 "https://$URL_HOST answers 200 on every public IP" all_https_ok
job_ran() { cli run list e2e-job --space "$SPACE" -o json | jq -e '[(.runs // [])[] | select(.state == "succeeded")] | length >= 1'; }
wait_for 180 "the job ran on its schedule" job_ran
internal_reset
sleep 10
internal_check "before the upgrade"

job_failed() { cli run list e2e-job --space "$SPACE" -o json | jq -e '[(.runs // [])[] | select(.state == "failed")] | length > 0' >/dev/null; }
vol_kept() { [ "$(cli app exec "e2e-vol.$SPACE" -- cat /data/notes.txt)" = "kept across the upgrade" ]; }

# runc_on N: what machine N has of runc's (ADR 0056): the records of
# containers runc created (they name no runtime) and, with "state", runc's
# state directories in the shims'; nothing printed when there is none.
runc_on() {
	_state=
	[ "${2:-}" != state ] || _state='ls -d /run/armada/shim/*/runc/* 2>/dev/null;'
	on "$1" "grep -L '\"runtime\":\"crun\"' /var/lib/armada/supervisor/containers/*/record.json 2>/dev/null; $_state true"
}
# no_runc [state]: no machine has a container runc created (or its state).
no_runc() {
	_i=1
	while [ "$_i" -le "$N" ]; do
		[ -z "$(runc_on "$_i" "${1:-}")" ] || return 1
		_i=$((_i + 1))
	done
}

# check WHEN BEFORE [new-members]: every check, against the snapshot BEFORE,
# once no machine has a container or state of runc's left, still under
# load; new-members: the state moved to a new store.
check() {
	wait_for 300 "$1: no container or state of runc's on any machine" no_runc state
	load_stop "$1"
	internal_check "$1"
	snapshot "$WORK/after"
	unchanged "$2" "$WORK/after" "$1" "${3:-}"
	vol_kept || fail "$1: the volume lost its file"
	job_failed && fail "$1: a run of the job failed"
	wait_for 120 "$1: the job runs on its schedule" job_ran
	ok "$1: the volume and the job are as before"
	rm -rf "$WORK/after"
}

# E2E_FROM moves every container runc created to crun (ADR 0056); E2E_TO
# carries no runc, so the upgrade waits until none is left.
wait_for 1800 "every container runs on crun before the upgrade" no_runc
log "upgrade every machine to $E2E_TO under load"
snapshot "$WORK/before"
load_start
internal_reset
_leader=$(leader)
[ -n "$_leader" ] || fail "no leader"
_li=$(index "$_leader")
i=1
while [ "$i" -le "$SERVERS" ]; do
	[ "$i" = "$_li" ] || upgrade_machine "$i" "$E2E_TO"
	i=$((i + 1))
done
upgrade_machine "$_li" "$E2E_TO"
# A release with armada-kv moves the state ten minutes after every server
# runs it (ADR 0057): held until the move scenario.
MOVES=
if cli cluster update --help 2>/dev/null | grep -q -- --state-move; then
	MOVES=1
	cli cluster update --state-move off >/dev/null || fail "holding the state move"
	ok "the state move held (--state-move off)"
fi
i=$((SERVERS + 1))
while [ "$i" -le "$N" ]; do
	upgrade_machine "$i" "$E2E_TO"
	i=$((i + 1))
done
check "the upgrade" "$WORK/before"
i=1
while [ "$i" -le "$N" ]; do
	_want="armada-agent "
	[ "$i" -gt "$SERVERS" ] || _want="armada-etcd armada-server armada-agent "
	[ "$(units_of "$i")" = "$_want" ] || fail "$(host "$i" 1) runs $(units_of "$i")instead of $_want"
	i=$((i + 1))
done
ok "servers run armada-etcd, armada-server, and armada-agent; nodes armada-agent"
if ! on 1 'armadad doctor' >"$WORK/doctor" 2>&1; then :; fi
grep -E '^\[FAIL\]' "$WORK/doctor" >&2 && fail "armadad doctor on $(host 1 1) after the upgrade"
ok "armadad doctor passes on $(host 1 1)"

# moved: the state is in armada-kv, every server switched.
moved() { cli cluster status -o json | jq -e '.stateMove.store == "kv" and .stateMove.step == "moved"'; }
if want move && [ -n "$MOVES" ]; then
	log "move the control plane's state to armada-kv under load"
	snapshot "$WORK/before"
	load_start
	internal_reset
	cli cluster update --state-move now >/dev/null || fail "starting the state move"
	wait_for 600 "the state moved to armada-kv" moved
	wait_for 180 "control plane has $SERVERS voting members" voting "$SERVERS"
	wait_for 180 "all $N nodes ready" nodes_ready
	STATE_DIR=/var/lib/armada/kv
	STATE_PORT=7445
	check "the move" "$WORK/before" new-members
	i=1
	while [ "$i" -le "$SERVERS" ]; do
		[ "$(units_of "$i")" = "armada-kv armada-server armada-agent " ] ||
			fail "$(host "$i" 1) runs $(units_of "$i")instead of armada-kv armada-server armada-agent"
		on "$i" 'test -d /var/lib/armada/kv && test -d /var/lib/armada/etcd.moved && ! test -e /var/lib/armada/etcd && ! test -e /var/lib/armada/kv.moving && ! systemctl is-enabled --quiet armada-etcd && systemctl is-enabled --quiet armada-kv' ||
			fail "$(host "$i" 1): the data directory or the units did not switch to armada-kv"
		i=$((i + 1))
	done
	ok "every server runs armada-kv, armada-etcd disabled, etcd's data kept as etcd.moved"
	cli cluster events --since 1h | grep -q StateMoved || fail "no StateMoved event"
	ok "StateMoved recorded"
	on 1 'armadad backup -o /root/e2e-kv-backup.tar.gz >/dev/null 2>&1 && tar -tzf /root/e2e-kv-backup.tar.gz | grep -qx kv.snapshot && rm -f /root/e2e-kv-backup.tar.gz' ||
		fail "armadad backup of armada-kv's state on $(host 1 1)"
	ok "armadad backup takes armada-kv's snapshot"
	if ! on 1 'armadad doctor' >"$WORK/doctor" 2>&1; then :; fi
	grep -E '^\[FAIL\]' "$WORK/doctor" >&2 && fail "armadad doctor on $(host 1 1) after the move"
	ok "armadad doctor passes on $(host 1 1) after the move"
elif want move; then
	ok "$E2E_TO has no armada-kv move; the move scenario is skipped"
fi

log "passed in $((($(date +%s) - STARTED) / 60)) minutes (scenarios: ${E2E_ONLY:-all})"
