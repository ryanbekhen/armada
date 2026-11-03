#!/bin/sh
# Network benchmark between two machines (see README.md).
#
#   ARMADA_BIN=bin/armada BENCH_WIPE=yes sh test/bench/network.sh hosts
#
# The hosts file lists exactly two Linux machines, one per line:
#
#   NAME  SSH-TARGET  PRIVATE-IP  PUBLIC-IP
#
# Machine A (the first) runs the control plane and every client; machine B
# (the second) joins as a node. For each mode in BENCH_MODES the script
# builds a two-node cluster, measures container to container throughput,
# HTTP through HAProxy for four replica placements, and a large upload,
# then removes the cluster again. It prints a Markdown table and keeps the
# raw output in BENCH_OUT. The machines lose their Armada state: use
# machines you can throw away.
set -eu

HOSTS=${1:?usage: network.sh HOSTS-FILE}
ARMADA_BIN=${ARMADA_BIN:-}
ARMADA_BIN_AMD64=${ARMADA_BIN_AMD64:-$ARMADA_BIN}
ARMADA_BIN_ARM64=${ARMADA_BIN_ARM64:-$ARMADA_BIN}
if [ -z "$ARMADA_BIN_AMD64$ARMADA_BIN_ARM64" ]; then
	echo "bench: set ARMADA_BIN (or ARMADA_BIN_AMD64/ARMADA_BIN_ARM64) to Linux armada binaries with the runtime embedded (make build-bundle)" >&2
	exit 2
fi
BENCH_MODES=${BENCH_MODES:-plain wireguard}
BENCH_WG_UNDERLAY=${BENCH_WG_UNDERLAY:-private} # private | public: the addresses the tunnel runs over
BENCH_WG_PORT=${BENCH_WG_PORT:-51820}
BENCH_WG_MTU=${BENCH_WG_MTU:-auto} # auto: the underlay's MTU less WireGuard's 80 bytes
BENCH_WG_NET=${BENCH_WG_NET:-10.99.0} # tunnel addresses: .1 for A, .2 for B
BENCH_DURATION=${BENCH_DURATION:-30}  # seconds per HTTP run
BENCH_IPERF_SECONDS=${BENCH_IPERF_SECONDS:-20}
BENCH_UPLOAD_MB=${BENCH_UPLOAD_MB:-1024}
BENCH_CONCURRENCY=${BENCH_CONCURRENCY:-32}
BENCH_BRIDGE_GW=${BENCH_BRIDGE_GW:-10.121.0.1} # armada0 address on A
BENCH_OUT=${BENCH_OUT:-bench-$(date +%Y%m%d-%H%M%S)}
BENCH_SSH_OPTS=${BENCH_SSH_OPTS:-}
BENCH_SUDO=${BENCH_SUDO:-} # "sudo" when SSH-TARGET is not root
BENCH_WIPE=${BENCH_WIPE:-}  # "yes" lets the script remove existing Armada state
HEY_VERSION=v0.1.4

for tool in ssh scp jq awk go; do
	command -v "$tool" >/dev/null || {
		echo "bench: $tool is required" >&2
		exit 2
	}
done
for m in $BENCH_MODES; do
	case $m in
	plain | wireguard) ;;
	*)
		echo "bench: unknown mode $m (plain, wireguard)" >&2
		exit 2
		;;
	esac
done
case $BENCH_WG_UNDERLAY in
private | public) ;;
*)
	echo "bench: BENCH_WG_UNDERLAY must be private or public" >&2
	exit 2
	;;
esac
UNITS=$(cd "$(dirname "$0")/../../deploy/systemd" && pwd)

# host N COLUMN prints a column of the Nth machine (1 name, 2 SSH target,
# 3 private IP, 4 public IP).
host() { awk -v n="$1" -v c="$2" 'NF && $1 !~ /^#/ { if (++i == n) print $c }' "$HOSTS"; }
[ "$(awk 'NF && $1 !~ /^#/' "$HOSTS" | wc -l | tr -d ' ')" -eq 2 ] || {
	echo "bench: the hosts file needs exactly two machines" >&2
	exit 2
}
A=$(host 1 1)
B=$(host 2 1)
WORK=$(mktemp -d)
mkdir -p "$BENCH_OUT"
RESULTS=$BENCH_OUT/results.md
MODE=
LABEL=
IP_A=
IP_B=

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
	# shellcheck disable=SC2086 # BENCH_SSH_OPTS is a list of options
	ssh $BENCH_SSH_OPTS -o BatchMode=yes -o ConnectTimeout=10 "$_target" "$BENCH_SUDO sh -c $(q "PATH=/usr/local/bin:\$PATH; $*")"
}
copy() { # copy FILE N DEST
	# shellcheck disable=SC2086
	scp -q $BENCH_SSH_OPTS -o BatchMode=yes -o ServerAliveInterval=10 "$1" "$(host "$2" 2):$3"
}
cli() { on 1 "armada $*"; }

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

status() { cli status -o json; }
nodes_ready() { status | jq -e '[.nodes[] | select(.state == "ready")] | length == 2'; }
# placed APP NODES: the app serves from exactly NODES (space separated, in
# order of machine), with no rollout and nothing draining.
placed() {
	status | jq -e --arg app "$1" --arg nodes "$2" '
		.apps[] | select(.name == $app)
		| [.replicas[]? | select((.draining // false) | not)] as $live
		| (.rolloutState // "") == ""
		  and ([$live[] | select(.state == "running" and (.ready // false))] | length) == ($live | length)
		  and ([$live[].nodeId] | sort | join(" ")) == ($nodes | split(" ") | sort | join(" "))'
}
address() { # address APP: the published address of the app's replica
	status | jq -r --arg app "$1" '.apps[] | select(.name == $app) | .replicas[0].address'
}

# cpu N prints "busy total" jiffies of machine N.
# Guest time is already in user time, so only the first eight count.
cpu() { on "$1" "head -n1 /proc/stat" | awk '{ t = 0; for (i = 2; i <= 9; i++) t += $i; print t - $5 - $6, t }'; }
# pct BEFORE AFTER prints the busy share in between, in percent.
pct() { printf '%s %s\n' "$1" "$2" | awk '{ d = $4 - $2; printf "%.0f%%", (d > 0 ? 100 * ($3 - $1) / d : 0) }'; }
# measure LABEL CMD... runs CMD with the CPU of both machines sampled
# around it; sets CPU_A and CPU_B.
measure() {
	_a0=$(cpu 1) _b0=$(cpu 2)
	shift
	"$@"
	_a1=$(cpu 1) _b1=$(cpu 2)
	CPU_A=$(pct "$_a0" "$_a1") CPU_B=$(pct "$_b0" "$_b1")
}
row() { # row TEST RESULT
	printf '| %s | %s | %s | %s | %s |\n' "$LABEL" "$1" "$2" "$CPU_A" "$CPU_B" | tee -a "$RESULTS"
}

deploy() { cli deploy -f - >/dev/null; }

# wipe N removes Armada's cluster state, containers, and the tunnel from
# machine N, leaving the binary and units installed.
wipe() {
	on "$1" 'systemctl disable --now -q armada-agent armada-server 2>/dev/null
		if systemctl is-active -q armada-runtime; then armada runtime reset >/dev/null 2>&1 || true; fi
		systemctl disable --now -q armada-runtime 2>/dev/null
		umount /var/lib/armada/volumes 2>/dev/null
		rm -rf /var/lib/armada /etc/armada ~root/.armada /run/armada/bench
		ip link del armada-bench 2>/dev/null
		rm -f /var/tmp/armada-bench.upload
		if systemctl is-active -q firewalld 2>/dev/null; then
			firewall-cmd -q --remove-port='"$BENCH_WG_PORT"'/udp 2>/dev/null
			firewall-cmd -q --zone=trusted --remove-interface=armada-bench 2>/dev/null
		fi
		install -d -m 0700 /etc/armada /run/armada/secrets
		true'
}

cleanup() {
	_rc=$?
	if [ "$_rc" -ne 0 ] && [ -n "$MODE" ]; then
		printf '\n==> diagnostics\n' >&2
		cli status >&2 || true
	fi
	printf '\n==> removing the cluster from both machines\n' >&2
	wipe 1 || true
	wipe 2 || true
	on 1 'rm -f /usr/local/bin/armada-bench-hey' || true
	chmod -R u+w "$WORK" 2>/dev/null
	rm -rf "$WORK"
	exit "$_rc"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

log "check the machines"
i=1
while [ "$i" -le 2 ]; do
	if on "$i" 'test -e /var/lib/armada' && [ "$BENCH_WIPE" != yes ]; then
		echo "bench: $(host "$i" 1) already has /var/lib/armada; the benchmark removes it. Set BENCH_WIPE=yes to go ahead." >&2
		trap - EXIT
		rm -rf "$WORK"
		exit 2
	fi
	on "$i" 'command -v curl >/dev/null' || fail "$(host "$i" 1) needs curl"
	case " $BENCH_MODES " in
	*" wireguard "*) on "$i" 'command -v wg >/dev/null && { modprobe wireguard 2>/dev/null; command -v wireguard-go >/dev/null ||
		{ ip link add armada-bchk type wireguard && ip link del armada-bchk; }; }' ||
		fail "$(host "$i" 1) needs wireguard-tools (wg) and the wireguard kernel module (or wireguard-go) for the wireguard mode" ;;
	esac
	i=$((i + 1))
done
ok "$A and $B"

log "install armada and hey"
i=1
while [ "$i" -le 2 ]; do
	case $(on "$i" 'uname -m') in
	x86_64 | amd64) _bin=$ARMADA_BIN_AMD64 _arch=amd64 ;;
	aarch64 | arm64) _bin=$ARMADA_BIN_ARM64 _arch=arm64 ;;
	*) _bin='' _arch='' ;;
	esac
	[ -n "$_bin" ] || fail "no binary for the architecture of $(host "$i" 1)"
	copy "$_bin" "$i" /tmp/armada.bench
	for unit in armada-server armada-agent armada-runtime; do
		on "$i" "cat > /etc/systemd/system/$unit.service" <"$UNITS/$unit.service"
	done
	on "$i" 'install -m 0755 /tmp/armada.bench /usr/local/bin/armada && rm /tmp/armada.bench && systemctl daemon-reload'
	wipe "$i"
	if [ "$i" = 1 ]; then
		# hey sends the HTTP load from A, built for A's architecture.
		_modcache=$(go env GOMODCACHE)
		GOBIN='' GOPATH=$WORK/go GOMODCACHE=$_modcache GOOS=linux GOARCH=$_arch CGO_ENABLED=0 \
			go install "github.com/rakyll/hey@$HEY_VERSION"
		_hey=$WORK/go/bin/linux_$_arch/hey
		[ -x "$_hey" ] || _hey=$WORK/go/bin/hey
		copy "$_hey" 1 /tmp/hey.bench
		on 1 'install -m 0755 /tmp/hey.bench /usr/local/bin/armada-bench-hey && rm /tmp/hey.bench'
	fi
	ok "$(host "$i" 1): $(on "$i" 'armada version' | head -1) ($_arch)"
	i=$((i + 1))
done

# tunnel_up builds the prototype tunnel: a WireGuard interface on each
# machine, keys made there (only public keys leave), one UDP port.
tunnel_up() {
	_col=3
	[ "$BENCH_WG_UNDERLAY" = private ] || _col=4
	for i in 1 2; do
		on "$i" "umask 077; install -d -m 0700 /run/armada/bench && wg genkey > /run/armada/bench/wg.key"
	done
	_mtu=$BENCH_WG_MTU
	if [ "$_mtu" = auto ]; then
		# The smaller underlay MTU of the two, less the largest WireGuard
		# overhead (IPv6 outer header): larger inner packets would be
		# dropped without an error.
		_m1=$(on 1 "cat /sys/class/net/\$(ip -o route get $(host 2 "$_col") | sed -n 's/.* dev \\([^ ]*\\).*/\\1/p')/mtu")
		_m2=$(on 2 "cat /sys/class/net/\$(ip -o route get $(host 1 "$_col") | sed -n 's/.* dev \\([^ ]*\\).*/\\1/p')/mtu")
		_mtu=$(($([ "$_m1" -lt "$_m2" ] && echo "$_m1" || echo "$_m2") - 80))
	fi
	_pub1=$(on 1 'wg pubkey < /run/armada/bench/wg.key')
	_pub2=$(on 2 'wg pubkey < /run/armada/bench/wg.key')
	for i in 1 2; do
		if [ "$i" = 1 ]; then _peer=$_pub2 _end=$(host 2 "$_col") _other=2; else _peer=$_pub1 _end=$(host 1 "$_col") _other=1; fi
		# The kernel's WireGuard, or wireguard-go where the kernel has
		# none; the results say which.
		on "$i" "{ ip link add armada-bench type wireguard 2>/dev/null ||
				{ wireguard-go armada-bench >/dev/null 2>&1 && echo userspace > /run/armada/bench/kind; }; } &&
			wg set armada-bench listen-port $BENCH_WG_PORT private-key /run/armada/bench/wg.key \
				peer $_peer endpoint $_end:$BENCH_WG_PORT allowed-ips $BENCH_WG_NET.$_other/32 persistent-keepalive 25 &&
			ip addr add $BENCH_WG_NET.$i/24 dev armada-bench &&
			ip link set armada-bench mtu $_mtu up"
		if on "$i" 'systemctl is-active -q firewalld'; then
			on "$i" "firewall-cmd -q --add-port=$BENCH_WG_PORT/udp && firewall-cmd -q --zone=trusted --add-interface=armada-bench"
		fi
	done
	tunnel_ok() { on 1 "ping -c 1 -W 2 $BENCH_WG_NET.2"; }
	wait_for 30 "tunnel up over the $BENCH_WG_UNDERLAY addresses (MTU $_mtu)" tunnel_ok
	LABEL="wireguard ($BENCH_WG_UNDERLAY"
	for i in 1 2; do
		if on "$i" 'test -f /run/armada/bench/kind'; then
			LABEL="$LABEL, userspace on $(host "$i" 1)"
		fi
	done
	LABEL="$LABEL)"
}

# doctor N IP runs armada doctor on machine N for the private IP the mode
# uses (the tunnel's in the wireguard mode).
doctor() {
	if ! on "$1" "armada doctor --private-ip $2" >"$WORK/doctor" 2>&1 || grep -q FAIL "$WORK/doctor"; then
		cat "$WORK/doctor" >&2
		fail "armada doctor on $(host "$1" 1)"
	fi
}

cluster_up() {
	doctor 1 "$IP_A"
	doctor 2 "$IP_B"
	ok "armada doctor passes on $A and $B"
	on 1 "umask 077; echo 'ARMADA_SERVER_FLAGS=\"--tls=false\"' > /etc/armada/server.env"
	on 1 "systemctl enable --now -q armada-runtime && armada init --node-name $A --private-ip $IP_A >/dev/null &&
		systemctl enable --now -q armada-server"
	wait_for 120 "control plane answers" nodes_one
	cli token create >"$WORK/token"
	_tok=$(sed -n 's/^Token (shown once): //p' "$WORK/token")
	_cmd=$(sed -n 's/^  \(armada .*join .*\)$/\1/p' "$WORK/token")
	rm -f "$WORK/token"
	if [ -z "$_tok" ] || [ -z "$_cmd" ]; then fail "armada token create printed no token"; fi
	printf '%s\n' "$_tok" | on 2 'umask 077; cat > /run/armada/bench.token'
	_tok=
	on 2 "systemctl enable --now -q armada-runtime && $_cmd --node-name $B --private-ip $IP_B --token-file /run/armada/bench.token >/dev/null;
		rc=\$?; rm -f /run/armada/bench.token; [ \$rc -eq 0 ] && systemctl enable --now -q armada-agent"
	wait_for 180 "$A and $B ready" nodes_ready
	cli node label "$A" bench=a >/dev/null
	cli node label "$B" bench=b >/dev/null
}
nodes_one() { status | jq -e '[.nodes[] | select(.state == "ready")] | length == 1'; }

# Apps. Every image is multi-architecture; iperf3 and busybox's httpd come
# from Alpine packages when the container starts.
iperf_apps() {
	deploy <<EOF
name: ipsrv
image: alpine:3.20
command: ["sh", "-c", "apk add -q --no-cache iperf3 && exec iperf3 -s -p 5201"]
ingress:
  type: internal
  port: 5201
placement:
  require:
    bench: b
EOF
	deploy <<EOF
name: ipcli
image: alpine:3.20
command: ["sh", "-c", "apk add -q --no-cache iperf3 && exec sleep 86400"]
placement:
  require:
    bench: a
EOF
	deploy <<EOF
name: sink
image: alpine:3.20
command: ["sh", "-c", "apk add -q --no-cache busybox-extras && mkdir -p /www/cgi-bin && echo '#!/bin/sh' > /www/cgi-bin/up && echo 'cat > /dev/null; echo Content-Type: text/plain; echo; echo ok' >> /www/cgi-bin/up && chmod 755 /www/cgi-bin/up && exec httpd -f -p 8080 -h /www"]
ingress:
  type: internal
  port: 8080
placement:
  require:
    bench: b
EOF
}

# bench_app PLACEMENT deploys the HTTP app for a placement: remote (B
# only), local (A only), local-first (one on each), or round-robin (one on
# each, served by weight from one pool as before local-first routing).
bench_app() {
	case $1 in
	remote) _scale="scale:
  min: 1
placement:
  require:
    bench: b" ;;
	local) _scale="scale:
  min: 1
placement:
  require:
    bench: a" ;;
	local-first) _scale="scale:
  min: 2
placement:
  spreadBy: bench" ;;
	round-robin) _scale="scale:
  min: 2
placement:
  spreadBy: bench
revisions:
  mode: multiple
  traffic:
    - revision: latest
      weight: 100" ;;
	esac
	deploy <<EOF
name: web
image: nginx:1.27-alpine
command: ["sh", "-c", "echo 'worker_processes auto; pid /tmp/nginx.pid; events { worker_connections 4096; } http { access_log off; server { listen 8080; location / { return 200 ok; } } }' > /tmp/nginx.conf && exec nginx -c /tmp/nginx.conf -g 'daemon off;'"]
ingress:
  type: internal
  port: 8080
$_scale
EOF
}

iperf() { # iperf STREAMS [-R]: Gbit/s received
	on 1 "armada exec ipcli -- iperf3 -c $IP_B -p $IPERF_PORT -t $BENCH_IPERF_SECONDS -P $1 ${2:-} -J" >"$WORK/iperf.json"
	cp "$WORK/iperf.json" "$BENCH_OUT/$MODE-iperf-$1${2:-}.json"
	IPERF=$(jq -r '.end.sum_received.bits_per_second / 1e9 * 100 | round / 100' "$WORK/iperf.json")
}
iperf_ready() { on 1 "armada exec ipcli -- iperf3 -c $IP_B -p $IPERF_PORT -t 1" ; }

hey() { # hey CONCURRENCY NAME
	on 1 "armada-bench-hey -z ${BENCH_DURATION}s -c $1 -host web.internal http://$BENCH_BRIDGE_GW/" >"$BENCH_OUT/$MODE-$2-c$1.txt"
	_f=$BENCH_OUT/$MODE-$2-c$1.txt
	HEY_RPS=$(awk '/Requests\/sec:/ { printf "%.0f", $2 }' "$_f")
	HEY_P50=$(awk '/ 50%+ in / { printf "%.1f", $3 * 1000 }' "$_f")
	HEY_P99=$(awk '/ 99%+ in / { printf "%.1f", $3 * 1000 }' "$_f")
	_total=$(awk '/Status code distribution:/ { s = 1; next } s && /\[/ { n += $2 } END { print n + 0 }' "$_f")
	_good=$(awk '/\[200\]/ { print $2 }' "$_f")
	HEY_BAD=$((_total - ${_good:-0}))
	[ "$_total" -gt 0 ] || fail "hey sent no requests (see $_f)"
}
web_ok() { on 1 "curl -fsS -m 5 -H 'Host: web.internal' http://$BENCH_BRIDGE_GW/"; }
sink_ok() { on 1 "curl -fsS -m 5 -X POST --data x -H 'Host: sink.internal' http://$BENCH_BRIDGE_GW/cgi-bin/up"; }

# The upload is a file, so it has a length (the sink cannot read chunked
# bodies); a transfer that stalls until the timeout points at the MTU.
upload_file() { on 1 "dd if=/dev/zero of=/var/tmp/armada-bench.upload bs=1M count=$BENCH_UPLOAD_MB 2>/dev/null"; }
upload() {
	on 1 "curl -sS -o /dev/null -m 900 -X POST -H 'Content-Type: application/octet-stream' -H 'Host: sink.internal' \\
		-T /var/tmp/armada-bench.upload -w '%{http_code} %{time_total} %{speed_upload}' http://$BENCH_BRIDGE_GW/cgi-bin/up" >"$WORK/upload" 2>&1 || true
	UPLOAD=$(awk '$1 == 200 { printf "%.0f MB/s, %.1f s", $3 / 1e6, $2; next } { printf "failed: %s", $0 }' "$WORK/upload")
}

printf '# Armada network benchmark\n\n' >"$RESULTS"
printf -- '- A: %s (%s), B: %s (%s)\n- %s, HTTP runs of %ss, concurrency 1 and %s, upload of %s MB\n\n' \
	"$A" "$(on 1 'uname -m')" "$B" "$(on 2 'uname -m')" "$(date -u '+%Y-%m-%d %H:%M UTC')" "$BENCH_DURATION" "$BENCH_CONCURRENCY" "$BENCH_UPLOAD_MB" >>"$RESULTS"
printf '| Mode | Test | Result | CPU A | CPU B |\n| --- | --- | --- | --- | --- |\n' >>"$RESULTS"

for MODE in $BENCH_MODES; do
	log "mode $MODE"
	if [ "$MODE" = plain ]; then
		IP_A=$(host 1 3) IP_B=$(host 2 3) LABEL=plain
	else
		tunnel_up
		IP_A=$BENCH_WG_NET.1 IP_B=$BENCH_WG_NET.2
	fi
	cluster_up

	iperf_apps
	wait_for 180 "iperf3 server on $B, client on $A" placed ipsrv "$B"
	wait_for 120 "iperf3 client on $A" placed ipcli "$A"
	IPERF_PORT=$(address ipsrv)
	IPERF_PORT=${IPERF_PORT##*:}
	wait_for 120 "iperf3 reaches $B" iperf_ready
	# A path MTU below the container bridge's is the usual reason bulk
	# transfers between nodes stall.
	for i in 1 2; do
		if [ "$i" = 1 ]; then _to=$IP_B; else _to=$IP_A; fi
		_mtu=$(on "$i" "dev=\$(ip -o route get $_to | sed -n 's/.* dev \\([^ ]*\\).*/\\1/p'); cat /sys/class/net/\$dev/mtu /sys/class/net/armada0/mtu 2>/dev/null | tr '\\n' ' '")
		printf -- '- %s, %s: MTU %s towards the other node, %s on the container bridge\n' "$LABEL" "$(host "$i" 1)" \
			"${_mtu%% *}" "$(echo "$_mtu" | awk '{ print $2 }')" | tee -a "$BENCH_OUT/mtu.md"
	done
	for s in 1 4; do
		measure "iperf $s" iperf "$s"
		row "iperf3 A→B, $s stream(s)" "$IPERF Gbit/s"
		measure "iperf $s reverse" iperf "$s" -R
		row "iperf3 B→A, $s stream(s)" "$IPERF Gbit/s"
	done

	log "$MODE: upload through HAProxy"
	wait_for 180 "upload sink on $B" placed sink "$B"
	wait_for 60 "sink.internal answers" sink_ok
	upload_file
	measure upload upload
	on 1 'rm -f /var/tmp/armada-bench.upload'
	row "upload ${BENCH_UPLOAD_MB} MB A→B via HAProxy" "$UPLOAD"

	log "$MODE: HTTP through HAProxy (hey)"
	for p in remote local local-first round-robin; do
		bench_app "$p"
		case $p in
		remote) _nodes=$B ;;
		local) _nodes=$A ;;
		*) _nodes="$A $B" ;;
		esac
		wait_for 240 "web: $p" placed web "$_nodes"
		wait_for 60 "web.internal answers" web_ok
		sleep 5 # every server through its health checks
		for c in 1 "$BENCH_CONCURRENCY"; do
			measure "$p c$c" hey "$c" "$p"
			_res="p50 ${HEY_P50} ms, p99 ${HEY_P99} ms, ${HEY_RPS} req/s"
			[ "$HEY_BAD" -eq 0 ] || _res="$_res, $HEY_BAD not 200"
			row "HTTP $p, c=$c" "$_res"
		done
	done

	log "$MODE: done; removing the cluster"
	wipe 1
	wipe 2
done
MODE=

if [ -f "$BENCH_OUT/mtu.md" ]; then
	printf '\n' >>"$RESULTS"
	cat "$BENCH_OUT/mtu.md" >>"$RESULTS"
fi
log "results ($RESULTS)"
cat "$RESULTS"
