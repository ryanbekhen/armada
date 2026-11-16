#!/bin/bash
# Prototype check (ADR 0046): copy the binary to the node, then run this as root.
# Runs on a lab node as root: armada-shim supervising 3 copies of a running
# hello container, next to containerd's shim for comparison.
set -euo pipefail
BIN=/var/lib/armada/runtime/current/bin
SOCK=/run/armada-proto.sock
STATE=/run/armada-proto
W=/root/proto
req() { python3 - "$@" <<'EOF'
import socket, sys
s = socket.socket(socket.AF_UNIX); s.connect("/run/armada-proto.sock")
s.sendall((" ".join(sys.argv[1:]) + "\n").encode()); print(s.makefile().readline().strip())
EOF
}
mem() { awk '/^Pss:/{p=$2} /^Pss_Anon:/{a=$2} END{printf "pss=%dkB anon=%dkB", p, a}' /proc/"$1"/smaps_rollup; }

src=$(dirname "$(find /run/armada/containerd -path '*task/armada/*hello-r*/config.json' | head -1)")
echo "source bundle: $src"
rm -rf "$W"; mkdir -p "$W"
for i in 1 2 3; do
	b=$W/b$i; mkdir -p "$b/rootfs" "$W/logs$i"
	cp -a "$src/rootfs/." "$b/rootfs/"
	python3 - "$src/config.json" "$b/config.json" "$i" <<'EOF'
import json, sys
c = json.load(open(sys.argv[1]))
c["root"] = {"path": "rootfs", "readonly": False}
c["linux"]["namespaces"] = [n for n in c["linux"]["namespaces"] if n["type"] != "network"] + [{"type": "network"}]
c["linux"]["cgroupsPath"] = "/armada-proto/c" + sys.argv[3]
c.pop("hooks", None); c.pop("annotations", None)
c["process"]["terminal"] = False
json.dump(c, open(sys.argv[2], "w"))
EOF
done

cp "${SHIM_BIN:-/root/armada-shim}" /usr/local/bin/armada-shim
setsid /usr/local/bin/armada-shim serve $SOCK $STATE $BIN/runc $BIN/armada-log </dev/null >/root/shim.out 2>&1 &
sleep 0.5
SHIM=$(pgrep -x armada-shim)
for i in 1 2 3; do
	echo "create c$i: $(req create c$i $W/b$i $W/logs$i)"
	echo "start c$i: $(req start c$i)"
done
sleep 2
echo "list: $(req list)"
echo "log c1: $(head -c 300 $W/logs1/c1.log 2>/dev/null || ls -la $W/logs1)"
echo
echo "== memory"
echo "armada-shim (3 containers): $(mem "$SHIM")"
for p in $(pgrep -f containerd-shim-runc-v2); do
	echo "containerd shim pid $p ($(pgrep -P "$p" | wc -l) children): $(mem "$p")"
done
echo "containerd: $(mem $(pgrep -x containerd))"
for p in $(pgrep -P "$SHIM" -x armada-log); do echo "armada-log $p: $(mem "$p")"; done
echo
echo "== stop and exit codes"
echo "kill c2 TERM: $(req kill c2 15)"; sleep 1
echo "state c2: $(req state c2)"
P3=$(req state c3 | awk '{print $3}')
kill -9 "$P3"; sleep 1
echo "state c3 after SIGKILL from outside: $(req state c3)"
echo "state c1: $(req state c1)"
echo "unknown: $(req state nope)"
echo "bad id: $(req create ../x /a /b)"
for i in 1 2 3; do echo "delete c$i: $(req delete c$i)"; done
echo "list: $(req list)"
echo "runc list: $($BIN/runc --root $STATE/runc list -q | wc -l) containers left"
echo "armada-log left: $(pgrep -P "$SHIM" -x armada-log | wc -l)"
# shellcheck disable=SC2009 # the state of the shim's children, not a process search
echo "zombies under shim: $(ps -o stat= --ppid "$SHIM" | grep -c Z || true)"
echo "shim stderr: $(cat /root/shim.out)"
kill "$SHIM"
