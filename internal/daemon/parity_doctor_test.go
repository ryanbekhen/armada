package daemon

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// doctor's cases in the daemon parity harness (ADR 0055, pull request
// 18b). Both sides read the case's own machine: the host files under
// dir/host (ARMADA_DAEMON_TEST_HOST_ROOT, Go's hostRoot), needrestart's
// directory, the runtime pack this armadad carries
// (ARMADA_DAEMON_TEST_PACK_ID), being root, and the version, with
// timedatectl and ufw stand-ins first in PATH. What needs root, the
// kernel, or a running runtime (the runtime ready, whose code runs
// containers, the bridge, a node on containerd) is the root lab's, and
// the Rust side's unit tests'.

// doctorGo gives Go's doctor the case's machine, as the hooks give the
// Rust one; the returned function puts the package's back.
func doctorGo(dir string) func() {
	oldRoot, oldHook := hostRoot, doctorHook
	root := filepath.Join(dir, "host")
	hostRoot = root
	doctorHook = func(env *doctorEnv) {
		if v := os.Getenv("ARMADA_DAEMON_TEST_EUID"); v != "" {
			env.euid, _ = strconv.Atoi(v)
		}
		nr := os.Getenv("ARMADA_DAEMON_TEST_NEEDRESTART_DIR")
		env.needrestart = func() (bool, bool) { return needrestartState(nr) }
		pack, installed := os.Getenv("ARMADA_DAEMON_TEST_PACK_ID"), env.runtimePack
		env.runtimePack = func() (string, string) {
			i, _ := installed()
			return i, pack
		}
		if v := os.Getenv("ARMADA_DAEMON_TEST_VERSION"); v != "" {
			env.version = v
		}
		env.nfs = func() bool { return nfsSupportedIn(root) }
	}
	return func() { hostRoot, doctorHook = oldRoot, oldHook }
}

// nfsSupportedIn is agent.NFSSupported with the host files under root.
func nfsSupportedIn(root string) bool {
	if b, err := os.ReadFile(filepath.Join(root, "proc/filesystems")); err == nil && strings.Contains(string(b), "\tnfs4\n") {
		return true
	}
	rel, err := os.ReadFile(filepath.Join(root, "proc/sys/kernel/osrelease"))
	if err != nil {
		return false
	}
	b, err := os.ReadFile(filepath.Join(root, "lib/modules", filepath.Base(strings.TrimSpace(string(rel))), "modules.dep"))
	return err == nil && strings.Contains(string(b), "/nfsv4.ko")
}

// A machine's files, written under dir/host.
type doctorHost map[string]string

const (
	healthyCgroups = "cpuset cpu io memory hugetlb pids rdma misc\n"
	healthyFS      = "nodev\tsysfs\nnodev\ttmpfs\n\text4\nnodev\toverlay\nnodev\tnfs4\n"
	routeHeader    = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
	tcpHeader      = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
)

// tcpLine is a listening socket's line of /proc/net/tcp{,6}.
func tcpLine(addr string) string {
	return "   0: " + addr + " 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0000000000000000 100 0 0 10 0\n"
}

func healthyHost() doctorHost {
	return doctorHost{
		"sys/fs/cgroup/cgroup.controllers":          healthyCgroups,
		"proc/filesystems":                          healthyFS,
		"proc/sys/net/netfilter/nf_conntrack_count": "12\n",
		"proc/sys/net/netfilter/nf_conntrack_max":   "262144\n",
		"proc/net/route": routeHeader +
			"eth0\t00000000\t0100000A\t0003\t0\t0\t0\t00000000\t0\t0\t0\n" +
			"eth0\t0000000A\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n",
		// 10.0.0.5:7443 and 127.0.0.1:8404.
		"proc/net/tcp":  tcpHeader + tcpLine("0500000A:1D13") + tcpLine("0100007F:20D4"),
		"proc/net/tcp6": tcpHeader,
	}
}

func (m doctorHost) with(more doctorHost) doctorHost {
	out := doctorHost{}
	for k, v := range m {
		out[k] = v
	}
	for k, v := range more {
		if v == "" {
			delete(out, k)
		} else {
			out[k] = v
		}
	}
	return out
}

func (m doctorHost) write(t *testing.T, dir string) {
	t.Helper()
	for name, body := range m {
		fxWrite(t, filepath.Join(dir, "host", name), []byte(body), 0o644)
	}
}

// fxCertPEM is a self-signed certificate named cn, valid between nb and
// na: doctor reads only names and times.
func fxCertPEM(t *testing.T, cn string, nb, na time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}, NotBefore: nb, NotAfter: na}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// fxClientConfig is a client config holding cert.
func fxClientConfig(cert []byte) []byte {
	b, _ := json.Marshal(map[string]any{"servers": []string{"10.0.0.5:7443"}, "ca": "ca", "cert": string(cert), "key": "key"})
	return b
}

func (h *daemonHarness) doctorCases(t *testing.T) []daemonCase {
	t.Helper()
	now := time.Now()
	day := 24 * time.Hour
	good := func(cn string) []byte { return fxCertPEM(t, cn, now.Add(-day), now.Add(29*day)) }
	expired := fxCertPEM(t, "node:n1", now.Add(-40*day), now.Add(-10*day))
	expiring := fxCertPEM(t, "server:s1", now.Add(-25*day), now.Add(2*day))
	userSoon := fxCertPEM(t, "user:alice", now.Add(-350*day), now.Add(10*day))
	userGone := fxCertPEM(t, "admin:root", now.Add(-400*day), now.Add(-day))
	userGood := fxCertPEM(t, "user:alice", now.Add(-day), now.Add(300*day))

	base := []string{"doctor", "--data-dir", "data", "--secrets-dir", "run/secrets"}
	args := func(more ...string) []string { return append(append([]string{}, base...), more...) }
	machine := func(host doctorHost, more ...func(*testing.T, string)) func(*testing.T, string) {
		return func(t *testing.T, dir string) {
			host.write(t, dir)
			for _, f := range more {
				f(t, dir)
			}
		}
	}
	dataDir := func(mode os.FileMode) func(*testing.T, string) {
		return func(t *testing.T, dir string) {
			if err := os.MkdirAll(filepath.Join(dir, "data"), mode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(filepath.Join(dir, "data"), mode); err != nil {
				t.Fatal(err)
			}
		}
	}
	file := func(name string, b []byte, mode os.FileMode) func(*testing.T, string) {
		return func(t *testing.T, dir string) { fxWrite(t, filepath.Join(dir, name), b, mode) }
	}
	agent := func(body string) func(*testing.T, string) {
		return fxAll(dataDir(0o700), file("data/agent.json", []byte(body), 0o600))
	}
	// The runtime pack's programs in pack p1, so the supervisor runtime
	// opens on both sides alike (armada-node's image store already there).
	pack := func(t *testing.T, dir string) {
		for _, p := range []string{"armada-shim", "armada-node"} {
			fxWrite(t, filepath.Join(dir, "data/runtime/p1/bin", p), []byte("#!/bin/sh\nexit 1\n"), 0o755)
		}
		if err := os.Symlink("p1", filepath.Join(dir, "data/runtime/current")); err != nil {
			t.Fatal(err)
		}
		for _, d := range []string{"data/node/images/content/ingest", "data/logs", "data/containers", "run/cni"} {
			if err := os.MkdirAll(filepath.Join(dir, d), 0o700); err != nil {
				t.Fatal(err)
			}
		}
	}
	link := func(name, target string) func(*testing.T, string) {
		return func(t *testing.T, dir string) {
			p := filepath.Join(dir, name)
			if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, p); err != nil {
				t.Fatal(err)
			}
		}
	}
	releaseCache := func(tag string) func(*testing.T, string) {
		return file("cache/armada/latest.json", fmt.Appendf(nil, `{"tag":%q,"checked":%d}`, tag, now.Unix()), 0o600)
	}
	needrestart := func(body string) func(*testing.T, string) {
		return func(t *testing.T, dir string) {
			if err := os.MkdirAll(filepath.Join(dir, "needrestart"), 0o755); err != nil {
				t.Fatal(err)
			}
			if body != "" {
				fxWrite(t, filepath.Join(dir, "needrestart", needrestartFile), []byte(body), 0o644)
			}
		}
	}
	healthy := healthyHost()
	broken := healthy.with(doctorHost{
		"sys/fs/cgroup/cgroup.controllers":          "cpuset cpu io\n",
		"proc/filesystems":                          "nodev\tsysfs\n\text4\n",
		"proc/sys/net/netfilter/nf_conntrack_count": "230000\n",
		"proc/net/route": routeHeader +
			"eth1\t0000790A\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n",
		// 0.0.0.0:7443 and [::]:8404.
		"proc/net/tcp":  tcpHeader + tcpLine("00000000:1D13"),
		"proc/net/tcp6": tcpHeader + tcpLine("00000000000000000000000000000000:20D4"),
	})
	key := func(n byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{n}, 32)) }
	meshJSON, _ := json.Marshal(map[string]any{"mode": "plain", "clusterCidr": "10.120.0.0/16", "peers": []map[string]any{
		{"node": "n1", "privateIp": "10.0.0.5", "subnet": "10.120.0.0/24", "publicKey": key(1), "behindNat": true},
		{"node": "n2", "privateIp": "10.0.0.6", "subnet": "10.120.1.0/24", "publicKey": key(2), "site": "b", "behindNat": true},
		{"node": "n3", "privateIp": "10.0.0.7", "subnet": "10.120.2.0/24", "publicKey": key(3), "site": "b", "endpoint": "203.0.113.9"},
	}})
	sitesNode := `{"nodeId":"n1","privateIp":"10.0.0.5","servers":["10.0.0.5:7443"],"network":"plain","behindNat":true,"runtime":"embedded"}`
	ufwOpen := "Status: active\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW IN    Anywhere\n"
	ufwBridge := "Status: active\n\nTo                         Action      From\n--                         ------      ----\n53 on armada0              ALLOW IN    Anywhere\n80/tcp on armada0          ALLOW IN    Anywhere\n"
	return []daemonCase{
		{name: "doctor a fresh machine", args: args("--private-ip", "10.0.0.5"), setup: machine(healthy)},
		{name: "doctor a fresh machine as root", args: args("--private-ip", "10.0.0.5"), setup: machine(healthy), env: map[string]string{"ARMADA_DAEMON_TEST_EUID": "0"}},
		{name: "doctor a machine with no host files", args: args("--private-ip", "203.0.113.5")},
		{name: "doctor a broken host", args: args("--private-ip", "10.0.0.5"), setup: machine(broken),
			env: map[string]string{"STANDIN_NTP": "no", "STANDIN_UFW": ufwOpen}},
		{name: "doctor ufw allows the bridge, no timedatectl answer", args: args("--private-ip", "10.0.0.5"), setup: machine(healthy),
			env: map[string]string{"STANDIN_NTP": "fail", "STANDIN_UFW": ufwBridge}},
		{name: "doctor ufw inactive, the kernel's NFS module", args: args("--private-ip", "10.0.0.5"),
			setup: machine(healthy.with(doctorHost{"proc/filesystems": "nodev\toverlay\n", "proc/sys/kernel/osrelease": "7.0.0-31-generic\n",
				"lib/modules/7.0.0-31-generic/modules.dep": "kernel/fs/nfs/nfsv4.ko: kernel/fs/nfs/nfs.ko\n"})),
			env: map[string]string{"STANDIN_UFW": "Status: inactive"}},
		{name: "doctor a bad listening socket line", args: args("--private-ip", "10.0.0.5"),
			setup: machine(healthy.with(doctorHost{"proc/net/tcp": tcpHeader + tcpLine("0500000A:XYZ")}))},
		{name: "doctor no IPv4 listeners", args: args("--private-ip", "10.0.0.5"), setup: machine(healthy.with(doctorHost{"proc/net/tcp": ""}))},
		{name: "doctor a public private IP", args: args("--private-ip", "8.8.8.8"), setup: machine(healthy)},
		{name: "doctor a data directory open to others", args: args("--private-ip", "10.0.0.5"), setup: machine(healthy, dataDir(0o755))},
		{name: "doctor key files open to others", args: args("--private-ip", "10.0.0.5"),
			setup: machine(healthy, dataDir(0o700), file("data/ca.key", []byte("k"), 0o644), file("data/etcd/member.key", []byte("k"), 0o640),
				file("data/master.key", []byte("k"), 0o600), file("data/agent.json", []byte("{}"), 0o604))},
		{name: "doctor certificates that are fine", args: args("--config", "admin.config"),
			setup: machine(healthy, agent(`{"nodeId":"n1","privateIp":"10.0.0.5","servers":["10.0.0.5:7443"]}`),
				file("data/server.crt", good("server:s1"), 0o600), file("data/etcd/member.crt", good("etcd:member"), 0o600),
				file("data/node.crt", good("node:n1"), 0o600), file("admin.config", fxClientConfig(userGood), 0o600))},
		{name: "doctor certificates expired, expiring, and broken", args: args("--config", "admin.config", "--private-ip", "10.0.0.5"),
			setup: machine(healthy, dataDir(0o700), file("data/server.crt", expiring, 0o600), file("data/etcd/member.crt", []byte("not a certificate"), 0o600),
				file("data/node.crt", expired, 0o600), file("admin.config", fxClientConfig(userSoon), 0o600))},
		{name: "doctor a node certificate expired on a node", args: args("--config", "admin.config", "--private-ip", "10.0.0.5"),
			setup: machine(healthy, dataDir(0o700), file("data/node.crt", expired, 0o600), file("data/server.crt", good("server:s1"), 0o644),
				file("admin.config", fxClientConfig(userGone), 0o600))},
		{name: "doctor server.env with cluster settings", args: args("--private-ip", "10.0.0.5"),
			setup: machine(healthy.with(doctorHost{"etc/armada/server.env": "ARMADA_SERVER_FLAGS=\"--port 7443 --tls=false --acme-email a@example.com --node-lost-timeout\"\n"}))},
		{name: "doctor server.env without cluster settings", args: args("--private-ip", "10.0.0.5"),
			setup: machine(healthy.with(doctorHost{"etc/armada/server.env": "ARMADA_SERVER_FLAGS=\"--port 7443\"\n"}))},
		{name: "doctor needrestart with Armada's setting", args: args("--private-ip", "10.0.0.5"), setup: machine(healthy, needrestart(needrestartConf))},
		{name: "doctor needrestart without it", args: args("--private-ip", "10.0.0.5"), setup: machine(healthy, needrestart(""))},
		{name: "doctor the pack armada-runtime runs", args: args("--private-ip", "10.0.0.5"), setup: machine(healthy, link("data/runtime/current", "p1")),
			env: map[string]string{"ARMADA_DAEMON_TEST_PACK_ID": "p1"}},
		{name: "doctor another pack than this armadad's", args: args("--private-ip", "10.0.0.5"), setup: machine(healthy, link("data/runtime/current", "p1")),
			env: map[string]string{"ARMADA_DAEMON_TEST_PACK_ID": "p2"}},
		{name: "doctor a development pack", args: args("--private-ip", "10.0.0.5"), setup: machine(healthy, link("data/runtime/current", "dev")),
			env: map[string]string{"ARMADA_DAEMON_TEST_PACK_ID": "p2"}},
		{name: "doctor a supervisor node without root", args: args(),
			setup: machine(healthy, agent(`{"nodeId":"n1","privateIp":"10.0.0.5","servers":["10.0.0.5:7443"],"runtime":"supervisor"}`), pack)},
		{name: "doctor another pack on a supervisor node", args: args(),
			setup: machine(healthy, agent(`{"nodeId":"n1","privateIp":"10.0.0.5","servers":["10.0.0.5:7443"],"runtime":"supervisor"}`), pack),
			env:   map[string]string{"ARMADA_DAEMON_TEST_PACK_ID": "p2"}},
		{name: "doctor a containerd node without root", args: args(),
			setup: machine(healthy, agent(`{"nodeId":"n1","privateIp":"10.0.0.5","servers":["10.0.0.5:7443"],"runtime":"embedded"}`))},
		{name: "doctor an unknown runtime", args: args(),
			setup: machine(healthy, agent(`{"nodeId":"n1","privateIp":"10.0.0.5","servers":["10.0.0.5:7443"],"runtime":"podman"}`))},
		{name: "doctor a container subnet too small", args: args(),
			setup: machine(healthy, agent(`{"nodeId":"n1","privateIp":"10.0.0.5","servers":["10.0.0.5:7443"],"containerSubnet":"10.121.0.0/30"}`))},
		{name: "doctor a container subnet that does not parse", args: args(),
			setup: machine(healthy, agent(`{"nodeId":"n1","privateIp":"10.0.0.5","servers":["10.0.0.5:7443"],"containerSubnet":"10.121.0.0"}`))},
		{name: "doctor a node of a plain cluster network", args: args(),
			setup: machine(healthy, agent(`{"nodeId":"n1","privateIp":"10.0.0.5","servers":["10.0.0.5:7443"],"network":"plain","runtime":"embedded"}`))},
		{name: "doctor a node of a wireguard cluster network", args: args(),
			setup: machine(healthy, agent(`{"nodeId":"n1","privateIp":"10.0.0.5","servers":["10.0.0.5:7443"],"network":"wireguard","runtime":"embedded"}`))},
		{name: "doctor a plain network node on loopback", args: args(),
			setup: machine(healthy, agent(`{"nodeId":"n1","privateIp":"127.0.0.1","servers":["10.0.0.5:7443"],"network":"plain","runtime":"embedded"}`))},
		{name: "doctor a wireguard network node on loopback", args: args(),
			setup: machine(healthy, agent(`{"nodeId":"n1","privateIp":"127.0.0.1","servers":["10.0.0.5:7443"],"network":"wireguard","runtime":"embedded"}`))},
		{name: "doctor a node behind NAT with peers of another site", args: args(),
			setup: machine(healthy, agent(sitesNode), file("data/mesh.json", meshJSON, 0o600))},
		{name: "doctor a peer list open to others", args: args(),
			setup: machine(healthy, agent(sitesNode), file("data/mesh.json", meshJSON, 0o644))},
		{name: "doctor the join listener on the endpoint", args: args(),
			setup: machine(healthy.with(doctorHost{"proc/net/tcp": tcpHeader + tcpLine("077171CB:1D14") + tcpLine("077171CB:1D13")}),
				agent(`{"nodeId":"n1","privateIp":"10.0.0.5","servers":["10.0.0.5:7443"],"endpoint":"203.113.113.7","runtime":"embedded"}`))},
		{name: "doctor a newer release", args: args("--private-ip", "10.0.0.5"), setup: machine(healthy, releaseCache("v0.1.0-alpha.50")),
			env: map[string]string{"ARMADA_NO_UPDATE_CHECK": "", "ARMADA_DAEMON_TEST_VERSION": "v0.1.0-alpha.40"}},
		{name: "doctor the latest release", args: args("--private-ip", "10.0.0.5"), setup: machine(healthy, releaseCache("v0.1.0-alpha.40")),
			env: map[string]string{"ARMADA_NO_UPDATE_CHECK": "", "ARMADA_DAEMON_TEST_VERSION": "v0.1.0-alpha.40"}},
	}
}
