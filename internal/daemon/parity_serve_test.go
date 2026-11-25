package daemon

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The daemon parity harness's cases for the commands that set a machine
// up and run it (ADR 0055, pull request 18b, second part): init, join,
// server join, server, agent, runtime reset, and runtime migrate, as far
// as they run without root and without a cluster: their flags' checks,
// the refusals before anything is written, and what they leave in the
// case directory when they fail later (a join whose leader does not
// answer). A whole init writes the state through the pack's etcd in Rust
// and an embedded member in Go; it is checked by hand in the lab (see
// CLAUDE.md), with the Rust server's start against it.

// serveCases are those cases.
func (h *daemonHarness) serveCases() []daemonCase {
	dd := []string{"--data-dir", "data"}
	with := func(args ...string) []string { return append(slices.Clone(args), dd...) }
	const node = `{"nodeId": "n1", "privateIp": "10.0.0.6", "servers": ["10.0.0.5:7443"], "runtime": "supervisor", "network": "plain"}`
	token := strings.Repeat("ab", 6) + "." + strings.Repeat("cd", 32)
	hash := "sha256:" + strings.Repeat("0", 64)
	dataDir := func(t *testing.T, dir string) {
		t.Helper()
		fxWrite(t, filepath.Join(dir, "data", "keep"), nil, 0o600)
	}
	initialized := func(t *testing.T, dir string) {
		t.Helper()
		fxWrite(t, filepath.Join(dir, "data", fileCAKey), h.fx.caKey, 0o600)
	}
	config := func(t *testing.T, dir string) {
		t.Helper()
		fxWrite(t, filepath.Join(dir, "cfg", "admin.config"), []byte("{}\n"), 0o600)
	}
	emptyToken := func(t *testing.T, dir string) {
		t.Helper()
		fxWrite(t, filepath.Join(dir, "tok"), nil, 0o600)
	}
	initArgs := func(more ...string) []string {
		return with(append([]string{"init", "--private-ip", "10.0.0.5", "--node-name", "n1", "--user-name", "ops", "--config", "cfg/admin.config"}, more...)...)
	}
	return []daemonCase{
		// init: every refusal before the cluster is made.
		{name: "init mesh private ip", args: with("init", "--network", "mesh", "--private-ip", "10.0.0.5")},
		{name: "init endpoint without mesh", args: initArgs("--endpoint", "203.0.113.7")},
		{name: "init mesh cidr without mesh", args: initArgs("--mesh-cidr", "10.122.0.0/16")},
		{name: "init bad mesh cidr", args: with("init", "--network", "mesh", "--endpoint", "203.0.113.7", "--mesh-cidr", "10.122.0.0/33")},
		{name: "init mesh cidr not canonical", args: with("init", "--network", "mesh", "--endpoint", "203.0.113.7", "--mesh-cidr", "10.122.0.1/16")},
		{name: "init mesh cidr too small", args: with("init", "--network", "mesh", "--endpoint", "203.0.113.7", "--mesh-cidr", "10.122.0.0/28")},
		{name: "init public private ip", args: initArgs("--private-ip", "8.8.8.8")},
		{name: "init ipv6 private ip", args: initArgs("--private-ip", "fd00::5")},
		{name: "init bad private ip", args: initArgs("--private-ip", "10.0.0")},
		{name: "init container subnet", args: initArgs("--container-subnet", "10.50.0.0/24")},
		{name: "init container subnet holds ip", args: initArgs("--container-subnet", "10.0.0.0/24")},
		{name: "init bad container subnet", args: initArgs("--container-subnet", "10.50.0.0")},
		{name: "init bad network", args: initArgs("--network", "vxlan")},
		{name: "init bad cluster cidr", args: initArgs("--cluster-cidr", "10.120.0.0/24")},
		{name: "init cluster cidr not private", args: initArgs("--cluster-cidr", "11.0.0.0/16")},
		{name: "init cluster cidr holds ip", args: initArgs("--cluster-cidr", "10.0.0.0/16")},
		{name: "init bad runtime", args: initArgs("--runtime", "podman")},
		{name: "init bad port", args: initArgs("--port", "0")},
		{name: "init port too large", args: initArgs("--port", "70000")},
		{name: "init bad node name", args: initArgs("--node-name", "-bad")},
		{name: "init bad user name", args: initArgs("--user-name", "-")},
		{name: "init initialized", args: initArgs(), setup: initialized},
		{name: "init config exists", args: initArgs(), setup: config},

		// join and server join: before the leader is asked, and a leader
		// that does not answer.
		{name: "join bad address", args: with("join", "nope", "--ca-hash", hash)},
		{name: "join address without port", args: with("join", "10.0.0.2:0", "--ca-hash", hash)},
		{name: "join private and no private ip", args: with("join", "10.0.0.2:7444", "--ca-hash", hash, "--private-ip", "10.0.0.6", "--no-private-ip")},
		{name: "join endpoint on a private address", args: with("join", "10.0.0.2:7444", "--ca-hash", hash, "--private-ip", "10.0.0.6", "--endpoint", "203.0.113.7")},
		{name: "join no private ip on a private address", args: with("join", "10.0.0.2:7444", "--ca-hash", hash, "--no-private-ip")},
		{name: "join behind nat no private ip", args: with("join", "10.0.0.2:7444", "--ca-hash", hash, "--endpoint", "none", "--no-private-ip")},
		{name: "join bad mtu", args: with("join", "10.0.0.2:7444", "--ca-hash", hash, "--private-ip", "10.0.0.6", "--mtu", "100")},
		{name: "join empty token", args: with("join", "10.0.0.2:7444", "--ca-hash", hash, "--private-ip", "10.0.0.6")},
		{name: "join bad token", args: with("join", "10.0.0.2:7444", "--ca-hash", hash, "--private-ip", "10.0.0.6"), stdin: "nope\n"},
		{name: "join token file missing", args: with("join", "10.0.0.2:7444", "--ca-hash", hash, "--private-ip", "10.0.0.6", "--token-file", "missing")},
		{name: "join token file empty", args: with("join", "10.0.0.2:7444", "--ca-hash", hash, "--private-ip", "10.0.0.6", "--token-file", "tok"), setup: emptyToken},
		{name: "join bad ca hash", args: with("join", "10.0.0.2:7444", "--ca-hash", "sha256:3f1c", "--private-ip", "10.0.0.6"), stdin: token},
		{name: "join bad node name", args: with("join", "10.0.0.2:7444", "--ca-hash", hash, "--private-ip", "10.0.0.6", "--node-name", "-bad"), stdin: token},
		{name: "join bad runtime", args: with("join", "10.0.0.2:7444", "--ca-hash", hash, "--private-ip", "10.0.0.6", "--runtime", "podman"), stdin: token},
		{name: "join already joined", args: with("join", "10.0.0.2:7444", "--ca-hash", hash, "--private-ip", "10.0.0.6", "--node-name", "n2"), stdin: token, setup: agentJSON(node)},
		{name: "join no leader", args: with("join", "127.0.0.1:1", "--ca-hash", hash, "--private-ip", "10.0.0.6", "--node-name", "n2"), stdin: token},
		{name: "server join behind nat", args: with("server", "join", "203.0.113.2:7444", "--ca-hash", hash, "--endpoint", "none")},
		{name: "server join bad port", args: with("server", "join", "10.0.0.2:7444", "--ca-hash", hash, "--private-ip", "10.0.0.6", "--port", "65535")},
		{name: "server join bad join port", args: with("server", "join", "10.0.0.2:7444", "--ca-hash", hash, "--private-ip", "10.0.0.6", "--join-port", "70000")},
		{name: "server join bad token", args: with("server", "join", "10.0.0.2:7444", "--ca-hash", hash, "--private-ip", "10.0.0.6"), stdin: "nope"},
		{name: "server join bad name", args: with("server", "join", "10.0.0.2:7444", "--ca-hash", hash, "--private-ip", "10.0.0.6", "--name", "-bad"), stdin: token},
		{name: "server join initialized", args: with("server", "join", "10.0.0.2:7444", "--ca-hash", hash, "--private-ip", "10.0.0.6", "--name", "s2"), stdin: token, setup: initialized},
		{name: "server join no leader", args: with("server", "join", "127.0.0.1:1", "--ca-hash", hash, "--private-ip", "10.0.0.6", "--name", "s2"), stdin: token, setup: dataDir},

		// server: its flags' checks and an uninitialized machine.
		{name: "server bad log format", args: with("server", "--log-format", "xml")},
		{name: "server bad etcd member", args: with("server", "--etcd-member", "remote")},
		{name: "server short lost timeout", args: with("server", "--node-lost-timeout", "1s")},
		{name: "server bad acme ca", args: with("server", "--acme-ca", "http://acme.example")},
		{name: "server acme ca without tls", args: with("server", "--acme-ca", "http://acme.example", "--tls=false", "--etcd-member", "unit")},
		{name: "server bad dns provider", args: with("server", "--dns-provider", "route53")},
		{name: "server dns provider without tls", args: with("server", "--dns-provider", "cloudflare", "--tls=false", "--dns-token-file", "tok")},
		{name: "server dns token alone", args: with("server", "--dns-token-file", "tok")},
		{name: "server dns token empty", args: with("server", "--dns-provider", "cloudflare", "--dns-token-file", "tok"), setup: emptyToken},
		{name: "server dns token missing", args: with("server", "--dns-provider", "cloudflare", "--dns-token-file", "missing")},
		{name: "server not initialized", args: with("server", "--etcd-member", "unit", "--tls=false")},
		{name: "server not initialized embedded", args: with("server")},

		// agent: before the runtime starts.
		{name: "agent bad log format", args: with("agent", "--log-format", "xml")},
		{name: "agent no data dir", args: with("agent")},
		{name: "agent no agent.json", args: with("agent"), setup: dataDir},
		{name: "agent bad server flag", args: with("agent", "--server", "8.8.8.8:7443"), setup: agentJSON(node)},
		{name: "agent bad private ip", args: with("agent"), setup: agentJSON(`{"nodeId": "n1", "privateIp": "8.8.8.8", "servers": ["10.0.0.5:7443"]}`)},
		{name: "agent no credentials", args: with("agent"), setup: agentJSON(node)},

		// runtime reset and migrate.
		{name: "runtime migrate bad to", args: with("runtime", "migrate", "--to", "podman")},
		{name: "runtime migrate no agent.json", args: with("runtime", "migrate", "--to", "supervisor")},
		{name: "runtime migrate already", args: with("runtime", "migrate", "--to", "supervisor"), setup: agentJSON(node)},
		{name: "runtime migrate already embedded", args: with("runtime", "migrate", "--to", "embedded"), setup: agentJSON(`{"nodeId": "n1", "privateIp": "10.0.0.6", "servers": ["10.0.0.5:7443"]}`)},
		{name: "runtime migrate unknown runtime", args: with("runtime", "migrate", "--to", "supervisor"), setup: agentJSON(`{"nodeId": "n1", "privateIp": "10.0.0.6", "servers": ["10.0.0.5:7443"], "runtime": "podman"}`)},
		{name: "runtime reset no agent.json", args: with("runtime", "reset")},
		{name: "runtime reset unknown runtime", args: with("runtime", "reset"), setup: agentJSON(`{"nodeId": "n1", "privateIp": "10.0.0.6", "servers": ["10.0.0.5:7443"], "runtime": "podman"}`)},
	}
}
