package daemon

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// Where the Rust armadad differs from Go's on purpose (ADR 0055, pull
// request 19): a server machine runs its etcd member and its agent as
// units of their own beside armada-server, so
//
//   - `armadad server` runs no agent: its help says so, and the flags Go's
//     server gave its embedded agent are hidden (still accepted);
//   - `armadad upgrade` restarts armada-etcd, armada-server, and
//     armada-agent where each runs (Go's restarted the first of the
//     server and the agent), enables armada-etcd and armada-agent on a
//     server machine where they are new, and rolls a machine back to the
//     last Go release, which Go's armadad has no path for (rustOnly);
//   - `armadad endpoint set` restarts the server and the agent of a server
//     machine.
//
// rustWants turns Go's result into the one the Rust armadad must give.

const (
	goServerShort   = "Run the control plane (and, by default, this node's agent)"
	rustServerShort = "Run the control plane"
	rustServerUnits = "On a server machine, systemd runs this server's etcd member (armada-etcd, `armadad\n" +
		"etcd`) and the node's agent (armada-agent, `armadad agent`) as units of their own;\n" +
		"starting armada-server starts both.\n"
	goUpgradeRestarts   = "armada-runtime (containers keep running), armada-etcd where it runs, and armada-server or armada-agent.\nUpgrade servers first, one at a time, then the other\nnodes (docs/operations.md#upgrades). ARMADA_DOWNLOAD_BASE points at a mirror.\n"
	rustUpgradeRestarts = "armada-runtime (containers keep running), armada-etcd, armada-server, and armada-agent,\neach where it runs. Upgrade servers first, one at a time, then the other\nnodes (docs/operations.md#upgrades). ARMADA_DOWNLOAD_BASE points at a mirror.\n\n" +
		"It refuses older releases but one: --version v0.1.0-alpha.42, the last release\n" +
		"before armadad moved to Rust, rolls this machine back to it (stops armada-server,\n" +
		"armada-agent, and armada-etcd, removes the units that release lacks, installs\n" +
		"it, and starts its service; docs/operations.md#rolling-back-to-the-last-go-release).\n"
)

// goAgentFlags are the lines of the flags Go's server gives its embedded
// agent, in the server's help.
var goAgentFlags = regexp.MustCompile(`(?m)^ +--(agent\[|internal-dns\[|proxy string |secrets-dir string ).*\n`)

func rustWants(c daemonCase, r daemonResult) daemonResult {
	r.Stdout = strings.ReplaceAll(r.Stdout, goServerShort, rustServerShort)
	if c.name == "help armadad server" || c.name == "servers alias help" {
		r.Stdout = strings.Replace(r.Stdout, "`armadad server join`.\n", "`armadad server join`.\n\n"+rustServerUnits, 1)
		r.Stdout = goAgentFlags.ReplaceAllString(r.Stdout, "")
	}
	if c.name == "help armadad upgrade" {
		r.Stdout = strings.Replace(r.Stdout, goUpgradeRestarts, rustUpgradeRestarts, 1)
	}
	if c.name == "endpoint set restarts server" {
		// The agent of a server machine is a unit of its own: restarted too.
		r.Stdout = strings.Replace(r.Stdout, "Restarted armada-server:", "Restarted armada-server and armada-agent:", 1)
		for i, f := range r.Files {
			if strings.HasPrefix(f, "standin.log ") {
				r.Files[i] = strings.Replace(f, "systemctl restart armada-server\n",
					"systemctl restart armada-server\nsystemctl is-active --quiet armada-agent\nsystemctl restart armada-agent\n", 1)
			}
		}
	}
	if c.upgrade != nil && r.Code == 0 {
		// After restarting the server, the Rust upgrade goes on to the
		// agent, a unit of its own beside it (Go's stopped at the server).
		const server = "systemctl restart armada-server\nsystemctl is-active --quiet armada-server\n"
		for i, f := range r.Files {
			if strings.HasPrefix(f, "standin.log ") {
				r.Files[i] = strings.Replace(f, server, server+"systemctl is-active --quiet armada-agent\n", 1)
			}
		}
	}
	if c.rust != nil {
		r = c.rust(r)
	}
	return r
}

// fxUnits writes units into the case's unit directory, each enabled when
// named in enabled (its link in multi-user.target.wants).
func fxUnits(units []string, enabled ...string) func(*testing.T, string) {
	return func(t *testing.T, dir string) {
		t.Helper()
		for _, u := range units {
			fxWrite(t, filepath.Join(dir, "units", u+".service"), []byte("rust "+u+"\n"), 0o644)
		}
		for _, u := range enabled {
			wants := filepath.Join(dir, "units", "multi-user.target.wants")
			if err := os.MkdirAll(wants, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(dir, "units", u+".service"), filepath.Join(wants, u+".service")); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// unitFile is the content the case left in a unit file, or "" when it
// is gone.
func unitFile(dir string, r daemonResult, name string) string {
	prefix := "units/" + name + " "
	for _, f := range r.Files {
		if strings.HasPrefix(f, prefix) {
			_, body, _ := strings.Cut(f, "\n")
			return strings.ReplaceAll(body, dir, "DIR")
		}
	}
	return ""
}

// downloadSize is a download's size and time in the steps upgrade prints.
var downloadSize = regexp.MustCompile(`\.\.\. [0-9.]+ (KiB|MiB) in ELAPSED`)

// standinLog is what the stand-ins were asked.
func standinLog(r daemonResult) string {
	for _, f := range r.Files {
		if strings.HasPrefix(f, "standin.log ") {
			_, body, _ := strings.Cut(f, "\n")
			return body
		}
	}
	return ""
}

func expectRust(t *testing.T, dir string, r daemonResult, code int, stdout, log string) {
	t.Helper()
	if r.Code != code {
		t.Errorf("exit code %d, want %d (stderr %q)", r.Code, code, r.Stderr)
	}
	got := downloadSize.ReplaceAllString(normalizeDaemon(r.Stdout), "... SIZE")
	if got = strings.ReplaceAll(got, dir, "DIR"); got != stdout {
		t.Errorf("stdout:\n%s--- want\n%s", got, stdout)
	}
	if got := standinLog(r); got != log {
		t.Errorf("systemctl was asked:\n%s--- want\n%s", got, log)
	}
}

// unitCases are the cases of the units of a server machine: the upgrades
// both armadads answer alike, and the Rust armadad's own paths.
func (h *daemonHarness) unitCases() []daemonCase {
	const last = "v0.1.0-alpha.42" // LAST_GO_RELEASE in daemon/src/commands/upgrade.rs
	const after = "v0.1.0-alpha.43"
	all := []string{"armada-agent", "armada-etcd", "armada-runtime", "armada-server"}
	// The last Go release's units: armada-agent, armada-runtime, and
	// armada-server (git show v0.1.0-alpha.42:deploy/systemd).
	release := fxRelease(last, func(f map[string]string) {
		f["deploy/systemd/armada-runtime.service"] = "[Service]\nExecStart=/usr/local/bin/armadad runtime\n"
	}, false)
	machine := fxMachine(false, false)
	downloads := func(head string) string {
		return head +
			"  download   armada_0.1.0-alpha.42_linux_" + runtime.GOARCH + ".tar.gz ... SIZE\n" +
			"  download   checksums.txt ... SIZE\n" +
			"  download   checksums.txt.sigstore.json ... SIZE\n" +
			"  signature  verified with cosign (release workflow of ryanbekhen/armada, tag " + last + ")\n" +
			"  checksum   OK (SHA-256 matches checksums.txt)\n"
	}
	rollback := downloads("Rolling this machine back from " + after + " to " + last + ", the last release before armadad moved to Rust\n")
	installs := "  install    DIR/bin/armada\n  install    DIR/bin/armadad\n" +
		"  install    systemd units armada-agent.service, armada-runtime.service, armada-server.service (daemon reloaded)\n"
	cosign := "cosign verify-blob for https://github.com/ryanbekhen/armada/.github/workflows/release.yml@refs/tags/" + last + "\n"
	return []daemonCase{
		// Older than the last Go release: refused by both, as every
		// downgrade was.
		{name: "upgrade older than the last go release", upgrade: &upgradeCase{current: after, target: "v0.1.0-alpha.41"}, setup: fxAll(fxRelease("v0.1.0-alpha.41", nil, false), machine)},

		// A server machine of this release back on the last Go release:
		// its services stop (the server first), the agent's unit is
		// disabled (Go's server runs the agent), etcd's unit goes, and the
		// server starts again on Go's armadad.
		{name: "upgrade rollback server", upgrade: &upgradeCase{current: after, target: last},
			setup:  fxAll(release, machine, fxUnits(all, "armada-server", "armada-etcd", "armada-agent")),
			active: []string{"armada-server", "armada-etcd", "armada-agent"},
			rustOnly: func(t *testing.T, dir string, r daemonResult) {
				expectRust(t, dir, r, 0, rollback+
					"  stop       armada-server (a leader hands over) ... stopped after ELAPSED\n"+
					"  stop       armada-agent (containers keep running) ... stopped after ELAPSED\n"+
					"  stop       armada-etcd ... stopped after ELAPSED\n"+
					"  disable    armada-agent ("+last+"'s armada-server runs this machine's agent)\n"+
					"  remove     DIR/units/armada-etcd.service ("+last+" has no such unit)\n"+
					installs+
					"  start      armada-server ... running after ELAPSED\n"+
					"Rolled back to "+last+" (from "+after+"); stopped armada-server, armada-agent, armada-etcd; disabled armada-agent; removed armada-etcd.service; started armada-server.\n",
					cosign+
						"systemctl is-active --quiet armada-server\nsystemctl stop armada-server\n"+
						"systemctl is-active --quiet armada-agent\nsystemctl stop armada-agent\n"+
						"systemctl is-active --quiet armada-etcd\nsystemctl stop armada-etcd\n"+
						"systemctl disable armada-agent\n"+
						"systemctl disable armada-etcd\n"+
						"systemctl daemon-reload\n"+
						"systemctl is-active --quiet armada-runtime\n"+
						"systemctl start armada-server\nsystemctl is-active --quiet armada-server\n")
				if unitFile(dir, r, "armada-etcd.service") != "" {
					t.Error("armada-etcd.service is still installed")
				}
				if got := unitFile(dir, r, "armada-server.service"); got != "[Service]\nExecStart=DIR/bin/armadad server\n" {
					t.Errorf("armada-server.service is %q, want the release's", got)
				}
				if got := unitFile(dir, r, "armada-runtime.service"); got != "[Service]\nExecStart=DIR/bin/armadad runtime\n" {
					t.Errorf("armada-runtime.service is %q, want the release's", got)
				}
			}},

		// A node: its agent stops and starts again on Go's armadad; etcd's
		// unit, which every machine of this release has, goes.
		{name: "upgrade rollback node", upgrade: &upgradeCase{current: after, target: last},
			setup:  fxAll(release, machine, fxUnits(all, "armada-agent")),
			active: []string{"armada-agent", "armada-runtime"},
			rustOnly: func(t *testing.T, dir string, r daemonResult) {
				expectRust(t, dir, r, 0, rollback+
					"  stop       armada-agent (containers keep running) ... stopped after ELAPSED\n"+
					"  remove     DIR/units/armada-etcd.service ("+last+" has no such unit)\n"+
					installs+
					"  restart    armada-runtime (containers keep running) ... running again after ELAPSED\n"+
					"  start      armada-agent ... running after ELAPSED\n"+
					"Rolled back to "+last+" (from "+after+"); stopped armada-agent; removed armada-etcd.service; restarted armada-runtime; started armada-agent.\n",
					cosign+
						"systemctl is-active --quiet armada-server\n"+
						"systemctl is-active --quiet armada-server\n"+
						"systemctl is-active --quiet armada-agent\nsystemctl stop armada-agent\n"+
						"systemctl is-active --quiet armada-etcd\n"+
						"systemctl disable armada-etcd\n"+
						"systemctl daemon-reload\n"+
						"systemctl is-active --quiet armada-runtime\nsystemctl restart armada-runtime\nsystemctl is-active --quiet armada-runtime\n"+
						"systemctl start armada-agent\nsystemctl is-active --quiet armada-agent\n")
				if unitFile(dir, r, "armada-agent.service") != "[Service]\nExecStart=DIR/bin/armadad agent\n" {
					t.Errorf("armada-agent.service is %q, want the release's", unitFile(dir, r, "armada-agent.service"))
				}
			}},

		// --no-restart still stops what runs and removes the units the
		// release lacks: Go's server would otherwise meet a member
		// armada-etcd runs. It starts nothing.
		{name: "upgrade rollback no restart", upgrade: &upgradeCase{current: after, target: last, noRestart: true},
			setup:  fxAll(release, machine, fxUnits(all, "armada-server", "armada-etcd", "armada-agent")),
			active: []string{"armada-server", "armada-etcd", "armada-agent"},
			rustOnly: func(t *testing.T, dir string, r daemonResult) {
				if r.Code != 0 || !strings.Contains(r.Stdout, "  start      skipped (--no-restart): start armada-server yourself\n") {
					t.Errorf("exit %d, stdout:\n%s", r.Code, r.Stdout)
				}
				if strings.Contains(standinLog(r), "systemctl start ") {
					t.Error("started a service with --no-restart")
				}
				if !strings.Contains(standinLog(r), "systemctl stop armada-etcd\n") || unitFile(dir, r, "armada-etcd.service") != "" {
					t.Error("armada-etcd was not stopped and removed")
				}
			}},

		// A stop that fails ends the rollback before anything is installed.
		{name: "upgrade rollback stop fails", upgrade: &upgradeCase{current: after, target: last},
			setup:  fxAll(release, machine, fxUnits(all, "armada-server")),
			active: []string{"armada-server"},
			fail:   []string{"stop"},
			rustOnly: func(t *testing.T, dir string, r daemonResult) {
				if r.Code != 1 || !strings.Contains(r.Stderr, "Error: systemctl stop armada-server: exit status 5: Failed to stop armada-server: Unit armada-server not found.\n") {
					t.Errorf("exit %d, stderr:\n%s", r.Code, r.Stderr)
				}
				if unitFile(dir, r, "armada-etcd.service") == "" {
					t.Error("removed a unit after a failed stop")
				}
				for _, f := range r.Files {
					if strings.HasPrefix(f, "bin/armadad ") && strings.Contains(f, "new armadad") {
						t.Error("installed armadad after a failed stop")
					}
				}
			}},

		// An upgrade of a server machine whose server is enabled and whose
		// member and agent are not (after the first upgrade from the last
		// Go release, which installed their units): both enabled, then
		// every unit restarted in order.
		{name: "upgrade server machine enables etcd and agent", upgrade: &upgradeCase{current: last, target: after},
			setup:  fxAll(fxRelease(after, withEtcdUnit, false), machine, fxUnits(all, "armada-server")),
			active: []string{"armada-server", "armada-etcd", "armada-agent"},
			rustOnly: func(t *testing.T, dir string, r daemonResult) {
				expectRust(t, dir, r, 0, "Upgrading this machine from "+last+" to "+after+"\n"+
					"  download   armada_0.1.0-alpha.43_linux_"+runtime.GOARCH+".tar.gz ... SIZE\n"+
					"  download   checksums.txt ... SIZE\n"+
					"  download   checksums.txt.sigstore.json ... SIZE\n"+
					"  signature  verified with cosign (release workflow of ryanbekhen/armada, tag "+after+")\n"+
					"  checksum   OK (SHA-256 matches checksums.txt)\n"+
					"  install    DIR/bin/armada\n  install    DIR/bin/armadad\n"+
					"  install    systemd units armada-agent.service, armada-etcd.service, armada-server.service (daemon reloaded)\n"+
					"  enable     armada-etcd, armada-agent (run beside armada-server on this server machine)\n"+
					"  restart    armada-etcd ... running again after ELAPSED\n"+
					"  restart    armada-server ... running again after ELAPSED\n"+
					"  restart    armada-agent ... running again after ELAPSED\n"+
					"Upgraded to "+after+" (from "+last+"); restarted armada-etcd; restarted armada-server; restarted armada-agent.\n",
					"cosign verify-blob for https://github.com/ryanbekhen/armada/.github/workflows/release.yml@refs/tags/"+after+"\n"+
						"systemctl daemon-reload\n"+
						"systemctl enable armada-etcd armada-agent\n"+
						"systemctl is-active --quiet armada-runtime\n"+
						"systemctl is-active --quiet armada-etcd\nsystemctl restart armada-etcd\nsystemctl is-active --quiet armada-etcd\n"+
						"systemctl is-active --quiet armada-server\nsystemctl restart armada-server\nsystemctl is-active --quiet armada-server\n"+
						"systemctl is-active --quiet armada-agent\nsystemctl restart armada-agent\nsystemctl is-active --quiet armada-agent\n")
			}},
	}
}

// withEtcdUnit adds armada-etcd.service to a release.
func withEtcdUnit(f map[string]string) {
	f["deploy/systemd/armada-etcd.service"] = "[Service]\nExecStart=/usr/local/bin/armadad etcd\n"
}
