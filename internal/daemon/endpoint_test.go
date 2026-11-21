package daemon

import (
	"context"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ryanbekhen/armada/internal/store"
)

// A node announces the endpoint agent.json records, else the one found on
// its interfaces; a node without a cluster network announces none (ADR
// 0050).
func TestAnnouncedEndpoint(t *testing.T) {
	log := slog.New(slog.DiscardHandler)
	if got := announcedEndpoint(&agentConfig{Network: store.NetworkPlain, Endpoint: "203.0.113.7"}, log); got != "203.0.113.7" {
		t.Errorf("recorded = %q", got)
	}
	if got := announcedEndpoint(&agentConfig{Network: store.NetworkPlain}, log); got != "" {
		t.Errorf("none found = %q", got)
	}
	orig := detectEndpoint
	t.Cleanup(func() { detectEndpoint = orig })
	detectEndpoint = func() (netip.Addr, error) { return netip.MustParseAddr("198.51.100.4"), nil }
	if got := announcedEndpoint(&agentConfig{Network: store.NetworkWireGuard}, log); got != "198.51.100.4" {
		t.Errorf("found = %q", got)
	}
	if got := announcedEndpoint(&agentConfig{}, log); got != "" {
		t.Errorf("no cluster network = %q", got)
	}
}

func TestEndpointCommand(t *testing.T) {
	dir := t.TempDir()
	base := agentConfig{NodeID: "n1", PrivateIP: "10.0.0.1", Servers: []string{"10.0.0.1:7443"}, Runtime: runtimeEmbedded, Network: store.NetworkPlain}
	if err := saveAgentConfig(dir, base); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) (string, error) {
		t.Helper()
		cmd := newEndpointCommand()
		var out strings.Builder
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SetArgs(append(args, "--data-dir", dir))
		err := cmd.ExecuteContext(context.Background())
		return out.String(), err
	}
	if out, err := run("show"); err != nil || !strings.Contains(out, "none") {
		t.Errorf("show = %q, %v", out, err)
	}
	for _, bad := range []string{"not-an-ip", "127.0.0.1", "::1", "2001:db8::1", "255.255.255.255"} {
		if _, err := run("set", bad); err == nil {
			t.Errorf("set %s accepted", bad)
		}
	}
	restarted := 0
	orig := restartService
	t.Cleanup(func() { restartService = orig })
	restartService = func(context.Context) (string, error) { restarted++; return "armada-agent", nil }
	out, err := run("set", "203.0.113.9")
	if err != nil || !strings.Contains(out, "Restarted armada-agent") || restarted != 1 {
		t.Fatalf("set = %q, %v, restarted %d", out, err, restarted)
	}
	ac, err := loadAgentConfig(dir)
	if err != nil || ac.Endpoint != "203.0.113.9" || ac.NodeID != "n1" || ac.Network != store.NetworkPlain {
		t.Fatalf("agent.json = %+v, %v", ac, err)
	}
	if out, _ := run("show"); !strings.Contains(out, "203.0.113.9 (set)") {
		t.Errorf("show = %q", out)
	}
	if _, err := run("set", "203.0.113.10", "--no-restart"); err != nil || restarted != 1 {
		t.Errorf("--no-restart: %v, restarted %d", err, restarted)
	}

	// Behind NAT (ADR 0050), and back; never on a server.
	if _, err := run("set", "none", "--no-restart"); err != nil {
		t.Fatal(err)
	}
	if ac, err := loadAgentConfig(dir); err != nil || !ac.BehindNAT || ac.Endpoint != "" {
		t.Errorf("behind NAT: %+v, %v", ac, err)
	}
	if out, _ := run("show"); !strings.Contains(out, "behind NAT") {
		t.Errorf("show = %q", out)
	}
	if _, err := run("set", "203.0.113.11", "--no-restart"); err != nil {
		t.Fatal(err)
	}
	if ac, err := loadAgentConfig(dir); err != nil || ac.BehindNAT || ac.Endpoint != "203.0.113.11" {
		t.Errorf("endpoint again: %+v, %v", ac, err)
	}
	if err := os.WriteFile(filepath.Join(dir, fileServerCert), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := run("set", "none", "--no-restart"); err == nil {
		t.Error("a server behind NAT accepted")
	}
	_ = os.Remove(filepath.Join(dir, fileServerCert))

	// A cluster without a cluster network has no use for one.
	base.Network = ""
	if err := saveAgentConfig(dir, base); err != nil {
		t.Fatal(err)
	}
	if _, err := run("set", "203.0.113.9"); err == nil {
		t.Error("set without a cluster network accepted")
	}
}
