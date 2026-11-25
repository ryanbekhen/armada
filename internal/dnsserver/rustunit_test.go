package dnsserver

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// refusing records the unit StartProcess starts and refuses to start it.
type refusing struct{ unit string }

func (r *refusing) Start(_ context.Context, unit string, _ []string) error {
	r.unit = unit
	return errors.New("refused")
}
func (r *refusing) Stop(context.Context, string) error      { return nil }
func (r *refusing) Units(context.Context) ([]string, error) { return nil, nil }

// TestUnitNameMatchesRust pins the unit name the Rust agent's DnsProcess
// makes for the same program and settings (agent/src/dnsprocess.rs,
// unit_names_as_go_makes_them), so either agent finds the other's unit.
func TestUnitNameMatchesRust(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	bin := filepath.Join(dir, "armada-dns")
	if err := os.WriteFile(bin, []byte("program"), 0o600); err != nil {
		t.Fatal(err)
	}
	l := &refusing{}
	_, err := StartProcess(context.Background(), ProcessConfig{
		Bin: bin, Addr: netip.MustParseAddr("10.120.0.1"), Clients: netip.MustParsePrefix("10.120.0.9/24"),
		Upstreams: []string{"1.1.1.1:53"}, UnknownWait: 3 * time.Second, Dir: filepath.Join(dir, "dns"), Launcher: l,
	})
	if err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("StartProcess = %v", err)
	}
	if want := UnitPrefix + "77580d36485337b0"; l.unit != want {
		t.Errorf("unit = %s, want %s", l.unit, want)
	}
}
