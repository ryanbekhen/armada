//go:build integration

package etcd

import (
	"bytes"
	"context"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ryanbekhen/armada/internal/pki"
)

// TestIntegrationUnitMember runs the pinned etcd (ARMADA_ETCD_BIN: the
// pack's etcd, e.g. extracted from the release archive lock.go pins) with
// the configuration file armadad etcd writes, on loopback with no root:
// the Go client reaches it over TLS 1.3 with the member certificate, other
// identities and TLS 1.2 are refused, and the same member directory moves
// from the embedded member to the program and back with its data and
// member ID intact.
//
//	ARMADA_ETCD_BIN=/path/to/etcd go test -tags integration -run IntegrationUnitMember ./internal/etcd/
func TestIntegrationUnitMember(t *testing.T) {
	bin := os.Getenv("ARMADA_ETCD_BIN")
	if bin == "" {
		t.Skip("ARMADA_ETCD_BIN names no etcd program (the pinned release's etcd, internal/runtime/embedded/lock.go)")
	}
	out, err := exec.Command(bin, "--version").Output()
	if err != nil {
		t.Fatalf("%s --version: %v", bin, err)
	}
	t.Logf("%s", bytes.SplitN(out, []byte("\n"), 2)[0])

	ca, _ := pki.NewCA("test")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	// Embedded first, as every server runs today.
	m, cfg := startMember(t, ca)
	id := m.ID()
	if _, err := m.Client().Put(ctx, "embedded", "1"); err != nil {
		t.Fatal(err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}

	// The same directory under the pinned etcd.
	stop := runUnit(t, bin, cfg)
	u, err := Connect(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if u.ID() != id || u.IsLearner() {
		t.Errorf("member %x (learner %v), want %x", u.ID(), u.IsLearner(), id)
	}
	resp, err := u.Client().Get(ctx, "embedded")
	if err != nil || len(resp.Kvs) != 1 || string(resp.Kvs[0].Value) != "1" {
		t.Fatalf("embedded key under the program: %v %v", resp, err)
	}
	if _, err := u.Client().Put(ctx, "unit", "2"); err != nil {
		t.Fatal(err)
	}
	members, err := Members(ctx, u.Client())
	if err != nil || len(members) != 1 || members[0].PeerURL != "https://"+netip.AddrPortFrom(cfg.Addr, uint16(cfg.PeerPort)).String() {
		t.Errorf("members %+v %v", members, err)
	}
	checkRejectsOthers(t, ca, cfg)
	// A renewed member certificate is read on the next handshake.
	if _, err := u.RenewCert(time.Now().Add(400 * 24 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := Dial(ctx, cfg); err != nil {
		t.Errorf("after renewal: %v", err)
	}
	_ = u.Close()
	stop()

	// And back to the embedded member.
	m2, err := Start(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer m2.Close()
	if m2.ID() != id {
		t.Errorf("member %x after the move back, want %x", m2.ID(), id)
	}
	for k, v := range map[string]string{"embedded": "1", "unit": "2"} {
		resp, err := m2.Client().Get(ctx, k)
		if err != nil || len(resp.Kvs) != 1 || string(resp.Kvs[0].Value) != v {
			t.Errorf("%s after the move back: %v %v", k, resp, err)
		}
	}
}

// A first start under the program makes a new member as the embedded one
// would, and Connect waits for a member that starts late.
func TestIntegrationUnitFirstStart(t *testing.T) {
	bin := os.Getenv("ARMADA_ETCD_BIN")
	if bin == "" {
		t.Skip("ARMADA_ETCD_BIN names no etcd program")
	}
	ca, _ := pki.NewCA("test")
	cfg := Config{Dir: filepath.Join(t.TempDir(), "etcd"), Name: "cp-1", Addr: netip.MustParseAddr("127.0.0.1"), CA: ca}
	cfg.ClientPort, cfg.PeerPort = freePort(t), freePort(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	type result struct {
		m   *Member
		err error
	}
	done := make(chan result, 1)
	// The certificate Connect reads is written by WriteConfigFile; start
	// waiting before the member exists.
	if _, err := WriteConfigFile(cfg); err != nil {
		t.Fatal(err)
	}
	go func() {
		m, err := Connect(ctx, cfg)
		done <- result{m, err}
	}()
	time.Sleep(2 * time.Second)
	stop := runUnit(t, bin, cfg)
	defer stop()
	r := <-done
	if r.err != nil {
		t.Fatal(r.err)
	}
	defer r.m.Close()
	if _, err := r.m.Client().Put(ctx, "k", "v"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(cfg.Dir, FileConfig))
	if err != nil || !strings.Contains(string(b), "initial-cluster-state: new") {
		t.Errorf("config: %s %v", b, err)
	}
}

// runUnit writes the configuration file and runs the program with it, as
// armadad etcd does, and returns a function that stops it (SIGTERM).
func runUnit(t *testing.T, bin string, cfg Config) (stop func()) {
	t.Helper()
	path, err := WriteConfigFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "--config-file", path)
	var logs bytes.Buffer
	cmd.Stdout, cmd.Stderr = &logs, &logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	stopped := false
	stop = func() {
		if stopped {
			return
		}
		stopped = true
		_ = cmd.Process.Signal(syscall.SIGTERM)
		exited := make(chan struct{})
		go func() {
			_ = cmd.Wait() // a SIGTERM'd etcd may exit non-zero
			close(exited)
		}()
		select {
		case <-exited:
		case <-time.After(30 * time.Second):
			_ = cmd.Process.Kill()
			<-exited
			t.Errorf("etcd did not stop on SIGTERM")
		}
		if t.Failed() {
			t.Logf("etcd's log:\n%s", logs.String())
		}
	}
	t.Cleanup(stop)
	return stop
}
