package daemon

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ryanbekhen/armada/internal/etcd"
)

// execProgram is replaced while a test of armadad etcd runs.
func captureExec(t *testing.T) *[]string {
	t.Helper()
	var got []string
	old := execProgram
	execProgram = func(path string, argv []string, _ []string) error {
		got = append([]string{path}, argv...)
		return nil
	}
	t.Cleanup(func() { execProgram = old })
	return &got
}

func TestEtcdCommand(t *testing.T) {
	got := captureExec(t)
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	if code, _, stderr := run(t, "init", "--data-dir", dataDir, "--config", filepath.Join(dir, "home", "config"), "--private-ip", "10.0.0.2"); code != 0 {
		t.Fatalf("init: %s", stderr)
	}
	if code, _, stderr := run(t, "etcd", "--data-dir", dataDir, "--bin-dir", filepath.Join(dir, "none")); code == 0 || !strings.Contains(stderr, "no etcd program") {
		t.Errorf("without a program: %d %s", code, stderr)
	}
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "etcd"), []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	// The unit passes the server's flags, which armadad etcd ignores.
	code, _, stderr := run(t, "etcd", "--data-dir", dataDir, "--bin-dir", bin, "--acme-email", "ops@example.com", "--tls", "-v")
	if code != 0 {
		t.Fatalf("etcd: %s", stderr)
	}
	config := filepath.Join(dataDir, dirEtcd, etcd.FileConfig)
	want := []string{filepath.Join(bin, "etcd"), filepath.Join(bin, "etcd"), "--config-file", config}
	if !slices.Equal(*got, want) {
		t.Errorf("exec %v, want %v", *got, want)
	}
	if fi, err := os.Stat(config); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("%s: %v %v", config, fi, err)
	}
	b, _ := os.ReadFile(config)
	for _, w := range []string{"\nname: ", "listen-client-urls: https://127.0.0.1:", "initial-cluster-state: new", "tls-min-version: TLS1.3", "- etcd:member"} {
		if !strings.Contains(string(b), w) {
			t.Errorf("config has no %q:\n%s", w, b)
		}
	}
	// init ran the member: its data is copied once, before the program's
	// first start.
	kept := filepath.Join(dataDir, dirEtcdBeforeUnit)
	if _, err := os.Stat(filepath.Join(kept, "member", "wal")); err != nil {
		t.Fatalf("no copy of the member: %v %s", err, stderr)
	}
	if !strings.Contains(stderr, "data.before-unit") {
		t.Errorf("the copy is not said: %s", stderr)
	}
	marker := filepath.Join(kept, "marker")
	if err := os.WriteFile(marker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := run(t, "etcd", "--data-dir", dataDir, "--bin-dir", bin); code != 0 {
		t.Fatalf("etcd again: %s", stderr)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Errorf("the copy was made again: %v", err)
	}

	// Refused while the server's embedded member runs on the same files.
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_, m, err := openState(ctx, dataDir, false, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := run(t, "etcd", "--data-dir", dataDir, "--bin-dir", bin); code == 0 || !strings.Contains(stderr, "another process runs the etcd member") {
		t.Errorf("with the embedded member running: %d %s", code, stderr)
	}

	// A server with --etcd-member unit connects to a member another
	// process runs (here the embedded one stands in) and leaves it running
	// when it closes.
	_, u, err := openState(ctx, dataDir, true, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	if u.ID() != m.ID() || u.IsLearner() {
		t.Errorf("connected to %x (learner %v), the member is %x", u.ID(), u.IsLearner(), m.ID())
	}
	_ = u.Close()
	if _, err := m.Client().Put(ctx, "still", "running"); err != nil {
		t.Errorf("closing the connection stopped the member: %v", err)
	}
	_ = m.Close()

	if code, _, stderr := run(t, "etcd", "--data-dir", filepath.Join(dir, "empty"), "--bin-dir", bin); code == 0 || !strings.Contains(stderr, "not a server's data directory") {
		t.Errorf("uninitialized: %d %s", code, stderr)
	}
}

func TestServerRefusesUnknownEtcdMember(t *testing.T) {
	if code, _, stderr := run(t, "server", "--data-dir", t.TempDir(), "--etcd-member", "remote"); code == 0 || !strings.Contains(stderr, "--etcd-member") {
		t.Errorf("%d %s", code, stderr)
	}
}

func TestEtcdEnv(t *testing.T) {
	t.Parallel()
	if got := etcdEnv([]string{"PATH=/bin", "ETCD_NAME=x", "ARMADA_SERVER_FLAGS=--tls"}); !slices.Equal(got, []string{"PATH=/bin", "ARMADA_SERVER_FLAGS=--tls"}) {
		t.Errorf("%v", got)
	}
}
