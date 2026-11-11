package store

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// A TCP port serves one app per project; other projects may use it too,
// since the caller's project picks the app (ADR 0039).
func TestTCPPortsPerProject(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	if _, err := s.CreateProject(ctx, "b", "admin:test", nil); err != nil {
		t.Fatal(err)
	}
	deploy := func(name, project, port string) error {
		sp := mustParse(t, "name: "+name+"\nimage: postgres:17\ningress:\n  type: internal\n  protocol: tcp\n  port: "+port+"\n")
		sp.Project = project
		_, _, err := s.Deploy(ctx, sp, "admin:test")
		return err
	}
	if err := deploy("db", "", "5432"); err != nil {
		t.Fatal(err)
	}
	err := deploy("other", "", "5432")
	if !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), "app db") {
		t.Fatalf("second app on the port = %v", err)
	}
	if _, err := s.GetApp(ctx, "other"); !errors.Is(err, ErrNotFound) {
		t.Error("conflicting deploy was partially applied")
	}
	// Another project, the same port.
	if err := deploy("db", "b", "5432"); err != nil {
		t.Fatalf("another project: %v", err)
	}
	// The app itself may redeploy; another port is free.
	if err := deploy("db", "", "5432"); err != nil {
		t.Fatalf("redeploy: %v", err)
	}
	if err := deploy("other", "", "6379"); err != nil {
		t.Fatal(err)
	}
	// An HTTP app does not hold its port.
	web := mustParse(t, "name: web\nimage: nginx:1\ningress:\n  type: internal\n  port: 7000\n")
	if _, _, err := s.Deploy(ctx, web, "admin:test"); err != nil {
		t.Fatal(err)
	}
	if err := deploy("echo", "", "7000"); err != nil {
		t.Fatalf("port of an HTTP app: %v", err)
	}
	// While db rolls out to another port, both stay its own.
	r2 := mustParse(t, "name: db\nimage: postgres:17\ningress:\n  type: internal\n  protocol: tcp\n  port: 5433\n")
	if _, _, err := s.Deploy(ctx, r2, "admin:test"); err != nil {
		t.Fatal(err)
	}
	if err := deploy("x", "", "5432"); !errors.Is(err, ErrConflict) {
		t.Errorf("port of a rolling app's active revision = %v", err)
	}
}
