package store

import (
	"context"
	"errors"
	"testing"
)

func TestRestartApp(t *testing.T) {
	t.Parallel()
	s, ctx, k := open(t), context.Background(), testKeyring(t)
	setSecret(t, s, k, "db", "url", "v1", false)
	if _, _, err := s.Deploy(ctx, parseIn(t, "", "name: api\nimage: nginx:1\nenv:\n  - name: DB\n    secretRef: db/url\n"), "a"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RestartApp(ctx, "nope", "a"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown app: %v", err)
	}
	// A restart with nothing changed still makes a revision to roll out.
	rev, err := s.RestartApp(ctx, "api", "a")
	if err != nil || rev.Name != "api--r2" {
		t.Fatalf("restart = %s, %v", rev.Name, err)
	}
	if a, _ := s.GetApp(ctx, "api"); a.TargetRevision != "api--r2" || a.ActiveRevision != "api--r1" {
		t.Errorf("app after restart: active %s, target %s", a.ActiveRevision, a.TargetRevision)
	}
	// It pins the secret's latest version, which a plain set leaves alone.
	setSecret(t, s, k, "db", "url", "v2", false)
	if rev, err = s.RestartApp(ctx, "api", "a"); err != nil || rev.Secrets["db/url"] != 2 || rev.Name != "api--r3" {
		t.Errorf("restart after a set = %s %v, %v", rev.Name, rev.Secrets, err)
	}

	deployJob(t, s, "kind: job\nname: migrate\nimage: nginx:1\n")
	if _, err := s.RestartApp(ctx, "migrate", "a"); !errors.Is(err, ErrPrecondition) {
		t.Errorf("job: %v", err)
	}
	if err := s.MarkAppRemoving(ctx, "api", "a"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RestartApp(ctx, "api", "a"); !errors.Is(err, ErrPrecondition) {
		t.Errorf("app being removed: %v", err)
	}
}
