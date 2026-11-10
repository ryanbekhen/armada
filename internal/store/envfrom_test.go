package store

import (
	"context"
	"errors"
	"testing"

	"github.com/ryanbekhen/armada/internal/spec"
)

func envFromSpec(t *testing.T, extra string) *spec.App {
	t.Helper()
	a, err := spec.Parse([]byte("name: ef\nimage: nginx:1\nenvFrom: secrets\n" + extra))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func envOf(r Revision) map[string]string {
	out := map[string]string{}
	for _, e := range r.Spec.Env {
		out[e.Name] = e.SecretRef + e.Value
	}
	return out
}

func TestDeployEnvFromSecrets(t *testing.T) {
	t.Parallel()
	s, ctx, k := open(t), context.Background(), testKeyring(t)
	for _, n := range []string{"database-url", "node-env", "ghcr-token", "port", "armada-x", "1st"} {
		setSecret(t, s, k, "ef", n, "v", false)
	}
	extra := "env:\n  - { name: NODE_ENV, value: production }\nregistry: { server: docker.io, username: u, passwordSecretRef: ghcr-token }\n"
	r1, created, err := s.Deploy(ctx, envFromSpec(t, extra), "a")
	if err != nil || !created {
		t.Fatalf("deploy: %v %v", created, err)
	}
	got := envOf(r1)
	want := map[string]string{"NODE_ENV": "production", "DATABASE_URL": "database-url"}
	if len(got) != len(want) {
		t.Errorf("env = %v, want %v (registry, reserved, invalid names, and set variables left out)", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("env %s = %q, want %q", k, got[k], v)
		}
	}
	if r1.Secrets["database-url"] != 1 || r1.Secrets["ghcr-token"] != 1 {
		t.Errorf("pins %v", r1.Secrets)
	}

	// The same spec with the same secrets is the same revision; a new
	// secret makes a new one.
	if r, created, err := s.Deploy(ctx, envFromSpec(t, extra), "a"); err != nil || created || r.Name != r1.Name {
		t.Errorf("redeploy unchanged: %s %v %v", r.Name, created, err)
	}
	setSecret(t, s, k, "ef", "redis-url", "v", false)
	r2, created, err := s.Deploy(ctx, envFromSpec(t, extra), "a")
	if err != nil || !created || envOf(r2)["REDIS_URL"] != "redis-url" {
		t.Errorf("deploy after a new secret: %v %v %v", envOf(r2), created, err)
	}

	// Too many variables is refused, not cut short.
	for i := range 520 {
		setSecret(t, s, k, "many", "s"+string(rune('a'+i/26%26))+string(rune('a'+i%26))+"-"+string(rune('a'+i/676)), "v", false)
	}
	big, err := spec.Parse([]byte("name: many\nimage: nginx:1\nenvFrom: secrets\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Deploy(ctx, big, "a"); !errors.Is(err, ErrPrecondition) {
		t.Errorf("520 secrets: %v, want ErrPrecondition", err)
	}
}
