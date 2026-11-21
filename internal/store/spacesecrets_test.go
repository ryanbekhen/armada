package store

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/ryanbekhen/armada/internal/secrets"
	"github.com/ryanbekhen/armada/internal/spec"
)

// Secrets of a space (ADR 0052): a secret's keys are stored under its ID
// like an app's own secret, and other apps reference them as SECRET/KEY.

func parseIn(t *testing.T, space, y string) *spec.App {
	t.Helper()
	sp, err := spec.ParseIn([]byte(y), space)
	if err != nil {
		t.Fatal(err)
	}
	return sp
}

func TestSpaceSecretPinsAndUsers(t *testing.T) {
	t.Parallel()
	s, ctx, k := open(t), context.Background(), testKeyring(t)
	setSecret(t, s, k, "db", "url", "v1", false)
	setSecret(t, s, k, "web", "token", "t", false)

	web := parseIn(t, "", "name: web\nimage: nginx:1\nenv:\n  - name: DB\n    secretRef: db/url\n  - name: TOKEN\n    secretRef: token\n")
	rev, _, err := s.Deploy(ctx, web, "a")
	if err != nil {
		t.Fatal(err)
	}
	if rev.Secrets["db/url"] != 1 || rev.Secrets["token"] != 1 || len(rev.Secrets) != 2 {
		t.Errorf("pins = %v", rev.Secrets)
	}

	keys, err := s.ListSecrets(ctx, "db")
	if err != nil || len(keys) != 1 || !slices.Equal(keys[0].UsedBy, []string{"web--r1"}) {
		t.Errorf("db keys = %+v, %v", keys, err)
	}
	list, err := s.ListSpaceSecrets(ctx, "default")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, sec := range list {
		names = append(names, sec.Name)
		if !slices.Equal(sec.UsedBy, []string{"web"}) || sec.Keys != 1 {
			t.Errorf("%s: %+v", sec.Name, sec)
		}
	}
	if !slices.Equal(names, []string{"db", "web"}) {
		t.Errorf("secrets = %v", names)
	}

	// Versions another app pins are kept when the secret changes.
	setSecret(t, s, k, "db", "url", "v2", false)
	setSecret(t, s, k, "db", "url", "v3", false)
	for v, want := range map[int]bool{1: true, 2: false, 3: true} {
		if _, err := s.GetSecret(ctx, "db", "url", v); (err == nil) != want {
			t.Errorf("db/url v%d kept = %v, want %v", v, err == nil, want)
		}
	}

	// Neither the key nor the secret goes while web uses it.
	if err := s.DeleteSecret(ctx, "db", "url", "a"); !errors.Is(err, ErrPrecondition) {
		t.Errorf("delete a used key: %v", err)
	}
	if err := s.DeleteSecret(ctx, "db", "", "a"); !errors.Is(err, ErrPrecondition) || !strings.Contains(err.Error(), "web--r1") {
		t.Errorf("delete a used secret: %v", err)
	}
	// web--r1 is no longer active or targeted once r2 serves.
	if err := s.CompleteRollout(ctx, "web", "web--r1"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Deploy(ctx, parseIn(t, "", "name: web\nimage: nginx:1\n"), "a"); err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteRollout(ctx, "web", "web--r2"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteSecret(ctx, "db", "", "a"); err != nil {
		t.Fatalf("delete an unused secret: %v", err)
	}
	if v, _ := setSecret(t, s, k, "db", "url", "again", false); v != 4 {
		t.Errorf("version after delete = %d, want 4 (never reused)", v)
	}
}

func TestSpaceSecretRollout(t *testing.T) {
	t.Parallel()
	s, ctx, k := open(t), context.Background(), testKeyring(t)
	setSecret(t, s, k, "db", "url", "v1", false)
	for _, app := range []string{"api", "worker"} {
		if _, _, err := s.Deploy(ctx, parseIn(t, "", "name: "+app+"\nimage: nginx:1\nenv:\n  - name: DB\n    secretRef: db/url\n"), "a"); err != nil {
			t.Fatal(err)
		}
	}
	_, revs, err := s.SetSecret(ctx, "db", "url", func(v int) (secrets.Sealed, error) {
		return k.Seal("db", "url", v, secrets.NewValue([]byte("v2")))
	}, true, "a")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(revs, []string{"api--r2", "worker--r2"}) {
		t.Errorf("rollouts = %v", revs)
	}
	rev, err := s.GetRevision(ctx, "worker--r2")
	if err != nil || rev.Secrets["db/url"] != 2 {
		t.Errorf("worker--r2 pins %v, %v", rev.Secrets, err)
	}
}

func TestSpaceSecretEnvFrom(t *testing.T) {
	t.Parallel()
	s, ctx, k := open(t), context.Background(), testKeyring(t)
	setSecret(t, s, k, "db", "DATABASE_URL", "u", false)
	setSecret(t, s, k, "db", "pool-size", "5", false)
	sp := parseIn(t, "", "name: api\nimage: nginx:1\nenvFrom:\n  - secret: db\n")
	rev, _, err := s.Deploy(ctx, sp, "a")
	if err != nil {
		t.Fatal(err)
	}
	var env []string
	for _, e := range rev.Spec.Env {
		env = append(env, e.Name+"="+e.SecretRef)
	}
	if !slices.Equal(env, []string{"DATABASE_URL=db/DATABASE_URL", "POOL_SIZE=db/pool-size"}) {
		t.Errorf("env = %v", env)
	}
	if rev.Secrets["db/DATABASE_URL"] != 1 || rev.Secrets["db/pool-size"] != 1 {
		t.Errorf("pins = %v", rev.Secrets)
	}
	if _, _, err := s.Deploy(ctx, parseIn(t, "", "name: api\nimage: nginx:1\nenvFrom:\n  - secret: nothing\n"), "a"); !errors.Is(err, ErrPrecondition) ||
		!strings.Contains(err.Error(), "nothing") {
		t.Errorf("envFrom of a missing secret: %v", err)
	}
	if _, _, err := s.Deploy(ctx, parseIn(t, "", "name: api\nimage: nginx:1\nenv:\n  - name: X\n    secretRef: db/missing\n"), "a"); !errors.Is(err, ErrPrecondition) ||
		!strings.Contains(err.Error(), "armada secret set SECRET KEY") {
		t.Errorf("missing key: %v", err)
	}
}

// TestSpaceSecretsStayInTheirSpace checks that SECRET/KEY names a secret of
// the app's own space, never another's.
func TestSpaceSecretsStayInTheirSpace(t *testing.T) {
	t.Parallel()
	s, ctx, k := open(t), context.Background(), testKeyring(t)
	if _, err := s.CreateSpace(ctx, "shop", "a", nil); err != nil {
		t.Fatal(err)
	}
	setSecret(t, s, k, "auth", "JWT_SECRET", "default's", false)
	if _, _, err := s.Deploy(ctx, parseIn(t, "shop", "name: web\nimage: nginx:1\nenv:\n  - name: JWT\n    secretRef: auth/JWT_SECRET\n"), "a"); !errors.Is(err, ErrPrecondition) {
		t.Errorf("a shop app read the default space's secret: %v", err)
	}
	setSecret(t, s, k, "auth.shop", "JWT_SECRET", "shop's", false)
	rev, _, err := s.Deploy(ctx, parseIn(t, "shop", "name: web\nimage: nginx:1\nenv:\n  - name: JWT\n    secretRef: auth/JWT_SECRET\n"), "a")
	if err != nil {
		t.Fatal(err)
	}
	if rev.Secrets["auth/JWT_SECRET"] != 1 {
		t.Errorf("pins = %v", rev.Secrets)
	}
	keys, _ := s.ListSecrets(ctx, "auth")
	if len(keys) != 1 || len(keys[0].UsedBy) != 0 {
		t.Errorf("the default space's auth is used by %v", keys)
	}
	if list, _ := s.ListSpaceSecrets(ctx, "shop"); len(list) != 1 || list[0].Name != "auth" || list[0].ID != "auth.shop" {
		t.Errorf("shop's secrets = %+v", list)
	}
}

// TestSpaceSecretsNeedSchema15 checks that a keyspace older servers may
// still lead refuses references they would misread, and nothing else.
func TestSpaceSecretsNeedSchema15(t *testing.T) {
	t.Parallel()
	s, ctx, k := open(t), context.Background(), testKeyring(t)
	atSchema(t, s, 14)
	setSecret(t, s, k, "db", "url", "v", false)
	setSecret(t, s, k, "web", "url", "v", false)
	for _, y := range []string{
		"name: web\nimage: nginx:1\nenv:\n  - name: DB\n    secretRef: db/url\n",
		"name: web\nimage: nginx:1\nenvFrom:\n  - secret: db\n",
	} {
		if _, _, err := s.Deploy(ctx, parseIn(t, "", y), "a"); !errors.Is(err, ErrPrecondition) || !strings.Contains(err.Error(), "control plane server") {
			t.Errorf("deploy at schema 14: %v", err)
		}
	}
	if _, _, err := s.Deploy(ctx, parseIn(t, "", "name: web\nimage: nginx:1\nenvFrom: secrets\nenv:\n  - name: X\n    secretRef: url\n"), "a"); err != nil {
		t.Errorf("an app's own secret at schema 14: %v", err)
	}
}

// TestDeleteAppKeepsASharedSecret checks that the secret with an app's ID
// stays while another app uses it.
func TestDeleteAppKeepsASharedSecret(t *testing.T) {
	t.Parallel()
	s, ctx, k := open(t), context.Background(), testKeyring(t)
	setSecret(t, s, k, "api", "jwt", "v", false)
	setSecret(t, s, k, "cron", "x", "v", false)
	if _, _, err := s.Deploy(ctx, parseIn(t, "", "name: api\nimage: nginx:1\nenvFrom: secrets\n"), "a"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Deploy(ctx, parseIn(t, "", "name: worker\nimage: nginx:1\nenv:\n  - name: JWT\n    secretRef: api/jwt\n"), "a"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Deploy(ctx, parseIn(t, "", "name: cron\nimage: nginx:1\nenvFrom: secrets\n"), "a"); err != nil {
		t.Fatal(err)
	}
	for _, app := range []string{"api", "cron"} {
		if err := s.MarkAppRemoving(ctx, app, "a"); err != nil {
			t.Fatal(err)
		}
		if err := s.DeleteApp(ctx, app); err != nil {
			t.Fatal(err)
		}
	}
	if keys, err := s.ListSecrets(ctx, "api"); err != nil || len(keys) != 1 {
		t.Errorf("api's secret after delete = %v, %v; worker still uses it", keys, err)
	}
	if keys, _ := s.ListSecrets(ctx, "cron"); len(keys) != 0 {
		t.Errorf("cron's unshared secret kept: %v", keys)
	}
}
