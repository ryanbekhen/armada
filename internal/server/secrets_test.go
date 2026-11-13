package server

import (
	"bytes"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/pki"
	"github.com/ryanbekhen/armada/internal/secrets"
	"github.com/ryanbekhen/armada/internal/store"
)

func withKeys(t *testing.T) func(*Config) {
	k, err := secrets.NewKeyring(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return func(c *Config) { c.Secrets = k }
}

func TestSecretRotationRollsOut(t *testing.T) {
	t.Parallel()
	c := newCluster(t, withKeys(t))
	d := c.addNode("n1", "127.0.0.1")

	if _, err := c.admin.SetSecret(c.ctx, &armadav1.SetSecretRequest{App: "api", Name: "db", Value: []byte("one"), Rollout: true}); err != nil {
		t.Fatal(err)
	}
	c.deploy("name: api\nimage: nginx:1\nenv:\n  - name: DB\n    secretRef: db\n")
	c.eventually("v1 running", func() bool { return len(c.running("api")) == 1 })

	resp, err := c.admin.SetSecret(c.ctx, &armadav1.SetSecretRequest{App: "api", Name: "db", Value: []byte("two"), Rollout: true})
	if err != nil || resp.Version != 2 || resp.Revision != "api--r2" {
		t.Fatalf("SetSecret = %v, %v", resp, err)
	}
	c.eventually("rollout complete", func() bool {
		a := c.app("api")
		return a.ActiveRevision == "api--r2" && a.RolloutState == "" && containerCount(d) == 1
	})
	cs, _ := d.List(c.ctx, nil)
	spec, _ := d.Spec(cs[0].ID)
	found := false
	for _, e := range spec.Env {
		found = found || e == "DB=two"
	}
	if !found {
		t.Errorf("env after rotation = %v", spec.Env)
	}
}

func TestSecretRPCValidation(t *testing.T) {
	t.Parallel()
	c := newCluster(t, withKeys(t))
	for name, req := range map[string]*armadav1.SetSecretRequest{
		"bad app":    {App: "Bad App", Name: "db", Value: []byte("x")},
		"bad name":   {App: "api", Name: "../db", Value: []byte("x")},
		"empty name": {App: "api", Value: []byte("x")},
		"too big":    {App: "api", Name: "db", Value: make([]byte, secrets.MaxSize+1)},
	} {
		if _, err := c.admin.SetSecret(c.ctx, req); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := c.admin.DeleteSecret(c.ctx, &armadav1.DeleteSecretRequest{App: "api", Name: "nope"}); status.Code(err) != codes.NotFound {
		t.Errorf("delete missing = %v", err)
	}
	if _, err := c.admin.ListSecrets(c.ctx, &armadav1.ListSecretsRequest{App: "-x"}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("list bad app = %v", err)
	}

	// Agents may not touch secrets.
	if err := c.store.UpsertNode(c.ctx, store.Node{ID: "n1", PrivateIP: "10.0.0.2"}); err != nil {
		t.Fatal(err)
	}
	agent := armadav1.NewAdminServiceClient(c.dial(c.ca, pki.Identity{Kind: pki.KindNode, Name: "n1"}))
	if _, err := agent.SetSecret(c.ctx, &armadav1.SetSecretRequest{App: "api", Name: "db", Value: []byte("x")}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("agent SetSecret = %v", err)
	}
	if _, err := agent.ListSecrets(c.ctx, &armadav1.ListSecretsRequest{App: "api"}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("agent ListSecrets = %v", err)
	}
}

func TestSecretsDisabledWithoutKey(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	_, err := c.admin.SetSecret(c.ctx, &armadav1.SetSecretRequest{App: "api", Name: "db", Value: []byte("x")})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "master key") {
		t.Errorf("SetSecret without key = %v", err)
	}
}

// An app of another space is named by its ID, like everywhere else past the API.
func TestSecretOfSpaceApp(t *testing.T) {
	t.Parallel()
	c := newCluster(t, withKeys(t))
	if _, err := c.admin.CreateSpace(c.ctx, &armadav1.CreateSpaceRequest{Name: "staging"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.admin.SetSecret(c.ctx, &armadav1.SetSecretRequest{App: "api.staging", Name: "db", Value: []byte("one")}); err != nil {
		t.Fatal(err)
	}
	resp, err := c.admin.ListSecrets(c.ctx, &armadav1.ListSecretsRequest{App: "api.staging"})
	if err != nil || len(resp.GetSecrets()) != 1 {
		t.Fatalf("ListSecrets = %v, %v", resp, err)
	}
	if _, err := c.admin.DeleteSecret(c.ctx, &armadav1.DeleteSecretRequest{App: "api.staging", Name: "db"}); err != nil {
		t.Error(err)
	}
	for _, app := range []string{"api.Staging", "api..staging", "a.b.c", "../api"} {
		if _, err := c.admin.SetSecret(c.ctx, &armadav1.SetSecretRequest{App: app, Name: "db", Value: []byte("x")}); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%q: %v", app, err)
		}
	}
	if _, err := c.admin.SetSecret(c.ctx, &armadav1.SetSecretRequest{App: "api.nowhere", Name: "db", Value: []byte("x")}); err == nil {
		t.Error("secret in a space that does not exist")
	}
}
