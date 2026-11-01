package store

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"

	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/ryanbekhen/armada/internal/secrets"
	"github.com/ryanbekhen/armada/internal/spec"
)

const plaintextMarker = "s3cr3t-marker-7f1c"

func testKeyring(t *testing.T) *secrets.Keyring {
	t.Helper()
	k, err := secrets.NewKeyring(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func setSecret(t *testing.T, s Store, k *secrets.Keyring, app, name, value string, rollout bool) (int, string) {
	t.Helper()
	v, rev, err := s.SetSecret(context.Background(), app, name, func(version int) (secrets.Sealed, error) {
		return k.Seal(app, name, version, secrets.NewValue([]byte(value)))
	}, rollout, "admin:test")
	if err != nil {
		t.Fatal(err)
	}
	return v, rev
}

func secretSpec(t *testing.T, refs ...string) *spec.App {
	t.Helper()
	y := "name: web\nimage: nginx:1\nscale:\n  min: 1\n  max: 10\nenv:\n"
	for _, r := range refs {
		y += "  - name: " + string(bytes.ToUpper([]byte(r))) + "\n    secretRef: " + r + "\n"
	}
	if len(refs) == 0 {
		y += "  - name: PLAIN\n    value: x\n"
	}
	a, err := spec.Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestDeployPinsSecretVersions(t *testing.T) {
	t.Parallel()
	s, ctx, k := open(t), context.Background(), testKeyring(t)

	if _, _, err := s.Deploy(ctx, secretSpec(t, "db"), "a"); !errors.Is(err, ErrPrecondition) {
		t.Fatalf("deploy with unset secret = %v, want ErrPrecondition", err)
	}
	if v, rev := setSecret(t, s, k, "web", "db", plaintextMarker+"-1", true); v != 1 || rev != "" {
		t.Errorf("first set = v%d, %q; want v1 and no rollout (no app yet)", v, rev)
	}
	r1, _, err := s.Deploy(ctx, secretSpec(t, "db"), "a")
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetRevision(ctx, r1.Name); got.Secrets["db"] != 1 {
		t.Errorf("r1 pins %v, want db=1", got.Secrets)
	}
	if err := s.SetReplicas(ctx, "web", 3, "a"); err != nil {
		t.Fatal(err)
	}

	// A new value rolls out as a new revision, keeping the scaled count.
	v, rev := setSecret(t, s, k, "web", "db", plaintextMarker+"-2", true)
	if v != 2 || rev != "web--r2" {
		t.Fatalf("set with rollout = v%d, %q", v, rev)
	}
	app, _ := s.GetApp(ctx, "web")
	if app.TargetRevision != "web--r2" || app.ActiveRevision != "web--r1" || app.Replicas != 3 {
		t.Errorf("after secret rollout: %+v", app)
	}
	if r2, _ := s.GetRevision(ctx, "web--r2"); r2.Secrets["db"] != 2 {
		t.Errorf("r2 pins %v", r2.Secrets)
	}

	// Without rollout nothing changes until the next deploy, which picks up
	// the new version even though the spec is the same.
	if _, rev := setSecret(t, s, k, "web", "db", plaintextMarker+"-3", false); rev != "" {
		t.Errorf("set without rollout created %s", rev)
	}
	r3, created, err := s.Deploy(ctx, secretSpec(t, "db"), "a")
	if err != nil || !created || r3.Secrets["db"] != 3 {
		t.Errorf("redeploy after secret change = %s %v %v %v", r3.Name, r3.Secrets, created, err)
	}

	// Setting a secret the app does not use never rolls it out.
	if _, rev := setSecret(t, s, k, "web", "unused", "x", true); rev != "" {
		t.Errorf("unused secret rolled out %s", rev)
	}

	sealed, err := s.GetSecret(ctx, "web", "db", 3)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := k.Open(sealed, "web", "db", 3); err != nil || string(got.Bytes()) != plaintextMarker+"-3" {
		t.Errorf("round trip = %v", err)
	}
}

func TestListAndPruneSecrets(t *testing.T) {
	t.Parallel()
	s, ctx, k := open(t), context.Background(), testKeyring(t)
	setSecret(t, s, k, "web", "db", "v1", false)
	setSecret(t, s, k, "web", "api-key", "k1", false)
	if _, _, err := s.Deploy(ctx, secretSpec(t, "db"), "a"); err != nil {
		t.Fatal(err)
	}
	setSecret(t, s, k, "web", "db", "v2", false)
	setSecret(t, s, k, "web", "db", "v3", false)

	// v1 is pinned by web--r1, v3 is the latest; v2 is garbage.
	for v, want := range map[int]bool{1: true, 2: false, 3: true} {
		_, err := s.GetSecret(ctx, "web", "db", v)
		if got := err == nil; got != want {
			t.Errorf("db v%d kept = %v, want %v (%v)", v, got, want, err)
		}
	}

	list, err := s.ListSecrets(ctx, "web")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].Name != "api-key" || list[1].Name != "db" || list[1].Version != 3 ||
		!slices.Equal(list[1].UsedBy, []string{"web--r1"}) || list[1].UpdatedBy != "admin:test" || len(list[0].UsedBy) != 0 {
		t.Errorf("ListSecrets = %+v", list)
	}
	if list, _ := s.ListSecrets(ctx, "other"); len(list) != 0 {
		t.Errorf("secrets leaked across apps: %+v", list)
	}
}

func TestDeleteSecret(t *testing.T) {
	t.Parallel()
	s, ctx, k := open(t), context.Background(), testKeyring(t)
	if err := s.DeleteSecret(ctx, "web", "db", "a"); !errors.Is(err, ErrNotFound) {
		t.Errorf("delete missing = %v", err)
	}
	setSecret(t, s, k, "web", "db", "v1", false)
	if _, _, err := s.Deploy(ctx, secretSpec(t, "db"), "a"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteSecret(ctx, "web", "db", "a"); !errors.Is(err, ErrPrecondition) {
		t.Errorf("delete of a secret in use = %v, want ErrPrecondition", err)
	}

	// Once nothing serving uses it, it can go, but rolling back to a
	// revision that needed it fails clearly.
	if _, _, err := s.Deploy(ctx, secretSpec(t), "a"); err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteRollout(ctx, "web", "web--r2"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteSecret(ctx, "web", "db", "a"); err != nil {
		t.Fatalf("delete unused secret: %v", err)
	}
	if _, err := s.Rollback(ctx, "web", "web--r1", "a"); !errors.Is(err, ErrPrecondition) {
		t.Errorf("rollback to revision with deleted secret = %v", err)
	}
	audit, _ := s.ListAudit(ctx, 20)
	var actions []string
	for _, e := range audit {
		actions = append(actions, e.Action+" "+e.Detail)
	}
	if !slices.Contains(actions, "secret.set db v1") || !slices.Contains(actions, "secret.delete db") {
		t.Errorf("audit = %v", actions)
	}
}

func TestSecretPlaintextNeverStored(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	k := testKeyring(t)
	setSecret(t, s, k, "web", "db", plaintextMarker, false)
	if _, _, err := s.Deploy(ctx, secretSpec(t, "db"), "a"); err != nil {
		t.Fatal(err)
	}
	resp, err := s.c.Get(ctx, s.prefix, clientv3.WithPrefix())
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range resp.Kvs {
		if bytes.Contains(e.Value, []byte(plaintextMarker)) {
			t.Errorf("%s holds the secret in plaintext", e.Key)
		}
	}
	// Nor on disk: the WAL and the database files of the member.
	err = filepath.WalkDir(testEtcdDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(b, []byte(plaintextMarker)) {
			t.Errorf("%s contains the secret in plaintext", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
