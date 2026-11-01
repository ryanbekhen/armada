package agent

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/runtime"
	"github.com/ryanbekhen/armada/internal/store"
)

const secretMarker = "agent-s3cr3t-9a7b"

func secretReplica(id string) *armadav1.ReplicaSpec {
	r := replica(id, "ghcr.io/acme/web:1", 80)
	r.Env = append(r.Env, &armadav1.EnvVar{Name: "DB", Value: secretMarker + "-env", Ref: "db@v2"})
	r.SecretFiles = []*armadav1.SecretFile{{Path: "/run/secrets/tls.key", Data: []byte(secretMarker + "-file"), Ref: "tls@v1"}}
	r.Registry = &armadav1.RegistryAuth{Server: "ghcr.io", Username: "bot", Password: secretMarker + "-pull", Ref: "ghcr@v3"}
	return r
}

func TestSecretFilesAndRegistryAuth(t *testing.T) {
	t.Parallel()
	a, d := newAgent(t)
	var logs bytes.Buffer
	a.log = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	a.cfg.SecretsDir = filepath.Join(t.TempDir(), "secrets")
	if err := os.Mkdir(a.cfg.SecretsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Something unrelated in the directory must survive cleanup.
	if err := os.WriteFile(filepath.Join(a.cfg.SecretsDir, "README"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	a.setDesired([]*armadav1.ReplicaSpec{secretReplica("web-r2-a")}, nil)
	report, err := a.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st := report.Replicas[0]; st.State != store.ReplicaRunning {
		t.Fatalf("replica = %v", st)
	}
	if len(d.PullAuths) != 1 || d.PullAuths[0] == nil || d.PullAuths[0].Password != secretMarker+"-pull" || d.PullAuths[0].ServerAddress != "ghcr.io" {
		t.Errorf("pull auth = %v", d.PullAuths)
	}

	cs, _ := d.List(context.Background(), nil)
	spec, _ := d.Spec(cs[0].ID)
	if !slices.Contains(spec.Env, "DB="+secretMarker+"-env") {
		t.Errorf("env = %v", spec.Env)
	}
	dir := filepath.Join(a.cfg.SecretsDir, "web-r2-a")
	want := runtime.FileMount{Source: filepath.Join(dir, "0"), Target: "/run/secrets/tls.key"}
	if len(spec.Files) != 1 || spec.Files[0] != want {
		t.Fatalf("files = %+v", spec.Files)
	}
	if b, err := os.ReadFile(want.Source); err != nil || string(b) != secretMarker+"-file" {
		t.Errorf("secret file = %q, %v", b, err)
	}
	if fi, _ := os.Stat(want.Source); fi.Mode().Perm() != 0o444 {
		t.Errorf("secret file mode = %v", fi.Mode())
	}
	if fi, _ := os.Stat(dir); fi.Mode().Perm() != 0o700 {
		t.Errorf("replica secrets dir mode = %v", fi.Mode())
	}
	for k, v := range spec.Labels {
		if strings.Contains(v, secretMarker) {
			t.Errorf("label %s holds a secret", k)
		}
	}

	// The replica goes away: its files go with it.
	a.setDesired(nil, nil)
	if _, err := a.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("secret files left behind: %v", err)
	}
	if _, err := os.Stat(filepath.Join(a.cfg.SecretsDir, "README")); err != nil {
		t.Errorf("cleanup removed an unrelated file: %v", err)
	}
	if strings.Contains(logs.String(), secretMarker) {
		t.Errorf("logs contain a secret:\n%s", logs.String())
	}
}

func TestSecretFilesNeedSecretsDir(t *testing.T) {
	t.Parallel()
	a, d := newAgent(t)
	a.setDesired([]*armadav1.ReplicaSpec{secretReplica("web-r2-a")}, nil)
	report, err := a.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st := report.Replicas[0]; st.State != store.ReplicaFailed || !strings.Contains(st.Message, "--secrets-dir") {
		t.Errorf("replica = %v", st)
	}
	if cs, _ := d.List(context.Background(), nil); len(cs) != 0 {
		t.Error("container started without its secret files")
	}
}

func TestSecretFilesRejectBadReplicaID(t *testing.T) {
	t.Parallel()
	a, _ := newAgent(t)
	a.cfg.SecretsDir = t.TempDir()
	for _, id := range []string{"../escape", "a/b", "", "UPPER"} {
		if _, err := a.writeSecretFiles(secretReplica(id)); err == nil {
			t.Errorf("replica id %q accepted", id)
		}
	}
	r := secretReplica("ok")
	r.SecretFiles[0].Path = "/run/../etc/passwd"
	if _, err := a.writeSecretFiles(r); err == nil {
		t.Error("unclean target path accepted")
	}
}

func TestSpecHashIgnoresSecretValues(t *testing.T) {
	t.Parallel()
	a, b := secretReplica("r"), secretReplica("r")
	b.Env[1].Value = "other"
	b.SecretFiles[0].Data = []byte("other")
	b.Registry.Password = "other"
	if specHash(a) != specHash(b) {
		t.Error("spec hash depends on secret values")
	}
	b.Env[1].Ref = "db@v3"
	if specHash(a) == specHash(b) {
		t.Error("spec hash ignores the secret version")
	}
	if a.Env[1].Value != secretMarker+"-env" {
		t.Error("specHash mutated its input")
	}
	// Plain env values still count.
	c := secretReplica("r")
	c.Env[0].Value = "2"
	if specHash(a) == specHash(c) {
		t.Error("spec hash ignores plain env")
	}
}
