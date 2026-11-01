package clientconfig

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ryanbekhen/armada/internal/fsutil"
	"github.com/ryanbekhen/armada/internal/pki"
)

func validConfig(t *testing.T) *Config {
	t.Helper()
	ca, err := pki.NewCA("t")
	if err != nil {
		t.Fatal(err)
	}
	c, k, err := ca.Issue(pki.IssueRequest{Identity: pki.Identity{Kind: pki.KindAdmin, Name: "me"}, Client: true})
	if err != nil {
		t.Fatal(err)
	}
	return &Config{Servers: []string{"127.0.0.1:7443", "127.0.0.1:7444"}, CA: string(ca.CertPEM), Cert: string(c), Key: string(k)}
}

func TestSaveLoad(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "nested", "config")
	want := validConfig(t)
	if err := want.Save(path); err != nil {
		t.Fatal(err)
	}
	if err := fsutil.CheckPrivate(path); err != nil {
		t.Error(err)
	}
	if err := fsutil.CheckPrivate(filepath.Dir(path)); err != nil {
		t.Error(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Error("round trip changed config")
	}
	conn, err := got.Dial()
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
}

func TestLoadErrors(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	if _, err := Load(filepath.Join(dir, "missing")); err == nil || !strings.Contains(err.Error(), "armada init") {
		t.Errorf("missing file err = %v", err)
	}

	loose := filepath.Join(dir, "loose")
	_ = os.WriteFile(loose, []byte("{}"), 0o600)
	_ = os.Chmod(loose, 0o644)
	if _, err := Load(loose); !errors.Is(err, fsutil.ErrInsecurePermissions) {
		t.Errorf("loose perms err = %v", err)
	}

	for name, body := range map[string]string{"garbage": "not json", "incomplete": `{"servers":["x"]}`, "no servers": `{"servers":[],"ca":"a","cert":"b","key":"c"}`} {
		p := filepath.Join(dir, name)
		_ = os.WriteFile(p, []byte(body), 0o600)
		if _, err := Load(p); err == nil {
			t.Errorf("%s accepted", name)
		}
	}

	bad := validConfig(t)
	bad.Key = "junk"
	if _, err := bad.Dial(); err == nil {
		t.Error("Dial accepted invalid key")
	}
}

func TestDefaultPath(t *testing.T) {
	t.Setenv(EnvPath, "/tmp/custom")
	if DefaultPath() != "/tmp/custom" {
		t.Errorf("DefaultPath() = %q", DefaultPath())
	}
	t.Setenv(EnvPath, "")
	if !strings.HasSuffix(DefaultPath(), filepath.Join(".armada", "config")) {
		t.Errorf("DefaultPath() = %q", DefaultPath())
	}
}
