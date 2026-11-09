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

	if _, err := Load(filepath.Join(dir, "missing")); err == nil || !strings.Contains(err.Error(), "armadad init") {
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

func TestDefaultPathSystem(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv(EnvPath, "")
	old := systemPath
	t.Cleanup(func() { systemPath = old })
	systemPath = filepath.Join(t.TempDir(), "admin.config")

	own := filepath.Join(home, ".armada", "config")
	if got := DefaultPath(); got != own {
		t.Errorf("nothing there: %q, want %q", got, own)
	}
	if err := os.WriteFile(systemPath, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := DefaultPath(); got != systemPath {
		t.Errorf("only the system config: %q", got)
	}
	if err := validConfig(t).Save(own); err != nil {
		t.Fatal(err)
	}
	if got := DefaultPath(); got != own {
		t.Errorf("own config first: %q", got)
	}
}

func TestSharedConfig(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("checks what a user other than root may not do")
	}
	t.Parallel()
	dir := t.TempDir()

	// Group-readable but not owned by root: refused.
	p := filepath.Join(dir, "own", "config")
	if err := validConfig(t).Save(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); !errors.Is(err, fsutil.ErrInsecurePermissions) {
		t.Errorf("0640 owned by a user: %v", err)
	}

	// Rewriting a private config keeps it private.
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validConfig(t).SaveFile(p); err != nil {
		t.Fatal(err)
	}
	if err := fsutil.CheckPrivate(p); err != nil {
		t.Error(err)
	}

	// SaveShared makes the directory searchable but not listable; without
	// root the file cannot be given to the group and stays 0600.
	etc := filepath.Join(dir, "etc")
	if err := os.Mkdir(etc, 0o700); err != nil {
		t.Fatal(err)
	}
	shared, err := validConfig(t).SaveShared(filepath.Join(etc, "admin.config"))
	if _, gerr := groupID(); gerr == nil {
		if err == nil {
			t.Error("a user gave the config to the group")
		}
	} else if err != nil || shared {
		t.Errorf("no group: shared %v, %v", shared, err)
	}
	if fi, err := os.Stat(etc); err != nil || fi.Mode().Perm() != 0o711 {
		t.Errorf("directory: %v %v", fi.Mode().Perm(), err)
	}
}
