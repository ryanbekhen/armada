package clientconfig

import (
	"errors"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func me(t *testing.T, home string) *user.User {
	t.Helper()
	return &user.User{Username: "me", Uid: strconv.Itoa(os.Getuid()), Gid: strconv.Itoa(os.Getgid()), HomeDir: home}
}

func TestSaveOwn(t *testing.T) {
	home := t.TempDir()
	c := validConfig(t)
	path, err := c.SaveOwn(me(t, home))
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(home, ".armada", "config"); path != want {
		t.Fatalf("path = %s, want %s", path, want)
	}
	for p, mode := range map[string]fs.FileMode{path: 0o600, filepath.Dir(path): 0o700} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != mode {
			t.Errorf("%s mode %04o, want %04o", p, fi.Mode().Perm(), mode)
		}
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Cert != c.Cert {
		t.Error("loaded config differs")
	}

	// Never replaces a file.
	if err := os.WriteFile(path, []byte("mine"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SaveOwn(me(t, home)); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("second SaveOwn: %v, want ErrExist", err)
	}
	if b, _ := os.ReadFile(path); string(b) != "mine" {
		t.Error("existing config replaced")
	}
}

func TestSaveOwnStaysInHome(t *testing.T) {
	home, elsewhere := t.TempDir(), t.TempDir()
	if err := os.Symlink(elsewhere, filepath.Join(home, ".armada")); err != nil {
		t.Fatal(err)
	}
	if _, err := validConfig(t).SaveOwn(me(t, home)); err == nil {
		t.Fatal("SaveOwn followed a link out of the home directory")
	}
	if _, err := os.Stat(filepath.Join(elsewhere, "config")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("file written outside the home directory: %v", err)
	}
}

func TestGroupAdvice(t *testing.T) {
	const gid = 4242
	oldS, oldA := sessionGroups, accountGroups
	t.Cleanup(func() { sessionGroups, accountGroups = oldS, oldA })
	for _, tc := range []struct {
		session []int
		account []string
		want    string
	}{
		{nil, nil, "not in the armada group"},
		{nil, []string{strconv.Itoa(gid)}, "log in again"},
		{[]int{gid}, []string{strconv.Itoa(gid)}, "not shared"},
	} {
		sessionGroups = func() ([]int, error) { return tc.session, nil }
		accountGroups = func() ([]string, error) { return tc.account, nil }
		if got := adviceFor(gid); !strings.Contains(got, tc.want) {
			t.Errorf("session %v, account %v: %q, want %q", tc.session, tc.account, got, tc.want)
		}
	}
}
