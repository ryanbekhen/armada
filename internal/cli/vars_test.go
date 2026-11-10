package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadVars(t *testing.T) {
	file := filepath.Join(t.TempDir(), "production.env")
	if err := os.WriteFile(file, []byte("# production\nDOMAIN=example.com\r\n\nTAG=old\nURL=https://x/?a=b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	vars, err := loadVars(file, []string{"TAG=sha-1", "EMPTY="})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"DOMAIN": "example.com", "TAG": "sha-1", "URL": "https://x/?a=b", "EMPTY": ""}
	if len(vars) != len(want) {
		t.Errorf("vars = %v", vars)
	}
	for k, v := range want {
		if vars[k] != v {
			t.Errorf("%s = %q, want %q", k, vars[k], v)
		}
	}

	for _, bad := range []string{"no-equals", "1X=a", "A-B=c"} {
		if _, err := loadVars("", []string{bad}); err == nil {
			t.Errorf("--var %q accepted", bad)
		}
	}
	dup := filepath.Join(t.TempDir(), "dup.env")
	if err := os.WriteFile(dup, []byte("A=1\nA=2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadVars(dup, nil); err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Errorf("duplicate: %v", err)
	}
}
