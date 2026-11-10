package daemon

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ryanbekhen/armada/internal/runtime/fake"
)

// testEnvFrom deploys a spec with variables and envFrom: secrets against the
// cluster of TestEndToEnd (ADR 0029).
func testEnvFrom(t *testing.T, d *fake.Driver, cli func(...string) (int, string, string), config string) {
	t.Helper()
	set := func(name, value string) {
		var out, errOut bytes.Buffer
		if code := execute(context.Background(), []string{"secret", "set", "envd", name, "--config", config}, strings.NewReader(value), &out, &errOut); code != 0 {
			t.Fatalf("secret set %s: %s", name, errOut.String())
		}
	}
	set("database-url", "postgres://db")
	set("node-env", "ignored")

	dir := t.TempDir()
	spec := filepath.Join(dir, "envd.yaml")
	vars := filepath.Join(dir, "dev.env")
	if err := os.WriteFile(spec, []byte("name: envd\nimage: nginx:${TAG}\nenvFrom: secrets\nenv:\n  - { name: NODE_ENV, value: ${MODE} }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vars, []byte("TAG=1.26\nMODE=development\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := cli("deploy", "-f", spec, "--var", "TAG=1.27"); code == 0 || !strings.Contains(stderr, "MODE") {
		t.Errorf("deploy without MODE: code=%d stderr=%q", code, stderr)
	}
	if code, _, stderr := cli("deploy", "-f", spec, "--vars", vars, "--var", "TAG=1.27", "--wait", "--timeout", "1m"); code != 0 {
		t.Fatalf("deploy with vars: %s", stderr)
	}
	ids := containersOf(d, "envd")
	if len(ids) == 0 {
		t.Fatal("no container for envd")
	}
	s, _ := d.Spec(ids[len(ids)-1])
	if s.Image != "nginx:1.27" || !slices.Contains(s.Env, "DATABASE_URL=postgres://db") || !slices.Contains(s.Env, "NODE_ENV=development") {
		t.Errorf("container image %s env %v", s.Image, s.Env)
	}
}
