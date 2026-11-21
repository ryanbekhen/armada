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

// testSpaceSecrets shares one secret between two apps of a space through
// the client (ADR 0052), against the cluster of TestEndToEnd.
func testSpaceSecrets(t *testing.T, d *fake.Driver, cli func(...string) (int, string, string), config string) {
	t.Helper()
	run := func(stdin string, args ...string) (int, string, string) {
		var out, errOut bytes.Buffer
		code := execute(context.Background(), append(args, "--config", config), strings.NewReader(stdin), &out, &errOut)
		return code, out.String(), errOut.String()
	}
	dir := t.TempDir()
	envFile := filepath.Join(dir, "db.env")
	if err := os.WriteFile(envFile, []byte("DATABASE_URL=postgres://shared\npool-size=5\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, stderr := cli("secret", "create", "shared-db", "--from-env-file", envFile); code != 0 || !strings.Contains(out, "DATABASE_URL (version 1)") {
		t.Fatalf("secret create: code=%d out=%q err=%q", code, out, stderr)
	}
	if code, _, stderr := cli("secret", "create", "shared-db", "--from-env-file", envFile); code == 0 || !strings.Contains(stderr, "exists") {
		t.Errorf("create of an existing secret: code=%d err=%q", code, stderr)
	}
	for _, app := range []string{"reader-a", "reader-b"} {
		if code, _, stderr := cli("app", "create", app, "--image", "nginx:1.27", "--ingress", "none", "--env-from", "shared-db", "--wait", "--timeout", "1m"); code != 0 {
			t.Fatalf("create %s: %s", app, stderr)
		}
		ids := containersOf(d, app)
		if len(ids) == 0 {
			t.Fatalf("no container for %s", app)
		}
		s, _ := d.Spec(ids[len(ids)-1])
		if !slices.Contains(s.Env, "DATABASE_URL=postgres://shared") || !slices.Contains(s.Env, "POOL_SIZE=5") {
			t.Errorf("%s env %v", app, s.Env)
		}
	}
	code, out, _ := cli("secret", "list")
	if code != 0 || !strings.Contains(out, "shared-db") || !strings.Contains(out, "reader-a,reader-b") {
		t.Errorf("secret list = %q", out)
	}
	code, out, _ = cli("secret", "show", "shared-db")
	if code != 0 || !strings.Contains(out, "KEY") || !strings.Contains(out, "reader-a:r1,reader-b:r1") {
		t.Errorf("secret show = %q", out)
	}
	if strings.Contains(out, "postgres://shared") {
		t.Error("secret show printed a value")
	}

	// One set rolls out both apps.
	code, out, stderr := run("postgres://rotated", "secret", "set", "shared-db", "DATABASE_URL", "--wait", "--timeout", "1m")
	if code != 0 || !strings.Contains(out, "reader-a--r2, reader-b--r2") {
		t.Fatalf("secret set with rollout: code=%d out=%q err=%q", code, out, stderr)
	}
	for _, app := range []string{"reader-a", "reader-b"} {
		ids := containersOf(d, app)
		s, _ := d.Spec(ids[len(ids)-1])
		if !slices.Contains(s.Env, "DATABASE_URL=postgres://rotated") {
			t.Errorf("%s after the rollout: %v", app, s.Env)
		}
	}

	if code, _, stderr := cli("secret", "delete", "shared-db", "--yes"); code == 0 || !strings.Contains(stderr, "used by revision") {
		t.Errorf("delete of a used secret: code=%d err=%q", code, stderr)
	}
	if code, _, stderr := cli("secret", "delete", "shared-db"); code == 0 || !strings.Contains(stderr, "--yes") {
		t.Errorf("delete without --yes: code=%d err=%q", code, stderr)
	}

	// The commands before ADR 0052 keep working, with a note on stderr.
	code, out, stderr = cli("secret", "list", "shared-db")
	if code != 0 || !strings.HasPrefix(out, "NAME") || !strings.Contains(stderr, `is now "armada secret show APP"`) || strings.Contains(out, "note:") {
		t.Errorf("old secret list: code=%d out=%q err=%q", code, out, stderr)
	}
}
