package cli

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/ryanbekhen/armada/internal/runtime/fake"
	"github.com/ryanbekhen/armada/internal/secrets"
)

// testSecrets runs the secret workflow against the cluster of TestEndToEnd
// and checks that the plaintext never shows up in CLI output, server logs,
// the state database, or container labels.
func testSecrets(t *testing.T, d *fake.Driver, cli func(...string) (int, string, string), config, dataDir, secretsDir string, serverLog *lockedBuffer) {
	t.Helper()
	const (
		marker1 = "e2e-s3cr3t-one-5d2c"
		marker2 = "e2e-s3cr3t-two-8e4f"
		fileVal = "e2e-s3cr3t-file-1b9a"
	)
	var outputs []string
	cliIn := func(stdin string, args ...string) (int, string, string) {
		var out, errOut bytes.Buffer
		code := execute(context.Background(), append(args, "--config", config), strings.NewReader(stdin), &out, &errOut)
		outputs = append(outputs, out.String(), errOut.String())
		return code, out.String(), errOut.String()
	}
	run := func(args ...string) (int, string, string) {
		code, out, errOut := cli(args...)
		outputs = append(outputs, out, errOut)
		return code, out, errOut
	}

	// A deploy that references unset secrets fails and names them.
	spec := filepath.Join(t.TempDir(), "api.yaml")
	if err := os.WriteFile(spec, []byte("name: api\nimage: nginx:1.27\nenv:\n  - name: DB_PASSWORD\n    secretRef: db-pass\n"+
		"secretFiles:\n  - secretRef: tls-key\n    path: /run/secrets/tls.key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := run("deploy", "-f", spec); code == 0 || !strings.Contains(stderr, "db-pass, tls-key") || !strings.Contains(stderr, "armada secret set api") {
		t.Fatalf("deploy with unset secrets: code=%d stderr=%q", code, stderr)
	}

	// Values never come from arguments.
	if code, _, _ := run("secret", "set", "api", "db-pass", marker1); code == 0 {
		t.Error("secret value accepted as an argument")
	}
	if code, _, stderr := cliIn("", "secret", "set", "api", "db-pass"); code == 0 || !strings.Contains(stderr, "empty") {
		t.Errorf("empty secret: code=%d stderr=%q", code, stderr)
	}
	if code, _, stderr := cliIn("x", "secret", "set", "api", "Bad_Name"); code == 0 || !strings.Contains(stderr, "secret name") {
		t.Errorf("bad secret name: code=%d stderr=%q", code, stderr)
	}
	big := strings.Repeat("x", secrets.MaxSize+1)
	if code, _, stderr := cliIn(big, "secret", "set", "api", "big"); code == 0 || !strings.Contains(stderr, "larger than") {
		t.Errorf("oversized secret: code=%d stderr=%q", code, stderr)
	}

	code, out, stderr := cliIn(marker1+"\n", "secret", "set", "api", "db-pass")
	if code != 0 || !strings.Contains(out, "Secret db-pass of app api set (version 1)") {
		t.Fatalf("secret set: code=%d out=%q err=%q", code, out, stderr)
	}
	keyFile := filepath.Join(t.TempDir(), "tls.key")
	if err := os.WriteFile(keyFile, []byte(fileVal+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := run("secret", "set", "api", "tls-key", "--from-file", keyFile); code != 0 {
		t.Fatalf("secret set --from-file: %q", stderr)
	}
	if code, out, stderr := run("deploy", "-f", spec, "--wait", "--timeout", "1m"); code != 0 {
		t.Fatalf("deploy with secrets: code=%d out=%q err=%q", code, out, stderr)
	}

	envOf := func() []string {
		for _, c := range containersOf(d, "api") {
			s, _ := d.Spec(c)
			return s.Env
		}
		return nil
	}
	if env := envOf(); !slices.Contains(env, "DB_PASSWORD="+marker1) {
		t.Errorf("container env = %v", env)
	}
	files, _ := filepath.Glob(filepath.Join(secretsDir, "api-*", "0"))
	if len(files) != 1 {
		t.Fatalf("secret files = %v", files)
	}
	// --from-file keeps the bytes exactly, trailing newline included.
	if b, _ := os.ReadFile(files[0]); string(b) != fileVal+"\n" {
		t.Errorf("secret file = %q", b)
	}

	// A new value rolls out by itself.
	code, out, stderr = cliIn(marker2, "secret", "set", "api", "db-pass", "--wait", "--timeout", "1m")
	if code != 0 || !strings.Contains(out, "version 2") || !strings.Contains(out, "Rolling out api--r2") {
		t.Fatalf("secret rotation: code=%d out=%q err=%q", code, out, stderr)
	}
	deadline := time.Now().Add(10 * time.Second)
	for !slices.Contains(envOf(), "DB_PASSWORD="+marker2) && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if env := envOf(); !slices.Contains(env, "DB_PASSWORD="+marker2) || len(containersOf(d, "api")) != 1 {
		t.Errorf("after rotation: env = %v, containers = %d", env, len(containersOf(d, "api")))
	}

	code, out, _ = run("secret", "list", "api")
	if code != 0 || !regexp.MustCompile(`db-pass\s+2\s+.*admin:ryan\s+api--r2,api--r1`).MatchString(out) || !strings.Contains(out, "tls-key") {
		t.Errorf("secret list:\n%s", out)
	}
	if code, _, stderr := run("secret", "rm", "api", "db-pass"); code == 0 || !strings.Contains(stderr, "used by revision api--r2") {
		t.Errorf("rm of a secret in use: code=%d stderr=%q", code, stderr)
	}
	if code, out, _ := cliIn("x", "secret", "set", "api", "spare", "--no-rollout"); code != 0 || !strings.Contains(out, "version 1") {
		t.Errorf("set unused secret: %q", out)
	}
	if code, _, stderr := run("secret", "rm", "api", "spare"); code != 0 {
		t.Errorf("rm unused secret: %q", stderr)
	}

	// The plaintext appears nowhere it should not.
	for _, m := range []string{marker1, marker2, fileVal} {
		for _, o := range outputs {
			if strings.Contains(o, m) {
				t.Errorf("CLI output contains a secret: %q", o)
			}
		}
		if strings.Contains(serverLog.String(), m) {
			t.Errorf("server log contains secret %s", m)
		}
		// The state on disk: etcd's WAL, snapshots, and database.
		var stateFiles int
		_ = filepath.WalkDir(filepath.Join(dataDir, dirEtcd), func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			stateFiles++
			if b, _ := os.ReadFile(p); bytes.Contains(b, []byte(m)) {
				t.Errorf("%s contains secret %s", p, m)
			}
			return nil
		})
		if stateFiles == 0 {
			t.Error("no state files found; is the data dir right?")
		}
		for _, c := range containersOf(d, "api") {
			s, _ := d.Spec(c)
			for k, v := range s.Labels {
				if strings.Contains(v, m) {
					t.Errorf("label %s contains a secret", k)
				}
			}
		}
	}
	if !strings.Contains(serverLog.String(), `"msg":"secret set"`) {
		t.Error("server log has no secret events; is it captured?")
	}
}

func containersOf(d *fake.Driver, app string) []string {
	cs, _ := d.List(context.Background(), map[string]string{"armada.app": app})
	ids := make([]string, 0, len(cs))
	for _, c := range cs {
		ids = append(ids, c.ID)
	}
	return ids
}

func TestSecretValueFromTerminal(t *testing.T) {
	orig := readTerminalSecret
	t.Cleanup(func() { readTerminalSecret = orig })
	readTerminalSecret = func(*cobra.Command) ([]byte, error) { return []byte("typed\n"), nil }
	cmd := &cobra.Command{}
	cmd.SetIn(strings.NewReader("piped"))
	b, err := readSecretValue(cmd, "")
	// Hidden prompt input is kept as typed (ReadPassword strips the Enter).
	if err != nil || string(b) != "typed\n" {
		t.Errorf("terminal value = %q, %v", b, err)
	}
	readTerminalSecret = func(*cobra.Command) ([]byte, error) { return nil, errNotTerminal }
	cmd.SetIn(strings.NewReader("piped\r\n"))
	if b, err := readSecretValue(cmd, ""); err != nil || string(b) != "piped" {
		t.Errorf("piped value = %q, %v", b, err)
	}
}
