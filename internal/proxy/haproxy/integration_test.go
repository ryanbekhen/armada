//go:build integration

package haproxy

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/ryanbekhen/armada/internal/proxy"
)

// TestIntegrationConfigValid renders configurations and checks them with
// the pinned HAProxy image (`haproxy -c`). It is a development check and
// needs a Docker-compatible CLI on the developer's machine (docker, podman,
// or nerdctl); Armada itself does not use one:
//
//	go test -tags integration ./internal/proxy/haproxy/ -run Integration
func TestIntegrationConfigValid(t *testing.T) {
	cli := ""
	for _, c := range []string{"docker", "podman", "nerdctl"} {
		if _, err := exec.LookPath(c); err == nil {
			cli = c
			break
		}
	}
	if cli == "" {
		t.Skip("no docker, podman, or nerdctl CLI")
	}
	cases := map[string]proxy.Config{
		"full":  sampleConfig(t),
		"empty": {},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			// The check runs as root without capabilities, so the files must
			// be readable without CAP_DAC_OVERRIDE.
			if err := os.Chmod(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			certs := filepath.Join(dir, certDir)
			if err := os.Mkdir(certs, 0o755); err != nil {
				t.Fatal(err)
			}
			write := func(path string, b []byte) {
				if err := os.WriteFile(path, b, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			write(filepath.Join(dir, defaultCertFile), cert(t))
			for _, c := range cfg.Certificates {
				write(filepath.Join(certs, c.FileName()), c.PEM)
			}
			write(filepath.Join(dir, configFile), render(cfg, assignLayout(nil, cfg, renderOptions{PrivateIP: "10.0.0.2"}.node()), renderOptions{PrivateIP: "10.0.0.2"}))

			out, err := exec.Command(cli, "run", "--rm", "--network", "none",
				"-v", dir+":"+containerConfDir+":ro", "--tmpfs", containerRunDir,
				Image, "haproxy", "-c", "-f", containerConfDir+"/"+configFile).CombinedOutput()
			if err != nil {
				t.Fatalf("haproxy -c failed: %v\n%s", err, out)
			}
		})
	}
}
