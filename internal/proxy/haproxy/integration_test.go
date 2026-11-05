//go:build integration

package haproxy

import (
	"net/netip"
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
	type tc struct {
		cfg  proxy.Config
		opts renderOptions
	}
	cases := map[string]tc{
		"full":  {sampleConfig(t), renderOptions{PrivateIP: "10.0.0.2"}},
		"empty": {proxy.Config{}, renderOptions{PrivateIP: "10.0.0.2"}},
		// The internal frontend with the clients map (ADR 0026).
		"callers": {callersConfig(t), callersOptions()},
	}
	for name, c := range cases {
		cfg, opts := c.cfg, c.opts
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
			clients, err := clientsMap(map[netip.Addr]string{netip.MustParseAddr("10.120.0.7"): "shop.staging", netip.MustParseAddr("10.120.0.8"): "frontend"}, netip.MustParsePrefix("10.120.0.0/24"))
			if err != nil {
				t.Fatal(err)
			}
			write(filepath.Join(dir, clientsFile), clients)
			for name, b := range routeFiles(cfg, opts) {
				write(filepath.Join(dir, name), b)
			}
			write(filepath.Join(dir, configFile), render(cfg, assignLayout(nil, cfg, opts.node()), opts))

			out, err := exec.Command(cli, "run", "--rm", "--network", "none",
				"-v", dir+":"+containerConfDir+":ro", "--tmpfs", containerRunDir,
				Image, "haproxy", "-c", "-f", containerConfDir+"/"+configFile).CombinedOutput()
			if err != nil {
				t.Fatalf("haproxy -c failed: %v\n%s", err, out)
			}
		})
	}
}
