package spec

import (
	"slices"
	"strings"
	"testing"
)

const withContainers = `name: web
image: ghcr.io/acme/web:1
resources:
  cpu: 500m
  memory: 512Mi
volumes:
  - name: data
    path: /data
secretFiles:
  - secretRef: tls
    path: /run/tls/key
scale:
  min: 1
  max: 1
initContainers:
  - name: migrate
    image: ghcr.io/acme/web:1
    command: ["./migrate"]
    env:
      - name: DATABASE_URL
        secretRef: database-url
    resources:
      memory: 1Gi
    volumes: [data]
sidecars:
  - name: log-shipper
    image: ghcr.io/acme/shipper:2
    args: ["--to", "logs.internal"]
    resources:
      cpu: 100m
      memory: 128Mi
    secretFiles: [/run/tls/key]
  - name: proxy
    image: envoy
`

func TestContainers(t *testing.T) {
	t.Parallel()
	a, err := Parse([]byte(withContainers))
	if err != nil {
		t.Fatal(err)
	}
	if !a.HasContainers() || !slices.Equal(a.ContainerNames(), []string{"migrate", "log-shipper", "proxy"}) {
		t.Fatalf("containers %v", a.ContainerNames())
	}
	// The app's env is not inherited; secrets of containers are the app's.
	if !slices.Contains(a.SecretRefs(), "database-url") {
		t.Errorf("secret refs %v", a.SecretRefs())
	}
	// Defaults: 64Mi and 10m reserved, no CPU limit.
	proxy := a.Sidecars[1]
	if proxy.MemoryBytes() != 64<<20 || proxy.CPUMillis() != DefaultContainerCPUMillis || proxy.NanoCPUs() != 0 {
		t.Errorf("defaults: %d %d %d", proxy.MemoryBytes(), proxy.CPUMillis(), proxy.NanoCPUs())
	}
	// The replica reserves the app and its sidecars, or its largest init
	// container if that is more.
	if got := a.ReservedCPUMillis(); got != 500+100+10 {
		t.Errorf("cpu reserved %d", got)
	}
	if got := a.ReservedMemoryBytes(); got != 1<<30 {
		t.Errorf("memory reserved %d, want the init container's 1Gi", got)
	}
	a.InitContainers[0].Resources.Memory = "128Mi"
	if got := a.ReservedMemoryBytes(); got != 512<<20+128<<20+64<<20 {
		t.Errorf("memory reserved %d", got)
	}
	// Without containers nothing changes.
	plain, err := Parse([]byte("name: x\nimage: y\n"))
	if err != nil {
		t.Fatal(err)
	}
	if plain.HasContainers() || plain.ReservedCPUMillis() != plain.CPUMillis() || plain.ReservedMemoryBytes() != plain.MemoryBytes() {
		t.Errorf("plain app reserves %d %d", plain.ReservedCPUMillis(), plain.ReservedMemoryBytes())
	}
	// Exported and parsed again, it is the same spec.
	out, err := a.Export()
	if err != nil {
		t.Fatal(err)
	}
	back, err := Parse(out)
	if err != nil || len(back.Sidecars) != 2 || back.InitContainers[0].Volumes[0] != "data" {
		t.Errorf("export: %v\n%s", err, out)
	}

	// A job may have them too.
	if _, err := Parse([]byte("kind: job\nname: j\nimage: y\nsidecars:\n  - name: proxy\n    image: envoy\n")); err != nil {
		t.Errorf("job with a sidecar: %v", err)
	}
}

func TestContainersInvalid(t *testing.T) {
	t.Parallel()
	app := func(rest string) string { return "name: web\nimage: nginx\n" + rest }
	side := func(entry string) string { return app("sidecars:\n  - " + entry) }
	for name, c := range map[string]struct{ yaml, field string }{
		"no name":           {side("image: envoy\n"), "sidecars[0].name"},
		"bad name":          {side("name: Proxy\n    image: envoy\n"), "sidecars[0].name"},
		"long name":         {side("name: " + strings.Repeat("a", 31) + "\n    image: envoy\n"), "sidecars[0].name"},
		"reserved name":     {side("name: app\n    image: envoy\n"), "sidecars[0].name"},
		"repeated name":     {app("initContainers:\n  - name: x\n    image: a\nsidecars:\n  - name: x\n    image: b\n"), "sidecars[0].name"},
		"no image":          {side("name: proxy\n"), "sidecars[0].image"},
		"bad image":         {side("name: proxy\n    image: 'Bad Image'\n"), "sidecars[0].image"},
		"reserved env":      {side("name: proxy\n    image: envoy\n    env:\n      - name: ARMADA_X\n        value: y\n"), "sidecars[0].env[0].name"},
		"port env":          {side("name: proxy\n    image: envoy\n    env:\n      - name: PORT\n        value: \"1\"\n"), "sidecars[0].env[0].name"},
		"bad secret":        {side("name: proxy\n    image: envoy\n    env:\n      - name: X\n        secretRef: Bad_Name\n"), "sidecars[0].env[0].secretRef"},
		"value and secret":  {side("name: proxy\n    image: envoy\n    env:\n      - name: X\n        value: a\n        secretRef: b\n"), "sidecars[0].env[0]"},
		"bad memory":        {side("name: proxy\n    image: envoy\n    resources:\n      memory: 1Ki\n"), "sidecars[0].resources.memory"},
		"bad cpu":           {side("name: proxy\n    image: envoy\n    resources:\n      cpu: lots\n"), "sidecars[0].resources.cpu"},
		"unknown volume":    {side("name: proxy\n    image: envoy\n    volumes: [data]\n"), "sidecars[0].volumes[0]"},
		"unknown file":      {side("name: proxy\n    image: envoy\n    secretFiles: [/run/key]\n"), "sidecars[0].secretFiles[0]"},
		"repeated file":     {app("secretFiles:\n  - secretRef: k\n    path: /k\nsidecars:\n  - name: p\n    image: e\n    secretFiles: [/k, /k]\n"), "sidecars[0].secretFiles[1]"},
		"long command":      {side("name: proxy\n    image: envoy\n    command: [\"" + strings.Repeat("a", 4097) + "\"]\n"), "sidecars[0].command[0]"},
		"probes":            {side("name: proxy\n    image: envoy\n    probes:\n      readiness: /\n"), ""},
		"ports":             {side("name: proxy\n    image: envoy\n    port: 80\n"), ""},
		"too many inits":    {app("initContainers:\n" + strings.Repeat("  - name: a\n    image: b\n", MaxInitContainers+1)), "initContainers"},
		"too many sidecars": {app("sidecars:\n" + strings.Repeat("  - name: a\n    image: b\n", MaxSidecars+1)), "sidecars"},
	} {
		_, err := Parse([]byte(c.yaml))
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if c.field != "" && !strings.Contains(err.Error(), c.field+":") {
			t.Errorf("%s: %v does not name %s", name, err, c.field)
		}
	}
}
