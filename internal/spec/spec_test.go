package spec

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

const fullSpec = `
apiVersion: armada.dev/v1alpha1
name: api-bengkel
image: ghcr.io/ryan/api:v1.4.0
command: ["/app/server"]
args: ["--verbose"]
env:
  - name: LOG_LEVEL
    value: debug
ingress:
  type: external
  port: 3000
  domains:
    - bengkele.id
    - www.bengkele.id
  routes:
    - path: /api
      stripPrefix: true
    - path: /
probes:
  readiness: /healthz
  liveness:
    path: /livez
    period: 5s
    timeout: 2s
    failureThreshold: 5
scale:
  min: 2
  max: 5
resources:
  cpu: 500m
  memory: 512Mi
`

func TestParseFullSpec(t *testing.T) {
	t.Parallel()

	app, err := Parse([]byte(fullSpec))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if app.Name != "api-bengkel" || app.Kind != KindApp {
		t.Errorf("name/kind = %q/%q", app.Name, app.Kind)
	}
	if app.Replicas() != 2 || *app.Scale.Max != 5 {
		t.Errorf("replicas = %d, max = %d", app.Replicas(), *app.Scale.Max)
	}
	if got := app.MemoryBytes(); got != 512<<20 {
		t.Errorf("MemoryBytes() = %d", got)
	}
	if got := app.NanoCPUs(); got != 500_000_000 {
		t.Errorf("NanoCPUs() = %d", got)
	}
	r := app.Probes.Readiness
	if r.Path != "/healthz" || r.Port != 3000 || r.Period.D() != 10*time.Second || r.Timeout.D() != time.Second || r.FailureThreshold != 3 {
		t.Errorf("readiness defaults not applied: %+v", r)
	}
	l := app.Probes.Liveness
	if l.Period.D() != 5*time.Second || l.Timeout.D() != 2*time.Second || l.FailureThreshold != 5 {
		t.Errorf("liveness = %+v", l)
	}
	if app.Revisions.Mode != RevisionsSingle {
		t.Errorf("revisions.mode = %q", app.Revisions.Mode)
	}
}

func TestParseInternalIngress(t *testing.T) {
	t.Parallel()

	app, err := Parse([]byte("name: shop-api\nimage: busybox\ningress:\n  type: internal\n  port: 8080\n  routes:\n    - path: /v1\n"))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if app.Ingress.Type != IngressInternal || InternalHost(app.Name) != "shop-api.internal" {
		t.Errorf("ingress = %+v", app.Ingress)
	}
}

func TestParseMinimalDefaults(t *testing.T) {
	t.Parallel()

	app, err := Parse([]byte("name: worker\nimage: busybox\n"))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if app.Ingress.Type != IngressNone {
		t.Errorf("ingress.type = %q, want none", app.Ingress.Type)
	}
	if app.Replicas() != 1 || *app.Scale.Max != 1 {
		t.Errorf("replicas = %d, max = %d", app.Replicas(), *app.Scale.Max)
	}
	if app.Resources.Memory != DefaultMemory || app.NanoCPUs() != 0 {
		t.Errorf("resources = %+v", app.Resources)
	}
	if app.Probes != nil {
		t.Errorf("probes = %+v, want nil", app.Probes)
	}
}

func TestParseRejects(t *testing.T) {
	t.Parallel()

	base := "name: web\nimage: nginx\n"
	ext := base + "ingress:\n  type: external\n  port: 80\n"

	tests := []struct {
		name        string
		yaml        string
		wantField   string
		unsupported bool
	}{
		{"empty", "", "", false},
		{"unknown field", base + "replicas: 3\n", "", false},
		{"unknown nested field", ext[:len(ext)-1] + "\n  tls: true\n", "", false},
		{"unknown probe field", base + "probes:\n  readiness:\n    path: /h\n    port: 80\n    retries: 2\n", "", false},
		{"two documents", base + "---\n" + base, "", false},
		{"wrong apiVersion", "apiVersion: v2\n" + base, "apiVersion", false},
		{"bad kind", "kind: service\n" + base, "kind", false},
		{"job kind", "kind: job\nname: x\nimage: y\n", "kind", true},
		{"missing name", "image: nginx\n", "name", false},
		{"uppercase name", "name: Web\nimage: nginx\n", "name", false},
		{"double hyphen name", "name: web--canary\nimage: nginx\n", "name", false},
		{"trailing hyphen", "name: web-\nimage: nginx\n", "name", false},
		{"long name", "name: " + strings.Repeat("a", 64) + "\nimage: nginx\n", "name", false},
		{"missing image", "name: web\n", "image", false},
		{"image with space", "name: web\nimage: \"nginx latest\"\n", "image", false},
		{"image with newline", "name: web\nimage: \"nginx\\nlatest\"\n", "image", false},
		{"bad env name", base + "env:\n  - name: 1BAD\n    value: x\n", "env[0].name", false},
		{"reserved env", base + "env:\n  - name: ARMADA_APP\n    value: x\n", "env[0].name", false},
		{"reserved PORT", base + "env:\n  - name: PORT\n    value: x\n", "env[0].name", false},
		{"duplicate env", base + "env:\n  - name: A\n    value: x\n  - name: A\n    value: y\n", "env[1].name", false},
		{"bad secretRef", base + "env:\n  - name: DB\n    secretRef: Db_Pass\n", "env[0].secretRef", false},
		{"value and secretRef", base + "env:\n  - name: DB\n    value: x\n    secretRef: db\n", "env[0]", false},
		{"secret file relative", base + "secretFiles:\n  - secretRef: k\n    path: run/k\n", "secretFiles[0].path", false},
		{"secret file dotdot", base + "secretFiles:\n  - secretRef: k\n    path: /run/../etc/shadow\n", "secretFiles[0].path", false},
		{"secret file proc", base + "secretFiles:\n  - secretRef: k\n    path: /proc/self/x\n", "secretFiles[0].path", false},
		{"secret file hosts", base + "secretFiles:\n  - secretRef: k\n    path: /etc/hosts\n", "secretFiles[0].path", false},
		{"secret file space", base + "secretFiles:\n  - secretRef: k\n    path: \"/run/a b\"\n", "secretFiles[0].path", false},
		{"secret file duplicate", base + "secretFiles:\n  - secretRef: a\n    path: /run/k\n  - secretRef: b\n    path: /run/k\n", "secretFiles[1].path", false},
		{"secret file overlap", base + "secretFiles:\n  - secretRef: a\n    path: /run/k\n  - secretRef: b\n    path: /run/k/x\n", "secretFiles[1].path", false},
		{"secret file bad ref", base + "secretFiles:\n  - secretRef: \"\"\n    path: /run/k\n", "secretFiles[0].secretRef", false},
		{"registry mismatch", base + "registry:\n  server: ghcr.io\n  username: u\n  passwordSecretRef: p\n", "registry.server", false},
		{"registry bad server", "name: web\nimage: ghcr.io/a/b:1\nregistry:\n  server: \"ghcr.io/evil\"\n  username: u\n  passwordSecretRef: p\n", "registry.server", false},
		{"registry no username", "name: web\nimage: ghcr.io/a/b:1\nregistry:\n  server: ghcr.io\n  passwordSecretRef: p\n", "registry.username", false},
		{"registry username newline", "name: web\nimage: ghcr.io/a/b:1\nregistry:\n  server: ghcr.io\n  username: \"a\\nb\"\n  passwordSecretRef: p\n", "registry.username", false},
		{"registry no password", "name: web\nimage: ghcr.io/a/b:1\nregistry:\n  server: ghcr.io\n  username: u\n", "registry.passwordSecretRef", false},
		{"NUL in arg", base + "args: [\"a\\0b\"]\n", "args[0]", false},
		{"ingress without type", base + "ingress:\n  port: 80\n", "ingress.type", false},
		{"ingress bad type", base + "ingress:\n  type: public\n", "ingress.type", false},
		{"internal with domains", base + "ingress:\n  type: internal\n  port: 80\n  domains: [shop.example.com]\n", "ingress.domains", false},
		{"domain in the internal zone", base + "ingress:\n  type: external\n  port: 80\n  domains: [shop.internal]\n", "ingress.domains[0]", false},
		{"ingress none with port", base + "ingress:\n  type: none\n  port: 80\n", "ingress", false},
		{"ingress port zero", base + "ingress:\n  type: external\n", "ingress.port", false},
		{"ingress port too big", base + "ingress:\n  type: external\n  port: 70000\n", "ingress.port", false},
		{"uppercase domain", ext + "  domains: [Example.com]\n", "ingress.domains[0]", false},
		{"single label domain", ext + "  domains: [localhost]\n", "ingress.domains[0]", false},
		{"wildcard domain", ext + "  domains: [\"*.example.com\"]\n", "ingress.domains[0]", false},
		{"ip domain", ext + "  domains: [10.0.0.1]\n", "ingress.domains[0]", false},
		{"domain injection", ext + "  domains: [\"a.com\\n  bind :8080\"]\n", "ingress.domains[0]", false},
		{"domain with space", ext + "  domains: [\"a.com b.com\"]\n", "ingress.domains[0]", false},
		{"duplicate domain", ext + "  domains: [a.com, a.com]\n", "ingress.domains[1]", false},
		{"route without slash", ext + "  routes:\n    - path: api\n", "ingress.routes[0].path", false},
		{"route trailing slash", ext + "  routes:\n    - path: /api/\n", "ingress.routes[0].path", false},
		{"route double slash", ext + "  routes:\n    - path: /a//b\n", "ingress.routes[0].path", false},
		{"route dotdot", ext + "  routes:\n    - path: /a/..\n", "ingress.routes[0].path", false},
		{"route with space", ext + "  routes:\n    - path: \"/a b\"\n", "ingress.routes[0].path", false},
		{"route with hash", ext + "  routes:\n    - path: \"/a#b\"\n", "ingress.routes[0].path", false},
		{"route with regex", ext + "  routes:\n    - path: \"/a.*\"\n", "ingress.routes[0].path", false},
		{"duplicate route", ext + "  routes:\n    - path: /a\n    - path: /a\n", "ingress.routes[1].path", false},
		{"strip root", ext + "  routes:\n    - path: /\n      stripPrefix: true\n", "ingress.routes[0].stripPrefix", false},
		{"multiple revisions", base + "revisions:\n  mode: multiple\n", "revisions.mode", true},
		{"bad revision mode", base + "revisions:\n  mode: blue\n", "revisions.mode", false},
		{"traffic in single", base + "revisions:\n  traffic:\n    - revision: latest\n      weight: 100\n", "revisions.traffic", false},
		{"probe without port", base + "probes:\n  readiness: /healthz\n", "probes.readiness.port", false},
		{"probe bad path", ext + "probes:\n  readiness: healthz\n", "probes.readiness.path", false},
		{"probe bad duration", ext + "probes:\n  readiness:\n    path: /h\n    period: soon\n", "", false},
		{"probe period too short", ext + "probes:\n  readiness:\n    path: /h\n    period: 500ms\n", "probes.readiness.period", false},
		{"probe timeout over period", ext + "probes:\n  readiness:\n    path: /h\n    period: 2s\n    timeout: 3s\n", "probes.readiness.timeout", false},
		{"probe threshold", ext + "probes:\n  liveness:\n    path: /h\n    failureThreshold: 101\n", "probes.liveness.failureThreshold", false},
		{"scale to zero", base + "scale:\n  min: 0\n", "scale.min", true},
		{"negative min", base + "scale:\n  min: -1\n", "scale.min", false},
		{"too many replicas", base + "scale:\n  min: 101\n", "scale.min", false},
		{"max below min", base + "scale:\n  min: 3\n  max: 2\n", "scale.max", false},
		{"scale rules", base + "scale:\n  rules:\n    - type: http\n      concurrent: 50\n", "scale.rules", true},
		{"bad memory", base + "resources:\n  memory: lots\n", "resources.memory", false},
		{"tiny memory", base + "resources:\n  memory: 1Mi\n", "resources.memory", false},
		{"huge memory", base + "resources:\n  memory: 128Gi\n", "resources.memory", false},
		{"bad cpu", base + "resources:\n  cpu: fast\n", "resources.cpu", false},
		{"tiny cpu", base + "resources:\n  cpu: 1m\n", "resources.cpu", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := Parse([]byte(tt.yaml))
			if err == nil {
				t.Fatal("Parse() succeeded, want error")
			}
			if tt.wantField != "" && !hasField(err, tt.wantField) {
				t.Errorf("error %q does not mention field %q", err, tt.wantField)
			}
			if got := errors.Is(err, ErrUnsupported); got != tt.unsupported {
				t.Errorf("errors.Is(err, ErrUnsupported) = %v, want %v (err: %v)", got, tt.unsupported, err)
			}
		})
	}
}

func hasField(err error, field string) bool {
	var fe *FieldError
	for _, e := range flatten(err) {
		if errors.As(e, &fe) && fe.Field == field {
			return true
		}
	}
	return false
}

func flatten(err error) []error {
	if j, ok := err.(interface{ Unwrap() []error }); ok {
		return j.Unwrap()
	}
	return []error{err}
}

func TestParseReportsAllErrors(t *testing.T) {
	t.Parallel()

	_, err := Parse([]byte("name: BAD\nimage: \"x y\"\nscale:\n  min: 200\n"))
	if err == nil {
		t.Fatal("want error")
	}
	for _, f := range []string{"name", "image", "scale.min"} {
		if !hasField(err, f) {
			t.Errorf("missing error for %s in %q", f, err)
		}
	}
}

func TestParseSizeLimit(t *testing.T) {
	t.Parallel()

	big := make([]byte, MaxSpecBytes+1)
	if _, err := Parse(big); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("Parse(big) error = %v", err)
	}
}

func TestImageReferences(t *testing.T) {
	t.Parallel()

	valid := []string{
		"nginx", "nginx:1.27", "library/nginx:latest", "ghcr.io/ryan/api:v1.4.0",
		"localhost:5000/app", "registry.example.com:5000/team/app:2026-10-30",
		"nginx@sha256:" + strings.Repeat("a", 64), "ghcr.io/a/b:v1@sha256:" + strings.Repeat("0", 64),
		"my_registry.io/a__b/c-d", "a.b-c.io/x.y",
	}
	invalid := []string{
		"", "NGINX", "nginx:", ":tag", "nginx:-bad", "nginx@sha256:abc", "nginx latest",
		"nginx;rm -rf /", "../etc/passwd", "nginx\n", "-nginx",
	}
	for _, s := range valid {
		var v validator
		v.image("image", s)
		if len(v.errs) > 0 {
			t.Errorf("image %q rejected: %v", s, v.errs)
		}
	}
	for _, s := range invalid {
		var v validator
		v.image("image", s)
		if len(v.errs) == 0 {
			t.Errorf("image %q accepted", s)
		}
	}
}

func TestValidateDomain(t *testing.T) {
	t.Parallel()

	for _, d := range []string{"a.co", "api-bengkel.apps.contoh.id", "xn--bcher-kva.example", "a1.b2.c3"} {
		if err := ValidateDomain(d); err != nil {
			t.Errorf("ValidateDomain(%q) = %v", d, err)
		}
	}
	for _, d := range []string{"", "a", "a..b", ".a.b", "a.b.", "-a.b", "a-.b", "a_b.c", "A.b",
		strings.Repeat("a", 64) + ".com", strings.Repeat("a.", 127) + "com", "1.2.3.4", "a.b/c", "a.b:80", "shop.internal", "a.b.internal"} {
		if err := ValidateDomain(d); err == nil {
			t.Errorf("ValidateDomain(%q) accepted", d)
		}
	}
}

func TestParseMemory(t *testing.T) {
	t.Parallel()

	tests := map[string]int64{
		"1024": 1024, "1K": 1000, "1Ki": 1024, "256Mi": 256 << 20, "1M": 1e6, "2Gi": 2 << 30, "1G": 1e9,
	}
	for in, want := range tests {
		got, err := ParseMemory(in)
		if err != nil || got != want {
			t.Errorf("ParseMemory(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"", "1.5Gi", "-1Mi", "1Ti", "Mi", "99999999999999999999Gi", "9999999999999Gi"} {
		if _, err := ParseMemory(in); err == nil {
			t.Errorf("ParseMemory(%q) accepted", in)
		}
	}
}

func TestParseCPU(t *testing.T) {
	t.Parallel()

	tests := map[string]int64{"500m": 5e8, "1": 1e9, "0.5": 5e8, "2.25": 2.25e9, "10m": 1e7}
	for in, want := range tests {
		got, err := ParseCPU(in)
		if err != nil || got != want {
			t.Errorf("ParseCPU(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"", "m", "0.1234", "-1", "1e3", "1.5m", "99999999999999999999m"} {
		if _, err := ParseCPU(in); err == nil {
			t.Errorf("ParseCPU(%q) accepted", in)
		}
	}
}

func TestJSONRoundTrip(t *testing.T) {
	t.Parallel()

	app, err := Parse([]byte(fullSpec))
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(app)
	if err != nil {
		t.Fatal(err)
	}
	var back App
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if err := back.Validate(); err != nil {
		t.Fatalf("round-tripped spec invalid: %v", err)
	}
	b2, _ := json.Marshal(&back)
	if string(b) != string(b2) {
		t.Errorf("JSON round trip changed spec:\n%s\n%s", b, b2)
	}

	var d Duration
	if err := d.UnmarshalJSON([]byte(`10`)); err == nil {
		t.Error("Duration accepted non-string JSON")
	}
	if err := d.UnmarshalJSON([]byte(`"nope"`)); err == nil {
		t.Error("Duration accepted invalid string")
	}
}

func TestDurationRejectsNonScalar(t *testing.T) {
	t.Parallel()

	_, err := Parse([]byte("name: a\nimage: b\ningress:\n  type: external\n  port: 80\nprobes:\n  readiness:\n    path: /\n    period: [1, 2]\n"))
	if err == nil || !strings.Contains(err.Error(), "duration") {
		t.Errorf("err = %v, want duration error", err)
	}
}

func TestReplicasWithoutScale(t *testing.T) {
	t.Parallel()

	var a App
	if a.Replicas() != 1 {
		t.Errorf("Replicas() on zero App = %d", a.Replicas())
	}
	if a.MemoryBytes() != 256<<20 {
		t.Errorf("MemoryBytes() on zero App = %d", a.MemoryBytes())
	}
	if a.NanoCPUs() != 0 {
		t.Errorf("NanoCPUs() on zero App = %d", a.NanoCPUs())
	}
}

// FuzzParse checks that Parse never panics and that every accepted spec only
// contains whitelisted characters in fields that reach proxy configuration.
func FuzzParse(f *testing.F) {
	f.Add([]byte(fullSpec))
	f.Add([]byte("name: a\nimage: b\n"))
	f.Add([]byte("name: a\nimage: b\ningress:\n  type: external\n  port: 1\n  domains: [a.b]\n  routes:\n    - path: /x\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		app, err := Parse(data)
		if err != nil {
			return
		}
		for _, d := range app.Ingress.Domains {
			if strings.ContainsAny(d, " \t\r\n#'\"\\{}") {
				t.Fatalf("accepted unsafe domain %q", d)
			}
		}
		for _, r := range app.Ingress.Routes {
			if strings.ContainsAny(r.Path, " \t\r\n#'\"\\{}*^$()[]|+?") {
				t.Fatalf("accepted unsafe path %q", r.Path)
			}
		}
		if strings.ContainsAny(app.Name, " \t\r\n.#") {
			t.Fatalf("accepted unsafe name %q", app.Name)
		}
	})
}

func TestSecretRefs(t *testing.T) {
	t.Parallel()
	a, err := Parse([]byte(`name: web
image: ghcr.io/acme/web:1
env:
  - name: DB
    secretRef: db
  - name: PLAIN
    value: x
  - name: DB_AGAIN
    secretRef: db
secretFiles:
  - secretRef: tls-key
    path: /run/secrets/tls.key
registry:
  server: ghcr.io
  username: acme
  passwordSecretRef: ghcr
`))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := a.SecretRefs(), []string{"db", "ghcr", "tls-key"}; !slices.Equal(got, want) {
		t.Errorf("SecretRefs() = %v, want %v", got, want)
	}
}

func TestRegistryHost(t *testing.T) {
	t.Parallel()
	for image, want := range map[string]string{
		"nginx:1":                    "docker.io",
		"library/nginx":              "docker.io",
		"ghcr.io/acme/web:1":         "ghcr.io",
		"registry.lab.test:5000/a/b": "registry.lab.test:5000",
		"localhost/a":                "localhost",
		"Registry.Example.com/a@sha256:" + strings.Repeat("a", 64): "registry.example.com",
	} {
		if got := RegistryHost(image); got != want {
			t.Errorf("RegistryHost(%q) = %q, want %q", image, got, want)
		}
	}
}
