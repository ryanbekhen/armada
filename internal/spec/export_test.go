package spec

import (
	"reflect"
	"strings"
	"testing"
)

// An exported spec parses back to the same spec: export and import lose
// nothing.
func TestExportRoundTrip(t *testing.T) {
	in := `name: api
image: ghcr.io/acme/api:1.2
command: [/app/api]
args: ["--flag", "x"]
env:
  - { name: A, value: "1" }
  - { name: DB, secretRef: database-url }
envFrom: secrets
secretFiles:
  - { secretRef: tls-key, path: /run/key }
registry: { server: ghcr.io, username: bot, passwordSecretRef: ghcr-token }
ingress:
  type: external
  port: 3000
  domains: [api.example.org]
  routes:
    - { path: /api, stripPrefix: true }
  timeout: 2m
probes:
  readiness: { path: /health, period: 2s, failureThreshold: 2 }
  liveness: { path: /health, initialDelay: 20s }
drain: 30s
scale:
  min: 1
  max: 4
  rules:
    - { type: cpu, utilization: 80 }
resources: { cpu: 500m, memory: 512Mi }
placement:
  require: { region: [a, b] }
  spreadBy: zone
`
	a, err := ParseIn([]byte(in), "shop")
	if err != nil {
		t.Fatal(err)
	}
	withSecrets, err := a.WithSecretEnv([]string{"redis-url", "database-url"})
	if err != nil {
		t.Fatal(err)
	}
	out, err := withSecrets.Export()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "REDIS_URL") || strings.Contains(string(out), "shop") {
		t.Errorf("export kept what envFrom added or the space:\n%s", out)
	}
	b, err := ParseIn(out, "shop")
	if err != nil {
		t.Fatalf("export does not parse: %v\n%s", err, out)
	}
	if !reflect.DeepEqual(a, b) {
		t.Errorf("round trip changed the spec:\nin  %+v\nout %+v\n%s", a, b, out)
	}

	job, err := Parse([]byte("kind: job\nname: backup\nimage: busybox\nschedule: \"0 3 * * *\"\ntimeZone: Asia/Jakarta\ntimeout: 1h\nretries: 2\n"))
	if err != nil {
		t.Fatal(err)
	}
	out, err = job.Export()
	if err != nil {
		t.Fatal(err)
	}
	if again, err := Parse(out); err != nil || !reflect.DeepEqual(job, again) {
		t.Errorf("job round trip: %v\n%s", err, out)
	}
}
