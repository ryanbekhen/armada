package spec

import (
	"encoding/json"
	"errors"
	"fmt"
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
	if got := app.CPUMillis(); got != 500 {
		t.Errorf("CPUMillis() = %d, want the limit reserved", got)
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
	if app.Resources.Memory != DefaultMemory || app.NanoCPUs() != 0 || app.CPUMillis() != DefaultCPUMillis {
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
		{"job with ingress", "kind: job\nname: x\nimage: y\ningress:\n  type: external\n  port: 80\n", "ingress", false},
		{"job with probes", "kind: job\nname: x\nimage: y\nprobes:\n  readiness: /\n", "probes", false},
		{"job with scale", "kind: job\nname: x\nimage: y\nscale:\n  min: 2\n", "scale", false},
		{"job with traffic", "kind: job\nname: x\nimage: y\nrevisions:\n  mode: multiple\n", "revisions", false},
		{"job bad schedule", "kind: job\nname: x\nimage: y\nschedule: \"61 * * * *\"\n", "schedule", false},
		{"job six fields", "kind: job\nname: x\nimage: y\nschedule: \"0 0 3 * * *\"\n", "schedule", false},
		{"job descriptor", "kind: job\nname: x\nimage: y\nschedule: \"@daily\"\n", "schedule", false},
		{"job cron tz", "kind: job\nname: x\nimage: y\nschedule: \"CRON_TZ=UTC 0 3 * * *\"\n", "schedule", false},
		{"job bad zone", "kind: job\nname: x\nimage: y\nschedule: \"0 3 * * *\"\ntimeZone: Mars/Base\n", "schedule", false},
		{"job zone without schedule", "kind: job\nname: x\nimage: y\ntimeZone: UTC\n", "timeZone", false},
		{"job timeout too long", "kind: job\nname: x\nimage: y\ntimeout: 25h\n", "timeout", false},
		{"job retries", "kind: job\nname: x\nimage: y\nretries: 11\n", "retries", false},
		{"job concurrency", "kind: job\nname: x\nimage: y\nconcurrency: allow\n", "concurrency", false},
		{"job history", "kind: job\nname: x\nimage: y\nhistory: 0\n", "history", false},
		{"schedule on app", base + "schedule: \"0 3 * * *\"\n", "schedule", false},
		{"allow without ingress", base + "ingress:\n  type: none\n  allow: [api]\n", "ingress", false},
		{"allow itself", ext + "  allow: [web]\n", "ingress.allow[0]", false},
		{"allow an app ID", ext + "  allow: [api.shop]\n", "ingress.allow[0]", false},
		{"allow a bad name", ext + "  allow: [\"Api;x\"]\n", "ingress.allow[0]", false},
		{"allow twice", ext + "  allow: [api, api]\n", "ingress.allow[1]", false},
		{"retries on app", base + "retries: 1\n", "retries", false},
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
		{"multiple without ingress", base + "revisions:\n  mode: multiple\n  traffic:\n    - revision: latest\n      weight: 100\n", "revisions.mode", false},
		{"multiple without traffic", ext + "revisions:\n  mode: multiple\n", "revisions.traffic", false},
		{"multiple with zero", ext + "scale:\n  min: 0\n  max: 2\n  rules:\n    - type: http\n      concurrent: 5\n" + "revisions:\n  mode: multiple\n  traffic:\n    - revision: latest\n      weight: 100\n", "revisions.mode", false},
		{"weights not 100", ext + "revisions:\n  mode: multiple\n  traffic:\n    - revision: latest\n      weight: 60\n    - revision: web--r1\n      weight: 30\n", "revisions.traffic", false},
		{"weight over 100", ext + "revisions:\n  mode: multiple\n  traffic:\n    - revision: latest\n      weight: 101\n", "revisions.traffic[0].weight", false},
		{"other app's revision", ext + "revisions:\n  mode: multiple\n  traffic:\n    - revision: api--r1\n      weight: 100\n", "revisions.traffic[0].revision", false},
		{"bad revision", ext + "revisions:\n  mode: multiple\n  traffic:\n    - revision: web--r01\n      weight: 100\n", "revisions.traffic[0].revision", false},
		{"revision twice", ext + "revisions:\n  mode: multiple\n  traffic:\n    - revision: web--r1\n      weight: 50\n    - revision: web--r1\n      weight: 50\n", "revisions.traffic[1].revision", false},
		{"zero weight without label", ext + "revisions:\n  mode: multiple\n  traffic:\n    - revision: latest\n      weight: 100\n    - revision: web--r1\n      weight: 0\n", "revisions.traffic[1].label", false},
		{"bad label", ext + "revisions:\n  mode: multiple\n  traffic:\n    - revision: latest\n      weight: 100\n      label: Canary\n", "revisions.traffic[0].label", false},
		{"label twice", ext + "revisions:\n  mode: multiple\n  traffic:\n    - revision: latest\n      weight: 50\n      label: a\n    - revision: web--r1\n      weight: 50\n      label: a\n", "revisions.traffic[1].label", false},
		{"long label", ext + "revisions:\n  mode: multiple\n  traffic:\n    - revision: latest\n      weight: 100\n      label: " + strings.Repeat("a", 59) + "\n", "revisions.traffic[0].label", false},
		{"too many targets", ext + "revisions:\n  mode: multiple\n  traffic:\n" + strings.Repeat("    - revision: latest\n      weight: 9\n", 11), "revisions.traffic", false},
		{"bad revision mode", base + "revisions:\n  mode: blue\n", "revisions.mode", false},
		{"traffic in single", base + "revisions:\n  traffic:\n    - revision: latest\n      weight: 100\n", "revisions.traffic", false},
		{"probe without port", base + "probes:\n  readiness: /healthz\n", "probes.readiness.port", false},
		{"probe command with path", base + "probes:\n  liveness:\n    command: [a]\n    path: /h\n", "probes.liveness.command", false},
		{"probe command with port", base + "probes:\n  liveness:\n    command: [a]\n    port: 80\n", "probes.liveness.command", false},
		{"probe command empty program", base + "probes:\n  liveness:\n    command: [\"\"]\n", "probes.liveness.command", false},
		{"probe no path or command", base + "probes:\n  liveness:\n    period: 5s\n", "probes.liveness.path", false},
		{"probe bad path", ext + "probes:\n  readiness: healthz\n", "probes.readiness.path", false},
		{"probe bad duration", ext + "probes:\n  readiness:\n    path: /h\n    period: soon\n", "", false},
		{"probe period too short", ext + "probes:\n  readiness:\n    path: /h\n    period: 500ms\n", "probes.readiness.period", false},
		{"probe timeout over period", ext + "probes:\n  readiness:\n    path: /h\n    period: 2s\n    timeout: 3s\n", "probes.readiness.timeout", false},
		{"probe threshold", ext + "probes:\n  liveness:\n    path: /h\n    failureThreshold: 101\n", "probes.liveness.failureThreshold", false},
		{"zero without rules", ext + "scale:\n  min: 0\n  max: 3\n", "scale.min", false},
		{"zero without ingress", base + "scale:\n  min: 0\n  max: 3\n  rules:\n    - type: cpu\n      utilization: 50\n", "scale.min", false},
		{"zero without max", ext + "scale:\n  min: 0\n  rules:\n    - type: http\n      concurrent: 5\n", "scale.max", false},
		{"idleAfter without zero", ext + "scale:\n  min: 1\n  max: 3\n  idleAfter: 5m\n  rules:\n    - type: http\n      concurrent: 5\n", "scale.idleAfter", false},
		{"idleAfter too short", ext + "scale:\n  min: 0\n  max: 3\n  idleAfter: 30s\n  rules:\n    - type: http\n      concurrent: 5\n", "scale.idleAfter", false},
		{"idleAfter too long", ext + "scale:\n  min: 0\n  max: 3\n  idleAfter: 25h\n  rules:\n    - type: http\n      concurrent: 5\n", "scale.idleAfter", false},
		{"negative min", base + "scale:\n  min: -1\n", "scale.min", false},
		{"too many replicas", base + "scale:\n  min: 101\n", "scale.min", false},
		{"max below min", base + "scale:\n  min: 3\n  max: 2\n", "scale.max", false},
		{"rules without max", ext + "scale:\n  min: 2\n  rules:\n    - type: cpu\n      utilization: 70\n", "scale.max", false},
		{"http rule without ingress", base + "scale:\n  max: 3\n  rules:\n    - type: http\n      concurrent: 50\n", "scale.rules[0].type", false},
		{"http rule no target", ext + "scale:\n  max: 3\n  rules:\n    - type: http\n", "scale.rules[0].concurrent", false},
		{"http rule huge target", ext + "scale:\n  max: 3\n  rules:\n    - type: http\n      concurrent: 10001\n", "scale.rules[0].concurrent", false},
		{"cpu rule over 100", ext + "scale:\n  max: 3\n  rules:\n    - type: cpu\n      utilization: 150\n", "scale.rules[0].utilization", false},
		{"cpu rule with concurrent", ext + "scale:\n  max: 3\n  rules:\n    - type: cpu\n      utilization: 50\n      concurrent: 5\n", "scale.rules[0].concurrent", false},
		{"http rule with utilization", ext + "scale:\n  max: 3\n  rules:\n    - type: http\n      concurrent: 5\n      utilization: 5\n", "scale.rules[0].utilization", false},
		{"duplicate rule", ext + "scale:\n  max: 3\n  rules:\n    - type: cpu\n      utilization: 50\n    - type: cpu\n      utilization: 60\n", "scale.rules[1].type", false},
		{"unknown rule", ext + "scale:\n  max: 3\n  rules:\n    - type: rps\n", "scale.rules[0].type", false},
		{"queue without command", base + "scale:\n  max: 3\n  rules:\n    - type: queue\n      length: 10\n", "scale.rules[0].command", false},
		{"queue without length", base + "scale:\n  max: 3\n  rules:\n    - type: queue\n      command: [sh, -c, echo 1]\n", "scale.rules[0].length", false},
		{"queue at zero", ext + "scale:\n  min: 0\n  max: 3\n  rules:\n    - type: queue\n      command: [sh, -c, echo 1]\n      length: 10\n", "scale.rules[0].type", false},
		{"queue with NUL", base + "scale:\n  max: 3\n  rules:\n    - type: queue\n      command: [\"a\\0b\"]\n      length: 10\n", "scale.rules[0].command", false},
		{"queue with concurrent", base + "scale:\n  max: 3\n  rules:\n    - type: queue\n      command: [x]\n      length: 10\n      concurrent: 5\n", "scale.rules[0].concurrent", false},
		{"two queues", base + "scale:\n  max: 3\n  rules:\n    - type: queue\n      command: [x]\n      length: 10\n    - type: queue\n      command: [y]\n      length: 10\n", "scale.rules[1].type", false},
		{"cpu with length", base + "scale:\n  max: 3\n  rules:\n    - type: cpu\n      utilization: 50\n      length: 3\n", "scale.rules[0].length", false},
		{"schedule without fields", base + "scale:\n  max: 3\n  rules:\n    - type: schedule\n", "scale.rules[0].schedule", false},
		{"bad schedule", base + "scale:\n  max: 3\n  rules:\n    - type: schedule\n      schedule: \"every day\"\n      duration: 1h\n      replicas: 2\n", "scale.rules[0].schedule", false},
		{"schedule zone", base + "scale:\n  max: 3\n  rules:\n    - type: schedule\n      schedule: \"0 8 * * *\"\n      timeZone: Mars/Base\n      duration: 1h\n      replicas: 2\n", "scale.rules[0].schedule", false},
		{"schedule too long", base + "scale:\n  max: 3\n  rules:\n    - type: schedule\n      schedule: \"0 8 * * *\"\n      duration: 200h\n      replicas: 2\n", "scale.rules[0].duration", false},
		{"schedule above max", base + "scale:\n  max: 3\n  rules:\n    - type: schedule\n      schedule: \"0 8 * * *\"\n      duration: 1h\n      replicas: 4\n", "scale.rules[0].replicas", false},
		{"redis without secret", base + "scale:\n  max: 3\n  rules:\n    - type: redis\n      list: jobs\n      length: 10\n", "scale.rules[0].urlSecretRef", false},
		{"redis without list", base + "scale:\n  max: 3\n  rules:\n    - type: redis\n      urlSecretRef: redis-url\n      length: 10\n", "scale.rules[0].list", false},
		{"redis list with newline", base + "scale:\n  max: 3\n  rules:\n    - type: redis\n      urlSecretRef: redis-url\n      list: \"a\\nb\"\n      length: 10\n", "scale.rules[0].list", false},
		{"redis with queue", base + "scale:\n  max: 3\n  rules:\n    - type: redis\n      urlSecretRef: redis-url\n      list: jobs\n      queue: q\n      length: 10\n", "scale.rules[0].queue", false},
		{"rabbitmq bad secret", base + "scale:\n  max: 3\n  rules:\n    - type: rabbitmq\n      urlSecretRef: \"../x\"\n      queue: q\n      length: 10\n", "scale.rules[0].urlSecretRef", false},
		{"rabbitmq long queue", base + "scale:\n  max: 3\n  rules:\n    - type: rabbitmq\n      urlSecretRef: amqp-url\n      queue: " + strings.Repeat("q", 256) + "\n      length: 10\n", "scale.rules[0].queue", false},
		{"rabbitmq at zero", ext + "scale:\n  min: 0\n  max: 3\n  rules:\n    - type: rabbitmq\n      urlSecretRef: amqp-url\n      queue: q\n      length: 10\n", "scale.rules[0].type", false},
		{"ip allow and deny", ext + "  ipAllow: [203.0.113.0/24]\n  ipDeny: [198.51.100.0/24]\n", "ingress", false},
		{"ip rules internal", base + "ingress:\n  type: internal\n  port: 80\n  ipAllow: [203.0.113.0/24]\n", "ingress", false},
		{"ip rules none", base + "ingress:\n  type: none\n  ipDeny: [203.0.113.0/24]\n", "ingress", false},
		{"ip not an address", ext + "  ipAllow: [example.org]\n", "ingress.ipAllow[0].range", false},
		{"ip everything", ext + "  ipDeny: [\"::/0\"]\n", "ingress.ipDeny[0].range", false},
		{"ip mapped", ext + "  ipAllow: [\"::ffff:203.0.113.7\"]\n", "ingress.ipAllow[0].range", false},
		{"ip zone", ext + "  ipAllow: [\"fe80::1%eth0\"]\n", "ingress.ipAllow[0].range", false},
		{"ip duplicate", ext + "  ipAllow: [203.0.113.7, 203.0.113.7/32]\n", "ingress.ipAllow[1].range", false},
		{"ip rule without range", ext + "  ipAllow:\n    - name: office\n", "ingress.ipAllow[0].range", false},
		{"ip rule name with newline", ext + "  ipAllow:\n    - range: 203.0.113.0/24\n      name: \"a\\nb\"\n", "ingress.ipAllow[0].name", false},
		{"ip rule long description", ext + "  ipAllow:\n    - range: 203.0.113.0/24\n      description: " + strings.Repeat("x", 257) + "\n", "ingress.ipAllow[0].description", false},
		{"ip rule names twice", ext + "  ipAllow:\n    - {range: 203.0.113.0/24, name: office}\n    - {range: 198.51.100.0/24, name: office}\n", "ingress.ipAllow[1].name", false},
		{"ip rule unknown field", ext + "  ipAllow:\n    - {range: 203.0.113.0/24, cidr: x}\n", "", false},
		{"tcp external", base + "ingress:\n  type: external\n  protocol: tcp\n  port: 5432\n", "ingress.protocol", false},
		{"tcp without ingress", base + "ingress:\n  type: none\n  protocol: tcp\n", "ingress", false},
		{"bad protocol", base + "ingress:\n  type: internal\n  protocol: udp\n  port: 5432\n", "ingress.protocol", false},
		{"tcp reserved port", base + "ingress:\n  type: internal\n  protocol: tcp\n  port: 53\n", "ingress.port", false},
		{"tcp port 80", base + "ingress:\n  type: internal\n  protocol: tcp\n  port: 80\n", "ingress.port", false},
		{"tcp with routes", base + "ingress:\n  type: internal\n  protocol: tcp\n  port: 5432\n  routes:\n    - path: /a\n", "ingress.routes", false},
		{"tcp sticky", base + "ingress:\n  type: internal\n  protocol: tcp\n  port: 5432\n  sticky: true\n", "ingress.sticky", false},
		{"tcp cors", base + "ingress:\n  type: internal\n  protocol: tcp\n  port: 5432\n  cors:\n    allowOrigins: [\"*\"]\n", "ingress.cors", false},
		{"tcp timeout", base + "ingress:\n  type: internal\n  protocol: tcp\n  port: 5432\n  timeout: 5m\n", "ingress.timeout", false},
		{"tcp domains", base + "ingress:\n  type: internal\n  protocol: tcp\n  port: 5432\n  domains: [db.example.org]\n", "ingress.domains", false},
		{"tcp scale to zero", base + "ingress:\n  type: internal\n  protocol: tcp\n  port: 5432\nscale:\n  min: 0\n  max: 2\n  rules:\n    - type: cpu\n      utilization: 50\n", "scale.min", false},
		{"tcp http rule", base + "ingress:\n  type: internal\n  protocol: tcp\n  port: 5432\nscale:\n  min: 1\n  max: 2\n  rules:\n    - type: http\n      concurrent: 5\n", "scale.rules[0].type", false},
		{"tcp multiple", base + "ingress:\n  type: internal\n  protocol: tcp\n  port: 5432\nrevisions:\n  mode: multiple\n  traffic:\n    - revision: latest\n      weight: 100\n", "revisions.mode", false},
		{"cors without origins", ext + "  cors:\n    allowMethods: [GET]\n", "ingress.cors.allowOrigins", false},
		{"cors bad origin", ext + "  cors:\n    allowOrigins: [\"https://a.example.org/x\"]\n", "ingress.cors.allowOrigins[0]", false},
		{"cors origin injection", ext + "  cors:\n    allowOrigins: [\"https://a.example.org }\"]\n", "ingress.cors.allowOrigins[0]", false},
		{"cors star with credentials", ext + "  cors:\n    allowOrigins: [\"*\"]\n    allowCredentials: true\n", "ingress.cors.allowOrigins[0]", false},
		{"cors star with others", ext + "  cors:\n    allowOrigins: [\"*\", \"https://a.example.org\"]\n", "ingress.cors.allowOrigins[0]", false},
		{"cors bad method", ext + "  cors:\n    allowOrigins: [\"*\"]\n    allowMethods: [TRACE]\n", "ingress.cors.allowMethods[0]", false},
		{"cors bad header", ext + "  cors:\n    allowOrigins: [\"*\"]\n    allowHeaders: [\"X-A, X-B\"]\n", "ingress.cors.allowHeaders[0]", false},
		{"cors long max age", ext + "  cors:\n    allowOrigins: [\"*\"]\n    maxAge: 48h\n", "ingress.cors.maxAge", false},
		{"cors without ingress", base + "ingress:\n  type: none\n  cors:\n    allowOrigins: [\"*\"]\n", "ingress", false},
		{"ip injection", ext + "  ipAllow: [\"203.0.113.0/24 } || { always_true\"]\n", "ingress.ipAllow[0].range", false},
		{"unknown rule", base + "scale:\n  max: 3\n  rules:\n    - type: kafka\n", "scale.rules[0].type", false},
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

	for _, d := range []string{"a.co", "api-bengkel.apps.example.org", "xn--bcher-kva.example", "a1.b2.c3"} {
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

// IP rules take a bare range or a range with a name and description; both
// export as written.
func TestParseIPRules(t *testing.T) {
	t.Parallel()
	a, err := Parse([]byte("name: admin\nimage: a\ningress:\n  type: external\n  port: 80\n  ipAllow:\n" +
		"    - range: 203.0.113.0/24\n      name: kantor jakarta\n      description: VPN kantor, untuk tim admin\n" +
		"    - 198.51.100.7\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := []IPRule{{Range: "203.0.113.0/24", Name: "kantor jakarta", Description: "VPN kantor, untuk tim admin"}, {Range: "198.51.100.7"}}
	if !slices.Equal(a.Ingress.IPAllow, want) {
		t.Errorf("rules = %+v", a.Ingress.IPAllow)
	}
	if got := IPRanges(a.Ingress.IPAllow); !slices.Equal(got, []string{"198.51.100.7/32", "203.0.113.0/24"}) {
		t.Errorf("ranges = %v", got)
	}
	out, err := a.Export()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "        - range: 203.0.113.0/24\n          name: kantor jakarta\n") && !strings.Contains(string(out), "    - range: 203.0.113.0/24\n      name: kantor jakarta\n") {
		t.Errorf("export:\n%s", out)
	}
	if !strings.Contains(string(out), "- 198.51.100.7\n") {
		t.Errorf("a bare range is not exported bare:\n%s", out)
	}
	b, err := Parse(out)
	if err != nil || !slices.Equal(b.Ingress.IPAllow, want) {
		t.Errorf("round trip: %+v %v", b, err)
	}
}

func TestParseQueueAndSchedule(t *testing.T) {
	t.Parallel()
	a, err := Parse([]byte("name: worker\nimage: w\nscale:\n  min: 1\n  max: 6\n  rules:\n" +
		"    - type: queue\n      command: [bun, queue-length.ts]\n      length: 100\n" +
		"    - type: redis\n      urlSecretRef: redis-url\n      list: mail:outbox\n      length: 50\n" +
		"    - type: rabbitmq\n      urlSecretRef: amqp-url\n      queue: emails\n      length: 20\n" +
		"    - type: schedule\n      schedule: \"0 8 * * 1-5\"\n      timeZone: Asia/Jakarta\n      duration: 10h\n      replicas: 3\n" +
		"    - type: schedule\n      schedule: \"0 9 * * 6\"\n      duration: 4h\n      replicas: 2\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !a.Autoscaled() || len(a.Scale.Rules) != 5 || a.Scale.Rules[3].Duration.D() != 10*time.Hour || len(a.QueueRules()) != 3 {
		t.Errorf("rules = %+v", a.Scale.Rules)
	}
	// The URLs' secrets are pinned with the revision like any other.
	if refs := a.SecretRefs(); !slices.Contains(refs, "redis-url") || !slices.Contains(refs, "amqp-url") {
		t.Errorf("secret refs %v", refs)
	}
}

func TestParseAutoscaled(t *testing.T) {
	t.Parallel()
	a, err := Parse([]byte("name: web\nimage: nginx\ningress:\n  type: internal\n  port: 80\nscale:\n  min: 2\n  max: 8\n  rules:\n    - type: http\n      concurrent: 40\n    - type: cpu\n      utilization: 70\n    - type: memory\n      utilization: 80\n"))
	if err != nil {
		t.Fatal(err)
	}
	if lo, hi := a.ScaleBounds(); !a.Autoscaled() || lo != 2 || hi != 8 || a.Replicas() != 2 {
		t.Errorf("autoscaled=%v bounds=%d..%d", a.Autoscaled(), lo, hi)
	}
	b, _ := Parse([]byte("name: web\nimage: nginx\nscale:\n  min: 2\n"))
	if lo, hi := b.ScaleBounds(); b.Autoscaled() || lo != 2 || hi != 2 {
		t.Errorf("fixed: autoscaled=%v bounds=%d..%d", b.Autoscaled(), lo, hi)
	}
}

func TestParseTraffic(t *testing.T) {
	t.Parallel()
	a, err := Parse([]byte("name: web\nimage: nginx\ningress:\n  type: internal\n  port: 80\nrevisions:\n  mode: multiple\n  traffic:\n    - revision: web--r3\n      weight: 90\n    - revision: latest\n      weight: 10\n      label: canary\n    - revision: web--r2\n      weight: 0\n      label: old\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !a.MultipleRevisions() || len(a.Revisions.Traffic) != 3 || a.Revisions.Traffic[1].Label != "canary" {
		t.Errorf("traffic %+v", a.Revisions)
	}
	for rev, ok := range map[string]bool{"web--r1": true, "web--r123": true, "web--r0": false, "web--r": false, "web--rx": false, "api--r1": false, "web-r1": false, "latest": false} {
		if ValidRevisionName("web", rev) != ok {
			t.Errorf("ValidRevisionName(web, %q) = %v", rev, !ok)
		}
	}
	for host, ok := range map[string]bool{"web": true, "canary--web": true, LabelHost("a", "b"): true, "a--b--c": false, "--web": false, "web--": false, "Canary--web": false, "a---b": false, strings.Repeat("a", 30) + "--" + strings.Repeat("b", 32): false} {
		if ValidHostName(host) != ok {
			t.Errorf("ValidHostName(%q) = %v", host, !ok)
		}
	}
	if errs := CheckTraffic("web", []TrafficTarget{{Revision: LatestRevision, Weight: 100}}, false); len(errs) == 0 {
		t.Error("latest accepted where it means nothing")
	}
}

func TestParseScaleToZero(t *testing.T) {
	t.Parallel()
	a, err := Parse([]byte("name: web\nimage: nginx\ningress:\n  type: internal\n  port: 80\nscale:\n  min: 0\n  max: 4\n  rules:\n    - type: http\n      concurrent: 10\n"))
	if err != nil {
		t.Fatal(err)
	}
	if lo, hi := a.ScaleBounds(); !a.ScalesToZero() || lo != 0 || hi != 4 || a.Replicas() != 1 || a.IdleAfter() != DefaultIdleAfter {
		t.Errorf("zero=%v bounds=%d..%d replicas=%d idle=%v", a.ScalesToZero(), lo, hi, a.Replicas(), a.IdleAfter())
	}
	b, err := Parse([]byte("name: web\nimage: nginx\ningress:\n  type: internal\n  port: 80\nscale:\n  min: 0\n  max: 4\n  idleAfter: 2m\n  rules:\n    - type: http\n      concurrent: 10\n"))
	if err != nil || b.IdleAfter() != 2*time.Minute {
		t.Errorf("idleAfter: %v %v", b.IdleAfter(), err)
	}
}

func TestParseJob(t *testing.T) {
	t.Parallel()
	a, err := Parse([]byte("kind: job\nname: backup\nimage: busybox\nschedule: \"30 3 * * *\"\ntimeZone: Asia/Jakarta\nretries: 2\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !a.IsJob() || a.Replicas() != 0 || a.JobTimeout() != DefaultJobTimeout || a.JobHistory() != DefaultJobHistory || a.JobConcurrency() != ConcurrencyForbid {
		t.Errorf("defaults: %+v", a)
	}
	s, ok := a.JobSchedule()
	if !ok {
		t.Fatal("no schedule")
	}
	// 03:30 in Jakarta (UTC+7) is 20:30 UTC the day before.
	next := s.Next(time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC))
	if want := time.Date(2026, 11, 3, 20, 30, 0, 0, time.UTC); !next.Equal(want) {
		t.Errorf("next = %v, want %v", next.UTC(), want)
	}
	manual, err := Parse([]byte("kind: job\nname: migrate\nimage: busybox\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := manual.JobSchedule(); ok {
		t.Error("a job without a schedule has one")
	}
}

func TestParseAllow(t *testing.T) {
	t.Parallel()
	app, err := Parse([]byte("name: db\nimage: postgres\ningress:\n  type: internal\n  port: 5432\n  allow: [api, worker]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(app.Ingress.Allow, []string{"api", "worker"}) {
		t.Errorf("allow = %v", app.Ingress.Allow)
	}
	many := "name: db\nimage: postgres\ningress:\n  type: internal\n  port: 5432\n  allow:\n"
	for i := range MaxAllow + 1 {
		many += fmt.Sprintf("    - a%d\n", i)
	}
	if _, err := Parse([]byte(many)); err == nil {
		t.Error("too many allowed apps accepted")
	}
}

func TestCommandProbes(t *testing.T) {
	t.Parallel()
	a, err := Parse([]byte("name: worker\nimage: y\nprobes:\n  liveness:\n    command: [bun, health.ts]\n    period: 60s\n    timeout: 15s\n"))
	if err != nil {
		t.Fatal(err)
	}
	if p := a.Probes.Liveness; len(p.Command) != 2 || p.Port != 0 || p.Path != "" || p.FailureThreshold != defaultFailures {
		t.Errorf("probe = %+v", p)
	}
	// An app with a port still does not give a command probe one.
	a, err = Parse([]byte("name: web\nimage: y\ningress:\n  type: internal\n  port: 80\nprobes:\n  readiness:\n    command: [check]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if a.Probes.Readiness.Port != 0 {
		t.Errorf("port = %d", a.Probes.Readiness.Port)
	}
	long := "name: x\nimage: y\nprobes:\n  liveness:\n    command: [" + strings.Repeat("a,", maxProbeArgs) + "a]\n"
	if _, err := Parse([]byte(long)); err == nil {
		t.Error("too many entries accepted")
	}
	big := "name: x\nimage: y\nprobes:\n  liveness:\n    command: [" + strings.Repeat("a", maxProbeArgLen+1) + "]\n"
	if _, err := Parse([]byte(big)); err == nil {
		t.Error("an oversized entry accepted")
	}
}

func TestEnvFromValidation(t *testing.T) {
	if _, err := Parse([]byte("name: a\nimage: nginx:1\nenvFrom: secrets\n")); err != nil {
		t.Errorf("envFrom: secrets: %v", err)
	}
	if _, err := Parse([]byte("name: a\nimage: nginx:1\nenvFrom: files\n")); err == nil {
		t.Error("envFrom: files accepted")
	}
}

func TestWithSecretEnv(t *testing.T) {
	a, err := Parse([]byte("name: a\nimage: nginx:1\nenv:\n  - { name: DATABASE_URL, value: x }\nsecretFiles:\n  - { secretRef: tls-key, path: /run/key }\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := a.WithSecretEnv([]string{"redis-url"}); err != nil || len(got.Env) != 1 {
		t.Errorf("without envFrom: %v %v", got, err)
	}
	a.EnvFrom = EnvFromSecrets
	got, err := a.WithSecretEnv([]string{"tls-key", "database-url", "redis-url", "port", "armada-token", "9lives"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Env) != 2 || got.Env[1] != (EnvVar{Name: "REDIS_URL", SecretRef: "redis-url"}) || got.Env[0].Value != "x" {
		t.Errorf("env = %+v", got.Env)
	}
	if len(a.Env) != 1 {
		t.Error("WithSecretEnv changed the original")
	}
}
