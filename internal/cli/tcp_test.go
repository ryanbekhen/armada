package cli

import (
	"strings"
	"testing"

	"github.com/ryanbekhen/armada/internal/spec"
)

// --protocol tcp makes an internal TCP app (ADR 0039); --protocol http goes
// back to the default, and an external TCP app is refused before anything
// is sent.
func TestAppProtocolFlag(t *testing.T) {
	f := newFakeAdmin()
	cfg := withFake(t, f)
	cli := func(args ...string) (int, string, string) { return run(t, append(args, "--config", cfg)...) }
	if code, _, stderr := cli("app", "create", "db", "--image", "postgres:17", "--port", "5432", "--ingress", "internal", "--protocol", "tcp"); code != 0 {
		t.Fatal(stderr)
	}
	ingress := func() *spec.Ingress {
		sp, err := spec.Parse([]byte(f.specs["db"]))
		if err != nil {
			t.Fatal(err)
		}
		return sp.Ingress
	}
	if in := ingress(); !in.TCP() || in.Port != 5432 || in.Type != spec.IngressInternal {
		t.Errorf("after create: %+v", in)
	}
	if code, _, stderr := cli("app", "update", "db", "--image", "postgres:18"); code != 0 || !ingress().TCP() {
		t.Errorf("another change dropped the protocol: %s", stderr)
	}
	if code, _, stderr := cli("app", "update", "db", "--protocol", "http"); code != 0 || ingress().TCP() || ingress().Protocol != "" {
		t.Errorf("--protocol http: %s", stderr)
	}
	if code, _, stderr := cli("app", "create", "pub", "--image", "postgres:17", "--port", "5432", "--ingress", "external", "--protocol", "tcp"); code == 0 || !strings.Contains(stderr, "internal only") {
		t.Errorf("external tcp: %d %q", code, stderr)
	}
	if _, ok := f.specs["pub"]; ok {
		t.Error("refused spec was sent")
	}
}
