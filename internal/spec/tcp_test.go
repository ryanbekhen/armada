package spec

import "testing"

// A TCP app is internal, on a port of its own, with callers and CPU or
// memory rules (ADR 0039).
func TestParseTCP(t *testing.T) {
	t.Parallel()
	app, err := Parse([]byte("name: db\nimage: postgres:17\ningress:\n  type: internal\n  protocol: tcp\n  port: 5432\n  allow: [api]\n" +
		"scale:\n  min: 1\n  max: 3\n  rules:\n    - type: cpu\n      utilization: 70\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !app.Ingress.TCP() || app.Ingress.Port != 5432 {
		t.Errorf("ingress = %+v", app.Ingress)
	}
	http, err := Parse([]byte("name: web\nimage: nginx\ningress:\n  type: internal\n  protocol: http\n  port: 8080\n"))
	if err != nil || http.Ingress.TCP() {
		t.Errorf("protocol http: %v", err)
	}
	for _, p := range ReservedTCPPorts {
		if CheckTCPPort(p) == nil {
			t.Errorf("port %d accepted", p)
		}
	}
	for _, p := range []int{0, -1, 65536} {
		if CheckTCPPort(p) == nil {
			t.Errorf("port %d accepted", p)
		}
	}
	if CheckTCPPort(6379) != nil || CheckTCPPort(25) != nil {
		t.Error("ordinary ports refused")
	}
}
