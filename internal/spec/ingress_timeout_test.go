package spec

import (
	"strings"
	"testing"
	"time"
)

func TestIngressTimeout(t *testing.T) {
	t.Parallel()
	head := "name: web\nimage: nginx:1\ningress:\n  type: external\n  port: 80\n  timeout: "
	a, err := Parse([]byte(head + "5m\n"))
	if err != nil {
		t.Fatal(err)
	}
	if a.Ingress.Timeout.D() != 5*time.Minute {
		t.Errorf("timeout %s", a.Ingress.Timeout.D())
	}
	for _, v := range []string{"500ms", "2h"} {
		if _, err := Parse([]byte(head + v + "\n")); err == nil || !strings.Contains(err.Error(), "ingress.timeout") {
			t.Errorf("%s: %v", v, err)
		}
	}
}
