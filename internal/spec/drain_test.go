package spec

import (
	"strings"
	"testing"
	"time"
)

func TestDrain(t *testing.T) {
	t.Parallel()
	a, err := Parse([]byte("name: web\nimage: nginx:1\ndrain: 2m\n"))
	if err != nil {
		t.Fatal(err)
	}
	if a.Drain.D() != 2*time.Minute {
		t.Errorf("drain %s", a.Drain.D())
	}
	for _, y := range []string{
		"name: web\nimage: nginx:1\ndrain: 500ms\n",
		"name: web\nimage: nginx:1\ndrain: 2h\n",
		"kind: job\nname: web\nimage: nginx:1\ndrain: 1m\n",
	} {
		if _, err := Parse([]byte(y)); err == nil || !strings.Contains(err.Error(), "drain") {
			t.Errorf("%q: %v", y, err)
		}
	}
}
