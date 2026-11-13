package runtime

import "testing"

func TestContainsFold(t *testing.T) {
	for _, c := range []struct {
		line, needle string
		want         bool
	}{
		{"GET /Health 500", "health 5", true},
		{"anything", "", true},
		{"short", "longer needle", false},
		{"ÉCHEC total", "échec", true},
		{"abcab", "abd", false},
	} {
		if got := ContainsFold([]byte(c.line), []byte(c.needle)); got != c.want {
			t.Errorf("ContainsFold(%q, %q) = %v", c.line, c.needle, got)
		}
	}
	if n := testing.AllocsPerRun(100, func() { ContainsFold([]byte("x ERROR y"), []byte("error")) }); n != 0 {
		t.Errorf("%v allocations for an ASCII needle", n)
	}
}
