package server

import (
	"strings"
	"testing"
)

func TestValidVersion(t *testing.T) {
	t.Parallel()
	for _, v := range []string{"v0.1.0", "v0.2.0-alpha.1", "dev", "v1.0.0+build.5"} {
		if !validVersion(v) {
			t.Errorf("%q refused", v)
		}
	}
	for _, v := range []string{"", "-v1", "v1 0", "v1\n", "v1\x1b[31m", strings.Repeat("a", 65), "v1;rm"} {
		if validVersion(v) {
			t.Errorf("%q accepted", v)
		}
	}
}
