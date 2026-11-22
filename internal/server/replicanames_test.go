package server

import (
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/ryanbekhen/armada/internal/store"
)

func TestFindReplica(t *testing.T) {
	t.Parallel()
	reps := []store.Replica{{ID: "api-r3-k3p9x"}, {ID: "api-r3-x7q2a"}, {ID: "api-r4-x7q2a"}}
	for name, want := range map[string]string{"api-r3-k3p9x": "api-r3-k3p9x", "k3p9x": "api-r3-k3p9x", "api-r4-x7q2a": "api-r4-x7q2a"} {
		if r, err := findReplica("api", reps, name); err != nil || r.ID != want {
			t.Errorf("%s = %s, %v; want %s", name, r.ID, err, want)
		}
	}
	// Two replicas with the same short name need the full ID.
	if _, err := findReplica("api", reps, "x7q2a"); status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "api-r3-x7q2a, api-r4-x7q2a") {
		t.Errorf("ambiguous: %v", err)
	}
	if _, err := findReplica("api", reps, "nope"); status.Code(err) != codes.NotFound || !strings.Contains(err.Error(), `api has no replica "nope"; its replicas: k3p9x, x7q2a`) {
		t.Errorf("unknown: %v", err)
	}
	if _, err := findReplica("api", nil, "nope"); status.Code(err) != codes.NotFound || !strings.Contains(err.Error(), "api has no replicas") {
		t.Errorf("none: %v", err)
	}
	if got := shortReplica("api.staging-r12-ab3de"); got != "ab3de" {
		t.Errorf("short = %s", got)
	}
}

func TestChoices(t *testing.T) {
	t.Parallel()
	names := make([]string, 0, 25)
	for i := range 25 {
		names = append(names, string(rune('a'+i)))
	}
	if got := choices(append(names, "a")); !strings.HasSuffix(got, ", t, and 5 more") || strings.Count(got, ", ") != 20 {
		t.Errorf("choices = %q", got)
	}
}
