package cli

import (
	"bytes"
	"strings"
	"testing"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
)

// While a rollout runs, the list shows where it goes, not only what serves.
func TestAppListShowsTheRolloutTarget(t *testing.T) {
	t.Parallel()
	var b bytes.Buffer
	if err := printAppList(&b, []*armadav1.AppSummary{
		{Name: "web", Image: "ghcr.io/acme/web:1.4.2", Revision: "web--r1", Ready: 0, Desired: 2, State: "progressing",
			TargetRevision: "web--r4", TargetImage: "traefik/whoami:latest"},
		{Name: "api", Image: "ghcr.io/acme/api:2", Revision: "api--r3", Ready: 2, Desired: 2, State: "ready"},
	}, false); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.Contains(out, "web--r1 → web--r4") || !strings.Contains(out, "traefik/whoami:latest") || strings.Contains(out, "ghcr.io/acme/web:1.4.2") {
		t.Errorf("rolling app:\n%s", out)
	}
	if !strings.Contains(out, "api--r3") || !strings.Contains(out, "ghcr.io/acme/api:2") {
		t.Errorf("steady app:\n%s", out)
	}
}
