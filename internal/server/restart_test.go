package server

import (
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
)

// A restart rolls out a new revision of the same spec, so every replica is
// replaced (ADR 0052).
func TestRestartApp(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	c.addNode("n1", "127.0.0.1")
	c.deploy(webSpec("nginx:1", 2))
	c.eventually("2 running", func() bool { return len(c.running("web")) == 2 })
	before := map[string]bool{}
	for _, r := range c.running("web") {
		before[r.Id] = true
	}
	resp, err := c.admin.RestartApp(c.ctx, &armadav1.RestartAppRequest{App: "web"})
	if err != nil || resp.Revision != "web--r2" {
		t.Fatalf("restart = %v, %v", resp, err)
	}
	c.eventually("replaced", func() bool {
		rs := c.running("web")
		if len(rs) != 2 {
			return false
		}
		for _, r := range rs {
			if before[r.Id] || r.Revision != "web--r2" {
				return false
			}
		}
		return true
	})
	if _, err := c.admin.RestartApp(c.ctx, &armadav1.RestartAppRequest{App: "ghost"}); status.Code(err) != codes.NotFound {
		t.Errorf("unknown app: %v", err)
	}
	c.deploy("kind: job\nname: once\nimage: busybox:1\n")
	if _, err := c.admin.RestartApp(c.ctx, &armadav1.RestartAppRequest{App: "once"}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("job: %v", err)
	}
}
