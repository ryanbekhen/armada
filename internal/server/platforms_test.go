package server

import (
	"context"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/store"
	"github.com/ryanbekhen/armada/internal/store/storetest"
)

// Platforms come from agents and are untrusted: only a node running a
// replica of the revision may report them, only valid "os/arch" lists are
// kept, and the first valid list wins.
func TestReportedImagePlatforms(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	st := storetest.Open(t)
	s := &Server{store: st, log: slog.New(slog.DiscardHandler), trigger: make(chan struct{}, 1)}
	for _, n := range []store.Node{{ID: "n1", PrivateIP: "10.0.0.2"}, {ID: "n2", PrivateIP: "10.0.0.3"}} {
		_ = st.UpsertNode(ctx, n)
	}
	if _, _, err := st.Deploy(ctx, mustSpec(t, "name: web\nimage: ghcr.io/me/web:v1\n"), "t"); err != nil {
		t.Fatal(err)
	}
	_ = st.CreateReplica(ctx, store.Replica{ID: "mine", App: "web", Revision: "web--r1", NodeID: "n1"})
	n1, _ := st.GetNode(ctx, "n1")
	n2, _ := st.GetNode(ctx, "n2")
	report := func(node store.Node, id string, ps ...string) {
		s.applyReport(ctx, node, &armadav1.ReplicaReport{Replicas: []*armadav1.ReplicaState{{Id: id, State: "failed", ImagePlatforms: ps}}})
	}
	platforms := func() []string {
		rev, _ := st.GetRevision(ctx, "web--r1")
		return rev.Platforms
	}

	report(n2, "mine", "linux/riscv64") // not n2's replica
	many := make([]string, 33)
	for i := range many {
		many[i] = "linux/a" + strings.Repeat("x", i)
	}
	for name, ps := range map[string][]string{
		"variant":    {"linux/arm/v7"},
		"upper case": {"Linux/amd64"},
		"newline":    {"linux\nx/amd64"},
		"no slash":   {"amd64"},
		"empty part": {"linux/"},
		"too many":   many,
		"one bad":    {"linux/amd64", "linux/../arm64"},
	} {
		report(n1, "mine", ps...)
		if got := platforms(); got != nil {
			t.Fatalf("%s: stored %v", name, got)
		}
	}
	report(n1, "mine", "linux/arm64", "linux/amd64", "linux/arm64")
	report(n1, "mine", "linux/s390x")
	if got := platforms(); !slices.Equal(got, []string{"linux/amd64", "linux/arm64"}) {
		t.Errorf("platforms = %v, want the first valid list, sorted and unique", got)
	}
}

// platformSetup returns a server with n1 on linux/amd64 and n2 on
// linux/arm64.
func platformSetup(t *testing.T) *clockServer {
	t.Helper()
	c := newClockServer(t)
	for _, n := range []store.Node{
		{ID: "n1", PrivateIP: "10.0.0.2", State: store.NodeReady, OS: "linux", Arch: "amd64"},
		{ID: "n2", PrivateIP: "10.0.0.3", State: store.NodeReady, OS: "linux", Arch: "arm64"},
	} {
		if err := c.st.UpsertNode(c.ctx, n); err != nil {
			t.Fatal(err)
		}
		if err := c.st.SetNodeStatus(c.ctx, n.ID, store.NodeStatus{State: store.NodeReady, LastSeen: c.clock, OS: n.OS, Arch: n.Arch}); err != nil {
			t.Fatal(err)
		}
	}
	return c
}

func TestImagePlatformsKeepReplicasOnMatchingNodes(t *testing.T) {
	t.Parallel()
	c := platformSetup(t)
	c.deploy(placedSpec)
	c.serveAll()
	if byNode, _ := c.split(); len(byNode["n1"]) != 1 || len(byNode["n2"]) != 1 {
		t.Fatalf("not spread before the platforms are known: %v", byNode)
	}
	// An agent reports that the image is amd64 only: the replica on the
	// arm64 node is replaced on n1 first, then retired.
	if err := c.st.SetRevisionPlatforms(c.ctx, c.app().TargetRevision, []string{"linux/amd64"}); err != nil {
		t.Fatal(err)
	}
	c.advance(time.Millisecond)
	if byNode, _ := c.split(); len(byNode["n1"]) != 2 || len(byNode["n2"]) != 1 {
		t.Fatalf("replacement not scheduled first: %v", byNode)
	}
	c.serveAll()
	c.advance(time.Millisecond)
	if byNode, _ := c.split(); len(byNode["n1"]) != 2 || len(byNode["n2"]) != 0 {
		t.Fatalf("after the move: %v", byNode)
	}
	if msg := c.placementNote(); msg != "" {
		t.Errorf("placement note with room: %q", msg)
	}

	// An image no node can run: nothing new is placed, and status says why.
	c.deploy(strings.Replace(placedSpec, "nginx:1", "nginx:2", 1))
	if err := c.st.SetRevisionPlatforms(c.ctx, c.app().TargetRevision, []string{"linux/riscv64"}); err != nil {
		t.Fatal(err)
	}
	for _, r := range c.replicas() {
		if !r.Draining() && r.Revision == c.app().TargetRevision {
			// Started before the platforms were known; failed on the node.
			if err := c.st.DeleteReplica(c.ctx, r.ID); err != nil {
				t.Fatal(err)
			}
		}
	}
	c.advance(time.Second)
	for _, r := range c.replicas() {
		if r.Revision == c.app().TargetRevision {
			t.Errorf("replica %s of an image no node can run placed on %s", r.ID, r.NodeID)
		}
	}
	if msg := c.placementNote(); !strings.Contains(msg, "no ready node can run the image, which is built for linux/riscv64") {
		t.Errorf("placement note = %q", msg)
	}
}

// A node that does not report its platform (an older agent) is not ruled
// out.
func TestNodeWithoutPlatformStaysEligible(t *testing.T) {
	t.Parallel()
	rev := store.Revision{Spec: mustSpec(t, "name: web\nimage: nginx:1\n"), Platforms: []string{"linux/amd64"}}
	if !placementAllows(store.Node{ID: "old", State: store.NodeReady}, rev) {
		t.Error("node without a reported platform ruled out")
	}
	if placementAllows(store.Node{ID: "arm", State: store.NodeReady, OS: "linux", Arch: "arm64"}, rev) {
		t.Error("arm64 node allowed for an amd64-only image")
	}
}
