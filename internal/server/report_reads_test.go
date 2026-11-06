package server

import (
	"context"
	"sync/atomic"
	"testing"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/store"
)

type countingStore struct {
	store.Store
	reads atomic.Int64
}

func (c *countingStore) GetRevision(ctx context.Context, name string) (store.Revision, error) {
	c.reads.Add(1)
	return c.Store.GetRevision(ctx, name)
}

// A report repeats every replica's image; once recorded, that costs no reads.
func TestReportsReadRevisionsOnce(t *testing.T) {
	t.Parallel()
	c := newClockServer(t)
	c.deploy("name: web\nimage: nginx:1\nscale:\n  min: 3\n")
	counting := &countingStore{Store: c.srv.store}
	c.srv.store = counting
	var rev string
	report := &armadav1.ReplicaReport{}
	for _, r := range c.replicas() {
		rev = r.Revision
		report.Replicas = append(report.Replicas, &armadav1.ReplicaState{
			Id: r.ID, State: store.ReplicaRunning, ContainerId: "c" + r.ID,
			ImageDigest: "docker.io/library/nginx@sha256:" + digestHex, ImagePlatforms: []string{"linux/amd64"},
		})
	}
	node := store.Node{ID: "n1", PrivateIP: "10.0.0.2"}
	c.srv.applyReport(c.ctx, node, report)
	got, err := c.st.GetRevision(c.ctx, rev)
	if err != nil {
		t.Fatal(err)
	}
	if got.ImageDigest == "" || len(got.Platforms) == 0 {
		t.Fatalf("image not recorded: %+v", got)
	}
	counting.reads.Store(0)
	for range 3 {
		c.srv.applyReport(c.ctx, node, report)
	}
	if n := counting.reads.Load(); n != 0 {
		t.Errorf("%d revision reads for reports that repeat what is recorded", n)
	}
}

const digestHex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
