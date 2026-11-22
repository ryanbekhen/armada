package agent

import (
	"context"
	"testing"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/proxy"
	proxyfake "github.com/ryanbekhen/armada/internal/proxy/fake"
	"github.com/ryanbekhen/armada/internal/runtime/fake"
)

// orderProxy notes how many containers ran when each configuration was
// applied.
type orderProxy struct {
	proxyfake.Driver
	d       *fake.Driver
	running []int
}

func (p *orderProxy) Apply(ctx context.Context, cfg proxy.Config) error {
	cs, _ := p.d.List(ctx, nil)
	p.running = append(p.running, len(cs))
	return p.Driver.Apply(ctx, cfg)
}

// A replica that is no longer wanted leaves the proxy before its container
// is removed, so no request is sent to an address nobody answers.
func TestProxyBeforeRemovingContainers(t *testing.T) {
	t.Parallel()
	d := fake.New()
	px := &orderProxy{d: d}
	ok := func(context.Context, string, string) error { return nil }
	a := New(Config{NodeID: "n1", PrivateIP: "10.0.0.2", Driver: d, Check: ok, Proxy: px, CPUMillis: 1000, MemoryBytes: 1 << 30})
	ctx := context.Background()
	a.setDesired([]*armadav1.ReplicaSpec{replica("web-r1-a", "nginx:1", 8080)}, &armadav1.ProxyConfig{})
	if _, err := a.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if cs, _ := d.List(ctx, nil); len(cs) != 1 {
		t.Fatalf("containers %v", cs)
	}
	px.running = nil
	// The next configuration differs, as one without the replica would.
	a.setDesired([]*armadav1.ReplicaSpec{}, &armadav1.ProxyConfig{PlainHttp: true})
	if _, err := a.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if cs, _ := d.List(ctx, nil); len(cs) != 0 {
		t.Fatalf("containers left %v", cs)
	}
	if len(px.running) == 0 || px.running[0] != 1 {
		t.Errorf("containers running at each proxy apply: %v, want the first with the replica still running", px.running)
	}
}
