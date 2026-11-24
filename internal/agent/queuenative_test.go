package agent

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/queuelen"
	"github.com/ryanbekhen/armada/internal/runtime"
	"github.com/ryanbekhen/armada/internal/runtime/fake"
)

// queueDriver reads queues itself, as the supervisor runtime does
// through armada-node, until it leaves a reading to queuelen.
type queueDriver struct {
	*fake.Driver
	mu      sync.Mutex
	reads   []runtime.QueueRead
	handled bool
}

func (d *queueDriver) ReadQueue(_ context.Context, _ string, q runtime.QueueRead) (int64, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.reads = append(d.reads, q)
	return 7, d.handled, nil
}

func (d *queueDriver) ReadSandboxQueue(ctx context.Context, sandbox string, q runtime.QueueRead) (int64, bool, error) {
	return d.ReadQueue(ctx, sandbox, q)
}

// The agent hands Redis and RabbitMQ rules to a runtime that reads queues
// itself, and reads them with queuelen when it does not.
func TestQueueReadByRuntime(t *testing.T) {
	t.Parallel()
	d := &queueDriver{Driver: fake.New(), handled: true}
	a := New(Config{NodeID: "n", Driver: d})
	ctx := context.Background()
	p := &armadav1.QueueProbe{Type: "redis", Url: "redis://10.0.0.9:6380/1", Name: "jobs"}
	if n, err := a.readQueue(ctx, "c1", p); n != 7 || err != nil {
		t.Fatalf("handled: %d %v", n, err)
	}
	if len(d.reads) != 1 || d.reads[0].URL != p.GetUrl() || d.reads[0].Name != "jobs" || len(d.reads[0].Addresses) != 0 {
		t.Fatalf("reads = %v", d.reads)
	}
	// A bad URL still goes to the runtime, which words the error.
	p.Url = "redis://"
	if _, err := a.readQueue(ctx, "c1", p); err != nil || len(d.reads) != 2 {
		t.Fatalf("bad URL: %v %v", err, d.reads)
	}
	// Left to Go: queuelen dials through the runtime's dialer, which the
	// fake runtime does not offer.
	d.handled = false
	p.Url = "redis://10.0.0.9"
	if _, err := a.readQueue(ctx, "c1", p); !errors.Is(err, queuelen.ErrUnreachable) {
		t.Fatalf("left to Go: %v", err)
	}
}

// A broker named by a name is resolved from the namespace first; one that
// does not resolve is unreachable without asking the runtime.
func TestQueueNameResolvedFirst(t *testing.T) {
	t.Parallel()
	a := New(Config{NodeID: "n", Driver: fake.New()})
	ctx := context.Background()
	refuse := func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("no") }
	p := &armadav1.QueueProbe{Type: "rabbitmq", Url: "amqp://u:p@broker.invalid/", Name: "q"}
	_, handled, err := a.nativeQueue(ctx, p, refuse, func(runtime.QueueRead) (int64, bool, error) {
		t.Error("the runtime was asked")
		return 0, true, nil
	})
	if !handled || !errors.Is(err, queuelen.ErrUnreachable) {
		t.Fatalf("unresolved: %v %v", handled, err)
	}
	var got runtime.QueueRead
	p.Url = "amqp://u:p@[fd00::7]:5673/"
	if _, _, err := a.nativeQueue(ctx, p, refuse, func(q runtime.QueueRead) (int64, bool, error) {
		got = q
		return 1, true, nil
	}); err != nil || got.URL != p.GetUrl() || len(got.Addresses) != 0 {
		t.Fatalf("an address: %v %v", got, err)
	}
}
