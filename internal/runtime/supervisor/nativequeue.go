package supervisor

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/ryanbekhen/armada/internal/queuelen"
	"github.com/ryanbekhen/armada/internal/runtime"
)

// nativeQueue is what `queue redis|rabbitmq` reads: the reading, and the
// namespace as `runtime dial` names it. It holds the broker's URL, so it
// never prints itself.
type nativeQueue struct {
	URL       string   `json:"url"`
	Name      string   `json:"name"`
	Addresses []string `json:"addresses,omitempty"`
	TimeoutMs int64    `json:"timeoutMs,omitempty"`
	Dir       string   `json:"dir,omitempty"`
	ShimDir   string   `json:"shimDir,omitempty"`
	ID        string   `json:"id,omitempty"`
	Proc      string   `json:"proc,omitempty"`
	Netns     string   `json:"netns,omitempty"`
}

func (q nativeQueue) String() string       { return "queue " + q.Name }
func (q nativeQueue) LogValue() slog.Value { return slog.StringValue(q.String()) }

// NativeQueue reads a queue's length through armada-node from a network
// namespace, as queuelen does through the driver's dials (ADR 0054 step
// 5): container id's (netnsPath empty, its process found under procRoot)
// or the one pinned at netnsPath (a sandbox). handled is false when Go
// must read it: the node is not on armada-node, the call failed (logged
// once per distinct failure), or armada-node left it to Go (a name with
// no addresses, a zone, a shim that is gone).
func (s *Store) NativeQueue(ctx context.Context, id, netnsPath, procRoot string, q runtime.QueueRead) (n int64, handled bool, err error) {
	nat := s.Native
	if nat == nil || (q.Type != "redis" && q.Type != "rabbitmq") {
		return 0, false, nil
	}
	req := nativeQueue{URL: q.URL, Name: q.Name, TimeoutMs: timeoutMs(ctx)}
	for _, a := range q.Addresses {
		req.Addresses = append(req.Addresses, a.String())
	}
	if netnsPath != "" {
		req.Netns = netnsPath
	} else {
		req.Dir, req.ShimDir, req.ID, req.Proc = s.Bundles.Dir, s.Shims.Dir, id, procRoot
	}
	op := "queue " + q.Type
	b, err := nat.exec(ctx, true, req, "queue", q.Type)
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			// queuelen's reading ends with its context.
			return 0, true, fmt.Errorf("%s: %w", op, cerr)
		}
		nat.fallback(op, err)
		return 0, false, nil
	}
	var a struct {
		Length *int64  `json:"length"`
		Error  *string `json:"error"`
		Redo   *string `json:"redo"`
	}
	if err := json.Unmarshal(b, &a); err != nil {
		nat.fallback(op, programError{fmt.Errorf("unreadable answer: %w", err)})
		return 0, false, nil
	}
	switch {
	case a.Length != nil:
		nat.fallback(op, nil)
		return *a.Length, true, nil
	case a.Error != nil:
		nat.fallback(op, nil)
		return 0, true, queuelen.FromText(*a.Error)
	case a.Redo != nil:
		nat.fallback(op, nil)
		nat.standIn(op)
		return 0, false, nil
	}
	nat.fallback(op, programError{fmt.Errorf("unreadable answer: %s", b)})
	return 0, false, nil
}
