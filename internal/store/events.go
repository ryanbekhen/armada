package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
)

// Event is something the cluster did (ADR 0018): a replica crashed, a
// rollout finished, a node was lost. Events expire on their own.
type Event struct {
	// Key identifies the stored event; set by PutEvent and ListEvents.
	Key string
	// Kind is what the event is about (replica, rollout, node, app,
	// domain, certificate), Object its name; App and Node, when set, let
	// readers filter.
	Kind, Object, App, Node string
	Reason                  string
	Message                 string
	// Count is how often it happened between First and Last.
	Count       int
	First, Last time.Time
}

const (
	pfxEvents = "events/" // events/<last, unix nanoseconds, 20 digits>-<random>
	// EventTTL is how long events are kept.
	EventTTL = 24 * time.Hour
	// eventLeaseSpan groups events into one etcd lease per hour; each
	// lease lasts EventTTL past its hour, so events live 24 to 25 hours.
	eventLeaseSpan = time.Hour
)

type eventRec struct {
	Kind    string `json:"kind"`
	Object  string `json:"object"`
	App     string `json:"app,omitempty"`
	Node    string `json:"node,omitempty"`
	Reason  string `json:"reason"`
	Message string `json:"message,omitempty"`
	Count   int    `json:"count"`
	First   int64  `json:"first"`
	Last    int64  `json:"last"`
}

// eventLeases caches the lease of the current hour. Fenced copies of a
// store share it.
type eventLeases struct {
	mu     sync.Mutex
	bucket int64
	id     clientv3.LeaseID
}

func (s *Etcd) eventLease(ctx context.Context, at time.Time) (clientv3.LeaseID, error) {
	bucket := at.Truncate(eventLeaseSpan).Unix()
	s.leases.mu.Lock()
	defer s.leases.mu.Unlock()
	if s.leases.id != 0 && s.leases.bucket == bucket {
		return s.leases.id, nil
	}
	l, err := s.c.Grant(ctx, int64((EventTTL + eventLeaseSpan).Seconds()))
	if err != nil {
		return 0, err
	}
	s.leases.bucket, s.leases.id = bucket, l.ID
	return l.ID, nil
}

// PutEvent stores e under a new key (ordered by e.Last) and deletes the
// key replace, if set: an event that happened again moves to the end. It
// bypasses the state transaction, since events never take part in its
// invariants, but a fenced store still writes only while it leads.
func (s *Etcd) PutEvent(ctx context.Context, e Event, replace string) (string, error) {
	lease, err := s.eventLease(ctx, e.Last)
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(eventRec{Kind: e.Kind, Object: e.Object, App: e.App, Node: e.Node, Reason: e.Reason, Message: e.Message,
		Count: e.Count, First: e.First.UnixMilli(), Last: e.Last.UnixMilli()})
	if err != nil {
		return "", err
	}
	key := fmt.Sprintf("%s%020d-%s", pfxEvents, e.Last.UnixNano(), randomSuffix())
	ops := []clientv3.Op{clientv3.OpPut(s.prefix+key, string(b), clientv3.WithLease(lease))}
	if replace != "" && replace != key {
		ops = append(ops, clientv3.OpDelete(s.prefix+replace))
	}
	var cmps []clientv3.Cmp
	if s.fenceKey != "" {
		cmps = append(cmps, clientv3.Compare(clientv3.CreateRevision(s.fenceKey), "=", s.fenceRev))
	}
	tr, err := s.c.Txn(ctx).If(cmps...).Then(ops...).Commit()
	if err != nil {
		return "", err
	}
	if !tr.Succeeded {
		return "", ErrNotLeader
	}
	return key, nil
}

// ListEvents returns the events whose last occurrence is at or after
// since, oldest first.
func (s *Etcd) ListEvents(ctx context.Context, since time.Time) ([]Event, error) {
	from := fmt.Sprintf("%s%020d", pfxEvents, max(0, since.UnixNano()))
	resp, err := s.c.Get(ctx, s.prefix+from, clientv3.WithRange(clientv3.GetPrefixRangeEnd(s.prefix+pfxEvents)))
	if err != nil {
		return nil, err
	}
	out := make([]Event, 0, len(resp.Kvs))
	for _, kv := range resp.Kvs {
		var r eventRec
		if err := json.Unmarshal(kv.Value, &r); err != nil {
			return nil, fmt.Errorf("decode %s: %w", kv.Key, err)
		}
		out = append(out, Event{Key: string(kv.Key[len(s.prefix):]), Kind: r.Kind, Object: r.Object, App: r.App, Node: r.Node,
			Reason: r.Reason, Message: r.Message, Count: r.Count, First: fromMS(r.First), Last: fromMS(r.Last)})
	}
	return out, nil
}

// TrimEvents deletes the oldest events beyond keep.
func (s *Etcd) TrimEvents(ctx context.Context, keep int) error {
	resp, err := s.c.Get(ctx, s.prefix+pfxEvents, clientv3.WithPrefix(), clientv3.WithKeysOnly())
	if err != nil {
		return err
	}
	drop := len(resp.Kvs) - keep
	if drop <= 0 {
		return nil
	}
	// The oldest come first (keys start with the time): one range delete
	// up to the first event kept, however many go.
	_, err = s.c.Delete(ctx, s.prefix+pfxEvents, clientv3.WithRange(string(resp.Kvs[drop].Key)))
	return err
}

func randomSuffix() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
