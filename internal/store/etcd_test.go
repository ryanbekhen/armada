package store

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
)

// Concurrent writers never lose an update: every transaction either sees
// the others' writes or retries.
func TestEtcdConcurrentWritesSerialize(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	const n = 40
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() {
			if err := s.RecordAudit(ctx, "a", "x", "t", ""); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	events, err := s.ListAudit(ctx, 1000)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[int64]bool{}
	for _, e := range events {
		seen[e.ID] = true
	}
	if len(events) != n || len(seen) != n {
		t.Errorf("%d events, %d distinct IDs, want %d", len(events), len(seen), n)
	}
}

// A join token redeemed concurrently is consumed exactly once.
func TestEtcdJoinTokenSingleUseUnderRace(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	exp := time.Now().Add(time.Hour)
	if err := s.CreateJoinToken(ctx, JoinToken{ID: "tok", SecretHash: "h", ExpiresAt: exp, CreatedBy: "a"}); err != nil {
		t.Fatal(err)
	}
	var ok atomic.Int32
	var wg sync.WaitGroup
	for i := range 10 {
		wg.Go(func() {
			n := Node{ID: "n" + string(rune('a'+i)), PrivateIP: "10.0.0." + string(rune('1'+i))}
			err := s.RedeemJoinToken(ctx, "tok", accept, n, issued("s"+n.ID, exp))
			switch {
			case err == nil:
				ok.Add(1)
			case !errors.Is(err, ErrNotFound):
				t.Error(err)
			}
		})
	}
	wg.Wait()
	nodes, _ := s.ListNodes(ctx)
	if ok.Load() != 1 || len(nodes) != 1 {
		t.Errorf("%d redemptions succeeded, %d nodes; want 1", ok.Load(), len(nodes))
	}
}

func TestEtcdRefusesNewerSchema(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	if _, err := s.c.Put(ctx, s.prefix+keySchema, "999"); err != nil {
		t.Fatal(err)
	}
	if _, err := NewEtcd(ctx, s.c, s.prefix); err == nil || !strings.Contains(err.Error(), "downgrades are not supported") {
		t.Errorf("newer schema = %v", err)
	}
}

func TestEtcdCorruptRecord(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	if _, err := s.c.Put(ctx, s.prefix+pfxNodes+"bad", "{not json"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ListNodes(ctx); err == nil {
		t.Error("corrupt record decoded")
	}
}

func TestEtcdPrefixIsolation(t *testing.T) {
	t.Parallel()
	a, b, ctx := open(t), open(t), context.Background()
	if err := a.SetMeta(ctx, "k", "v"); err != nil {
		t.Fatal(err)
	}
	if _, err := b.GetMeta(ctx, "k"); !errors.Is(err, ErrNotFound) {
		t.Errorf("other prefix sees the key: %v", err)
	}
	if _, err := NewEtcd(ctx, a.c, "/no-slash"); err == nil {
		t.Error("prefix without trailing slash accepted")
	}
	resp, _ := a.c.Get(ctx, a.prefix, clientv3.WithPrefix(), clientv3.WithKeysOnly())
	for _, kv := range resp.Kvs {
		if !strings.HasPrefix(string(kv.Key), a.prefix) {
			t.Errorf("key outside prefix: %s", kv.Key)
		}
	}
}

func TestParseRevisionName(t *testing.T) {
	t.Parallel()
	for name, want := range map[string]bool{"web--r1": true, "a-b--r12": true, "web--r0": false, "web": false, "--r1": false, "web--rx": false} {
		if _, _, ok := parseRevisionName(name); ok != want {
			t.Errorf("%s: ok = %v", name, ok)
		}
	}
}
