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

// atSchema rewinds a fresh store to schema v, as an old keyspace would be.
func atSchema(t *testing.T, s *Etcd, v int) {
	t.Helper()
	if err := s.tx(context.Background(), func(tx *etx) error { return tx.put(keySchema, v) }); err != nil {
		t.Fatal(err)
	}
}

func TestMigrateSteps(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	atSchema(t, s, 1)
	var ran []int
	step := func(n int) migration {
		return func(tx *etx) error {
			ran = append(ran, n)
			return tx.put("migrated", n)
		}
	}
	from, err := s.migrate(ctx, 3, []migration{step(1), step(2)})
	if err != nil || from != 1 {
		t.Fatalf("migrate: from %d, %v", from, err)
	}
	if v, _ := s.StoredSchema(ctx); v != 3 || len(ran) != 2 {
		t.Fatalf("schema %d after steps %v", v, ran)
	}
	// Already current: nothing runs.
	ran = nil
	if from, err := s.migrate(ctx, 3, []migration{step(1), step(2)}); err != nil || from != 3 || len(ran) != 0 {
		t.Errorf("second migrate: from %d, %v, ran %v", from, err, ran)
	}
	// A newer keyspace is refused, never rewritten.
	if _, err := s.migrate(ctx, 2, []migration{step(1)}); err == nil {
		t.Error("migrated a newer keyspace down")
	}
	if _, err := s.migrate(ctx, 4, []migration{step(1)}); err == nil {
		t.Error("accepted a step list that does not match the schema")
	}
}

func TestMigrateFailedStepKeepsSchema(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	atSchema(t, s, 1)
	boom := errors.New("boom")
	_, err := s.migrate(ctx, 2, []migration{func(tx *etx) error {
		_ = tx.put("half", 1)
		return boom
	}})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	if v, _ := s.StoredSchema(ctx); v != 1 {
		t.Errorf("schema = %d after a failed step", v)
	}
	if resp, _ := s.c.Get(ctx, s.prefix+"half"); len(resp.Kvs) != 0 {
		t.Error("a failed step left writes behind")
	}
}

// Schema 2 (node labels), 3 (jobs), 4 (traffic), 5 (volumes), 6 (the
// cluster network), 7 (projects), 8 (administrators), and 10 (init
// containers and sidecars) need no rewrites,
// and 9 (access control) has nothing to move on a fresh keyspace: every
// step runs.
func TestMigrateToCurrent(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	atSchema(t, s, 1)
	if from, err := s.Migrate(ctx); err != nil || from != 1 {
		t.Fatalf("migrate: from %d, %v", from, err)
	}
	if v, _ := s.StoredSchema(ctx); v != 10 {
		t.Errorf("schema = %d, want 10", v)
	}
}

func TestMigrationsMatchSchema(t *testing.T) {
	if len(migrations) != etcdSchema-1 {
		t.Fatalf("%d migrations for schema %d", len(migrations), etcdSchema)
	}
}

func TestServerAndNodeVersions(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	if err := s.UpsertServer(ctx, Server{Name: "s1", PrivateIP: "10.0.0.1", APIAddr: "10.0.0.1:7443"}); err != nil {
		t.Fatal(err)
	}
	srvs, _ := s.ListServers(ctx)
	if len(srvs) != 1 || srvs[0].Schema != 1 {
		t.Fatalf("a record without a schema must read as schema 1: %+v", srvs)
	}
	if err := s.UpsertServer(ctx, Server{Name: "s1", PrivateIP: "10.0.0.1", APIAddr: "10.0.0.1:7443", Schema: 2, Version: "v0.2.0"}); err != nil {
		t.Fatal(err)
	}
	if srvs, _ = s.ListServers(ctx); srvs[0].Schema != 2 || srvs[0].Version != "v0.2.0" {
		t.Errorf("upgrade not recorded: %+v", srvs[0])
	}

	if err := s.UpsertNode(ctx, Node{ID: "n1", PrivateIP: "10.0.0.2"}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetNodeStatus(ctx, "n1", NodeStatus{State: NodeReady, Version: "v0.2.0"}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetNodeStatus(ctx, "n1", NodeStatus{State: NodeUnknown}); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.GetNode(ctx, "n1"); n.Version != "v0.2.0" {
		t.Errorf("node version = %q", n.Version)
	}
}
