package etcd

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ryanbekhen/armada/internal/pki"
)

func memberConfig(t *testing.T, ca *pki.CA, name string) Config {
	t.Helper()
	return Config{
		Dir: filepath.Join(t.TempDir(), "etcd"), Name: name, Addr: netip.MustParseAddr("127.0.0.1"),
		ClientPort: freePort(t), PeerPort: freePort(t), CA: ca, UnsafeNoFsync: true,
	}
}

// joinMember adds a member through via and waits until it votes.
func joinMember(ctx context.Context, t *testing.T, via *Member, cfg Config) *Member {
	t.Helper()
	_, initial, err := AddLearner(ctx, via.Client(), cfg.Name, cfg.Addr, cfg.PeerPort)
	if err != nil {
		t.Fatal(err)
	}
	cfg.InitialCluster = initial
	m, err := Start(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	if !m.IsLearner() {
		t.Error("a joining member must start as a learner")
	}
	go func() {
		for m.IsLearner() && ctx.Err() == nil {
			_, _ = Promote(ctx, via.Client())
			time.Sleep(100 * time.Millisecond)
		}
	}()
	if err := m.WaitVoter(ctx); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestThreeMemberCluster(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	ca, _ := pki.NewCA("test")
	m1, err := Start(ctx, memberConfig(t, ca, "cp-1"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m1.Close() })
	m2 := joinMember(ctx, t, m1, memberConfig(t, ca, "cp-2"))
	m3 := joinMember(ctx, t, m2, memberConfig(t, ca, "cp-3"))

	if _, _, err := AddLearner(ctx, m1.Client(), "cp-2", netip.MustParseAddr("127.0.0.1"), freePort(t)); err == nil {
		t.Error("added a second member named cp-2")
	}
	members, err := Members(ctx, m3.Client())
	if err != nil || len(members) != 3 {
		t.Fatalf("members = %+v, %v", members, err)
	}
	if _, err := m1.Client().Put(ctx, "k", "v"); err != nil {
		t.Fatal(err)
	}
	resp, err := m3.Client().Get(ctx, "k")
	if err != nil || len(resp.Kvs) != 1 {
		t.Fatalf("replicated read: %v %v", resp, err)
	}

	// One of three may fail: the other two keep a quorum.
	_ = m1.Close()
	wctx, wcancel := context.WithTimeout(ctx, 20*time.Second)
	defer wcancel()
	if _, err := m2.Client().Put(wctx, "k", "after"); err != nil {
		t.Fatalf("write without cp-1: %v", err)
	}
	if err := RemoveMember(ctx, m2.Client(), m1.ID()); err != nil {
		t.Fatal(err)
	}
	if members, _ := Members(ctx, m2.Client()); len(members) != 2 {
		t.Errorf("members after remove = %+v", members)
	}
}

func TestElection(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ca, _ := pki.NewCA("test")
	m, err := Start(ctx, memberConfig(t, ca, "cp-1"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	c := m.Client()

	if name, err := Leader(ctx, c); err != nil || name != "" {
		t.Errorf("leader before any campaign = %q, %v", name, err)
	}
	a, err := Campaign(ctx, c, 5*time.Second, "cp-a")
	if err != nil {
		t.Fatal(err)
	}
	if name, _ := Leader(ctx, c); name != "cp-a" {
		t.Errorf("leader = %q", name)
	}
	won := make(chan *Leadership, 1)
	go func() {
		b, err := Campaign(ctx, c, 5*time.Second, "cp-b")
		if err == nil {
			won <- b
		}
	}()
	select {
	case <-won:
		t.Fatal("two leaders at once")
	case <-time.After(500 * time.Millisecond):
	}
	key, rev := a.Fence()
	resp, err := c.Get(ctx, key)
	if err != nil || len(resp.Kvs) != 1 || resp.Kvs[0].CreateRevision != rev {
		t.Fatalf("fence key %s rev %d: %v %v", key, rev, resp, err)
	}
	if err := a.Resign(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-a.Done():
	case <-time.After(5 * time.Second):
		t.Error("resigned leadership not done")
	}
	select {
	case b := <-won:
		if name, _ := Leader(ctx, c); name != "cp-b" {
			t.Errorf("leader after resign = %q", name)
		}
		_ = b.Resign(ctx)
	case <-time.After(10 * time.Second):
		t.Fatal("second candidate never won")
	}
}

func TestPeerURLFollowsAddress(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ca, _ := pki.NewCA("test")
	cfg := memberConfig(t, ca, "cp-1")
	m, err := Start(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	_ = m.Close()
	cfg.PeerPort = freePort(t)
	m, err = Start(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	members, err := Members(ctx, m.Client())
	want := memberURL(cfg.Addr, cfg.PeerPort)
	if err != nil || len(members) != 1 || members[0].PeerURL != want.String() {
		t.Errorf("members = %+v, %v; want peer %s", members, err, want.String())
	}
}

// A joining member whose first start failed half-way still joins on the
// next start instead of founding a cluster of its own.
func TestJoinAfterFailedFirstStart(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	ca, _ := pki.NewCA("test")
	m1, err := Start(ctx, memberConfig(t, ca, "cp-1"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m1.Close() })
	cfg := memberConfig(t, ca, "cp-2")
	if err := os.MkdirAll(filepath.Join(cfg.Dir, dirData, "member", "snap"), 0o700); err != nil {
		t.Fatal(err)
	}
	m2 := joinMember(ctx, t, m1, cfg)
	if members, _ := Members(ctx, m2.Client()); len(members) != 2 {
		t.Errorf("members = %+v", members)
	}
}
