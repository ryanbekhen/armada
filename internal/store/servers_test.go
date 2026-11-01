package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ryanbekhen/armada/internal/etcd"
)

func TestServers(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	if list, err := s.ListServers(ctx); err != nil || len(list) != 0 {
		t.Fatalf("empty list = %v, %v", list, err)
	}
	a := Server{Name: "cp-1", PrivateIP: "10.0.0.2", APIAddr: "10.0.0.2:7443", JoinAddr: "10.0.0.2:7444", MemberID: 1<<63 + 5}
	if err := s.UpsertServer(ctx, a); err != nil {
		t.Fatal(err)
	}
	a.APIAddr = "10.0.0.2:8443"
	if err := s.UpsertServer(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertServer(ctx, Server{Name: "cp-0", PrivateIP: "10.0.0.1", APIAddr: "10.0.0.1:7443"}); err != nil {
		t.Fatal(err)
	}
	list, err := s.ListServers(ctx)
	if err != nil || len(list) != 2 || list[0].Name != "cp-0" || list[1].APIAddr != "10.0.0.2:8443" || list[1].MemberID != 1<<63+5 || list[1].CreatedAt.IsZero() {
		t.Fatalf("list = %+v, %v", list, err)
	}
	if err := s.RemoveServer(ctx, "cp-0", "admin:me"); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveServer(ctx, "cp-0", "admin:me"); !errors.Is(err, ErrNotFound) {
		t.Errorf("second remove = %v", err)
	}
	if list, _ := s.ListServers(ctx); len(list) != 1 {
		t.Errorf("after remove = %+v", list)
	}
}

// A node token cannot add a server and a server token cannot add a node.
func TestTokenKinds(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	exp := time.Now().Add(time.Hour)
	for _, tok := range []JoinToken{{ID: "node", SecretHash: "h", ExpiresAt: exp}, {ID: "srv", SecretHash: "h", ExpiresAt: exp, Server: true}} {
		if err := s.CreateJoinToken(ctx, tok); err != nil {
			t.Fatal(err)
		}
	}
	srv := Server{Name: "cp-2", PrivateIP: "10.0.0.3", APIAddr: "10.0.0.3:7443"}
	n := Node{ID: "cp-2", PrivateIP: "10.0.0.3"}
	if err := s.RedeemServerToken(ctx, "node", accept, srv, n, issued("a", exp)); !errors.Is(err, ErrNotFound) {
		t.Errorf("server joined with a node token: %v", err)
	}
	if err := s.RedeemJoinToken(ctx, "srv", accept, n, issued("b", exp)); !errors.Is(err, ErrNotFound) {
		t.Errorf("node joined with a server token: %v", err)
	}
	if err := s.RedeemServerToken(ctx, "srv", func(string) bool { return false }, srv, n, issued("c", exp)); !errors.Is(err, ErrNotFound) {
		t.Errorf("wrong secret: %v", err)
	}
	if err := s.RedeemServerToken(ctx, "srv", accept, srv, n, issued("d", exp)); err != nil {
		t.Fatal(err)
	}
	if list, _ := s.ListServers(ctx); len(list) != 1 || list[0].Name != "cp-2" {
		t.Errorf("servers = %+v", list)
	}
	if ok, _ := s.NodeCertAllowed(ctx, "cp-2", "d"); !ok {
		t.Error("server's node certificate not recorded")
	}
	if err := s.RedeemServerToken(ctx, "srv", accept, srv, n, issued("e", exp)); !errors.Is(err, ErrNotFound) {
		t.Errorf("server token reused: %v", err)
	}
	// The node token still works for a node, and refuses a taken server name.
	if err := s.CreateJoinToken(ctx, JoinToken{ID: "srv2", SecretHash: "h", ExpiresAt: exp, Server: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.RedeemServerToken(ctx, "srv2", accept, srv, Node{ID: "other", PrivateIP: "10.0.0.9"}, issued("f", exp)); !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate server name: %v", err)
	}
}

// A store fenced to a leadership term stops writing once the term ends.
func TestFencedStore(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	l, err := etcd.Campaign(ctx, testMember.Client(), 5*time.Second, "cp-1")
	if err != nil {
		t.Fatal(err)
	}
	f := s.Fenced(l.Fence())
	if err := f.SetMeta(ctx, "k", "v1"); err != nil {
		t.Fatal(err)
	}
	if err := l.Resign(ctx); err != nil {
		t.Fatal(err)
	}
	if err := f.SetMeta(ctx, "k", "v2"); !errors.Is(err, ErrNotLeader) {
		t.Errorf("write after the term = %v", err)
	}
	if v, _ := f.GetMeta(ctx, "k"); v != "v1" {
		t.Errorf("value = %q", v)
	}
	// The unfenced store is unaffected.
	if err := s.SetMeta(ctx, "k", "v3"); err != nil {
		t.Error(err)
	}
}
