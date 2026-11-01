package store

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
)

func issued(serial string, notAfter time.Time) func() (NodeCert, error) {
	return func() (NodeCert, error) { return NodeCert{Serial: serial, NotAfter: notAfter}, nil }
}

func accept(string) bool { return true }
func reject(string) bool { return false }

func TestRedeemJoinToken(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	now := time.Now()
	s.SetNow(func() time.Time { return now })
	exp := now.Add(time.Hour)
	if err := s.CreateJoinToken(ctx, JoinToken{ID: "tok1", SecretHash: "h", ExpiresAt: exp, CreatedBy: "admin:a"}); err != nil {
		t.Fatal(err)
	}
	n2 := Node{ID: "node-2", PrivateIP: "10.0.0.2"}

	// A wrong secret, an unknown ID, or a failing issuer consume nothing.
	if err := s.RedeemJoinToken(ctx, "tok1", reject, n2, issued("a1", exp)); !errors.Is(err, ErrNotFound) {
		t.Errorf("wrong secret = %v", err)
	}
	if err := s.RedeemJoinToken(ctx, "nope", accept, n2, issued("a1", exp)); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown token = %v", err)
	}
	if err := s.RedeemJoinToken(ctx, "tok1", accept, n2, func() (NodeCert, error) { return NodeCert{}, errors.New("boom") }); err == nil {
		t.Error("issuer failure ignored")
	}
	if _, err := s.GetNode(ctx, "node-2"); !errors.Is(err, ErrNotFound) {
		t.Error("node registered despite failure")
	}
	// A name already taken is a conflict and keeps the token usable.
	if err := s.UpsertNode(ctx, Node{ID: "node-1", PrivateIP: "10.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	if err := s.RedeemJoinToken(ctx, "tok1", accept, Node{ID: "node-1", PrivateIP: "10.0.0.9"}, issued("a1", exp)); !errors.Is(err, ErrConflict) {
		t.Errorf("existing node = %v", err)
	}

	if err := s.RedeemJoinToken(ctx, "tok1", accept, n2, issued("a1", exp)); err != nil {
		t.Fatal(err)
	}
	n, err := s.GetNode(ctx, "node-2")
	if err != nil || n.PrivateIP != "10.0.0.2" || !n.CertNotAfter.Equal(time.UnixMilli(exp.UnixMilli())) {
		t.Errorf("joined node = %+v, %v", n, err)
	}
	if ok, _ := s.NodeCertAllowed(ctx, "node-2", "a1"); !ok {
		t.Error("issued certificate not allowed")
	}
	// Single use.
	if err := s.RedeemJoinToken(ctx, "tok1", accept, Node{ID: "node-3", PrivateIP: "10.0.0.3"}, issued("a2", exp)); !errors.Is(err, ErrNotFound) {
		t.Errorf("reused token = %v", err)
	}

	// Expiry.
	if err := s.CreateJoinToken(ctx, JoinToken{ID: "tok2", SecretHash: "h", ExpiresAt: now.Add(time.Minute), CreatedBy: "admin:a"}); err != nil {
		t.Fatal(err)
	}
	s.SetNow(func() time.Time { return now.Add(2 * time.Minute) })
	if err := s.RedeemJoinToken(ctx, "tok2", accept, Node{ID: "node-3", PrivateIP: "10.0.0.3"}, issued("a3", exp)); !errors.Is(err, ErrNotFound) {
		t.Errorf("expired token = %v", err)
	}

	audit, _ := s.ListAudit(ctx, 10)
	found := false
	for _, e := range audit {
		found = found || (e.Action == "node.join" && e.Actor == "token:tok1" && e.Target == "node-2")
	}
	if !found {
		t.Errorf("join not audited: %+v", audit)
	}
}

func TestNodeCertAllowlist(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	now := time.Now()
	s.SetNow(func() time.Time { return now })
	if err := s.UpsertNode(ctx, Node{ID: "n1", PrivateIP: "10.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.NodeCertAllowed(ctx, "n1", "s1"); ok {
		t.Error("unrecorded serial allowed")
	}
	if err := s.RecordNodeCert(ctx, "n1", NodeCert{Serial: "s1", NotAfter: now.Add(time.Hour)}, ""); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordNodeCert(ctx, "n1", NodeCert{Serial: "s2", NotAfter: now.Add(2 * time.Hour)}, ""); err != nil {
		t.Fatal(err)
	}
	for serial, want := range map[string]bool{"s1": true, "s2": true, "s3": false} {
		if ok, _ := s.NodeCertAllowed(ctx, "n1", serial); ok != want {
			t.Errorf("serial %s allowed = %v", serial, ok)
		}
	}
	if ok, _ := s.NodeCertAllowed(ctx, "ghost", "s1"); ok {
		t.Error("unknown node allowed")
	}
	if err := s.RecordNodeCert(ctx, "ghost", NodeCert{Serial: "x", NotAfter: now}, ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("record for unknown node = %v", err)
	}
	// Expired serials stop working and are dropped on the next renewal.
	s.SetNow(func() time.Time { return now.Add(90 * time.Minute) })
	if ok, _ := s.NodeCertAllowed(ctx, "n1", "s1"); ok {
		t.Error("expired serial allowed")
	}
	if err := s.RecordNodeCert(ctx, "n1", NodeCert{Serial: "s3", NotAfter: now.Add(3 * time.Hour)}, ""); err != nil {
		t.Fatal(err)
	}
	resp, err := s.c.Get(ctx, s.prefix+pfxCerts+"n1/", clientv3.WithPrefix(), clientv3.WithCountOnly())
	if err != nil {
		t.Fatal(err)
	}
	if count := resp.Count; count != 2 {
		t.Errorf("%d certs recorded, want the 2 unexpired ones", count)
	}
	// A renewal by s3 revokes every other certificate (s2 here, e.g. a
	// stolen one) and keeps only s3 and the new s4.
	if err := s.RecordNodeCert(ctx, "n1", NodeCert{Serial: "s4", NotAfter: now.Add(4 * time.Hour)}, "s3"); err != nil {
		t.Fatal(err)
	}
	for serial, want := range map[string]bool{"s2": false, "s3": true, "s4": true} {
		if ok, _ := s.NodeCertAllowed(ctx, "n1", serial); ok != want {
			t.Errorf("after renewal: serial %s allowed = %v", serial, ok)
		}
	}

	// Removing the node revokes everything.
	if _, _, err := s.Deploy(ctx, appSpec(t, "web", "nginx:1", 1), "a"); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateReplica(ctx, Replica{ID: "r1", App: "web", Revision: "web--r1", NodeID: "n1", State: ReplicaRunning}); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveNode(ctx, "n1", false, "admin:a"); !errors.Is(err, ErrPrecondition) {
		t.Errorf("remove with replicas = %v", err)
	}
	if err := s.RemoveNode(ctx, "n1", true, "admin:a"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.NodeCertAllowed(ctx, "n1", "s3"); ok {
		t.Error("certificate of a removed node allowed")
	}
	if rs, _ := s.ListReplicas(ctx, ReplicaFilter{NodeID: "n1"}); len(rs) != 0 {
		t.Errorf("replicas left on removed node: %v", rs)
	}
	if err := s.RemoveNode(ctx, "n1", false, "a"); !errors.Is(err, ErrNotFound) {
		t.Errorf("remove twice = %v", err)
	}
}

func TestLegacyNodeCerts(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	if err := s.UpsertNode(ctx, Node{ID: "old", PrivateIP: "10.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	// Nodes created before certificates were recorded.
	if err := s.setLegacyCerts(ctx); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.NodeCertAllowed(ctx, "old", "anything"); !ok {
		t.Error("legacy node rejected before renewal")
	}
	if err := s.RecordNodeCert(ctx, "old", NodeCert{Serial: "new", NotAfter: time.Now().Add(time.Hour)}, ""); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.NodeCertAllowed(ctx, "old", "anything"); ok {
		t.Error("legacy certificates still accepted after renewal")
	}
}

func TestCordonNode(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	if err := s.UpsertNode(ctx, Node{ID: "n1", PrivateIP: "10.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetNodeCordoned(ctx, "n1", true, "admin:a"); err != nil {
		t.Fatal(err)
	}
	// Upserts (e.g. status updates) keep the flag.
	if err := s.UpsertNode(ctx, Node{ID: "n1", PrivateIP: "10.0.0.1", State: NodeReady}); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.GetNode(ctx, "n1"); !n.Cordoned {
		t.Error("node not cordoned")
	}
	if err := s.SetNodeCordoned(ctx, "n1", false, "admin:a"); err != nil {
		t.Fatal(err)
	}
	if ns, _ := s.ListNodes(ctx); ns[0].Cordoned {
		t.Error("node still cordoned")
	}
	if err := s.SetNodeCordoned(ctx, "ghost", true, "a"); !errors.Is(err, ErrNotFound) {
		t.Errorf("cordon unknown = %v", err)
	}
}

func TestNodeLabelsAndRestriction(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	if err := s.UpsertNode(ctx, Node{ID: "n1", PrivateIP: "10.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	got, err := s.SetNodeLabels(ctx, "n1", map[string]string{"region": "sulawesi", "kind": "raspi"}, nil, "admin:a")
	if err != nil || len(got) != 2 {
		t.Fatalf("set labels: %v, %v", got, err)
	}
	if got, err = s.SetNodeLabels(ctx, "n1", map[string]string{"kind": "small"}, []string{"region"}, "admin:a"); err != nil ||
		len(got) != 1 || got["kind"] != "small" {
		t.Fatalf("change labels: %v, %v", got, err)
	}
	if err := s.SetNodeRestricted(ctx, "n1", true, "admin:a"); err != nil {
		t.Fatal(err)
	}
	// Status updates and upserts keep labels and the restriction, and the
	// reported OS and architecture stick until reported again.
	if err := s.SetNodeStatus(ctx, "n1", NodeStatus{State: NodeReady, OS: "linux", Arch: "arm64"}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetNodeStatus(ctx, "n1", NodeStatus{State: NodeReady}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertNode(ctx, Node{ID: "n1", PrivateIP: "10.0.0.1", State: NodeReady}); err != nil {
		t.Fatal(err)
	}
	n, _ := s.GetNode(ctx, "n1")
	all := n.AllLabels()
	if !n.Restricted || all["kind"] != "small" || all["armada.os"] != "linux" || all["armada.arch"] != "arm64" || len(all) != 3 {
		t.Errorf("node = %+v, labels %v", n, all)
	}
	// Removing the last label leaves none; too many labels are refused.
	if got, _ = s.SetNodeLabels(ctx, "n1", nil, []string{"kind"}, "admin:a"); got != nil {
		t.Errorf("labels after removing all = %v", got)
	}
	many := map[string]string{}
	for i := range 33 {
		many[fmt.Sprintf("k%d", i)] = "v"
	}
	if _, err := s.SetNodeLabels(ctx, "n1", many, nil, "admin:a"); !errors.Is(err, ErrPrecondition) {
		t.Errorf("33 labels = %v", err)
	}
	if err := s.SetNodeRestricted(ctx, "n1", false, "admin:a"); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.GetNode(ctx, "n1"); n.Restricted || n.Labels != nil {
		t.Errorf("after open: %+v", n)
	}
	if _, err := s.SetNodeLabels(ctx, "ghost", map[string]string{"a": "b"}, nil, "a"); !errors.Is(err, ErrNotFound) {
		t.Errorf("label unknown node = %v", err)
	}
	if err := s.SetNodeRestricted(ctx, "ghost", true, "a"); !errors.Is(err, ErrNotFound) {
		t.Errorf("restrict unknown node = %v", err)
	}
}

func TestJoinTokenLabels(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	exp := time.Now().Add(time.Hour)
	if err := s.CreateJoinToken(ctx, JoinToken{ID: "tok1", SecretHash: "h", ExpiresAt: exp, CreatedBy: "admin:a",
		Labels: map[string]string{"region": "papua"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.RedeemJoinToken(ctx, "tok1", accept, Node{ID: "n9", PrivateIP: "10.0.0.9"}, issued("s9", exp)); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.GetNode(ctx, "n9"); n.Labels["region"] != "papua" {
		t.Errorf("joined node labels = %v", n.Labels)
	}
}
