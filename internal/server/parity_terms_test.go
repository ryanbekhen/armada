package server

import (
	"bufio"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/etcd"
	"github.com/ryanbekhen/armada/internal/pki"
	"github.com/ryanbekhen/armada/internal/store"
	"github.com/ryanbekhen/armada/internal/store/storetest"
)

// TestArmadaServerTerms runs the Rust control plane as `armadad server`
// runs Go's (ADR 0055): it campaigns on the member's election, runs a
// term on a store fenced on its key (migrating a fresh keyspace first),
// runs the term's server again when the cluster's server settings
// change, keeping the leadership, and resigns when it stops.
func TestArmadaServerTerms(t *testing.T) {
	if serverBin() == "" {
		t.Skip("ARMADA_SERVER_BIN is not set (cargo build -p armada-server --features parity)")
	}
	fx := newParityFixtures(t)
	st, pfx := storetest.OpenNamed(t)
	ctx := t.Context()
	if err := st.KnowUser(ctx, "ryan"); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	api := l.Addr().String()
	_ = l.Close()
	endpoint, dir := storetest.Member()
	conf := map[string]any{
		"endpoint": endpoint, "dir": dir, "prefix": pfx, "elect": true, "leaseSeconds": 2,
		"caCert": string(fx.ca.CertPEM), "caKey": mustKeyPEM(t, fx.ca),
		"serverCert": string(fx.certPEM), "serverKey": string(fx.keyPEM),
		"name": "cp-1", "apiListen": api, "nowMs": fx.start.UnixMilli(), "resyncMs": time.Hour.Milliseconds(),
		"verbose": os.Getenv("ARMADA_SERVER_VERBOSE") != "",
	}
	cmd := exec.Command(serverBin())
	cmd.Stderr = os.Stderr
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	events := make(chan map[string]any, 16)
	go func() {
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			var m map[string]any
			if json.Unmarshal(sc.Bytes(), &m) == nil {
				events <- m
			}
		}
		close(events)
	}()
	b, _ := json.Marshal(conf)
	if _, err := in.Write(append(b, '\n')); err != nil {
		t.Fatal(err)
	}
	wait := func(event string) {
		t.Helper()
		deadline := time.After(30 * time.Second)
		for {
			select {
			case m, ok := <-events:
				if !ok {
					t.Fatalf("the program ended before %s", event)
				}
				if m["event"] == "failed" {
					t.Fatalf("the program failed: %v", m["error"])
				}
				if m["event"] == event {
					return
				}
			case <-deadline:
				t.Fatalf("no %s", event)
			}
		}
	}
	wait("leading")
	leader, err := etcd.Leader(ctx, storetest.Client())
	if err != nil || leader != "cp-1" {
		t.Fatalf("leader %q, %v", leader, err)
	}
	if schema, err := st.StoredSchema(ctx); err != nil || schema != store.SchemaVersion() {
		t.Errorf("schema %d, %v: the term migrates a fresh keyspace", schema, err)
	}
	certPEM, keyPEM, err := fx.ca.Issue(pki.IssueRequest{Identity: pki.Identity{Kind: pki.KindUser, Name: "ryan"}, Client: true})
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg, err := pki.ClientTLS(fx.ca.CertPEM, certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := grpc.NewClient(api, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	admin := armadav1.NewAdminServiceClient(conn)
	if _, err := admin.SetClusterConfig(ctx, &armadav1.SetClusterConfigRequest{SetNodeLostTimeout: true,
		Config: &armadav1.ClusterConfig{NodeLostTimeoutSeconds: 60}}); err != nil {
		t.Fatal(err)
	}
	// The settings changed: the term's server runs again, still leading.
	wait("leading")
	if leader, err := etcd.Leader(ctx, storetest.Client()); err != nil || leader != "cp-1" {
		t.Fatalf("leader after the restart %q, %v", leader, err)
	}
	var cc *armadav1.ClusterConfig
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if cc, err = admin.GetClusterConfig(ctx, &armadav1.GetClusterConfigRequest{}); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	_ = cc
	// Stopping resigns: the election is free at once.
	if _, err := in.Write([]byte(`{"op":"stop","id":1}` + "\n")); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if l, err := etcd.Leader(ctx, storetest.Client()); err == nil && l == "" {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Error("the leadership was not given up")
}
