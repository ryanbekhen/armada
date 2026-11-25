// Package storetest provides etcd-backed stores for tests in other
// packages. Call Main from TestMain; every Open returns a store under its
// own prefix of one shared embedded etcd member.
package storetest

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/ryanbekhen/armada/internal/etcd"
	"github.com/ryanbekhen/armada/internal/etcd/etcdtest"
	"github.com/ryanbekhen/armada/internal/pki"
	"github.com/ryanbekhen/armada/internal/store"
)

var (
	member    *etcd.Member
	memberDir string
	prefix    atomic.Int64
)

// Main starts the shared member, runs the tests, and removes the member.
func Main(m *testing.M) {
	os.Exit(run(m))
}

func run(m *testing.M) int {
	dir, err := os.MkdirTemp("", "armada-storetest-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer os.RemoveAll(dir)
	ca, err := pki.NewCA("test")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	memberDir = filepath.Join(dir, "etcd")
	member, err = etcdtest.Start(context.Background(), etcd.Config{
		Dir: filepath.Join(dir, "etcd"), Name: "test", Addr: netip.MustParseAddr("127.0.0.1"),
		CA: ca, UnsafeNoFsync: true,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer member.Close()
	return m.Run()
}

// Open returns an empty store.
func Open(t testing.TB) *store.Etcd {
	t.Helper()
	if member == nil {
		t.Fatal("storetest: call storetest.Main from TestMain")
	}
	s, err := store.NewEtcd(context.Background(), member.Client(), fmt.Sprintf("/test/%d/", prefix.Add(1)))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// OpenNamed returns an empty store and its prefix, for a program that
// opens the same keyspace (the Rust parity tests, ADR 0055).
func OpenNamed(t testing.TB) (*store.Etcd, string) {
	t.Helper()
	if member == nil {
		t.Fatal("storetest: call storetest.Main from TestMain")
	}
	pfx := fmt.Sprintf("/test/%d/", prefix.Add(1))
	s, err := store.NewEtcd(context.Background(), member.Client(), pfx)
	if err != nil {
		t.Fatal(err)
	}
	return s, pfx
}

// Member returns the shared member's client endpoint and the directory
// holding its certificates, which a program reads to connect.
func Member() (endpoint, dir string) {
	return member.Client().Endpoints()[0], memberDir
}

// Client returns a client of the shared member, to read keyspaces whole.
func Client() *clientv3.Client { return member.Client() }
