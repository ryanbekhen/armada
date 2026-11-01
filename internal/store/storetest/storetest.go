// Package storetest provides etcd-backed stores for tests in other
// packages. Call Main from TestMain; every Open returns a store under its
// own prefix of one shared embedded etcd member.
package storetest

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/ryanbekhen/armada/internal/etcd"
	"github.com/ryanbekhen/armada/internal/pki"
	"github.com/ryanbekhen/armada/internal/store"
)

var (
	member *etcd.Member
	prefix atomic.Int64
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
	member, err = etcd.Start(context.Background(), etcd.Config{
		Dir: filepath.Join(dir, "etcd"), Name: "test", Addr: netip.MustParseAddr("127.0.0.1"),
		ClientPort: freePort(), PeerPort: freePort(), CA: ca, UnsafeNoFsync: true,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer member.Close()
	return m.Run()
}

func freePort() int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
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
