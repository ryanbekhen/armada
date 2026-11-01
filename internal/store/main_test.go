package store

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
)

// One etcd member serves the whole package; every test gets its own prefix.
var (
	testMember  *etcd.Member
	testEtcdDir string
	testPrefix  atomic.Int64
)

func TestMain(m *testing.M) {
	os.Exit(runTests(m))
}

func runTests(m *testing.M) int {
	dir, err := os.MkdirTemp("", "armada-store-")
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
	testEtcdDir = filepath.Join(dir, "etcd")
	testMember, err = etcd.Start(context.Background(), etcd.Config{
		Dir: testEtcdDir, Name: "test", Addr: netip.MustParseAddr("127.0.0.1"),
		ClientPort: freePort(), PeerPort: freePort(), CA: ca, UnsafeNoFsync: true,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer testMember.Close()
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

func open(t *testing.T) *Etcd {
	t.Helper()
	s, err := NewEtcd(context.Background(), testMember.Client(), fmt.Sprintf("/test/%d/", testPrefix.Add(1)))
	if err != nil {
		t.Fatal(err)
	}
	return s
}
