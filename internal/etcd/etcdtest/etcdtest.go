// Package etcdtest starts embedded etcd members for tests on loopback ports
// picked at run time.
package etcdtest

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"syscall"

	"github.com/ryanbekhen/armada/internal/etcd"
)

// FreePort returns a loopback TCP port that was free a moment ago.
func FreePort() int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

// Start starts a new member with free client and peer ports. A port that
// another test took between the pick and the listen is tried again with
// new ones, after clearing the member's directory, so cfg.Dir must not hold
// data the test needs.
func Start(ctx context.Context, cfg etcd.Config) (*etcd.Member, error) {
	var err error
	for range 5 {
		cfg.ClientPort, cfg.PeerPort = FreePort(), FreePort()
		var m *etcd.Member
		if m, err = etcd.Start(ctx, cfg); err == nil || !AddrInUse(err) {
			return m, err
		}
		if rerr := os.RemoveAll(cfg.Dir); rerr != nil {
			return nil, rerr
		}
	}
	return nil, err
}

// AddrInUse reports whether err is a listen on a port someone else holds.
func AddrInUse(err error) bool {
	return errors.Is(err, syscall.EADDRINUSE) || strings.Contains(err.Error(), "address already in use")
}
