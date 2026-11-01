package cli

import (
	"net"
	"net/netip"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// Every data dir in the tests gets its own etcd ports, so clusters in
// parallel tests never collide; a server started later on the same data
// dir reuses them. They come from a range below the ephemeral ports that
// freePort hands out, so they never land on an API or join port.
func init() {
	etcdNoFsync = true
	// Members listen on loopback, whatever private IP a test uses.
	etcdAddrOverride = netip.MustParseAddr("127.0.0.1")
	leaderLease = 2 * time.Second
	var mu sync.Mutex
	ports := map[string][2]int{}
	etcdPorts = func(dataDir string) (int, int) {
		mu.Lock()
		defer mu.Unlock()
		key := filepath.Clean(dataDir)
		p, ok := ports[key]
		if !ok {
			p = [2]int{nextEtcdPort(), nextEtcdPort()}
			ports[key] = p
		}
		return p[0], p[1]
	}
}

var etcdPortNext atomic.Int32

func init() { etcdPortNext.Store(20000) }

func nextEtcdPort() int {
	for {
		p := int(etcdPortNext.Add(1))
		if p > 30000 {
			panic("out of etcd test ports")
		}
		l, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(p))
		if err == nil {
			_ = l.Close()
			return p
		}
	}
}
