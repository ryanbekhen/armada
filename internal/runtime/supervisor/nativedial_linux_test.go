package supervisor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"

	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	"github.com/ryanbekhen/armada/internal/runtime"
)

// dialResult is what a dial gives a caller.
type dialResult struct {
	Err                    string
	Refused, NotExist, Inv bool
	OpErr                  bool
	Remote                 string
}

func dialOutcome(conn net.Conn, err error) dialResult {
	r := dialResult{Err: errText(err), Refused: errors.Is(err, syscall.ECONNREFUSED), NotExist: errors.Is(err, os.ErrNotExist), Inv: errors.Is(err, syscall.EINVAL)}
	var op *net.OpError
	r.OpErr = errors.As(err, &op)
	if conn != nil {
		r.Remote = conn.RemoteAddr().Network() + " " + conn.RemoteAddr().String()
		_ = conn.Close()
	}
	return r
}

// armada-node's runtime dial connects from a network namespace and hands
// the connection back as Go's dialer would make it: TCP and UDP, IPv4 and
// IPv6, the same errors for a refused connection, a namespace that cannot
// be opened or entered, and a missing container; addresses Go's dialer
// handles alone (zones, service names, a family the network does not
// take) stay with Go. The namespace is the test's own, which needs no
// root (armada-node does not switch into the namespace it is in);
// switching namespaces is covered by the conformance suite.
func TestArmadaNodeDialMatchesGo(t *testing.T) {
	n := openNative(t)
	s := &Store{Bundles: Bundles{Dir: t.TempDir()}, Shims: &Shims{Dir: t.TempDir(), Native: n}, Native: n}
	ctx := context.Background()
	own := fmt.Sprintf("/proc/%d/ns/net", os.Getpid())

	tcp4, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp4.Close()
	go func() {
		for {
			c, err := tcp4.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	refused := closed.Addr().String()
	_ = closed.Close()
	addrs := []struct{ network, address string }{
		{"tcp", tcp4.Addr().String()},
		{"tcp4", tcp4.Addr().String()},
		{"tcp", "[::ffff:127.0.0.1]:" + fmt.Sprint(tcp4.Addr().(*net.TCPAddr).Port)},
		{"tcp", refused},
		{"udp", "127.0.0.1:53"},
		{"udp4", "127.0.0.1:9"},
	}
	if tcp6, err := net.Listen("tcp6", "[::1]:0"); err == nil {
		defer tcp6.Close()
		addrs = append(addrs, struct{ network, address string }{"tcp6", tcp6.Addr().String()}, struct{ network, address string }{"udp", "[::1]:53"})
	}
	for _, a := range addrs {
		want := dialOutcome((&net.Dialer{}).DialContext(ctx, a.network, a.address))
		conn, handled, err := s.NativeDial(ctx, "", own, "", a.network, a.address)
		if conn != nil && a.network[:3] == "tcp" {
			// net.FileConn makes the connection as the dialer does.
			raw, _ := conn.(*net.TCPConn).SyscallConn()
			var nodelay int
			_ = raw.Control(func(fd uintptr) { nodelay, _ = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NODELAY) })
			if nodelay == 0 {
				t.Errorf("%s %s: no TCP_NODELAY", a.network, a.address)
			}
		}
		got := dialOutcome(conn, err)
		if !handled || !reflect.DeepEqual(got, want) {
			t.Errorf("%s %s: handled %v\n go   %+v\n rust %+v", a.network, a.address, handled, want, got)
		}
	}

	// What Go's dialer handles alone.
	for _, a := range []struct{ network, address string }{
		{"tcp4", "[::1]:80"}, {"tcp6", "127.0.0.1:80"}, {"tcp6", "[::ffff:127.0.0.1]:80"},
		{"tcp", "127.0.0.1:http"}, {"tcp", "[fe80::1%lo]:80"}, {"ip4", "127.0.0.1:80"},
	} {
		if conn, handled, err := s.NativeDial(ctx, "", own, "", a.network, a.address); handled {
			t.Errorf("%s %s: armada-node dialled (%v, %v)", a.network, a.address, conn, err)
		}
	}

	// A namespace that cannot be opened, and a file that is none.
	missing := filepath.Join(t.TempDir(), "gone")
	_, gerr := netns.GetFromPath(missing)
	want := dialOutcome(nil, fmt.Errorf("sandbox namespace: %w", gerr))
	if _, handled, err := s.NativeDial(ctx, "", missing, "", "udp", "127.0.0.1:53"); !handled || !reflect.DeepEqual(dialOutcome(nil, err), want) {
		t.Errorf("missing namespace: %v %+v, want %+v", handled, dialOutcome(nil, err), want)
	}
	notNS := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(notNS, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	h, _ := netns.GetFromPath(notNS)
	serr := netns.Set(h)
	_ = h.Close()
	if _, handled, err := s.NativeDial(ctx, "", notNS, "", "udp", "127.0.0.1:53"); !handled || !reflect.DeepEqual(dialOutcome(nil, err), dialOutcome(nil, serr)) {
		t.Errorf("not a namespace: %v %+v, want %+v", handled, dialOutcome(nil, err), dialOutcome(nil, serr))
	}

	// A container: its shim names its process, whose namespace is dialled
	// from; a missing container or task is not found.
	mustWrite(t, filepath.Join(s.Bundles.Dir, "c1", bundleRecord), `{"id":"c1","image":"x","group":"g","created":"2026-11-23T08:00:00Z"}`)
	mustWrite(t, filepath.Join(s.Bundles.Dir, "c2", bundleRecord), `{"id":"c2","image":"x","group":"g","created":"2026-11-23T08:00:00Z"}`)
	fakeShim(t, s.Shims.Get("g").Socket, func(req string) string {
		if req == "state c1" {
			return fmt.Sprintf("ok running %d", os.Getpid())
		}
		return "err container c2 not found"
	})
	conn, handled, err := s.NativeDial(ctx, "c1", "", "/proc", "tcp", tcp4.Addr().String())
	if got := dialOutcome(conn, err); !handled || got.Err != "" || got.Remote != "tcp "+tcp4.Addr().String() {
		t.Errorf("container: %v %+v", handled, got)
	}
	for _, id := range []string{"c2", "c3"} {
		if _, handled, err := s.NativeDial(ctx, id, "", "/proc", "tcp", tcp4.Addr().String()); !handled || !errors.Is(err, runtime.ErrNotFound) {
			t.Errorf("%s: %v %v, want not found", id, handled, err)
		}
	}
	if got := n.StoodIn("dial"); got != 0 {
		t.Errorf("Go dialled %d times", got)
	}

	// Without armada-node, Go dials.
	gone, err := OpenNative(filepath.Join(t.TempDir(), "armada-node"), filepath.Join(t.TempDir(), "images"))
	if err != nil {
		t.Fatal(err)
	}
	if _, handled, _ := (&Store{Bundles: s.Bundles, Shims: s.Shims, Native: gone}).NativeDial(ctx, "", own, "", "tcp", tcp4.Addr().String()); handled || gone.StoodIn("dial") != 1 {
		t.Errorf("armada-node missing: handled %v, Go stood in %d", handled, gone.StoodIn("dial"))
	}
}
