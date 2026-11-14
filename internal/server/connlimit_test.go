package server

import (
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	"github.com/ryanbekhen/armada/internal/pki"
)

// connLimit closes connections beyond its bounds as soon as they arrive.
func TestConnLimit(t *testing.T) {
	t.Parallel()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	lim := newConnLimit(l, 2, 1)
	t.Cleanup(func() { _ = lim.Close() })
	accepted := make(chan net.Conn, 4)
	go func() {
		for {
			c, err := lim.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	dial := func() net.Conn {
		c, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		return c
	}
	closed := func(c net.Conn) bool {
		_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		_, err := c.Read(make([]byte, 1))
		return err == io.EOF
	}
	first := dial()
	got := <-accepted
	if second := dial(); !closed(second) {
		t.Error("a second connection from the same source was kept")
	}
	if closed(first) {
		t.Error("the first connection was closed")
	}
	_ = got.Close() // frees the source's slot
	third := dial()
	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Error("a connection after a release was not accepted")
	}
	_ = third
}

// The join listener closes a connection that completed TLS and HTTP/2's
// preface but never makes a call.
func TestJoinListenerClosesIdleConnections(t *testing.T) {
	t.Parallel()
	c := newCluster(t, withJoin(t), func(cfg *Config) { cfg.JoinIdle = 500 * time.Millisecond })
	tok := c.token()
	pin, err := pki.ParseCAHash(tok.CaHash)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := pki.FetchPinnedCA(c.ctx, tok.JoinAddr, pin)
	if err != nil {
		t.Fatal(err)
	}
	cfg := pki.JoinClientTLS(ca)
	cfg.NextProtos = []string{"h2"}
	conn, err := tls.Dial("tcp", tok.JoinAddr, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := conn.Write(append([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), 0, 0, 0, 4, 0, 0, 0, 0, 0)); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 4096)
	for {
		if _, err := conn.Read(buf); err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				t.Fatal("an idle join connection is still open after 10s")
			}
			return // closed by the server
		}
	}
}
