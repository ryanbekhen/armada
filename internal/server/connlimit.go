package server

import (
	"net"
	"sync"
)

// connLimit bounds the connections a listener keeps open, in total and per
// source address. It guards listeners that accept unauthenticated peers
// (the join listener): a connection beyond a bound is closed as soon as it
// is accepted, before any TLS or HTTP/2 work.
type connLimit struct {
	net.Listener
	total, perSource int

	mu    sync.Mutex
	open  int
	bySrc map[string]int
}

func newConnLimit(l net.Listener, total, perSource int) *connLimit {
	return &connLimit{Listener: l, total: total, perSource: perSource, bySrc: map[string]int{}}
}

func (l *connLimit) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		src := c.RemoteAddr().String()
		if host, _, err := net.SplitHostPort(src); err == nil {
			src = host
		}
		l.mu.Lock()
		ok := l.open < l.total && l.bySrc[src] < l.perSource
		if ok {
			l.open++
			l.bySrc[src]++
		}
		l.mu.Unlock()
		if !ok {
			_ = c.Close()
			continue
		}
		return &limitedConn{Conn: c, release: func() { l.release(src) }}, nil
	}
}

func (l *connLimit) release(src string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.open--
	if l.bySrc[src]--; l.bySrc[src] <= 0 {
		delete(l.bySrc, src)
	}
}

type limitedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}
