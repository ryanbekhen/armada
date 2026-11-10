package haproxy

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"
)

// A reply past the bound is an error, never a silently shorter answer.
func TestRuntimeAPIReplyBound(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	old := maxResponse
	maxResponse = 1000
	t.Cleanup(func() { maxResponse = old })
	reply := ""
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 256)
			_, _ = c.Read(buf)
			_, _ = c.Write([]byte(reply))
			_ = c.Close()
		}
	}()
	s := Socket{Path: path}
	reply = strings.Repeat("x", 1000)
	if out, err := s.Command(context.Background(), "show stat"); err != nil || len(out) != 1000 {
		t.Errorf("reply at the bound: %d bytes, %v", len(out), err)
	}
	reply = strings.Repeat("x", 1001)
	if _, err := s.Command(context.Background(), "show stat"); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("reply past the bound: %v", err)
	}
}
