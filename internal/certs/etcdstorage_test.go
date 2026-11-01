package certs

import (
	"context"
	"errors"
	"io/fs"
	"net"
	"net/netip"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/ryanbekhen/armada/internal/etcd"
	"github.com/ryanbekhen/armada/internal/pki"
)

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func newEtcdStorage(t *testing.T) *EtcdStorage {
	t.Helper()
	ca, _ := pki.NewCA("test")
	m, err := etcd.Start(context.Background(), etcd.Config{
		Dir: filepath.Join(t.TempDir(), "etcd"), Name: "cp-1", Addr: netip.MustParseAddr("127.0.0.1"),
		ClientPort: freePort(t), PeerPort: freePort(t), CA: ca, UnsafeNoFsync: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	s, err := NewEtcdStorage(m.Client(), "/acme/")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestEtcdStorage(t *testing.T) {
	t.Parallel()
	s, ctx := newEtcdStorage(t), context.Background()
	if _, err := s.Load(ctx, "certificates/a/x.crt"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing key: %v", err)
	}
	before := time.Now()
	for _, k := range []string{"certificates/a/x/x.crt", "certificates/a/x/x.key", "certificates/a/y/y.crt", "acme/account.json"} {
		if err := s.Store(ctx, k, []byte("v:"+k)); err != nil {
			t.Fatal(err)
		}
	}
	if b, err := s.Load(ctx, "certificates/a/x/x.key"); err != nil || string(b) != "v:certificates/a/x/x.key" {
		t.Errorf("load = %q, %v", b, err)
	}
	if !s.Exists(ctx, "certificates/a/x") || !s.Exists(ctx, "acme/account.json") || s.Exists(ctx, "certificates/b") {
		t.Error("Exists is wrong")
	}
	info, err := s.Stat(ctx, "certificates/a/x/x.crt")
	if err != nil || !info.IsTerminal || info.Size != int64(len("v:certificates/a/x/x.crt")) || info.Modified.Before(before.Add(-time.Second)) {
		t.Errorf("stat = %+v, %v", info, err)
	}
	if info, err := s.Stat(ctx, "certificates/a"); err != nil || info.IsTerminal {
		t.Errorf("dir stat = %+v, %v", info, err)
	}
	if got, err := s.List(ctx, "certificates/a", false); err != nil || !slices.Equal(got, []string{"certificates/a/x", "certificates/a/y"}) {
		t.Errorf("list = %v, %v", got, err)
	}
	if got, _ := s.List(ctx, "certificates", true); len(got) != 3 {
		t.Errorf("recursive list = %v", got)
	}
	if err := s.Delete(ctx, "certificates/a/x"); err != nil {
		t.Fatal(err)
	}
	if s.Exists(ctx, "certificates/a/x/x.crt") || !s.Exists(ctx, "certificates/a/y/y.crt") {
		t.Error("Delete removed the wrong keys")
	}
	if _, err := s.List(ctx, "nothing", false); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("empty list: %v", err)
	}
}

func TestEtcdStorageLock(t *testing.T) {
	t.Parallel()
	s, ctx := newEtcdStorage(t), context.Background()
	if err := s.Lock(ctx, "issue_cert_x"); err != nil {
		t.Fatal(err)
	}
	other, _ := NewEtcdStorage(s.c, "/acme/")
	defer other.Close()
	wctx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()
	if err := other.Lock(wctx, "issue_cert_x"); err == nil {
		t.Fatal("lock taken twice")
	}
	if err := s.Unlock(ctx, "issue_cert_x"); err != nil {
		t.Fatal(err)
	}
	if err := other.Lock(ctx, "issue_cert_x"); err != nil {
		t.Fatal(err)
	}
	if err := s.Unlock(ctx, "never"); err == nil {
		t.Error("unlocked a lock never taken")
	}
}

func TestCertificateFromEtcdStorage(t *testing.T) {
	t.Parallel()
	s, ctx := newEtcdStorage(t), context.Background()
	a, err := NewACME(Options{Storage: s, CA: LetsEncryptStaging})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	_ = s.Store(ctx, "certificates/"+a.issuerKey+"/web.example.org/web.example.org.crt", []byte("C\n"))
	_ = s.Store(ctx, "certificates/"+a.issuerKey+"/web.example.org/web.example.org.key", []byte("K\n"))
	if got, ok := a.Certificate(ctx, "web.example.org"); !ok || string(got) != "C\nK\n" {
		t.Errorf("bundle = %q, %v", got, ok)
	}
}
