package cli

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ryanbekhen/armada/internal/clientconfig"
	"github.com/ryanbekhen/armada/internal/pki"
	"github.com/ryanbekhen/armada/internal/store"
)

// serverDir writes a CA and a server certificate valid for validity.
func serverDir(t *testing.T, validity time.Duration) (string, *pki.CA) {
	t.Helper()
	dir := t.TempDir()
	ca, _ := pki.NewCA("test")
	caKey, _ := ca.KeyPEM()
	certPEM, keyPEM, err := ca.Issue(pki.IssueRequest{Identity: pki.Identity{Kind: pki.KindServer, Name: "cp-1"}, DNSNames: []string{pki.ServerName}, IPs: []net.IP{net.ParseIP("10.0.0.2")}, Server: true, Validity: validity})
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{fileCACert: ca.CertPEM, fileCAKey: caKey, fileServerCert: certPEM, fileServerKey: keyPEM} {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir, ca
}

func TestCertRenewerRenewsServerCertificate(t *testing.T) {
	t.Parallel()
	for name, tt := range map[string]struct {
		later   time.Duration // how long after issue the check runs
		renewed bool
	}{
		"fresh":   {0, false},
		"due":     {50 * time.Minute, true},
		"expired": {2 * time.Hour, true},
	} {
		dir, ca := serverDir(t, time.Hour)
		old, _ := os.ReadFile(filepath.Join(dir, fileServerCert))
		keyPEM, _ := os.ReadFile(filepath.Join(dir, fileServerKey))
		sc, err := pki.NewServerCert(ca.CertPEM, old, keyPEM)
		if err != nil {
			t.Fatal(err)
		}
		r := &certRenewer{dataDir: dir, ca: ca, server: sc, log: slog.New(slog.NewTextHandler(io.Discard, nil)), now: func() time.Time { return time.Now().Add(tt.later) }}
		r.check()
		onDisk, _ := os.ReadFile(filepath.Join(dir, fileServerCert))
		if changed := !bytes.Equal(onDisk, old); changed != tt.renewed {
			t.Errorf("%s: file changed %v, want %v", name, changed, tt.renewed)
		}
		after := sc.Leaf()
		if !tt.renewed {
			continue
		}
		if _, err := tls.X509KeyPair(onDisk, keyPEM); err != nil {
			t.Errorf("%s: renewed file does not match the key: %v", name, err)
		}
		if disk, _ := pki.ParseCertPEM(onDisk); !bytes.Equal(disk.Raw, after.Raw) {
			t.Errorf("%s: served certificate is not the renewed one", name)
		}
		if time.Until(after.NotAfter) < 300*24*time.Hour || after.Subject.CommonName != "server:cp-1" || !after.IPAddresses[0].Equal(net.ParseIP("10.0.0.2")) {
			t.Errorf("%s: renewed %s %v until %v", name, after.Subject.CommonName, after.IPAddresses, after.NotAfter)
		}
	}
}

// A server that was off past its certificate's expiry renews the file
// before it loads it.
func TestCertRenewerRenewsExpiredFileBeforeLoad(t *testing.T) {
	t.Parallel()
	dir, ca := serverDir(t, -time.Hour)
	r := &certRenewer{dataDir: dir, ca: ca, log: slog.New(slog.NewTextHandler(io.Discard, nil)), now: time.Now}
	r.check()
	pem, err := readPrivate(dir, fileCACert, fileServerCert, fileServerKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pki.NewServerCert(pem[0], pem[1], pem[2]); err != nil {
		t.Errorf("renewed file does not load: %v", err)
	}
}

func TestAdminRenewFromDataDir(t *testing.T) {
	t.Parallel()
	dir, ca := serverDir(t, time.Hour)
	certPEM, keyPEM, _ := ca.Issue(pki.IssueRequest{Identity: pki.Identity{Kind: pki.KindAdmin, Name: "root"}, Client: true, Validity: -time.Hour})
	cfgPath := filepath.Join(t.TempDir(), "config")
	cc := &clientconfig.Config{Servers: []string{"10.0.0.2:7443"}, CA: string(ca.CertPEM), Cert: string(certPEM), Key: string(keyPEM)}
	if err := cc.SaveFile(cfgPath); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := run(t, "--config", cfgPath, "admin", "renew", "--data-dir", dir)
	if code != 0 || !strings.Contains(out, "Renewed admin:root") {
		t.Fatalf("code %d: %s %s", code, out, errOut)
	}
	got, err := clientconfig.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := pki.ParseCertPEM([]byte(got.Cert))
	if id, _ := pki.IdentityFromCert(c); id.String() != "admin:root" || time.Until(c.NotAfter) < 300*24*time.Hour || got.Key == string(keyPEM) || len(got.Servers) != 1 {
		t.Errorf("config holds %v until %v", id, c.NotAfter)
	}
	if _, err := tls.X509KeyPair([]byte(got.Cert), []byte(got.Key)); err != nil {
		t.Error(err)
	}

	// A config without an administrator certificate is refused.
	nodePEM, nodeKey, _ := ca.Issue(pki.IssueRequest{Identity: pki.Identity{Kind: pki.KindNode, Name: "n1"}, Client: true})
	cc.Cert, cc.Key = string(nodePEM), string(nodeKey)
	_ = cc.SaveFile(cfgPath)
	if code, _, errOut := run(t, "--config", cfgPath, "admin", "renew", "--data-dir", dir); code == 0 || !strings.Contains(errOut, "administrator certificate") {
		t.Errorf("node certificate renewed as admin: %d %s", code, errOut)
	}
}

// recordingStore records node certificates for known nodes only.
type recordingStore struct {
	store.Store
	nodes    map[string]bool
	recorded []store.NodeCert
}

func (s *recordingStore) RecordNodeCert(_ context.Context, node string, c store.NodeCert, _ string) error {
	if !s.nodes[node] {
		return store.ErrNotFound
	}
	s.recorded = append(s.recorded, c)
	return nil
}

func TestCertRenewerRenewsExpiredNodeCertificate(t *testing.T) {
	t.Parallel()
	for name, tt := range map[string]struct {
		later   time.Duration // how long after issue the server starts
		known   bool
		renewed bool
	}{
		"valid":        {29 * 24 * time.Hour, true, false},
		"expired":      {31 * 24 * time.Hour, true, true},
		"removed node": {31 * 24 * time.Hour, false, false},
	} {
		dir, ca := serverDir(t, 365*24*time.Hour)
		keyPEM, csr, _ := pki.NewNodeCSR("c1")
		nc, err := ca.SignNodeCSR(csr, "c1", pki.NodeValidity)
		if err != nil {
			t.Fatal(err)
		}
		short := nc.PEM
		_ = os.WriteFile(filepath.Join(dir, fileNodeCert), short, 0o600)
		_ = os.WriteFile(filepath.Join(dir, fileNodeKey), keyPEM, 0o600)
		st := &recordingStore{nodes: map[string]bool{"c1": tt.known}}
		at := time.Now().Add(tt.later)
		r := &certRenewer{dataDir: dir, ca: ca, log: slog.New(slog.NewTextHandler(io.Discard, nil)), now: func() time.Time { return at }}
		r.renewNode(context.Background(), st)
		onDisk, _ := os.ReadFile(filepath.Join(dir, fileNodeCert))
		if changed := !bytes.Equal(onDisk, short); changed != tt.renewed {
			t.Errorf("%s: file changed %v, want %v", name, changed, tt.renewed)
		}
		if (len(st.recorded) == 1) != tt.renewed {
			t.Errorf("%s: recorded %d serials", name, len(st.recorded))
		}
		if !tt.renewed {
			continue
		}
		got, _ := pki.ParseCertPEM(onDisk)
		if id, _ := pki.IdentityFromCert(got); id.String() != "node:c1" || pki.SerialString(got) != st.recorded[0].Serial || time.Until(got.NotAfter) < 29*24*time.Hour || time.Until(got.NotAfter) > pki.NodeValidity {
			t.Errorf("%s: renewed %v serial %s until %v", name, id, pki.SerialString(got), got.NotAfter)
		}
		if _, err := tls.X509KeyPair(onDisk, keyPEM); err != nil {
			t.Errorf("%s: renewed certificate does not match the key: %v", name, err)
		}
	}
}
