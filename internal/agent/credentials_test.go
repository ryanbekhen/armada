package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/fsutil"
	"github.com/ryanbekhen/armada/internal/pki"
)

// renewer signs renewal CSRs with ca, optionally for another identity.
type renewer struct {
	armadav1.AgentServiceClient
	ca   *pki.CA
	name string
	err  error
}

func (r renewer) RenewCertificate(_ context.Context, in *armadav1.RenewCertificateRequest, _ ...grpc.CallOption) (*armadav1.RenewCertificateResponse, error) {
	if r.err != nil {
		return nil, r.err
	}
	c, err := r.ca.SignNodeCSR(in.GetCsr(), r.name, time.Hour)
	if err != nil {
		return nil, err
	}
	return &armadav1.RenewCertificateResponse{Cert: c.PEM}, nil
}

func writeCreds(t *testing.T, ca *pki.CA, node string) string {
	t.Helper()
	dir := t.TempDir()
	key, csr, err := pki.NewNodeCSR(node)
	if err != nil {
		t.Fatal(err)
	}
	c, err := ca.SignNodeCSR(csr, node, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{FileCACert: ca.CertPEM, FileNodeCert: c.PEM, FileNodeKey: key} {
		if err := fsutil.WriteFileAtomic(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestCredentialsRenew(t *testing.T) {
	t.Parallel()
	ca, _ := pki.NewCA("test")
	dir := writeCreds(t, ca, "n1")
	creds, err := LoadCredentials(dir, "n1")
	if err != nil {
		t.Fatal(err)
	}
	first := creds.Leaf()
	if err := creds.Renew(context.Background(), renewer{ca: ca, name: "n1"}); err != nil {
		t.Fatal(err)
	}
	if creds.Leaf().SerialNumber.Cmp(first.SerialNumber) == 0 {
		t.Error("not renewed")
	}
	for _, f := range []string{FileNodeCert, FileNodeKey} {
		if err := fsutil.CheckPrivate(filepath.Join(dir, f)); err != nil {
			t.Error(err)
		}
		if _, err := os.Stat(filepath.Join(dir, f+pendingExt)); err == nil {
			t.Errorf("%s left behind", f+pendingExt)
		}
	}
	again, err := LoadCredentials(dir, "n1")
	if err != nil || again.Leaf().SerialNumber.Cmp(creds.Leaf().SerialNumber) != 0 {
		t.Errorf("reload = %v", err)
	}
}

func TestCredentialsRejectBadRenewal(t *testing.T) {
	t.Parallel()
	ca, _ := pki.NewCA("test")
	evil, _ := pki.NewCA("evil")
	for name, r := range map[string]renewer{
		"other identity": {ca: ca, name: "n2"},
		"other CA":       {ca: evil, name: "n1"},
	} {
		dir := writeCreds(t, ca, "n1")
		creds, _ := LoadCredentials(dir, "n1")
		before, _ := os.ReadFile(filepath.Join(dir, FileNodeCert))
		if err := creds.Renew(context.Background(), r); err == nil {
			t.Errorf("%s: renewal accepted", name)
		}
		after, _ := os.ReadFile(filepath.Join(dir, FileNodeCert))
		if string(before) != string(after) {
			t.Errorf("%s: certificate file replaced", name)
		}
	}
}

func TestLoadCredentials(t *testing.T) {
	t.Parallel()
	ca, _ := pki.NewCA("test")

	t.Run("wrong node", func(t *testing.T) {
		if _, err := LoadCredentials(writeCreds(t, ca, "n1"), "n2"); err == nil {
			t.Error("loaded another node's certificate")
		}
	})
	t.Run("loose permissions", func(t *testing.T) {
		dir := writeCreds(t, ca, "n1")
		_ = os.Chmod(filepath.Join(dir, FileNodeKey), 0o644)
		if _, err := LoadCredentials(dir, "n1"); err == nil {
			t.Error("loaded a world-readable key")
		}
	})
	t.Run("completes an interrupted renewal", func(t *testing.T) {
		dir := writeCreds(t, ca, "n1")
		key, csr, _ := pki.NewNodeCSR("n1")
		c, _ := ca.SignNodeCSR(csr, "n1", time.Hour)
		_ = fsutil.WriteFileAtomic(filepath.Join(dir, FileNodeKey+pendingExt), key, 0o600)
		_ = fsutil.WriteFileAtomic(filepath.Join(dir, FileNodeCert+pendingExt), c.PEM, 0o600)
		creds, err := LoadCredentials(dir, "n1")
		if err != nil {
			t.Fatal(err)
		}
		if pki.SerialString(creds.Leaf()) != c.Serial {
			t.Error("pending pair not promoted")
		}
	})
	t.Run("discards a half-written renewal", func(t *testing.T) {
		dir := writeCreds(t, ca, "n1")
		key, _, _ := pki.NewNodeCSR("n1")
		_ = fsutil.WriteFileAtomic(filepath.Join(dir, FileNodeKey+pendingExt), key, 0o600)
		if _, err := LoadCredentials(dir, "n1"); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(dir, FileNodeKey+pendingExt)); err == nil {
			t.Error("stray pending key kept")
		}
	})
}
