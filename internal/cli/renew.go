package cli

import (
	"context"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/ryanbekhen/armada/internal/etcd"
	"github.com/ryanbekhen/armada/internal/fsutil"
	"github.com/ryanbekhen/armada/internal/pki"
	"github.com/ryanbekhen/armada/internal/store"
)

// certRenewInterval is how often a server checks its own certificates.
const certRenewInterval = 12 * time.Hour

// certRenewer renews a server's own certificates, the API's and the etcd
// member's, once pki.RenewDue says so. Every server holds the CA, so it
// signs them itself, for the keys it already has; nothing restarts.
type certRenewer struct {
	dataDir string
	ca      *pki.CA
	// server, when set, takes the renewed certificate for the next
	// handshake; before the server loads it, only the file changes.
	server *pki.ServerCert
	member *etcd.Member
	log    *slog.Logger
	now    func() time.Time
}

func (r *certRenewer) loop(ctx context.Context) {
	t := time.NewTicker(certRenewInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.check()
		}
	}
}

func (r *certRenewer) check() {
	if err := r.renewServer(); err != nil {
		r.log.Warn("server certificate renewal failed; retrying", "err", err)
	}
	if r.member == nil {
		return
	}
	if ok, err := r.member.RenewCert(r.now()); err != nil {
		r.log.Warn("etcd member certificate renewal failed; retrying", "err", err)
	} else if ok {
		r.log.Info("etcd member certificate renewed")
	}
}

func (r *certRenewer) renewServer() error {
	path := filepath.Join(r.dataDir, fileServerCert)
	b, err := fsutil.ReadPrivateFile(path)
	if err != nil {
		return err
	}
	leaf, err := pki.ParseCertPEM(b)
	if err != nil {
		return err
	}
	if !pki.RenewDue(leaf, r.now()) {
		return nil
	}
	certPEM, err := r.ca.Reissue(leaf, 0)
	if err != nil {
		return err
	}
	keyPEM, err := fsutil.ReadPrivateFile(filepath.Join(r.dataDir, fileServerKey))
	if err != nil {
		return err
	}
	// Check the pair before it replaces the file.
	renewed, err := pki.NewServerCert(r.ca.CertPEM, certPEM, keyPEM)
	if err != nil {
		return err
	}
	if err := fsutil.WriteFileAtomic(path, certPEM, 0o600); err != nil {
		return err
	}
	if r.server != nil {
		if err := r.server.Set(certPEM, keyPEM); err != nil {
			return err
		}
	}
	r.log.Info("server certificate renewed", "expires", renewed.Leaf().NotAfter)
	return nil
}

// renewNode re-signs this machine's node certificate, for the same key,
// if it has expired: the agent renews it over the API while it is valid,
// but a machine that was off for longer than its lifetime could not start
// the agent, and with it this server. The new serial is recorded first, so
// a node that was removed meanwhile stays out. Call it before the agent
// starts: afterwards only the agent writes these files.
func (r *certRenewer) renewNode(ctx context.Context, st store.Store) {
	path := filepath.Join(r.dataDir, fileNodeCert)
	b, err := fsutil.ReadPrivateFile(path)
	if err != nil {
		return
	}
	leaf, err := pki.ParseCertPEM(b)
	if err != nil || r.now().Before(leaf.NotAfter) {
		return
	}
	id, err := pki.IdentityFromCert(leaf)
	if err != nil || id.Kind != pki.KindNode {
		return
	}
	certPEM, err := r.ca.Reissue(leaf, pki.NodeValidity)
	if err != nil {
		r.log.Warn("node certificate renewal failed", "err", err)
		return
	}
	c, err := pki.ParseCertPEM(certPEM)
	if err != nil {
		return
	}
	if err := st.RecordNodeCert(ctx, id.Name, store.NodeCert{Serial: pki.SerialString(c), NotAfter: c.NotAfter}, ""); err != nil {
		r.log.Warn("expired node certificate not renewed: the node may have been removed; join it again", "node", id.Name, "err", err)
		return
	}
	if err := fsutil.WriteFileAtomic(path, certPEM, 0o600); err != nil {
		r.log.Warn("node certificate renewal failed", "err", err)
		return
	}
	r.log.Info("expired node certificate renewed", "node", id.Name, "expires", c.NotAfter)
}
