package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/ryanbekhen/armada/internal/clientconfig"
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
	// st and adminConfig, when set, renew the user certificate in the
	// machine's shared admin config (renewAdmin).
	st          store.Store
	adminConfig string
	log         *slog.Logger
	now         func() time.Time
}

func (r *certRenewer) loop(ctx context.Context) {
	t := time.NewTicker(certRenewInterval)
	defer t.Stop()
	r.renewAdmin(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.check()
			r.renewAdmin(ctx)
		}
	}
}

// renewAdmin renews the user certificate in the machine's shared admin
// config (/etc/armada/admin.config) once a third of its life is left, or
// after it expired. That file is how the machine's cluster-admins (root and
// the armada group) reach the cluster, and root here holds the CA anyway,
// so renewing it gives nobody anything new; it only keeps the people who
// run the machine from being locked out a year after init. The cluster
// must still accept the certificate being replaced (store.RenewedUser): a
// user deleted, or replaced with `armada rbac user credentials`, is not
// brought back.
func (r *certRenewer) renewAdmin(ctx context.Context) {
	if r.st == nil || r.adminConfig == "" {
		return
	}
	if _, err := os.Stat(r.adminConfig); err != nil {
		return // no shared config on this machine
	}
	renewed, err := r.renewAdminConfig(ctx)
	switch {
	case err != nil:
		r.log.Warn("admin config not renewed; renew it with `sudo armadad user renew`", "file", r.adminConfig, "err", err)
	case !renewed.IsZero():
		r.log.Info("admin config renewed", "file", r.adminConfig, "expires", renewed)
	}
}

// renewAdminConfig renews the certificate in r.adminConfig when it is due
// and returns its new expiry (zero when nothing was due).
func (r *certRenewer) renewAdminConfig(ctx context.Context) (time.Time, error) {
	cc, err := clientconfig.Load(r.adminConfig)
	if err != nil {
		return time.Time{}, err
	}
	old, err := pki.ParseCertPEM([]byte(cc.Cert))
	if err != nil {
		return time.Time{}, err
	}
	if !pki.RenewDue(old, r.now()) {
		return time.Time{}, nil
	}
	if err := old.CheckSignatureFrom(r.ca.Cert); err != nil {
		return time.Time{}, fmt.Errorf("its certificate is not from this cluster's CA: %w", err)
	}
	id, err := pki.IdentityFromCert(old)
	ok := false
	if err == nil {
		id, ok = id.Principal()
	}
	if !ok || id.Kind != pki.KindUser {
		return time.Time{}, errors.New("it holds no user certificate")
	}
	keyPEM, csr, err := pki.NewCSR(id)
	if err != nil {
		return time.Time{}, err
	}
	c, err := r.ca.SignUserCSR(csr, id.Name)
	if err != nil {
		return time.Time{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	if err := r.st.RenewedUser(ctx, id.Name, old.NotBefore, pki.SerialString(old), c.Serial); err != nil {
		return time.Time{}, fmt.Errorf("the cluster no longer accepts the certificate of %s: %w", id, err)
	}
	cc.Cert, cc.Key, cc.CA = string(c.PEM), string(keyPEM), string(r.ca.CertPEM)
	// SaveFile keeps a shared file's owner, group, and mode.
	if err := cc.SaveFile(r.adminConfig); err != nil {
		return time.Time{}, err
	}
	return c.NotAfter, nil
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
