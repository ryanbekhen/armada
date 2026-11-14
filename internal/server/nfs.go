package server

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/ryanbekhen/armada/internal/spec"
	"github.com/ryanbekhen/armada/internal/store"
)

// checkNFSExports lets only cluster-admins add an NFS export to an app, or
// make one writable (ADR 0042): nodes mount exports from their own
// addresses, so the NFS server cannot tell spaces apart. Deploys and
// rollbacks that keep the exports of the revision the app is heading to
// (its target, else its active one) are anyone's who may deploy it, so a
// cluster-admin's removal of an export cannot be undone by someone else,
// not even while it is still rolling out.
func (s *Server) checkNFSExports(ctx context.Context, acc access, app *spec.App) error {
	if acc.admin() || !app.HasNFSVolumes() {
		return nil
	}
	allowed := map[spec.NFSSource]bool{}
	a, err := s.store.GetApp(ctx, app.ID())
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return storeErr(err)
	}
	if err == nil {
		rn := a.TargetRevision
		if rn == "" {
			rn = a.ActiveRevision
		}
		if rn != "" {
			rev, err := s.store.GetRevision(ctx, rn)
			if err != nil {
				return storeErr(err)
			}
			for _, v := range rev.Spec.Volumes {
				if n := v.NFS; n != nil {
					allowed[*n] = true
					ro := *n
					ro.ReadOnly = true
					allowed[ro] = true // read-only is never more
				}
			}
		}
	}
	for _, v := range app.Volumes {
		if n := v.NFS; n != nil && !allowed[*n] {
			return status.Errorf(codes.PermissionDenied, "volume %s: adding an NFS export (%s:%s) or making one writable needs cluster-admin, since it reaches storage outside the cluster", v.Name, n.Server, n.Path)
		}
	}
	return nil
}
