package server

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/secrets"
	"github.com/ryanbekhen/armada/internal/spec"
)

// Secret handlers never log, return, or audit secret values.

// checkSecretTarget validates an app name and, unless listing, a secret
// name.
func checkSecretTarget(app, name string, listing bool) error {
	if err := spec.ValidateName(app); err != nil {
		return status.Errorf(codes.InvalidArgument, "app: %v", err)
	}
	if listing {
		return nil
	}
	if err := spec.ValidateSecretName(name); err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	return nil
}

// SetSecret stores a new version of an app secret, encrypted with the
// master key, and optionally rolls the app out with it.
func (s *Server) SetSecret(ctx context.Context, req *armadav1.SetSecretRequest) (*armadav1.SetSecretResponse, error) {
	app, name := req.GetApp(), req.GetName()
	if err := checkSecretTarget(app, name, false); err != nil {
		return nil, err
	}
	if len(req.GetValue()) > secrets.MaxSize {
		return nil, status.Errorf(codes.InvalidArgument, "secret is %d bytes; the limit is %d", len(req.GetValue()), secrets.MaxSize)
	}
	if s.keys == nil {
		return nil, status.Error(codes.FailedPrecondition, "secrets are disabled: the server has no master key")
	}
	val := secrets.NewValue(req.GetValue())
	version, rev, err := s.store.SetSecret(ctx, app, name, func(v int) (secrets.Sealed, error) {
		return s.keys.Seal(app, name, v, val)
	}, req.GetRollout(), actor(ctx))
	if err != nil {
		s.log.Error("set secret failed", "app", app, "secret", name, "err", err)
		return nil, storeErr(err)
	}
	s.log.Info("secret set", "app", app, "secret", name, "version", version, "rollout", rev, "by", actor(ctx))
	if rev != "" {
		s.Trigger()
	}
	return &armadav1.SetSecretResponse{Version: int32(version), Revision: rev}, nil //nolint:gosec // versions are small
}

// ListSecrets lists an app's secrets without their values.
func (s *Server) ListSecrets(ctx context.Context, req *armadav1.ListSecretsRequest) (*armadav1.ListSecretsResponse, error) {
	if err := checkSecretTarget(req.GetApp(), "", true); err != nil {
		return nil, err
	}
	list, err := s.store.ListSecrets(ctx, req.GetApp())
	if err != nil {
		return nil, storeErr(err)
	}
	resp := &armadav1.ListSecretsResponse{}
	for _, si := range list {
		resp.Secrets = append(resp.Secrets, &armadav1.SecretInfo{
			Name: si.Name, Version: int32(si.Version), //nolint:gosec // versions are small
			UpdatedAt: timestamppb.New(si.UpdatedAt), UpdatedBy: si.UpdatedBy, UsedBy: si.UsedBy,
		})
	}
	return resp, nil
}

// DeleteSecret removes every version of a secret the app no longer uses.
func (s *Server) DeleteSecret(ctx context.Context, req *armadav1.DeleteSecretRequest) (*armadav1.DeleteSecretResponse, error) {
	app, name := req.GetApp(), req.GetName()
	if err := checkSecretTarget(app, name, false); err != nil {
		return nil, err
	}
	if err := s.store.DeleteSecret(ctx, app, name, actor(ctx)); err != nil {
		return nil, storeErr(err)
	}
	s.log.Info("secret deleted", "app", app, "secret", name, "by", actor(ctx))
	return &armadav1.DeleteSecretResponse{}, nil
}
