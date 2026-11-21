package server

import (
	"context"
	"strconv"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/secrets"
	"github.com/ryanbekhen/armada/internal/spec"
	"github.com/ryanbekhen/armada/internal/store"
)

// Secret handlers never log, return, or audit secret values.

// checkSecretTarget validates a secret's ID (an app's own, or NAME or
// NAME.SPACE, ADR 0052) and, unless listing, a key name.
func checkSecretTarget(secret, key string, listing bool) error {
	if !spec.ValidAppID(secret) {
		return status.Errorf(codes.InvalidArgument, "invalid secret %q: want NAME, or NAME.SPACE for a secret of another space", secret)
	}
	if listing {
		return nil
	}
	if err := spec.ValidateSecretKey(key); err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	return nil
}

// SetSecret stores a new version of a secret's key, encrypted with the
// master key, and optionally rolls out every app that uses the key.
func (s *Server) SetSecret(ctx context.Context, req *armadav1.SetSecretRequest) (*armadav1.SetSecretResponse, error) {
	if err := accessFrom(ctx).app(req.GetApp()); err != nil {
		return nil, err
	}
	secret, key := req.GetApp(), req.GetName()
	if err := checkSecretTarget(secret, key, false); err != nil {
		return nil, err
	}
	if len(req.GetValue()) > secrets.MaxSize {
		return nil, status.Errorf(codes.InvalidArgument, "secret is %d bytes; the limit is %d", len(req.GetValue()), secrets.MaxSize)
	}
	if s.keys == nil {
		return nil, status.Error(codes.FailedPrecondition, "secrets are disabled: the server has no master key")
	}
	if err := s.checkSecretBackups(ctx, secret, key, req.GetValue()); err != nil {
		return nil, err
	}
	val := secrets.NewValue(req.GetValue())
	version, revs, err := s.store.SetSecret(ctx, secret, key, func(v int) (secrets.Sealed, error) {
		return s.keys.Seal(secret, key, v, val)
	}, req.GetRollout(), actor(ctx))
	if err != nil {
		s.log.Error("set secret failed", "secret", secret, "key", key, "err", err)
		return nil, storeErr(err)
	}
	s.log.Info("secret set", "secret", secret, "key", key, "version", version, "rollouts", revs, "by", actor(ctx))
	resp := &armadav1.SetSecretResponse{Version: int32(version), Revisions: revs} //nolint:gosec // versions are small
	for _, rev := range revs {
		app := rev[:strings.LastIndex(rev, "--r")]
		s.record(ctx, store.Event{Kind: eventRollout, Object: rev, App: app, Reason: "Started", Message: "rolling out " + rev + " for secret " + secret + " key " + key + " version " + strconv.Itoa(version)})
	}
	if len(revs) > 0 {
		resp.Revision = revs[0]
		s.Trigger()
	}
	return resp, nil
}

// ListSecrets lists a secret's keys without their values.
func (s *Server) ListSecrets(ctx context.Context, req *armadav1.ListSecretsRequest) (*armadav1.ListSecretsResponse, error) {
	if err := accessFrom(ctx).app(req.GetApp()); err != nil {
		return nil, err
	}
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

// ListSpaceSecrets lists the secrets of a space without their values.
func (s *Server) ListSpaceSecrets(ctx context.Context, req *armadav1.ListSpaceSecretsRequest) (*armadav1.ListSpaceSecretsResponse, error) {
	space := req.GetSpace()
	if space == "" {
		space = spec.DefaultSpace
	}
	if err := accessFrom(ctx).space(space); err != nil {
		return nil, err
	}
	if !spec.ValidSpace(space) {
		return nil, status.Errorf(codes.InvalidArgument, "invalid space %q", space)
	}
	list, err := s.store.ListSpaceSecrets(ctx, space)
	if err != nil {
		return nil, storeErr(err)
	}
	resp := &armadav1.ListSpaceSecretsResponse{}
	for _, si := range list {
		resp.Secrets = append(resp.Secrets, &armadav1.SpaceSecretInfo{
			Name: si.Name, Keys: int32(si.Keys), //nolint:gosec // at most a few hundred keys
			UpdatedAt: timestamppb.New(si.UpdatedAt), UpdatedBy: si.UpdatedBy, UsedBy: si.UsedBy,
		})
	}
	return resp, nil
}

// DeleteSecret removes every version of a key no app uses, or with whole
// every key of the secret.
func (s *Server) DeleteSecret(ctx context.Context, req *armadav1.DeleteSecretRequest) (*armadav1.DeleteSecretResponse, error) {
	if err := accessFrom(ctx).app(req.GetApp()); err != nil {
		return nil, err
	}
	secret, key := req.GetApp(), req.GetName()
	if err := checkSecretTarget(secret, key, req.GetWhole()); err != nil {
		return nil, err
	}
	if req.GetWhole() && key != "" {
		return nil, status.Error(codes.InvalidArgument, "deleting a whole secret names no key")
	}
	if err := s.store.DeleteSecret(ctx, secret, key, actor(ctx)); err != nil {
		return nil, storeErr(err)
	}
	s.opened.forget(secret, key)
	s.log.Info("secret deleted", "secret", secret, "key", key, "by", actor(ctx))
	return &armadav1.DeleteSecretResponse{}, nil
}
