package server

import (
	"errors"
	"fmt"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/ryanbekhen/armada/internal/store"
)

func TestStoreErrMessages(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		err  error
		code codes.Code
		msg  string
	}{
		{fmt.Errorf("user ana exists: %w", store.ErrConflict), codes.AlreadyExists, "user ana exists"},
		{fmt.Errorf("web is a job: %w", store.ErrPrecondition), codes.FailedPrecondition, "web is a job"},
		{fmt.Errorf("app web: %w", store.ErrNotFound), codes.NotFound, "app web: not found"},
		{errors.New("disk on fire"), codes.Internal, "internal error"},
	} {
		st := status.Convert(storeErr(tt.err))
		if st.Code() != tt.code || st.Message() != tt.msg {
			t.Errorf("storeErr(%v) = %v %q, want %v %q", tt.err, st.Code(), st.Message(), tt.code, tt.msg)
		}
	}
}
