package cli

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
)

// fakeRuns answers ListJobRuns with one state per call, repeating the last.
type fakeRuns struct {
	armadav1.AdminServiceClient
	steps []*armadav1.JobRunInfo
	err   error
}

func (f *fakeRuns) ListJobRuns(context.Context, *armadav1.ListJobRunsRequest, ...grpc.CallOption) (*armadav1.ListJobRunsResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	if len(f.steps) == 0 {
		return &armadav1.ListJobRunsResponse{}, nil
	}
	r := f.steps[0]
	if len(f.steps) > 1 {
		f.steps = f.steps[1:]
	}
	return &armadav1.ListJobRunsResponse{Runs: []*armadav1.JobRunInfo{{Run: 9, State: "running"}, r}}, nil
}

func TestWaitJobRun(t *testing.T) {
	orig := waitPoll
	waitPoll = 5 * time.Millisecond
	t.Cleanup(func() { waitPoll = orig })
	run := func(state string, exit int32, msg string) *armadav1.JobRunInfo {
		return &armadav1.JobRunInfo{Job: "migrate", Run: 3, State: state, ExitCode: exit, Message: msg}
	}
	for name, tc := range map[string]struct {
		steps []*armadav1.JobRunInfo
		err   error
		want  string // empty means success
	}{
		"succeeded":     {steps: []*armadav1.JobRunInfo{run("pending", 0, ""), run("running", 0, ""), run("succeeded", 0, "")}},
		"exit code":     {steps: []*armadav1.JobRunInfo{run("running", 0, ""), run("failed", 2, "")}, want: "failed with exit code 2"},
		"no exit":       {steps: []*armadav1.JobRunInfo{run("failed", 0, "lost node")}, want: "failed: lost node"},
		"cancelled":     {steps: []*armadav1.JobRunInfo{run("cancelled", 0, "cancelled by admin:x")}, want: "cancelled"},
		"gone":          {want: "is gone"},
		"timeout":       {steps: []*armadav1.JobRunInfo{run("running", 0, "")}, want: "did not end within"},
		"rpc failed":    {err: status.Error(codes.PermissionDenied, "no"), want: "no"},
		"leader change": {err: status.Error(codes.Unavailable, "down"), want: "did not end within"},
	} {
		t.Run(name, func(t *testing.T) {
			err := waitJobRun(context.Background(), &fakeRuns{steps: tc.steps, err: tc.err}, "migrate", 3, 300*time.Millisecond, io.Discard)
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
	// The caller going away is not a timeout.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := waitJobRun(ctx, &fakeRuns{steps: []*armadav1.JobRunInfo{run("running", 0, "")}}, "migrate", 3, time.Minute, io.Discard); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v", err)
	}
}
