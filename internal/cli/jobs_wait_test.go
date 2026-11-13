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

func TestJobRunShowTasks(t *testing.T) {
	f := &fakeRuns{steps: []*armadav1.JobRunInfo{{Job: "report", Run: 3, State: "running", Tasks: []*armadav1.JobTaskInfo{
		{Index: 0, State: "succeeded", Attempts: 1, Node: "n1"},
		{Index: 1, State: "running", Attempts: 2, Node: "n2", Message: "exited with code 4"},
		{Index: 2, State: "pending"},
	}}}}
	orig := dialAdmin
	dialAdmin = func(*globals) (armadav1.AdminServiceClient, io.Closer, error) { return f, nopCloser{}, nil }
	t.Cleanup(func() { dialAdmin = orig })
	cfg := withFake(t, newFakeAdmin())
	dialAdmin = func(*globals) (armadav1.AdminServiceClient, io.Closer, error) { return f, nopCloser{}, nil }
	code, out, stderr := run(t, "job", "run", "show", "report", "3", "--config", cfg)
	if code != 0 || !strings.Contains(out, "1/3 tasks") || !strings.Contains(out, "TASK  STATE") ||
		!strings.Contains(out, "1     running    2         n2    -     exited with code 4") {
		t.Errorf("job run show = %d %q\n%s", code, stderr, out)
	}
	if code, _, stderr := run(t, "job", "run", "show", "report", "7", "--config", cfg); code == 0 || !strings.Contains(stderr, "not found") {
		t.Errorf("missing run: %d %q", code, stderr)
	}
}

func TestParseWhen(t *testing.T) {
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	for in, want := range map[string]time.Time{
		"2h":                        now.Add(-2 * time.Hour),
		"3d":                        now.Add(-72 * time.Hour),
		"90m":                       now.Add(-90 * time.Minute),
		"2026-11-13T09:00:00+07:00": time.Date(2026, 11, 13, 2, 0, 0, 0, time.UTC),
	} {
		got, err := parseWhen(in, now)
		if err != nil || !got.Equal(want) {
			t.Errorf("parseWhen(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"", "-1h", "xd", "yesterday", "2026-11-13"} {
		if _, err := parseWhen(in, now); err == nil {
			t.Errorf("parseWhen(%q) accepted", in)
		}
	}
}
