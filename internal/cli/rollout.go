package cli

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
)

// Rollout states as reported by the server.
const (
	rolloutProgressing = "progressing"
	rolloutFailed      = "failed"
)

// waitPoll is how often --wait checks the rollout.
var waitPoll = time.Second

// waitFlags adds --wait and --timeout to a command that starts a rollout.
type waitFlags struct {
	wait    bool
	timeout time.Duration
}

func (w *waitFlags) register(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&w.wait, "wait", false, "wait until the rollout completes; fail if it is aborted")
	cmd.Flags().DurationVar(&w.timeout, "timeout", 15*time.Minute, "how long --wait waits")
}

// serving counts replicas that receive traffic.
func serving(a *armadav1.AppStatus) int {
	n := 0
	for _, r := range a.Replicas {
		if r.Ready && !r.Draining {
			n++
		}
	}
	return n
}

// waitRollout polls until revision of app is live, or returns an error when
// its rollout fails or another rollout replaces it.
func waitRollout(ctx context.Context, client armadav1.AdminServiceClient, app, revision string, timeout time.Duration, out io.Writer) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	last := ""
	for {
		resp, err := client.Status(ctx, &armadav1.StatusRequest{App: app})
		if err != nil {
			if ctx.Err() != nil {
				return fmt.Errorf("timed out after %s waiting for %s; the rollout continues on the server", timeout, revision)
			}
			return RPCError(err)
		}
		a := resp.Apps[0]
		ready, desired := 0, int(a.DesiredReplicas)
		if len(a.Traffic) > 0 && a.ActiveRevision == revision {
			// Split traffic (ADR 0022): wait for the revision's own share.
			desired = -1
			for _, t := range a.Traffic {
				if t.Revision == revision {
					desired = int(t.Replicas)
				}
			}
			if desired < 0 {
				_, err := fmt.Fprintf(out, "%s takes no traffic; traffic: %s\n", revision, trafficSummary(a.Traffic))
				return err
			}
		}
		for _, r := range a.Replicas {
			if r.Revision == revision && r.Ready && !r.Draining {
				ready++
			}
		}
		switch {
		case a.ActiveRevision == revision && a.RolloutState == "" && ready >= desired:
			_, err := fmt.Fprintf(out, "%s is live (%d/%d ready)\n", revision, ready, desired)
			return err
		case a.TargetRevision != revision:
			if a.RolloutState == rolloutFailed {
				return fmt.Errorf("rollout of %s failed, %s keeps serving: %s", revision, a.ActiveRevision, a.RolloutMessage)
			}
			return fmt.Errorf("rollout of %s was replaced by %s", revision, a.TargetRevision)
		}
		if line := fmt.Sprintf("%s: %d/%d ready", revision, ready, desired); line != last {
			_, _ = fmt.Fprintln(out, line)
			last = line
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out after %s waiting for %s; the rollout continues on the server", timeout, revision)
		case <-time.After(waitPoll):
		}
	}
}

// trafficSummary reads like "web--r3 90%, web--r4 10% (canary)".
func trafficSummary(traffic []*armadav1.TrafficTarget) string {
	parts := make([]string, 0, len(traffic))
	for _, t := range traffic {
		p := fmt.Sprintf("%s %d%%", t.Revision, t.Weight)
		if t.Label != "" {
			p += " (" + t.Label + ")"
		}
		parts = append(parts, p)
	}
	return strings.Join(parts, ", ")
}
