package cli

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"

	"google.golang.org/protobuf/types/known/timestamppb"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/clientconfig"
)

// dialAdmin loads the client config and returns an admin client; tests
// replace it.
var dialAdmin = func(g *globals) (armadav1.AdminServiceClient, io.Closer, error) {
	cc, err := clientconfig.Load(g.configPath)
	if err != nil {
		return nil, nil, err
	}
	ss := &serverSync{path: g.configPath, servers: cc.Servers}
	conn, err := cc.Dial(grpc.WithChainUnaryInterceptor(ss.unary), grpc.WithChainStreamInterceptor(ss.stream))
	if err != nil {
		return nil, nil, err
	}
	return armadav1.NewAdminServiceClient(conn), conn.ClientConn, nil
}

// RPCError strips the gRPC wrapping from server errors for display.
func RPCError(err error) error {
	if s, ok := status.FromError(err); ok {
		return errors.New(s.Message())
	}
	return err
}

// restarts reads like "3 (12m ago)": how often the replica's container was
// recreated, and when it last was.
func restarts(r *armadav1.ReplicaStatus) string {
	n := strconv.Itoa(int(r.GetRestarts()))
	if t := r.GetLastRestartAt(); t != nil && r.GetRestarts() > 0 {
		n += " (" + time.Since(t.AsTime()).Round(time.Second).String() + " ago)"
	}
	return n
}

// autoscaleNote reads like "2-10 replicas, http 34/50, cpu 61%/70%:
// steady".
func autoscaleNote(as *armadav1.Autoscale) string {
	parts := []string{fmt.Sprintf("%d-%d replicas", as.Min, as.Max)}
	for _, r := range as.Rules {
		switch r.Type {
		case "schedule":
			if t := r.GetUntil(); t != nil {
				parts = append(parts, fmt.Sprintf("schedule %d until %s", r.Target, t.AsTime().Local().Format("Mon 15:04")))
			} else {
				parts = append(parts, fmt.Sprintf("schedule %d (closed)", r.Target))
			}
			continue
		case "queue", "redis", "rabbitmq":
			cur := "-"
			if r.Measured {
				cur = fmt.Sprint(r.Current)
			}
			parts = append(parts, fmt.Sprintf("%s %s/%d per replica", r.Type, cur, r.Target))
			continue
		}
		unit := ""
		if r.Type != "http" {
			unit = "%"
		}
		cur := "-"
		if r.Measured {
			cur = fmt.Sprintf("%d%s", r.Current, unit)
		}
		parts = append(parts, fmt.Sprintf("%s %s/%d%s", r.Type, cur, r.Target, unit))
	}
	note := strings.Join(parts, ", ")
	if as.Message != "" {
		note += ": " + printable(as.Message)
	}
	return note
}

func replicaState(r *armadav1.ReplicaStatus) string {
	switch {
	case r.Draining:
		return "draining"
	case r.State == "running" && !r.Ready:
		return "running (not ready)"
	}
	return r.State
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func humanBytes(b int64) string {
	switch {
	case b <= 0:
		return "-"
	case b >= 1<<30:
		return fmt.Sprintf("%.1fGi", float64(b)/(1<<30))
	default:
		return fmt.Sprintf("%dMi", b>>20)
	}
}

func newLogsCommand(g *globals, job bool) *cobra.Command {
	var (
		follow  bool
		tail    int
		replica string
		run     int64
		task    int
		ctr     string

		since, until, grep string
		limit              int
		stamps             bool
	)
	cmd := &cobra.Command{
		Use:   "logs APP",
		Short: "Print logs from an app's replicas",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := g.qualify(args); err != nil {
				return err
			}
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			req := &armadav1.LogsRequest{
				App: args[0], Follow: follow, Tail: int32(min(max(tail, 0), 10000)), Replica: replica, Run: run, Container: ctr,
				Grep: grep, Limit: int32(min(max(limit, 0), 100000)),
			}
			now := time.Now()
			if since != "" {
				t, err := parseWhen(since, now)
				if err != nil {
					return fmt.Errorf("--since: %w", err)
				}
				req.Since = timestamppb.New(t)
			}
			if until != "" {
				t, err := parseWhen(until, now)
				if err != nil {
					return fmt.Errorf("--until: %w", err)
				}
				req.Until = timestamppb.New(t)
			}
			if since == "" && (until != "" || grep != "" || limit != 0) {
				return errors.New("--until, --grep, and --limit search the log history: give --since too, e.g. --since 1h")
			}
			if job && cmd.Flags().Changed("task") {
				t := int32(min(max(task, -1), 1<<20))
				req.Task = &t
			}
			stream, err := client.Logs(cmd.Context(), req)
			if err != nil {
				return RPCError(err)
			}
			for {
				e, err := stream.Recv()
				if errors.Is(err, io.EOF) {
					return nil
				}
				if err != nil {
					if cmd.Context().Err() != nil {
						return nil
					}
					return RPCError(err)
				}
				w := cmd.OutOrStdout()
				if e.Stream == armadav1.Stream_STREAM_STDERR {
					w = cmd.ErrOrStderr()
				}
				if stamps && e.Time != nil {
					_, _ = fmt.Fprintf(w, "%s ", e.Time.AsTime().Local().Format("2006-01-02T15:04:05.000Z07:00"))
				}
				if replica == "" && (!job || since != "") && e.Replica != "" {
					_, _ = fmt.Fprintf(w, "%s | ", e.Replica)
				}
				_, _ = w.Write(e.Data)
			}
		},
	}
	f := cmd.Flags()
	f.BoolVarP(&follow, "follow", "f", false, "stream new log lines")
	f.IntVar(&tail, "tail", 100, "lines per replica to show")
	f.StringVar(&ctr, "container", "", "show an init container or sidecar instead of the app's own container")
	f.StringVar(&since, "since", "", "search the log history from this long ago (2h, 3d) or this time (RFC 3339), across every node, including replicas that are gone")
	f.StringVar(&until, "until", "", "with --since: up to this long ago or this time (default now)")
	f.StringVar(&grep, "grep", "", "with --since: only lines containing this text, ignoring case (plain text, not a pattern)")
	f.IntVar(&limit, "limit", 0, "with --since: the newest lines to show (default 500, at most 5000)")
	f.BoolVar(&stamps, "timestamps", false, "with --since: show when each line was written")
	if job {
		cmd.Use = "logs JOB"
		cmd.Short = "Print the logs of a job's run"
		cmd.Long = "Print the logs of the latest attempt of a job's newest run (--run N for another\n" +
			"run, --task I for one task of a run that has several). A finished run's logs are\n" +
			"kept for 24 hours; --since searches the log history of every run (ADR 0043)."
		f.Int64Var(&run, "run", 0, "the run to show (default: the newest)")
		f.IntVar(&task, "task", 0, "the task to show, for a job with tasks (default: the latest attempt of any task)")
	} else {
		f.StringVar(&replica, "replica", "", "only show this replica")
	}
	return cmd
}

// parseWhen reads a time as a duration before now ("2h", "3d") or RFC 3339.
func parseWhen(s string, now time.Time) (time.Time, error) {
	if d, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(d)
		if err != nil || n < 0 || n > 3650 {
			return time.Time{}, fmt.Errorf("%q is not a number of days", s)
		}
		return now.Add(-time.Duration(n) * 24 * time.Hour), nil
	}
	if d, err := time.ParseDuration(s); err == nil {
		if d < 0 {
			return time.Time{}, fmt.Errorf("%q is negative", s)
		}
		return now.Add(-d), nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("%q is neither a duration such as 2h or 3d nor a time such as 2026-11-13T09:00:00+07:00", s)
	}
	return t, nil
}
