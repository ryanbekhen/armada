package cli

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc/status"

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
	conn, err := cc.Dial()
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
			stream, err := client.Logs(cmd.Context(), &armadav1.LogsRequest{
				App: args[0], Follow: follow, Tail: int32(min(max(tail, 0), 10000)), Replica: replica, Run: run,
			})
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
				if replica == "" && !job {
					_, _ = fmt.Fprintf(w, "%s | ", e.Replica)
				}
				_, _ = w.Write(e.Data)
			}
		},
	}
	f := cmd.Flags()
	f.BoolVarP(&follow, "follow", "f", false, "stream new log lines")
	f.IntVar(&tail, "tail", 100, "lines per replica to show")
	if job {
		cmd.Use = "logs JOB"
		cmd.Short = "Print the logs of a job's run"
		cmd.Long = "Print the logs of the latest attempt of a job's newest run (--run N for another\n" +
			"run). A finished run's logs are kept for 24 hours."
		f.Int64Var(&run, "run", 0, "the run to show (default: the newest)")
	} else {
		f.StringVar(&replica, "replica", "", "only show this replica")
	}
	return cmd
}
