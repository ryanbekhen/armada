package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/clientconfig"
	"github.com/ryanbekhen/armada/internal/spec"
)

// dialAdmin loads the client config and returns an admin client.
func dialAdmin(g *globals) (armadav1.AdminServiceClient, *grpc.ClientConn, error) {
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

// rpcErr strips the gRPC wrapping from server errors for display.
func rpcErr(err error) error {
	if s, ok := status.FromError(err); ok {
		return errors.New(s.Message())
	}
	return err
}

func newDeployCommand(g *globals) *cobra.Command {
	var file string
	var w waitFlags
	cmd := &cobra.Command{
		Use:   "deploy -f app.yaml",
		Short: "Deploy an app or a job from a spec file",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var r io.Reader
			if file == "-" {
				r = cmd.InOrStdin()
			} else {
				f, err := os.Open(file) //nolint:gosec // user-chosen spec file
				if err != nil {
					return err
				}
				defer f.Close()
				r = f
			}
			data, err := io.ReadAll(io.LimitReader(r, spec.MaxSpecBytes+1))
			if err != nil {
				return err
			}
			if g.project != "" && !spec.ValidProject(g.project) {
				return fmt.Errorf("invalid project %q", g.project)
			}
			// Validate locally for fast feedback; the server validates again.
			sp, err := spec.ParseIn(data, g.project)
			if err != nil {
				return err
			}
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			resp, err := client.Deploy(cmd.Context(), &armadav1.DeployRequest{Spec: data, Project: g.project})
			if err != nil {
				return rpcErr(err)
			}
			if sp.IsJob() {
				// Jobs have no rollout to wait for.
				_, err := fmt.Fprintf(cmd.OutOrStdout(), "Deployed job %s (revision %s); start a run with `armada job run %s`\n", resp.App, resp.Revision, resp.App)
				return err
			}
			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Deployed %s (revision %s)\n", resp.App, resp.Revision); err != nil {
				return err
			}
			if !w.wait {
				return nil
			}
			return waitRollout(cmd.Context(), client, resp.App, resp.Revision, w.timeout, cmd.OutOrStdout())
		},
	}
	w.register(cmd)
	cmd.Flags().StringVarP(&file, "file", "f", "", "spec file, or - for stdin")
	_ = cmd.MarkFlagRequired("file")
	return cmd
}

func newScaleCommand(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "scale APP REPLICAS",
		Short: "Set the number of replicas until the next deploy (not for autoscaled apps)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := g.qualify(args); err != nil {
				return err
			}
			n, err := strconv.Atoi(args[1])
			if err != nil || n < 1 || n > spec.MaxReplicas {
				return fmt.Errorf("replicas must be a number between 1 and %d", spec.MaxReplicas)
			}
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			if _, err := client.Scale(cmd.Context(), &armadav1.ScaleRequest{App: args[0], Replicas: int32(n)}); err != nil { //nolint:gosec // bounded above
				return rpcErr(err)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Scaled %s to %d replicas\n", args[0], n)
			return err
		},
	}
}

func newTrafficCommand(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "traffic APP REVISION=WEIGHT...",
		Short: "Split an app's requests between revisions until the next deploy",
		Long: "Split the requests of an app in multiple revision mode (revisions.mode:\n" +
			"multiple) between its revisions until its next deploy. Weights are\n" +
			"percent and add up to 100; a revision left out stops serving, and one\n" +
			"with weight 0 is reached only through its label. Labels stay as the\n" +
			"spec set them. REVISION is a full name (web--r3) or its number (r3).",
		Example: "  armada traffic web web--r3=90 web--r4=10\n  armada traffic web r4=100",
		Args:    cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := g.qualify(args); err != nil {
				return err
			}
			app := args[0]
			req := &armadav1.SetTrafficRequest{App: app}
			for _, a := range args[1:] {
				rev, w, ok := strings.Cut(a, "=")
				n, err := strconv.Atoi(w)
				if !ok || err != nil || n < 0 || n > 100 {
					return fmt.Errorf("%q: want REVISION=WEIGHT with a weight from 0 to 100", a)
				}
				if strings.HasPrefix(rev, "r") && !strings.Contains(rev, "--") {
					rev = app + "--" + rev
				}
				req.Traffic = append(req.Traffic, &armadav1.TrafficTarget{Revision: rev, Weight: int32(n)}) //nolint:gosec // bounded above
			}
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			resp, err := client.SetTraffic(cmd.Context(), req)
			if err != nil {
				return rpcErr(err)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Traffic of %s: %s\n", app, trafficSummary(resp.Traffic))
			return err
		},
	}
}

func newStatusCommand(g *globals) *cobra.Command {
	var output string
	cmd := &cobra.Command{
		Use:   "status [APP]",
		Short: "Show apps, replicas, and nodes",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := g.qualify(args); err != nil {
				return err
			}
			if output != outputText && output != outputJSON {
				return fmt.Errorf("unsupported output format %q (want %q or %q)", output, outputText, outputJSON)
			}
			req := &armadav1.StatusRequest{}
			if len(args) == 1 {
				req.App = args[0]
			}
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			resp, err := client.Status(cmd.Context(), req)
			if err != nil {
				return rpcErr(err)
			}
			resp.Apps = slices.DeleteFunc(resp.Apps, func(a *armadav1.AppStatus) bool { return !g.listed(a.Name) })
			out := cmd.OutOrStdout()
			if output == outputJSON {
				b, err := protojson.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(resp)
				if err != nil {
					return err
				}
				_, err = fmt.Fprintln(out, string(b))
				return err
			}
			return printStatus(out, resp)
		},
	}
	cmd.Flags().StringVarP(&output, "output", "o", outputText, "output format: text or json")
	return cmd
}

func printStatus(out io.Writer, resp *armadav1.StatusResponse) error {
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	if len(resp.Apps) == 0 {
		_, _ = fmt.Fprintln(tw, "No apps deployed.")
	} else {
		_, _ = fmt.Fprintln(tw, "APP\tREVISION\tREADY\tINGRESS\tIMAGE")
		for _, a := range resp.Apps {
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%d/%d\t%s\t%s\n", a.Name, a.ActiveRevision, serving(a), a.DesiredReplicas, a.Ingress, a.Image)
		}
		var notes []string
		for _, a := range resp.Apps {
			switch a.RolloutState {
			case rolloutProgressing:
				notes = append(notes, fmt.Sprintf("%s: rolling out %s; %s serves until it is ready", a.Name, a.TargetRevision, a.ActiveRevision))
			case rolloutFailed:
				notes = append(notes, fmt.Sprintf("%s: last rollout failed, %s kept serving: %s", a.Name, a.ActiveRevision, a.RolloutMessage))
			}
			if a.PlacementMessage != "" {
				notes = append(notes, fmt.Sprintf("%s: %s", a.Name, a.PlacementMessage))
			}
			if as := a.Autoscale; as != nil {
				notes = append(notes, fmt.Sprintf("%s: %s", a.Name, autoscaleNote(as)))
			}
			if len(a.Traffic) > 0 {
				notes = append(notes, fmt.Sprintf("%s: traffic %s", a.Name, trafficSummary(a.Traffic)))
			}
		}
		if len(notes) > 0 {
			_, _ = fmt.Fprintln(tw)
			for _, n := range notes {
				_, _ = fmt.Fprintln(tw, n)
			}
		}
		urls := false
		for _, a := range resp.Apps {
			for _, u := range a.Urls {
				if !urls {
					_, _ = fmt.Fprintln(tw, "\nAPP\tURL")
					urls = true
				}
				_, _ = fmt.Fprintf(tw, "%s\t%s\n", a.Name, u)
			}
			for _, t := range a.Traffic {
				for _, u := range t.Urls {
					_, _ = fmt.Fprintf(tw, "%s\t%s (%s)\n", a.Name, u, t.Revision)
				}
			}
		}
		_, _ = fmt.Fprintln(tw, "\nREPLICA\tREVISION\tNODE\tSTATE\tADDRESS\tMESSAGE")
		for _, a := range resp.Apps {
			for _, r := range a.Replicas {
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", r.Id, r.Revision, r.NodeId, replicaState(r), dash(r.Address), dash(r.Message))
			}
		}
	}
	if len(resp.Nodes) == 0 {
		// Automation identities see no nodes (ADR 0029).
		return tw.Flush()
	}
	_, _ = fmt.Fprintln(tw, "\nNODE\tPRIVATE IP\tSTATE\tCPU\tMEMORY\tLAST SEEN")
	for _, n := range resp.Nodes {
		seen := "never"
		if n.LastSeen != nil {
			seen = time.Since(n.LastSeen.AsTime()).Round(time.Second).String() + " ago"
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", n.Id, n.PrivateIp, nodeState(n),
			fmt.Sprintf("%.1f", float64(n.CpuMillis)/1000), humanBytes(n.MemoryBytes), seen)
	}
	return tw.Flush()
}

// autoscaleNote reads like "autoscale 2-10, http 34/50, cpu 61%/70%:
// steady".
func autoscaleNote(as *armadav1.Autoscale) string {
	parts := []string{fmt.Sprintf("autoscale %d-%d", as.Min, as.Max)}
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

func newLogsCommand(g *globals) *cobra.Command {
	var (
		follow  bool
		tail    int
		replica string
		run     int64
	)
	cmd := &cobra.Command{
		Use:   "logs APP|JOB",
		Short: "Print logs from an app's replicas or a job's run",
		Long: "Print logs from an app's replicas, or from the latest attempt of a job's newest run\n" +
			"(--run N for another run). A finished run's logs are kept for 24 hours.",
		Args: cobra.ExactArgs(1),
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
				return rpcErr(err)
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
					return rpcErr(err)
				}
				w := cmd.OutOrStdout()
				if e.Stream == armadav1.Stream_STREAM_STDERR {
					w = cmd.ErrOrStderr()
				}
				if replica == "" {
					_, _ = fmt.Fprintf(w, "%s | ", e.Replica)
				}
				_, _ = w.Write(e.Data)
			}
		},
	}
	f := cmd.Flags()
	f.BoolVarP(&follow, "follow", "f", false, "stream new log lines")
	f.IntVar(&tail, "tail", 100, "lines per replica to show")
	f.StringVar(&replica, "replica", "", "only show this replica")
	f.Int64Var(&run, "run", 0, "for a job: the run to show (default: the newest)")
	return cmd
}
