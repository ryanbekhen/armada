package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/spec"
)

func newJobCommand(g *globals) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "job",
		Aliases: []string{"jobs"},
		Short:   "Create, run, and inspect jobs",
		Long: "Jobs run a container to completion, on demand (`armada job run`) or on a\n" +
			"schedule. Create one from flags or a spec file (kind: job).",
	}
	cmd.AddCommand(newJobCreateCommand(g), newJobUpdateCommand(g), newJobListCommand(g), newJobShowCommand(g),
		newJobRunCommand(g), newLogsCommand(g, true), newJobCancelCommand(g), newJobDeleteCommand(g))
	return cmd
}

func newJobCreateCommand(g *globals) *cobra.Command {
	var d deployFlags
	cmd := &cobra.Command{
		Use:   "create NAME [flags] | --file FILE",
		Short: "Create a job from flags or a spec file",
		Long: "Create a job from flags, or from a spec file (kind: job) with --file (- for\n" +
			"stdin). It refuses a name that exists; change a job with `armada job update`.",
		Example: "  armada job create migrate --image ghcr.io/acme/api:1.4 --command ./migrate --secret-env DATABASE_URL=database-url\n" +
			"  armada job create report --image ghcr.io/acme/report:2 --schedule \"0 3 * * *\" --time-zone Asia/Jakarta",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error { return runCreate(cmd, g, args, &d) },
	}
	d.registerCreate(cmd, true)
	return cmd
}

func newJobUpdateCommand(g *globals) *cobra.Command {
	var d deployFlags
	cmd := &cobra.Command{
		Use:   "update NAME [flags] | --file FILE",
		Short: "Change a job: some fields with flags, or the whole spec with --file",
		Long: "Change a job; new runs use the new revision. With flags, only what they name\n" +
			"changes, and the update is refused when another change landed since the spec\n" +
			"was read. With --file, the file replaces the whole spec. --diff prints what\n" +
			"would change and changes nothing; --create-if-missing creates the job when it\n" +
			"does not exist.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error { return runUpdate(cmd, g, args, &d) },
	}
	d.registerUpdate(cmd, true)
	return cmd
}

func newJobRunCommand(g *globals) *cobra.Command {
	var (
		wait    bool
		timeout time.Duration
	)
	cmd := &cobra.Command{
		Use:   "run JOB",
		Short: "Start a run of a job now; run list lists its runs",
		Long: "Start a run of a job now.\n\n" +
			"With --wait the command ends when the run does and fails unless the run\n" +
			"succeeded, so a script can stop on a failed step such as a migration. A\n" +
			"run still going after --timeout keeps going; cancel it with `armada job cancel`.",
		Example: "  armada job run migrate --wait --timeout 5m\n  armada job run list migrate",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := g.qualify(args); err != nil {
				return err
			}
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			resp, err := client.RunJob(cmd.Context(), &armadav1.RunJobRequest{Job: args[0]})
			if err != nil {
				return RPCError(err)
			}
			out := cmd.OutOrStdout()
			_, _ = fmt.Fprintf(out, "Started run %d of %s.\n", resp.Run, args[0])
			if !wait {
				return nil
			}
			return waitJobRun(cmd.Context(), client, args[0], resp.Run, timeout, out)
		},
	}
	cmd.Flags().BoolVar(&wait, "wait", false, "wait until the run ends; fail unless it succeeded")
	cmd.Flags().DurationVar(&timeout, "timeout", 15*time.Minute, "how long --wait waits")
	cmd.AddCommand(newJobRunListCommand(g))
	return cmd
}

// waitJobRun polls until a run has ended and fails unless it succeeded.
func waitJobRun(ctx context.Context, client armadav1.AdminServiceClient, job string, run int64, timeout time.Duration, out io.Writer) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	tick := time.NewTicker(waitPoll)
	defer tick.Stop()
	for {
		resp, err := client.ListJobRuns(ctx, &armadav1.ListJobRunsRequest{Job: job})
		switch {
		case err == nil:
			i := slices.IndexFunc(resp.GetRuns(), func(r *armadav1.JobRunInfo) bool { return r.GetRun() == run })
			if i < 0 {
				return fmt.Errorf("run %d of %s is gone; it left the job's history before it could be read", run, job)
			}
			if done, err := jobRunResult(resp.GetRuns()[i]); done {
				if err == nil {
					_, _ = fmt.Fprintf(out, "Run %d of %s succeeded.\n", run, job)
				}
				return err
			}
		case ctx.Err() == nil && status.Code(err) != codes.Unavailable:
			// Unavailable passes: the control plane changes leader and the
			// run goes on.
			return RPCError(err)
		}
		select {
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return fmt.Errorf("run %d of %s did not end within %s; it keeps going (`armada job cancel %s` stops it)", run, job, timeout, job)
			}
			return ctx.Err()
		case <-tick.C:
		}
	}
}

// jobRunResult reports whether a run has ended, and why when it did not succeed.
func jobRunResult(r *armadav1.JobRunInfo) (bool, error) {
	switch r.GetState() {
	case "pending", "running":
		return false, nil
	case "succeeded":
		return true, nil
	}
	why := r.GetState()
	if c := r.GetExitCode(); c != 0 {
		why += fmt.Sprintf(" with exit code %d", c)
	}
	if m := printable(r.GetMessage()); m != "" {
		why += ": " + m
	}
	return true, fmt.Errorf("run %d of %s %s; see `armada job logs %s --run %d`", r.GetRun(), r.GetJob(), why, r.GetJob(), r.GetRun())
}

func newJobListCommand(g *globals) *cobra.Command {
	var o *outputFlag
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List jobs with their schedule and latest run",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := o.check(); err != nil {
				return err
			}
			resp, err := listJobs(cmd.Context(), g)
			if err != nil {
				return err
			}
			resp.Jobs = slices.DeleteFunc(resp.Jobs, func(j *armadav1.JobInfo) bool { return !g.listed(j.Name) })
			out := cmd.OutOrStdout()
			if o.json() {
				return printJSON(out, resp)
			}
			now := time.Now()
			tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
			head := "NAME\tSCHEDULE\tLAST RUN\tSTATE\tFINISHED\tNEXT RUN"
			if g.allProjects {
				head = "PROJECT\t" + head
			}
			_, _ = fmt.Fprintln(tw, head)
			for _, j := range resp.Jobs {
				last, state, finished := "-", "-", "-"
				if r := j.LastRun; r != nil {
					last, state, finished = strconv.FormatInt(r.Run, 10), r.State, ago(r.FinishedAt, now)
				}
				next := "-"
				if j.NextRun != nil {
					next = "in " + humanDuration(j.NextRun.AsTime().Sub(now))
				}
				p, name, _ := spec.SplitAppID(j.Name)
				line := fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s", name, jobSchedule(j), last, state, finished, next)
				if g.allProjects {
					line = p + "\t" + line
				}
				_, _ = fmt.Fprintln(tw, line)
			}
			return tw.Flush()
		},
	}
	o = addOutput(cmd, false)
	return cmd
}

func listJobs(ctx context.Context, g *globals) (*armadav1.ListJobsResponse, error) {
	client, conn, err := dialAdmin(g)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	resp, err := client.ListJobs(ctx, &armadav1.ListJobsRequest{})
	if err != nil {
		return nil, RPCError(err)
	}
	return resp, nil
}

func jobSchedule(j *armadav1.JobInfo) string {
	if j.Schedule == "" {
		return "-"
	}
	if j.TimeZone != "" {
		return j.Schedule + " (" + j.TimeZone + ")"
	}
	return j.Schedule
}

func newJobShowCommand(g *globals) *cobra.Command {
	var o *outputFlag
	cmd := &cobra.Command{
		Use:   "show JOB",
		Short: "Show a job: its schedule, revision, and latest run",
		Long: "Show a job: its schedule, revision, and latest run. -o yaml prints the spec\n" +
			"it runs as a file holds it, ready for create --file or update --file.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := g.qualify(args); err != nil {
				return err
			}
			if err := o.check(); err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if o.format == outputYAML {
				client, conn, err := dialAdmin(g)
				if err != nil {
					return err
				}
				defer conn.Close()
				return printSpec(cmd.Context(), client, args[0], true, out)
			}
			resp, err := listJobs(cmd.Context(), g)
			if err != nil {
				return err
			}
			i := slices.IndexFunc(resp.Jobs, func(j *armadav1.JobInfo) bool { return j.Name == args[0] })
			if i < 0 {
				return fmt.Errorf("job %s not found", args[0])
			}
			j := resp.Jobs[i]
			if o.json() {
				return printJSON(out, j)
			}
			now := time.Now()
			next := "-"
			if j.NextRun != nil {
				next = j.NextRun.AsTime().Local().Format(time.DateTime) + " (in " + humanDuration(j.NextRun.AsTime().Sub(now)) + ")"
			}
			last := "-"
			if r := j.LastRun; r != nil {
				last = fmt.Sprintf("%d, %s", r.Run, r.State)
				if r.FinishedAt != nil {
					last += ", finished " + ago(r.FinishedAt, now)
				}
			}
			tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintf(tw, "Name:\t%s\nRevision:\t%s\nImage:\t%s\nSchedule:\t%s\nNext run:\t%s\nLast run:\t%s\nActive runs:\t%d\n",
				j.Name, dash(j.Revision), j.Image, jobSchedule(j), next, last, j.Active)
			return tw.Flush()
		},
	}
	o = addOutput(cmd, true)
	return cmd
}

func newJobRunListCommand(g *globals) *cobra.Command {
	var o *outputFlag
	cmd := &cobra.Command{
		Use:     "list JOB",
		Aliases: []string{"ls"},
		Short:   "List a job's runs, newest first",
		Long: "List a job's runs, newest first. Finished runs beyond the job's history (5 by default)\n" +
			"are removed; their logs are kept for 24 hours.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := g.qualify(args); err != nil {
				return err
			}
			if err := o.check(); err != nil {
				return err
			}
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			resp, err := client.ListJobRuns(cmd.Context(), &armadav1.ListJobRunsRequest{Job: args[0]})
			if err != nil {
				return RPCError(err)
			}
			out := cmd.OutOrStdout()
			if o.json() {
				return printJSON(out, resp)
			}
			return printRuns(out, resp.Runs, time.Now())
		},
	}
	o = addOutput(cmd, false)
	return cmd
}

func printRuns(out io.Writer, runs []*armadav1.JobRunInfo, now time.Time) error {
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "RUN\tSTATE\tTRIGGER\tATTEMPTS\tNODE\tSTARTED\tDURATION\tEXIT\tMESSAGE")
	for _, r := range runs {
		dur, exit := "-", "-"
		if r.StartedAt != nil {
			end := now
			if r.FinishedAt != nil {
				end = r.FinishedAt.AsTime()
			}
			dur = humanDuration(end.Sub(r.StartedAt.AsTime()))
		}
		// Only an exited container has an exit code; a timeout or a lost
		// node does not.
		if r.State == "succeeded" || r.ExitCode != 0 {
			exit = strconv.Itoa(int(r.ExitCode))
		}
		node := r.Node
		if node == "" {
			node = "-"
		}
		msg := printable(r.Message)
		if msg == "" {
			msg = "-"
		}
		_, _ = fmt.Fprintf(tw, "%d\t%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\n", r.Run, r.State, r.Trigger, r.Attempts, node, ago(r.StartedAt, now), dur, exit, msg)
	}
	return tw.Flush()
}

func newJobCancelCommand(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "cancel JOB",
		Short: "Stop a job's pending and running runs",
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
			resp, err := client.CancelJob(cmd.Context(), &armadav1.CancelJobRequest{Job: args[0]})
			if err != nil {
				return RPCError(err)
			}
			out := cmd.OutOrStdout()
			if len(resp.Runs) == 0 {
				_, err := fmt.Fprintf(out, "%s has no active runs.\n", args[0])
				return err
			}
			for _, r := range resp.Runs {
				if _, err := fmt.Fprintf(out, "Cancelled run %d of %s.\n", r, args[0]); err != nil {
					return err
				}
			}
			return nil
		},
	}
}

func newJobDeleteCommand(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:     "delete JOB",
		Aliases: []string{"rm"},
		Short:   "Delete a job, stopping its runs and removing their records and logs",
		Long:    "Delete a job, stopping its runs and removing their records and logs. Its secrets are kept;\ndelete them with `armada secret delete`.",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := g.qualify(args); err != nil {
				return err
			}
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			if _, err := client.DeleteJob(cmd.Context(), &armadav1.DeleteJobRequest{Job: args[0]}); err != nil {
				return RPCError(err)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Deleted job %s.\n", args[0])
			return err
		},
	}
}

// ago shows how long ago t was, or "-" if unset.
func ago(t *timestamppb.Timestamp, now time.Time) string {
	if t == nil {
		return "-"
	}
	return humanDuration(now.Sub(t.AsTime())) + " ago"
}

// humanDuration rounds d for display: 42s, 5m, 3h, 2d.
func humanDuration(d time.Duration) string {
	switch {
	case d < 0:
		d = 0
		fallthrough
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}
