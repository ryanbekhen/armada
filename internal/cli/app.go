package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/spec"
)

func newAppCommand(g *globals) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "app",
		Aliases: []string{"apps"},
		Short:   "Create, change, and inspect apps",
		Long: "Apps are long-running containers with replicas, rolling updates, and\n" +
			"ingress. Create one from flags or a spec file; `armada app show NAME -o yaml`\n" +
			"prints the spec it runs, ready for `armada app create --file` or\n" +
			"`armada app update --file` on any cluster.",
	}
	cmd.AddCommand(
		newAppCreateCommand(g),
		newAppUpdateCommand(g),
		newAppListCommand(g),
		newAppShowCommand(g),
		newAppScaleCommand(g),
		newAppRollbackCommand(g),
		newAppTrafficCommand(g),
		newLogsCommand(g, false),
		newAppExecCommand(g),
		newAppTopCommand(g),
		newEventsCommand(g, eventsOfApps),
		newAppDeleteCommand(g),
		newRevisionCommand(g),
	)
	return cmd
}

func newAppCreateCommand(g *globals) *cobra.Command {
	var d deployFlags
	cmd := &cobra.Command{
		Use:   "create NAME [flags] | --file FILE",
		Short: "Create an app from flags or a spec file",
		Long: "Create an app from flags, or from a spec file with --file (- for stdin).\n" +
			"It refuses a name that exists; change an app with `armada app update`. Flags\n" +
			"cover what is changed often; the rest of the spec (custom probes, routes,\n" +
			"secret files, volumes, placement, traffic splitting) is written in a file.",
		Example: "  armada app create hello --image traefik/whoami:v1.10 --port 80 --ingress external --replicas 2\n" +
			"  armada app create --file web.yaml --var TAG=1.4.2",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error { return runCreate(cmd, g, args, &d) },
	}
	d.registerCreate(cmd, false)
	return cmd
}

func newAppUpdateCommand(g *globals) *cobra.Command {
	var d deployFlags
	cmd := &cobra.Command{
		Use:   "update NAME [flags] | --file FILE",
		Short: "Change an app: some fields with flags, or the whole spec with --file",
		Long: "Change an app as a new revision, rolled out like every change.\n\n" +
			"With flags, only what they name changes in the spec the app runs, and the\n" +
			"update is refused when another change landed since that spec was read.\n" +
			"With --file, the file replaces the whole spec. --diff prints what would\n" +
			"change and changes nothing; --create-if-missing creates the app when it\n" +
			"does not exist.",
		Example: "  armada app update web --image ghcr.io/acme/web:1.4.3 --wait\n" +
			"  armada app update web --env LOG_LEVEL=debug --remove-env DEBUG\n" +
			"  armada app update web --file web.yaml --diff",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error { return runUpdate(cmd, g, args, &d) },
	}
	d.registerUpdate(cmd, false)
	return cmd
}

// appLister is the part of the API app list needs.
type appLister interface {
	ListApps(ctx context.Context, in *armadav1.ListAppsRequest, opts ...grpc.CallOption) (*armadav1.ListAppsResponse, error)
}

// listApps reads every page of ListApps.
func listApps(ctx context.Context, c appLister, req *armadav1.ListAppsRequest) ([]*armadav1.AppSummary, error) {
	var apps []*armadav1.AppSummary
	for {
		resp, err := c.ListApps(ctx, req)
		if err != nil {
			return nil, RPCError(err)
		}
		apps = append(apps, resp.Apps...)
		if resp.NextPageToken == "" || resp.NextPageToken == req.PageToken {
			return apps, nil
		}
		req = &armadav1.ListAppsRequest{Project: req.Project, AllProjects: req.AllProjects, PageSize: req.PageSize, PageToken: resp.NextPageToken}
	}
}

func newAppListCommand(g *globals) *cobra.Command {
	var o *outputFlag
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List apps",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := o.check(); err != nil {
				return err
			}
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			apps, err := listApps(cmd.Context(), client, &armadav1.ListAppsRequest{Project: g.project, AllProjects: g.allProjects})
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if o.json() {
				return printJSON(out, &armadav1.ListAppsResponse{Apps: apps})
			}
			return printAppList(out, apps, g.allProjects)
		},
	}
	o = addOutput(cmd, false)
	return cmd
}

func printAppList(out io.Writer, apps []*armadav1.AppSummary, projects bool) error {
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	head := "NAME\tREADY\tSTATE\tREVISION\tIMAGE\tURL"
	if projects {
		head = "PROJECT\t" + head
	}
	_, _ = fmt.Fprintln(tw, head)
	for _, a := range apps {
		p, name, ok := spec.SplitAppID(a.Name)
		if !ok {
			name = a.Name
		}
		line := fmt.Sprintf("%s\t%d/%d\t%s\t%s\t%s\t%s", name, a.Ready, a.Desired, dash(a.State), dash(a.Revision), a.Image, dash(a.Url))
		if projects {
			line = p + "\t" + line
		}
		_, _ = fmt.Fprintln(tw, line)
	}
	return tw.Flush()
}

func newAppShowCommand(g *globals) *cobra.Command {
	var o *outputFlag
	cmd := &cobra.Command{
		Use:   "show APP",
		Short: "Show an app: its revision, replicas, and URLs",
		Long: "Show an app: its revision, image, replicas, and URLs. -o yaml prints the spec\n" +
			"it runs as a file holds it, ready for create --file or update --file.",
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
			out := cmd.OutOrStdout()
			if o.format == outputYAML {
				return printSpec(cmd.Context(), client, args[0], false, out)
			}
			resp, err := client.Status(cmd.Context(), &armadav1.StatusRequest{App: args[0]})
			if err != nil {
				return RPCError(err)
			}
			if len(resp.Apps) == 0 {
				return fmt.Errorf("app %s not found", args[0])
			}
			if o.json() {
				return printJSON(out, resp.Apps[0])
			}
			return printApp(out, resp.Apps[0])
		},
	}
	o = addOutput(cmd, true)
	return cmd
}

// printSpec prints the spec an app or job runs, exactly as GetAppSpec
// returns it.
func printSpec(ctx context.Context, client armadav1.AdminServiceClient, id string, job bool, out io.Writer) error {
	resp, err := client.GetAppSpec(ctx, &armadav1.GetAppSpecRequest{App: id})
	if err != nil {
		return RPCError(err)
	}
	p, _ := appTarget(id)
	if sp, err := spec.ParseIn(resp.Spec, p); err == nil {
		if err := checkKind(sp, job, "show"); err != nil {
			return err
		}
	}
	_, err = out.Write(resp.Spec)
	return err
}

func printApp(out io.Writer, a *armadav1.AppStatus) error {
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	field := func(k, v string) { _, _ = fmt.Fprintf(tw, "%s:\t%s\n", k, v) }
	field("Name", a.Name)
	field("Revision", dash(a.ActiveRevision))
	field("Image", a.Image)
	field("Ready", fmt.Sprintf("%d/%d", serving(a), a.DesiredReplicas))
	field("Ingress", dash(a.Ingress))
	switch a.RolloutState {
	case rolloutProgressing:
		field("Rollout", fmt.Sprintf("rolling out %s; %s serves until it is ready", a.TargetRevision, a.ActiveRevision))
	case rolloutFailed:
		field("Rollout", fmt.Sprintf("%s failed, %s kept serving: %s", a.TargetRevision, a.ActiveRevision, printable(a.RolloutMessage)))
	}
	if a.PlacementMessage != "" {
		field("Placement", printable(a.PlacementMessage))
	}
	if as := a.Autoscale; as != nil {
		field("Autoscale", autoscaleNote(as))
	}
	if len(a.Traffic) > 0 {
		field("Traffic", trafficSummary(a.Traffic))
	}
	for i, u := range a.Urls {
		k := ""
		if i == 0 {
			k = "URLs"
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\n", k+":", u)
	}
	for _, t := range a.Traffic {
		for _, u := range t.Urls {
			_, _ = fmt.Fprintf(tw, "\t%s (%s)\n", u, t.Revision)
		}
	}
	if len(a.Replicas) > 0 {
		_, _ = fmt.Fprintln(tw, "\nREPLICA\tREVISION\tNODE\tSTATE\tRESTARTS\tADDRESS\tMESSAGE")
		for _, r := range a.Replicas {
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", r.Id, r.Revision, r.NodeId, replicaState(r), restarts(r), dash(r.Address), dash(printable(r.Message)))
		}
	}
	return tw.Flush()
}

func newAppScaleCommand(g *globals) *cobra.Command {
	var n int
	cmd := &cobra.Command{
		Use:   "scale APP --replicas N",
		Short: "Set the number of replicas until the next update (not for autoscaled apps)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := g.qualify(args); err != nil {
				return err
			}
			if !cmd.Flags().Changed("replicas") {
				return errors.New("give --replicas N")
			}
			if n < 1 || n > spec.MaxReplicas {
				return fmt.Errorf("--replicas must be between 1 and %d", spec.MaxReplicas)
			}
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			if _, err := client.Scale(cmd.Context(), &armadav1.ScaleRequest{App: args[0], Replicas: int32(n)}); err != nil {
				return RPCError(err)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Scaled %s to %d replicas.\n", args[0], n)
			return err
		},
	}
	cmd.Flags().IntVar(&n, "replicas", 0, "number of replicas")
	return cmd
}

// revisionName turns r3 into APP--r3; full names pass unchanged.
func revisionName(app, rev string) string {
	if strings.HasPrefix(rev, "r") && !strings.Contains(rev, "--") {
		return app + "--" + rev
	}
	return rev
}

func newAppRollbackCommand(g *globals) *cobra.Command {
	var (
		w  waitFlags
		to string
	)
	cmd := &cobra.Command{
		Use:   "rollback APP [--to REVISION]",
		Short: "Roll an app back to an earlier revision",
		Long: "Roll an app back to an earlier revision with a rolling update.\n\n" +
			"Without --to, a rollout in progress is cancelled; otherwise the app\n" +
			"returns to the revision before the active one. Revisions keep their\n" +
			"pinned image digest, so a rollback runs exactly the image that ran before.\n" +
			"REVISION is a full name (web--r3) or its number (r3).",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := g.qualify(args); err != nil {
				return err
			}
			req := &armadav1.RollbackRequest{App: args[0]}
			if to != "" {
				req.Revision = revisionName(args[0], to)
			}
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			resp, err := client.Rollback(cmd.Context(), req)
			if err != nil {
				return RPCError(err)
			}
			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Rolling %s back to %s.\n", args[0], resp.Revision); err != nil {
				return err
			}
			if !w.wait {
				return nil
			}
			return waitRollout(cmd.Context(), client, args[0], resp.Revision, w.timeout, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&to, "to", "", "the revision to return to (default: the one before the active one)")
	w.register(cmd)
	return cmd
}

func newAppTrafficCommand(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "traffic APP REVISION=WEIGHT...",
		Short: "Split an app's requests between revisions until the next update",
		Long: "Split the requests of an app in multiple revision mode (revisions.mode:\n" +
			"multiple) between its revisions until its next update. Weights are\n" +
			"percent and add up to 100; a revision left out stops serving, and one\n" +
			"with weight 0 is reached only through its label. Labels stay as the\n" +
			"spec set them. REVISION is a full name (web--r3) or its number (r3).",
		Example: "  armada app traffic web web--r3=90 web--r4=10\n  armada app traffic web r4=100",
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
				req.Traffic = append(req.Traffic, &armadav1.TrafficTarget{Revision: revisionName(app, rev), Weight: int32(n)}) //nolint:gosec // bounded above
			}
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			resp, err := client.SetTraffic(cmd.Context(), req)
			if err != nil {
				return RPCError(err)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Traffic of %s: %s.\n", app, trafficSummary(resp.Traffic))
			return err
		},
	}
}

func newAppDeleteCommand(g *globals) *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:     "delete APP --yes",
		Aliases: []string{"rm"},
		Short:   "Stop an app's replicas and delete it with its revisions and secrets",
		Long: "Stops serving the app, drains its replicas, and deletes it with its revisions\n" +
			"and secrets. This cannot be undone. Its volumes and their data stay until\n" +
			"`armada volume delete`, and creating the same name again finds them.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := g.qualify(args); err != nil {
				return err
			}
			if !yes {
				return fmt.Errorf("this deletes app %s with its revisions and secrets; pass --yes to confirm", args[0])
			}
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			if _, err := client.RemoveApp(cmd.Context(), &armadav1.RemoveAppRequest{App: args[0]}); err != nil {
				return RPCError(err)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Deleting %s: it is gone once its replicas have drained.\n", args[0])
			return err
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "confirm deleting the app")
	return cmd
}

func newRevisionCommand(g *globals) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "revision",
		Aliases: []string{"revisions"},
		Short:   "List and show an app's revisions",
	}
	var lo *outputFlag
	list := &cobra.Command{
		Use:     "list APP",
		Aliases: []string{"ls"},
		Short:   "List an app's revisions",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := g.qualify(args); err != nil {
				return err
			}
			if err := lo.check(); err != nil {
				return err
			}
			resp, err := listRevisions(cmd.Context(), g, args[0])
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if lo.json() {
				return printJSON(out, resp)
			}
			tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(tw, "REVISION\tSTATUS\tCREATED\tIMAGE\tPLATFORMS\tDIGEST")
			for _, r := range resp.Revisions {
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", r.Name, revisionStatus(r),
					r.CreatedAt.AsTime().Local().Format(time.DateTime), r.Image, dash(strings.Join(r.Platforms, ",")), dash(r.ImageDigest))
			}
			return tw.Flush()
		},
	}
	lo = addOutput(list, false)
	var so *outputFlag
	show := &cobra.Command{
		Use:   "show REVISION",
		Short: "Show one revision of an app",
		Long:  "Show one revision of an app. REVISION is its full name, such as web--r3.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := so.check(); err != nil {
				return err
			}
			i := strings.LastIndex(args[0], "--")
			if i <= 0 {
				return fmt.Errorf("%q: want a revision name such as web--r3", args[0])
			}
			app, err := g.app(args[0][:i])
			if err != nil {
				return err
			}
			name := app + args[0][i:]
			resp, err := listRevisions(cmd.Context(), g, app)
			if err != nil {
				return err
			}
			for _, r := range resp.Revisions {
				if r.Name != name {
					continue
				}
				out := cmd.OutOrStdout()
				if so.json() {
					return printJSON(out, r)
				}
				tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
				_, _ = fmt.Fprintf(tw, "Revision:\t%s\nStatus:\t%s\nCreated:\t%s\nImage:\t%s\nDigest:\t%s\nPlatforms:\t%s\n",
					r.Name, revisionStatus(r), r.CreatedAt.AsTime().Local().Format(time.DateTime), r.Image, dash(r.ImageDigest), dash(strings.Join(r.Platforms, ",")))
				return tw.Flush()
			}
			return fmt.Errorf("revision %s not found", name)
		},
	}
	so = addOutput(show, false)
	cmd.AddCommand(list, show)
	return cmd
}

func listRevisions(ctx context.Context, g *globals, app string) (*armadav1.ListRevisionsResponse, error) {
	client, conn, err := dialAdmin(g)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	resp, err := client.ListRevisions(ctx, &armadav1.ListRevisionsRequest{App: app})
	if err != nil {
		return nil, RPCError(err)
	}
	return resp, nil
}

func revisionStatus(r *armadav1.RevisionInfo) string {
	switch {
	case r.Active && r.Target:
		return "active"
	case r.Active:
		return "active (rolling out another)"
	case r.Target:
		return "rolling out"
	}
	return "-"
}
