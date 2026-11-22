package cli

import (
	"fmt"
	"io"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/spec"
)

func newReplicaCommand(g *globals) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "replica",
		Aliases: []string{"replicas"},
		Short:   "List the replicas of apps",
		Long: "A replica is one running copy of an app, with its containers, on one node.\n" +
			"`armada replica list` names them the way --replica takes them.",
	}
	var o *outputFlag
	list := &cobra.Command{
		Use:     "list [APP]",
		Aliases: []string{"ls"},
		Short:   "List an app's replicas, or every app's",
		Long: "List replicas with their short name, node, state, revision, and\n" +
			"containers. The short name is what `--replica` takes in `armada app exec`\n" +
			"and `armada app logs`, and the containers what `--container` takes.",
		Example: "  armada replica list api\n" +
			"  armada app exec api --replica k3p9x --container log-ship",
		Args: cobra.MaximumNArgs(1),
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
			req := &armadav1.StatusRequest{}
			if len(args) == 1 {
				req.App = args[0]
			}
			resp, err := client.Status(cmd.Context(), req)
			if err != nil {
				return RPCError(err)
			}
			apps := make([]*armadav1.AppStatus, 0, len(resp.Apps))
			for _, a := range resp.Apps {
				if len(args) == 1 || g.listed(a.Name) {
					apps = append(apps, a)
				}
			}
			if o.json() {
				return printJSON(cmd.OutOrStdout(), &armadav1.StatusResponse{Apps: apps})
			}
			return printReplicas(cmd.OutOrStdout(), apps, len(args) == 0, g.allSpaces, time.Now())
		},
	}
	o = addOutput(list, false)
	cmd.AddCommand(list)
	return cmd
}

// printReplicas prints one line per replica; withApp adds the app's
// name, and withSpace its space.
func printReplicas(out io.Writer, apps []*armadav1.AppStatus, withApp, withSpace bool, now time.Time) error {
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	head := "REPLICA\tNODE\tSTATE\tREVISION\tCONTAINERS\tRESTARTS\tAGE"
	if withApp {
		head = "APP\t" + head
	}
	if withSpace {
		head = "SPACE\t" + head
	}
	_, _ = fmt.Fprintln(tw, head)
	for _, a := range apps {
		space, name, _ := spec.SplitAppID(a.Name)
		for _, r := range a.Replicas {
			line := fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s\t%s", shortReplica(r.Id), dash(r.NodeId), replicaState(r),
				shortRevision(r.Revision), containerList(r), restarts(r), strings.TrimSuffix(ago(r.CreatedAt, now), " ago"))
			if withApp {
				line = name + "\t" + line
			}
			if withSpace {
				line = space + "\t" + line
			}
			_, _ = fmt.Fprintln(tw, line)
		}
	}
	return tw.Flush()
}

// shortReplica is a replica's short name: its ID after the last hyphen,
// which --replica takes (ADR 0052).
func shortReplica(id string) string {
	return id[strings.LastIndexByte(id, '-')+1:]
}

// shortRevision is r12 for api--r12.
func shortRevision(rev string) string {
	if i := strings.LastIndex(rev, "--"); i >= 0 {
		return rev[i+2:]
	}
	return rev
}

// containerList names a replica's containers, init containers last.
func containerList(r *armadav1.ReplicaStatus) string {
	if len(r.Containers) == 0 {
		return "-" // a server before replicas named their containers
	}
	s := strings.Join(r.Containers, ", ")
	if len(r.InitContainers) > 0 {
		s += " (init: " + strings.Join(r.InitContainers, ", ") + ")"
	}
	return s
}

// maxChoices bounds the names an error lists as choices.
const maxChoices = 20

// choiceList lists names for an error, at most maxChoices of them.
func choiceList(names []string) string {
	names = slices.Clone(names)
	slices.Sort(names)
	names = slices.Compact(names)
	if len(names) > maxChoices {
		return strings.Join(names[:maxChoices], ", ") + fmt.Sprintf(", and %d more", len(names)-maxChoices)
	}
	return strings.Join(names, ", ")
}
