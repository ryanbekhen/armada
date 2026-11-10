package cli

import (
	"errors"
	"fmt"
	"io"
	"slices"
	"text/tabwriter"

	"github.com/spf13/cobra"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
)

func newAppTopCommand(g *globals) *cobra.Command {
	var (
		o        *outputFlag
		projects bool
	)
	cmd := &cobra.Command{
		Use:   "top [APP]",
		Short: "Show the CPU and memory apps and their replicas use",
		Long: "Show the CPU and memory replicas use, from samples their nodes take every 10 seconds.\n\n" +
			"Without arguments it lists the project's apps (every project's with -A); with APP, that\n" +
			"app's replicas; with --projects, every project, with the requests it received and the\n" +
			"bytes it sent since the control plane's leader started counting.\n" +
			"CPU is shown as used/reserved and memory as used/limit; \"-\" means no recent sample\n" +
			"(the replica is not running, or its node's runtime cannot measure containers).",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := g.qualify(args); err != nil {
				return err
			}
			if err := o.check(); err != nil {
				return err
			}
			if projects && len(args) == 1 {
				return errors.New("--projects lists every project; leave out APP")
			}
			req := &armadav1.TopRequest{}
			if len(args) == 1 {
				req.App = args[0]
			}
			resp, err := top(cmd, g, req)
			if err != nil {
				return err
			}
			resp.Nodes = nil
			if projects {
				resp.Replicas = nil
			} else {
				resp.Projects, resp.CountedSince = nil, nil
				if req.App == "" {
					resp.Replicas = slices.DeleteFunc(resp.Replicas, func(r *armadav1.ReplicaTop) bool { return !g.listed(r.App) })
				}
			}
			out := cmd.OutOrStdout()
			switch {
			case o.json():
				return printJSON(out, resp)
			case projects:
				return printTopProjects(out, resp)
			case req.App != "":
				return printTopReplicas(out, resp)
			default:
				return printTopApps(out, resp)
			}
		},
	}
	o = addOutput(cmd, false)
	cmd.Flags().BoolVar(&projects, "projects", false, "list projects instead of apps")
	return cmd
}

func newNodeTopCommand(g *globals) *cobra.Command {
	var o *outputFlag
	cmd := &cobra.Command{
		Use:   "top",
		Short: "Show the CPU and memory each node's replicas use and reserve",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := o.check(); err != nil {
				return err
			}
			resp, err := top(cmd, g, &armadav1.TopRequest{})
			if err != nil {
				return err
			}
			if o.json() {
				return printJSON(cmd.OutOrStdout(), &armadav1.TopResponse{Nodes: resp.Nodes})
			}
			return printTopNodes(cmd.OutOrStdout(), resp)
		},
	}
	o = addOutput(cmd, false)
	return cmd
}

func top(cmd *cobra.Command, g *globals, req *armadav1.TopRequest) (*armadav1.TopResponse, error) {
	client, conn, err := dialAdmin(g)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	resp, err := client.Top(cmd.Context(), req)
	if err != nil {
		return nil, RPCError(err)
	}
	return resp, nil
}

// appTop sums an app's replicas.
type appTop struct {
	name                string
	replicas, measured  int
	cpu, cpuReserved    int64
	memory, memoryLimit int64
}

func printTopApps(out io.Writer, resp *armadav1.TopResponse) error {
	var apps []*appTop
	byName := map[string]*appTop{}
	for _, r := range resp.GetReplicas() {
		a := byName[r.GetApp()]
		if a == nil {
			a = &appTop{name: r.GetApp()}
			byName[a.name] = a
			apps = append(apps, a)
		}
		a.replicas++
		a.cpuReserved += r.GetCpuReservedMillis()
		a.memoryLimit += r.GetMemoryLimitBytes()
		if r.GetMeasured() {
			a.measured++
			a.cpu += r.GetCpuMillis()
			a.memory += r.GetMemoryBytes()
		}
	}
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "APP\tMEASURED\tCPU\tMEMORY")
	for _, a := range apps {
		cpu, mem := "-", "-"
		if a.measured > 0 {
			cpu, mem = millis(a.cpu), usedBytes(a.memory)
		}
		_, _ = fmt.Fprintf(tw, "%s\t%d/%d\t%s/%s\t%s/%s\n", a.name, a.measured, a.replicas, cpu, millis(a.cpuReserved), mem, humanBytes(a.memoryLimit))
	}
	return tw.Flush()
}

func printTopReplicas(out io.Writer, resp *armadav1.TopResponse) error {
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "REPLICA\tNODE\tSTATE\tCPU\tMEMORY")
	for _, r := range resp.GetReplicas() {
		cpu, mem := "-", "-"
		if r.GetMeasured() {
			cpu, mem = millis(r.GetCpuMillis()), usedBytes(r.GetMemoryBytes())
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s/%s\t%s/%s\n", r.GetId(), dash(r.GetNodeId()), dash(r.GetState()),
			cpu, millis(r.GetCpuReservedMillis()), mem, humanBytes(r.GetMemoryLimitBytes()))
	}
	return tw.Flush()
}

func printTopNodes(out io.Writer, resp *armadav1.TopResponse) error {
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "NODE\tREPLICAS\tCPU USED\tCPU RESERVED\tMEMORY USED\tMEMORY RESERVED")
	for _, n := range resp.GetNodes() {
		cpu, mem := "-", "-"
		if n.GetMeasured() {
			cpu, mem = millis(n.GetCpuMillis()), usedBytes(n.GetMemoryBytes())
		}
		_, _ = fmt.Fprintf(tw, "%s\t%d\t%s\t%s/%s\t%s\t%s/%s\n", n.GetId(), n.GetReplicas(), cpu,
			millis(n.GetCpuReservedMillis()), millis(n.GetCpuAllocatableMillis()),
			mem, usedBytes(n.GetMemoryReservedBytes()), humanBytes(n.GetMemoryAllocatableBytes()))
	}
	return tw.Flush()
}

func printTopProjects(out io.Writer, resp *armadav1.TopResponse) error {
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "PROJECT\tREPLICAS\tCPU\tMEMORY\tVOLUMES\tREQUESTS\tEGRESS")
	for _, p := range resp.GetProjects() {
		cpu, mem := "-", "-"
		if p.GetMeasured() > 0 {
			cpu, mem = millis(p.GetCpuMillis()), usedBytes(p.GetMemoryBytes())
		}
		_, _ = fmt.Fprintf(tw, "%s\t%d\t%s/%s\t%s/%s\t%s\t%d\t%s\n", p.GetName(), p.GetReplicas(),
			cpu, millis(p.GetCpuReservedMillis()), mem, humanBytes(p.GetMemoryReservedBytes()),
			usedBytes(p.GetVolumeBytes()), p.GetRequests(), usedBytes(p.GetEgressBytes()))
	}
	return tw.Flush()
}

// millis formats millicores; 0 is shown, unlike an unknown capacity.
func millis(m int64) string { return fmt.Sprintf("%dm", m) }

// usedBytes formats memory in use, where 0 is a value rather than unknown.
func usedBytes(b int64) string {
	if b <= 0 {
		return "0Mi"
	}
	return humanBytes(b)
}
