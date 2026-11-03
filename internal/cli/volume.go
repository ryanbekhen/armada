package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
)

// volumeChunk is the most archive data one restore message carries.
const volumeChunk = 64 << 10

func newVolumeCommand(g *globals) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "volume",
		Aliases: []string{"volumes"},
		Short:   "List, back up, restore, and remove persistent volumes",
		Long: "Volumes keep an app's data on the node that runs its replica (ADR 0025). They are\n" +
			"created with the app's first replica, stay on that node, and are kept until removed\n" +
			"with `armada volume rm`. `armada backup` does not include their contents: back them\n" +
			"up with `armada volume backup`.",
	}
	cmd.AddCommand(newVolumeListCommand(g), newVolumeRemoveCommand(g), newVolumeBackupCommand(g), newVolumeRestoreCommand(g))
	return cmd
}

func newVolumeListCommand(g *globals) *cobra.Command {
	var output string
	cmd := &cobra.Command{
		Use:     "list [APP]",
		Aliases: []string{"ls"},
		Short:   "List volumes, their node, and how much they hold",
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := checkOutput(output); err != nil {
				return err
			}
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			req := &armadav1.ListVolumesRequest{}
			if len(args) == 1 {
				req.App = args[0]
			}
			resp, err := client.ListVolumes(cmd.Context(), req)
			if err != nil {
				return rpcErr(err)
			}
			out := cmd.OutOrStdout()
			if output == outputJSON {
				return printJSON(out, resp)
			}
			if len(resp.Volumes) == 0 {
				_, err := fmt.Fprintln(out, "No volumes.")
				return err
			}
			tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(tw, "APP\tVOLUME\tNODE\tPATH\tUSED\tAGE")
			now := time.Now()
			for _, v := range resp.Volumes {
				path := v.Path
				if !v.InUse {
					path = "(not mounted)"
				}
				used := "-"
				if v.UsedBytes >= 0 {
					used = diskBytes(v.UsedBytes)
				}
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", v.App, v.Name, v.Node, path, used, humanDuration(now.Sub(v.CreatedAt.AsTime())))
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVarP(&output, "output", "o", outputText, "output format: text or json")
	return cmd
}

func newVolumeRemoveCommand(g *globals) *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:     "remove APP VOLUME --yes",
		Aliases: []string{"rm", "delete"},
		Short:   "Delete a volume and its data",
		Long: "Delete a volume and its data on its node. The app must no longer mount it: deploy it\n" +
			"without the volume first. This cannot be undone; back the volume up first if in doubt.",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !yes {
				return fmt.Errorf("this deletes the data of volume %s of %s; pass --yes to confirm", args[1], args[0])
			}
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			if _, err := client.RemoveVolume(cmd.Context(), &armadav1.RemoveVolumeRequest{App: args[0], Name: args[1]}); err != nil {
				return rpcErr(err)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Volume %s of %s removed.\n", args[1], args[0])
			return err
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "confirm deleting the data")
	return cmd
}

func newVolumeBackupCommand(g *globals) *cobra.Command {
	var output string
	var stop bool
	cmd := &cobra.Command{
		Use:   "backup APP VOLUME -o FILE",
		Short: "Copy a volume's contents into a gzipped tar archive",
		Long: `Copies a volume's contents from its node into a gzipped tar archive. The copy is
taken while the app runs; files it writes meanwhile may be copied half-written.
With --stop the app's replica is stopped for the backup and started again
afterwards, for a consistent copy at the cost of downtime. For databases,
prefer their own dump tool (armada exec APP -- pg_dump ...) or --stop.

The archive holds the app's data as it is: store it as carefully as the app's
own data.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			var w io.Writer
			switch output {
			case "":
				return errors.New("pass -o FILE, or -o - to write to stdout")
			case "-":
				if isTerminal(cmd.OutOrStdout()) {
					return errors.New("refusing to write a binary archive to a terminal; redirect stdout")
				}
				w = cmd.OutOrStdout()
			default:
				f, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // operator-chosen output path
				if err != nil {
					return err
				}
				defer f.Close()
				w = f
			}
			fail := func(err error) error {
				if output != "-" {
					_ = os.Remove(output)
				}
				return err
			}
			client, conn, err := dialAdmin(g)
			if err != nil {
				return fail(err)
			}
			defer conn.Close()
			stream, err := client.BackupVolume(cmd.Context(), &armadav1.BackupVolumeRequest{App: args[0], Name: args[1], Stop: stop})
			if err != nil {
				return fail(rpcErr(err))
			}
			var n int64
			for {
				m, err := stream.Recv()
				if err != nil {
					return fail(rpcErr(err))
				}
				k, err := w.Write(m.GetData())
				n += int64(k)
				if err != nil {
					return fail(err)
				}
				if m.GetDone() {
					break
				}
			}
			if f, ok := w.(*os.File); ok && output != "-" {
				if err := f.Sync(); err != nil {
					return fail(err)
				}
			}
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Backed up volume %s of %s (%s compressed).\n", args[1], args[0], diskBytes(n))
			return nil
		},
	}
	cmd.Flags().StringVarP(&output, "output", "o", "", "archive to create (never overwritten), or - for stdout")
	cmd.Flags().BoolVar(&stop, "stop", false, "stop the app's replica during the backup")
	return cmd
}

func newVolumeRestoreCommand(g *globals) *cobra.Command {
	var node string
	cmd := &cobra.Command{
		Use:   "restore APP VOLUME FILE",
		Short: "Replace a volume's contents with a backup",
		Long: `Replaces a volume's contents with an archive from armada volume backup (FILE, or
- for stdin). The app's replica is stopped while the archive is unpacked and
started again afterwards; a broken archive leaves the volume as it was.

With --node the volume is restored onto that node and bound to it, and the app
follows. This is how an app comes back when the node holding its volume is lost
for good; it is refused while that node is still connected.`,
		Args: cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			r := cmd.InOrStdin()
			if args[2] != "-" {
				f, err := os.Open(args[2])
				if err != nil {
					return err
				}
				defer f.Close()
				r = f
			}
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			stream, err := client.RestoreVolume(cmd.Context())
			if err != nil {
				return rpcErr(err)
			}
			start := &armadav1.RestoreVolumeStart{App: args[0], Name: args[1], Node: node}
			if err := stream.Send(&armadav1.RestoreVolumeMessage{Msg: &armadav1.RestoreVolumeMessage_Start{Start: start}}); err != nil {
				_, err = stream.CloseAndRecv()
				return rpcErr(err)
			}
			buf := make([]byte, volumeChunk)
			for {
				k, rerr := r.Read(buf)
				if k > 0 {
					if err := stream.Send(&armadav1.RestoreVolumeMessage{Msg: &armadav1.RestoreVolumeMessage_Data{Data: append([]byte(nil), buf[:k]...)}}); err != nil {
						break // the server's error comes with CloseAndRecv
					}
				}
				if errors.Is(rerr, io.EOF) {
					break
				}
				if rerr != nil {
					return rerr
				}
			}
			resp, err := stream.CloseAndRecv()
			if err != nil {
				return rpcErr(err)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Restored volume %s of %s on %s.\n", args[1], args[0], resp.Node)
			return err
		},
	}
	cmd.Flags().StringVar(&node, "node", "", "restore onto this node and bind the volume to it (when its node is lost)")
	return cmd
}

// diskBytes formats a size on disk: 512B, 4.0Ki, 1.2Gi.
func diskBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%dB", b)
	}
	v, i := float64(b)/unit, 0
	for v >= unit && i < 4 {
		v /= unit
		i++
	}
	return fmt.Sprintf("%.1f%ci", v, "KMGTP"[i])
}
