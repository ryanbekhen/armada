package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
)

// volumeChunk is the most archive data one restore message carries.
const volumeChunk = 64 << 10

func newVolumeCommand(g *globals) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "volume",
		Aliases: []string{"volumes"},
		Short:   "List, back up, restore, and delete persistent volumes",
		Long: "Volumes keep an app's data on the node that runs its replica (ADR 0023). They are\n" +
			"created with the app's first replica, stay on that node, and are kept until deleted\n" +
			"with `armada volume delete`. `armadad backup` does not include their contents: back\n" +
			"them up with `armada volume backup`, or to a bucket on a schedule (volumes[].backup,\n" +
			"ADR 0041) with `armada volume snapshot` to list them and take one now.",
	}
	cmd.AddCommand(newVolumeListCommand(g), newVolumeBackupCommand(g), newVolumeRestoreCommand(g), newVolumeDeleteCommand(g), newVolumeSnapshotCommand(g))
	return cmd
}

func newVolumeListCommand(g *globals) *cobra.Command {
	var o *outputFlag
	cmd := &cobra.Command{
		Use:     "list [APP]",
		Aliases: []string{"ls"},
		Short:   "List volumes, their node, and how much they hold",
		Args:    cobra.MaximumNArgs(1),
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
			req := &armadav1.ListVolumesRequest{}
			if len(args) == 1 {
				req.App = args[0]
			}
			resp, err := client.ListVolumes(cmd.Context(), req)
			if err != nil {
				return RPCError(err)
			}
			resp.Volumes = slices.DeleteFunc(resp.Volumes, func(v *armadav1.Volume) bool { return !g.listed(v.App) })
			out := cmd.OutOrStdout()
			if o.json() {
				return printJSON(out, resp)
			}
			tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(tw, "APP\tVOLUME\tNODE\tPATH\tUSED\tLAST BACKUP\tBACKUPS\tAGE")
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
				last, backups := "-", "-"
				if v.Backup {
					last = "never"
					if v.LastBackupAt != nil {
						last = humanDuration(now.Sub(v.LastBackupAt.AsTime())) + " ago"
						backups = fmt.Sprintf("%d (%s)", v.BackupSnapshots, diskBytes(v.BackupStoredBytes))
					}
					if v.BackupFailedAt != nil {
						last += ", failing"
					}
				}
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", v.App, v.Name, v.Node, path, used, last, backups, humanDuration(now.Sub(v.CreatedAt.AsTime())))
			}
			return tw.Flush()
		},
	}
	o = addOutput(cmd, false)
	return cmd
}

func newVolumeDeleteCommand(g *globals) *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:     "delete APP VOLUME --yes",
		Aliases: []string{"rm"},
		Short:   "Delete a volume and its data",
		Long: "Delete a volume and its data on its node. The app must no longer mount it: update it\n" +
			"without the volume first. This cannot be undone; back the volume up first if in doubt.",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := g.qualify(args); err != nil {
				return err
			}
			if !yes {
				return fmt.Errorf("this deletes the data of volume %s of %s; pass --yes to confirm", args[1], args[0])
			}
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			if _, err := client.RemoveVolume(cmd.Context(), &armadav1.RemoveVolumeRequest{App: args[0], Name: args[1]}); err != nil {
				return RPCError(err)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Deleted volume %s of %s.\n", args[1], args[0])
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
prefer their own dump tool (armada app exec APP -- pg_dump ...) or --stop.

The archive holds the app's data as it is: store it as carefully as the app's
own data.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := g.qualify(args); err != nil {
				return err
			}
			var w io.Writer
			switch output {
			case "":
				return errors.New("pass -o FILE, or -o - to write to stdout")
			case "-":
				if IsTerminal(cmd.OutOrStdout()) {
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
				return fail(RPCError(err))
			}
			var n int64
			for {
				m, err := stream.Recv()
				if err != nil {
					return fail(RPCError(err))
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
	var node, snapshot string
	cmd := &cobra.Command{
		Use:   "restore APP VOLUME FILE | --snapshot ID|latest",
		Short: "Replace a volume's contents with a backup",
		Long: `Replaces a volume's contents with an archive from armada volume backup (FILE, or
- for stdin), or with a backup from the volume's bucket (--snapshot, see
armada volume snapshot list). The app's replica is stopped while the backup is
written and started again afterwards; a broken backup leaves the volume as it was.

With --node the volume is restored onto that node and bound to it, and the app
follows. This is how an app comes back when the node holding its volume is lost
for good; it is refused while that node is still connected.`,
		Args: cobra.RangeArgs(2, 3),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := g.qualify(args[:2]); err != nil {
				return err
			}
			if (snapshot != "") == (len(args) == 3) {
				return errors.New("give an archive FILE or --snapshot ID|latest")
			}
			if snapshot != "" {
				client, conn, err := dialAdmin(g)
				if err != nil {
					return err
				}
				defer conn.Close()
				resp, err := client.RestoreVolumeSnapshot(cmd.Context(), &armadav1.RestoreVolumeSnapshotRequest{App: args[0], Name: args[1], Snapshot: snapshot, Node: node})
				if err != nil {
					return RPCError(err)
				}
				_, err = fmt.Fprintf(cmd.OutOrStdout(), "Restored volume %s of %s on %s from backup %s.\n", args[1], args[0], resp.Node, snapshot)
				return err
			}
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
				return RPCError(err)
			}
			start := &armadav1.RestoreVolumeStart{App: args[0], Name: args[1], Node: node}
			if err := stream.Send(&armadav1.RestoreVolumeMessage{Msg: &armadav1.RestoreVolumeMessage_Start{Start: start}}); err != nil {
				_, err = stream.CloseAndRecv()
				return RPCError(err)
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
				return RPCError(err)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Restored volume %s of %s on %s.\n", args[1], args[0], resp.Node)
			return err
		},
	}
	cmd.Flags().StringVar(&node, "node", "", "restore onto this node and bind the volume to it (when its node is lost)")
	cmd.Flags().StringVar(&snapshot, "snapshot", "", "restore this backup from the volume's bucket (an ID, or latest)")
	return cmd
}

func newVolumeSnapshotCommand(g *globals) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "snapshot",
		Aliases: []string{"snapshots"},
		Short:   "List a volume's backups in its bucket, or take one now",
		Long: "Volumes whose spec has backup (volumes[].backup, ADR 0041) are backed up to a bucket\n" +
			"on a schedule. These commands list those backups and take one now; restore one with\n" +
			"`armada volume restore APP VOLUME --snapshot ID|latest`.",
	}
	var o *outputFlag
	list := &cobra.Command{
		Use:     "list APP VOLUME",
		Aliases: []string{"ls"},
		Short:   "List a volume's backups, oldest first",
		Args:    cobra.ExactArgs(2),
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
			resp, err := client.ListVolumeSnapshots(cmd.Context(), &armadav1.ListVolumeSnapshotsRequest{App: args[0], Name: args[1]})
			if err != nil {
				return RPCError(err)
			}
			out := cmd.OutOrStdout()
			if o.json() {
				return printJSON(out, resp)
			}
			tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(tw, "ID\tTIME\tAGE")
			now := time.Now()
			for _, s := range resp.Snapshots {
				t := s.Time.AsTime()
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\n", s.Id, t.Local().Format(time.DateTime), humanDuration(now.Sub(t)))
			}
			return tw.Flush()
		},
	}
	o = addOutput(list, false)
	var co *outputFlag
	create := &cobra.Command{
		Use:   "create APP VOLUME",
		Short: "Back a volume up to its bucket now",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := g.qualify(args); err != nil {
				return err
			}
			if err := co.check(); err != nil {
				return err
			}
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			resp, err := client.CreateVolumeSnapshot(cmd.Context(), &armadav1.CreateVolumeSnapshotRequest{App: args[0], Name: args[1]})
			if err != nil {
				return RPCError(err)
			}
			out := cmd.OutOrStdout()
			if co.json() {
				return printJSON(out, resp)
			}
			s := resp.Snapshot
			_, err = fmt.Fprintf(out, "Backed up volume %s of %s as %s: %d files, %s, %s new; the bucket holds %d backups in %s.\n",
				args[1], args[0], s.Id, s.Files, diskBytes(s.Bytes), diskBytes(resp.NewBytes), resp.Snapshots, diskBytes(resp.StoredBytes))
			return err
		},
	}
	co = addOutput(create, false)
	cmd.AddCommand(list, create)
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

// IsTerminal reports whether w is a terminal.
func IsTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}
