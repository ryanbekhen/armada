package daemon

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"

	"github.com/spf13/cobra"

	"github.com/ryanbekhen/armada/internal/backup"
	"github.com/ryanbekhen/armada/internal/cli"
	"github.com/ryanbekhen/armada/internal/fsutil"
)

// hostHasIP reports whether ip is assigned to an interface; tests replace it.
var hostHasIP = func(ip netip.Addr) bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if have, ok := netip.AddrFromSlice(n.IP); ok && have.Unmap() == ip {
				return true
			}
		}
	}
	return false
}

func newBackupCommand() *cobra.Command {
	var dataDir, output string
	cmd := &cobra.Command{
		Use:   "backup -o FILE",
		Short: "Back up the control plane (state, keys, certificates)",
		Long: `Writes a consistent backup of the control plane: a snapshot of the state
(etcd), the secrets master key, the cluster CA, the server certificate,
ACME certificates, and this node's agent identity. Safe to run while the
server is running.

The archive contains the CA key and the master key in plaintext. It is
created with mode 0600; encrypt it before it leaves the machine, e.g.

  armadad backup -o - | age -r age1... > armada-$(date +%F).tar.gz.age`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var w io.Writer
			switch output {
			case "":
				return errors.New("pass -o FILE, or -o - to write to stdout")
			case "-":
				if cli.IsTerminal(cmd.OutOrStdout()) {
					return errors.New("refusing to write a binary archive with private keys to a terminal; redirect stdout")
				}
				w = cmd.OutOrStdout()
			default:
				// Never overwrite: an older backup may be the only good one.
				f, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // operator-chosen output path
				if err != nil {
					return err
				}
				defer f.Close()
				w = f
			}
			c, release, err := stateClient(cmd.Context(), dataDir)
			if err != nil {
				if output != "-" {
					_ = os.Remove(output)
				}
				return err
			}
			defer func() { _ = release() }()
			m, err := backup.Create(cmd.Context(), dataDir, c, w)
			if err != nil {
				if output != "-" {
					_ = os.Remove(output)
				}
				return err
			}
			if f, ok := w.(*os.File); ok && output != "-" {
				if err := f.Sync(); err != nil {
					return err
				}
			}
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Backup written (%d files, schema v%d, master key %s, CA %s).\n",
				len(m.Files), m.Schema, m.MasterKeyID, m.CAFingerprint)
			_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "It contains the CA key and the master key: store it encrypted.")
			return nil
		},
	}
	cmd.Flags().StringVar(&dataDir, "data-dir", defaultDataDir, "control plane data directory")
	cmd.Flags().StringVarP(&output, "output", "o", "", "archive to create (never overwritten), or - for stdout")
	return cmd
}

func newRestoreCommand() *cobra.Command {
	var dataDir string
	cmd := &cobra.Command{
		Use:   "restore FILE",
		Short: "Restore the control plane from a backup",
		Long: `Restores a backup made with 'armadad backup' into an empty data directory
("-" reads the archive from stdin). The archive is verified completely
before anything is written to the data directory. Stop any other control
plane of this cluster first: two servers must never run at the same time.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r := cmd.InOrStdin()
			if args[0] != "-" {
				f, err := os.Open(args[0])
				if err != nil {
					return err
				}
				defer f.Close()
				r = f
			}
			m, err := backup.Restore(cmd.Context(), r, dataDir, memberConfig(dataDir))
			if err != nil {
				return fmt.Errorf("restore failed, nothing was changed: %w", err)
			}
			if err := fsutil.CheckPrivate(dataDir); err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			_, _ = fmt.Fprintf(out, "Restored backup from %s (Armada %s, schema v%d) into %s.\n\n",
				m.Created.Format("2006-01-02 15:04 MST"), m.ArmadaVersion, m.Schema, dataDir)
			_, _ = fmt.Fprintf(out, "  control plane: %s\n  master key:    %s\n  CA SHA-256:    %s\n\n", m.Listen, m.MasterKeyID, m.CAFingerprint)
			if ap, err := netip.ParseAddrPort(m.Listen); err == nil && !hostHasIP(ap.Addr()) {
				_, _ = fmt.Fprintf(out, "WARNING: %s is not assigned to this host. Nodes and certificates use that\n"+
					"address: give this host that private IP before starting the server.\n\n", ap.Addr())
			}
			_, _ = fmt.Fprintf(out, "Next: systemctl start armada-server (or armadad server --data-dir %s).\n", dataDir)
			_, _ = fmt.Fprintln(out, "Changes made after the backup are gone: nodes that joined since must join again,")
			_, _ = fmt.Fprintln(out, "and apps, secrets, or nodes changed since must be redeployed or removed again.")
			return nil
		},
	}
	cmd.Flags().StringVar(&dataDir, "data-dir", defaultDataDir, "data directory to restore into (must not exist or be empty)")
	return cmd
}
