package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/ryanbekhen/armada/internal/backup"
	"github.com/ryanbekhen/armada/internal/cli"
	"github.com/ryanbekhen/armada/internal/fsutil"
	"github.com/ryanbekhen/armada/internal/volbackup"
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

  armadad backup -o - | age -r age1... > armada-$(date +%F).tar.gz.age

To have the leader back the control plane up to a bucket on a schedule
instead, see armada cluster update --backup-url (ADR 0051); armadad backup
list shows what the bucket holds.`,
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
	cmd.AddCommand(newBackupListCommand())
	return cmd
}

func newRestoreCommand() *cobra.Command {
	var dataDir, bucketURL, bucketKey, snapshot string
	cmd := &cobra.Command{
		Use:   "restore FILE | --backup-url FILE --backup-key FILE [--snapshot ID|latest]",
		Short: "Restore the control plane from a backup",
		Long: `Restores a backup made with 'armadad backup' into an empty data directory
("-" reads the archive from stdin). The archive is verified completely
before anything is written to the data directory. Stop any other control
plane of this cluster first: two servers must never run at the same time.

With --backup-url and --backup-key, the backup comes from the bucket the
control plane backs itself up to (armada cluster update --backup-url, ADR 0051)
instead of an archive: --snapshot names one (armadad backup list), latest by
default. Both flags take a file (mode 0600) holding the URL or the key, or
- for stdin (one of them). The snapshot is checked exactly like an archive.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fromBucket := cmd.Flags().Changed("backup-url") || cmd.Flags().Changed("backup-key")
			switch {
			case fromBucket && len(args) > 0:
				return errors.New("give an archive or --backup-url and --backup-key, not both")
			case !fromBucket && len(args) == 0:
				return errors.New("give the archive to restore (- for stdin), or --backup-url FILE --backup-key FILE")
			case !fromBucket && cmd.Flags().Changed("snapshot"):
				return errors.New("--snapshot needs --backup-url and --backup-key")
			}
			var m backup.Manifest
			if fromBucket {
				repo, err := openControlPlaneRepo(cmd, bucketURL, bucketKey)
				if err != nil {
					return err
				}
				id := snapshot
				if id == "" || id == "latest" {
					if id, err = latestSnapshot(cmd.Context(), repo); err != nil {
						return err
					}
				}
				m, _, err = backup.RestoreSnapshot(cmd.Context(), repo, id, dataDir, memberConfig(dataDir))
				if err != nil {
					return fmt.Errorf("restore failed, nothing was changed: %w", err)
				}
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Restored backup %s.\n", id)
			} else {
				r := cmd.InOrStdin()
				if args[0] != "-" {
					f, err := os.Open(args[0])
					if err != nil {
						return err
					}
					defer f.Close()
					r = f
				}
				var err error
				m, err = backup.Restore(cmd.Context(), r, dataDir, memberConfig(dataDir))
				if err != nil {
					return fmt.Errorf("restore failed, nothing was changed: %w", err)
				}
			}
			if err := fsutil.CheckPrivate(dataDir); err != nil {
				return err
			}
			printRestored(cmd.OutOrStdout(), m, dataDir)
			return nil
		},
	}
	cmd.Flags().StringVar(&dataDir, "data-dir", defaultDataDir, "data directory to restore into (must not exist or be empty)")
	cmd.Flags().StringVar(&bucketURL, "backup-url", "", "file holding the URL of the bucket the control plane backs itself up to, or - for stdin")
	cmd.Flags().StringVar(&bucketKey, "backup-key", "", "file holding the key the control plane's backups are encrypted with, or - for stdin")
	cmd.Flags().StringVar(&snapshot, "snapshot", "latest", "backup to restore from the bucket: an ID from armadad backup list, or latest")
	return cmd
}

func printRestored(out io.Writer, m backup.Manifest, dataDir string) {
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
	_, _ = fmt.Fprintln(out, "Users and services are as of the backup: those created since are refused (create")
	_, _ = fmt.Fprintln(out, "them again), and roles, deletions, or certificate replacements made since are undone")
	_, _ = fmt.Fprintln(out, "(make them again; a deleted user's certificates are valid again until then).")
	if m.Schema < 14 {
		_, _ = fmt.Fprintln(out, "\nWARNING: this backup predates user records of schema v14. A user created after it")
		_, _ = fmt.Fprintln(out, "and missing from it would be a cluster-admin: delete each one at once with")
		_, _ = fmt.Fprintln(out, "`armada user delete NAME --yes`, then create it again.")
	}
}

func newBackupListCommand() *cobra.Command {
	var bucketURL, bucketKey string
	var o string
	cmd := &cobra.Command{
		Use:   "list --backup-url FILE --backup-key FILE",
		Short: "List the control plane's backups in its bucket",
		Long: `Lists the backups the leader keeps of the control plane in its bucket
(armada cluster update --backup-url, ADR 0051), oldest first, with the server
each was taken on: armadad restore --snapshot ID restores one onto a
machine with that server's private IP. Both flags take a file (mode 0600)
holding the URL or the key, or - for stdin (one of them).`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if o != "" && o != "json" {
				return fmt.Errorf("-o %s: only json is known", o)
			}
			repo, err := openControlPlaneRepo(cmd, bucketURL, bucketKey)
			if err != nil {
				return err
			}
			snaps, err := repo.Snapshots(cmd.Context())
			if err != nil {
				return err
			}
			type row struct {
				ID     string    `json:"id"`
				Time   time.Time `json:"time"`
				Server string    `json:"server"`
				Files  int       `json:"files"`
				Bytes  int64     `json:"bytes"`
			}
			rows := make([]row, 0, len(snaps))
			for _, s := range snaps {
				info, err := repo.Info(cmd.Context(), s.ID)
				if err != nil {
					return fmt.Errorf("read backup %s: %w", s.ID, err)
				}
				rows = append(rows, row{ID: s.ID, Time: info.Time, Server: info.Node, Files: info.Files, Bytes: info.Bytes})
			}
			out := cmd.OutOrStdout()
			if o == "json" {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(rows)
			}
			if len(rows) == 0 {
				_, _ = fmt.Fprintln(out, "No backups yet.")
				return nil
			}
			tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(tw, "ID\tTAKEN\tSERVER\tSIZE")
			for _, r := range rows {
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%d bytes\n", r.ID, r.Time.Local().Format(time.DateTime), r.Server, r.Bytes)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVar(&bucketURL, "backup-url", "", "file holding the URL of the bucket the control plane backs itself up to, or - for stdin")
	cmd.Flags().StringVar(&bucketKey, "backup-key", "", "file holding the key the control plane's backups are encrypted with, or - for stdin")
	cmd.Flags().StringVarP(&o, "output", "o", "", "json for JSON")
	return cmd
}

// openBucket opens the bucket of a control plane's backups; tests replace
// it.
var openBucket = volbackup.S3

// openControlPlaneRepo opens the control plane's backup repository from the
// URL and key in the files the flags name.
func openControlPlaneRepo(cmd *cobra.Command, urlFile, keyFile string) (*volbackup.Repo, error) {
	if urlFile == "" || keyFile == "" {
		return nil, errors.New("give both --backup-url FILE and --backup-key FILE")
	}
	if urlFile == "-" && keyFile == "-" {
		return nil, errors.New("only one of --backup-url and --backup-key can read stdin")
	}
	raw, err := readSecretFile(cmd, "--backup-url", urlFile)
	if err != nil {
		return nil, err
	}
	key, err := readSecretFile(cmd, "--backup-key", keyFile)
	if err != nil {
		return nil, err
	}
	t, err := volbackup.ParseTarget(string(raw))
	if err != nil {
		return nil, err // never holds the URL
	}
	obj, err := openBucket(t)
	if err != nil {
		return nil, err
	}
	return volbackup.Open(cmd.Context(), obj, volbackup.ControlPlaneRoot(t), key)
}

// latestSnapshot is the newest backup in the repository.
func latestSnapshot(ctx context.Context, repo *volbackup.Repo) (string, error) {
	snaps, err := repo.Snapshots(ctx)
	if err != nil {
		return "", err
	}
	if len(snaps) == 0 {
		return "", errors.New("the bucket holds no backup of the control plane at that URL")
	}
	return snaps[len(snaps)-1].ID, nil
}

// readSecretFile reads a URL or key: a file (mode 0600) or "-" for stdin.
func readSecretFile(cmd *cobra.Command, flag, arg string) ([]byte, error) {
	var b []byte
	var err error
	if arg == "-" {
		b, err = io.ReadAll(io.LimitReader(cmd.InOrStdin(), 64<<10))
	} else {
		b, err = fsutil.ReadPrivateFile(arg)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", flag, err)
	}
	return bytes.TrimSpace(b), nil
}
