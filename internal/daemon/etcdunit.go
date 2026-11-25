package daemon

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"

	"github.com/ryanbekhen/armada/internal/etcd"
	"github.com/ryanbekhen/armada/internal/fsutil"
	"github.com/ryanbekhen/armada/internal/runtime/embedded"
)

// Where a server's etcd member runs (`armadad server --etcd-member`, ADR
// 0055): in armadad server's process, or in armada-etcd.service.
const (
	etcdEmbedded = "embedded"
	etcdUnit     = "unit"
)

// dirEtcdBeforeUnit is the copy of the member's data `armadad etcd` makes
// before the pinned etcd first starts on it, the way back should that
// start damage it (ADR 0055).
const dirEtcdBeforeUnit = "etcd/data.before-unit"

// execProgram replaces this process with the program; tests replace it.
var execProgram = syscall.Exec

func newEtcdCommand() *cobra.Command {
	var dataDir, binDir string
	cmd := &cobra.Command{
		Use:   "etcd",
		Short: "Run this server's etcd member from the runtime pack (started by systemd)",
		Long: "etcd runs this server's etcd member with the etcd program of the runtime pack\n" +
			"instead of inside `armadad server` (ADR 0055). It works the member out as the\n" +
			"server does (name, data, addresses, certificate), writes etcd's configuration\n" +
			"file (etcd/" + etcd.FileConfig + ", 0600) beside it, and replaces itself with etcd.\n" +
			"Before etcd first runs on a member the server ran, it copies the member's data\n" +
			"to etcd/data.before-unit once. It refuses while another process holds the\n" +
			"member. For now only lab machines run it, with `armadad server --etcd-member unit`.\n" +
			"Flags it does not know (the server's, from ARMADA_SERVER_FLAGS) are ignored.",
		Args: cobra.NoArgs,
		// armada-etcd.service passes the server's flags.
		FParseErrWhitelist: cobra.FParseErrWhitelist{UnknownFlags: true},
		RunE: func(cmd *cobra.Command, _ []string) error {
			bin, config, err := prepareEtcd(dataDir, binDir, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			return execProgram(bin, []string{bin, "--config-file", config}, etcdEnv(os.Environ()))
		},
	}
	f := cmd.Flags()
	f.StringVar(&dataDir, "data-dir", defaultDataDir, "Armada data directory")
	f.StringVar(&binDir, "bin-dir", "", "use the etcd program in this directory (builds without the runtime pack)")
	return cmd
}

// prepareEtcd finds the etcd program, checks that no other process holds
// the member, copies a member the server ran once (dirEtcdBeforeUnit),
// and writes etcd's configuration file. It returns the program and the
// file.
func prepareEtcd(dataDir, binDir string, w io.Writer) (bin, config string, err error) {
	if _, err := os.Stat(filepath.Join(dataDir, fileServerCert)); errors.Is(err, fs.ErrNotExist) {
		return "", "", fmt.Errorf("%s is not a server's data directory; run `armadad init` or `armadad server join`", dataDir)
	}
	cfg, err := etcdConfig(dataDir, nil)
	if err != nil {
		return "", "", err
	}
	if bin, err = etcdProgram(dataDir, binDir); err != nil {
		return "", "", err
	}
	release, err := holdMember(cfg.Dir)
	if err != nil {
		return "", "", err
	}
	defer release()
	if err := keepBeforeUnit(dataDir, w); err != nil {
		return "", "", err
	}
	if config, err = etcd.WriteConfigFile(cfg); err != nil {
		return "", "", err
	}
	return bin, config, nil
}

// etcdProgram is the pinned etcd: in binDir when given, else from the
// runtime pack this armadad carries (installed first), else from the
// pack installed earlier.
func etcdProgram(dataDir, binDir string) (string, error) {
	p := runtimePaths(dataDir)
	path := filepath.Join(p.Bin(), embedded.BinEtcd)
	switch {
	case binDir != "":
		path = filepath.Join(binDir, embedded.BinEtcd)
	case len(embedded.Bundled()) > 0:
		if _, _, err := embedded.Install(p.Bundle(), embedded.Bundled()); err != nil {
			return "", fmt.Errorf("runtime pack: %w", err)
		}
	}
	fi, err := os.Stat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return "", fmt.Errorf("no etcd program at %s: this armadad carries no runtime pack with etcd; pass --bin-dir", path)
	}
	return path, nil
}

// holdMember takes the lock etcd's database file takes (an exclusive
// flock), so a member another process runs, armadad server's embedded one,
// is never copied or started twice. The returned function releases it,
// before etcd starts.
func holdMember(dir string) (func(), error) {
	db := filepath.Join(dir, "data", "member", "snap", "db")
	f, err := os.OpenFile(db, os.O_RDWR, 0) //nolint:gosec // the member's own database, under the data directory
	if errors.Is(err, fs.ErrNotExist) {
		return func() {}, nil
	}
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, fmt.Errorf("another process runs the etcd member in %s (armadad server with --etcd-member %s?); stop it first", dir, etcdEmbedded)
		}
		return nil, fmt.Errorf("lock %s: %w", db, err)
	}
	return func() { _ = f.Close() }, nil
}

// keepBeforeUnit copies the member's data to dirEtcdBeforeUnit once, when
// it has a write-ahead log (a member that ran) and no copy exists yet.
func keepBeforeUnit(dataDir string, w io.Writer) error {
	data := filepath.Join(dataDir, dirEtcd, "data")
	dst := filepath.Join(dataDir, dirEtcdBeforeUnit)
	if _, err := os.Stat(filepath.Join(data, "member", "wal")); err != nil {
		return nil //nolint:nilerr // a member that never ran has nothing to keep
	}
	if _, err := os.Lstat(dst); err == nil {
		return nil
	}
	tmp := dst + ".tmp"
	if err := os.RemoveAll(tmp); err != nil {
		return err
	}
	if err := copyTree(data, tmp); err != nil {
		_ = os.RemoveAll(tmp)
		return fmt.Errorf("copy the etcd member's data: %w", err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(w, "copied the etcd member's data to %s before its first start from the runtime pack\n", dst)
	return nil
}

// copyTree copies a directory of directories and regular files (an etcd
// data directory), owner-only.
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		to := filepath.Join(dst, rel)
		switch {
		case d.IsDir():
			return fsutil.MkdirPrivate(to)
		case d.Type().IsRegular():
			return copyFile(path, to)
		default:
			return fmt.Errorf("%s is not a regular file or directory", path)
		}
	})
}

func copyFile(src, dst string) error {
	in, err := os.Open(src) //nolint:gosec // under the member's data directory
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // under the data directory
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// etcdEnv is the environment etcd runs with: armadad's without etcd's own
// variables, which the configuration file replaces.
func etcdEnv(env []string) []string {
	out := make([]string, 0, len(env))
	for _, e := range env {
		if !strings.HasPrefix(e, "ETCD_") {
			out = append(out, e)
		}
	}
	return out
}
