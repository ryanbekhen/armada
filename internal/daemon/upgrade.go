package daemon

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ryanbekhen/armada/internal/release"
	"github.com/ryanbekhen/armada/internal/version"
)

const (
	defaultDownloadBase = "https://github.com/" + release.Repo + "/releases/download"
	oidcIssuer          = "https://token.actions.githubusercontent.com"
	// maxDownload bounds every file of a release.
	maxDownload = 512 << 20
	// installedBinary is where the systemd units in a release run armadad.
	installedBinary = "/usr/local/bin/armadad"
)

// upgrader replaces this machine's binaries and units with a release, the
// way install.sh does, and restarts the service that runs (ADR 0030).
type upgrader struct {
	base       string // release downloads, without the tag
	binDir     string // where armadad and armada are installed
	unitDir    string // systemd units; empty skips them
	cosign     string // cosign binary; empty skips the signature
	requireSig bool
	restart    bool
	goarch     string
	systemctl  func(ctx context.Context, args ...string) error
	isActive   func(ctx context.Context, unit string) bool
	out, warn  io.Writer
}

func newUpgradeCommand() *cobra.Command {
	var target string
	var requireSig, noRestart bool
	cmd := &cobra.Command{
		Use:   "upgrade [--version vX.Y.Z]",
		Short: "Upgrade this machine to the latest (or a given) release and restart its service",
		Long: "upgrade downloads a release, verifies its checksum (and its signature when cosign is\n" +
			"installed), replaces armadad and armada and the systemd units, and restarts\n" +
			"armada-server or armada-agent. Upgrade servers first, one at a time, then the other\n" +
			"nodes (docs/operations.md#upgrades). ARMADA_DOWNLOAD_BASE points at a mirror.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if os.Geteuid() != 0 {
				return errors.New("run it as root: sudo armadad upgrade")
			}
			exe, err := os.Executable()
			if err != nil {
				return err
			}
			if exe, err = filepath.EvalSymlinks(exe); err != nil {
				return err
			}
			u := upgrader{
				base:       os.Getenv("ARMADA_DOWNLOAD_BASE"),
				binDir:     filepath.Dir(exe),
				unitDir:    "/etc/systemd/system",
				requireSig: requireSig || os.Getenv("ARMADA_REQUIRE_SIGNATURE") == "1",
				restart:    !noRestart,
				goarch:     runtime.GOARCH,
				systemctl:  systemctl,
				isActive:   unitActive,
				out:        cmd.OutOrStdout(),
				warn:       cmd.ErrOrStderr(),
			}
			if u.base == "" {
				u.base = defaultDownloadBase
			}
			if p, err := exec.LookPath("cosign"); err == nil {
				u.cosign = p
			}
			current := version.Get().Version
			if target == "" {
				if target, err = release.Latest(cmd.Context()); err != nil {
					return fmt.Errorf("%w; pass --version", err)
				}
			}
			return u.run(cmd.Context(), current, target)
		},
	}
	cmd.Flags().StringVar(&target, "version", "", "release to install (default: the latest)")
	cmd.Flags().BoolVar(&requireSig, "require-signature", false, "fail unless cosign verifies the release signature (or ARMADA_REQUIRE_SIGNATURE=1)")
	cmd.Flags().BoolVar(&noRestart, "no-restart", false, "install only; restart the service yourself")
	return cmd
}

func (u *upgrader) run(ctx context.Context, current, target string) error {
	if !release.IsRelease(target) {
		return fmt.Errorf("invalid version %q (want vX.Y.Z)", target)
	}
	if target == current {
		_, err := fmt.Fprintf(u.out, "Already at %s.\n", current)
		return err
	}
	if release.Newer(current, target) {
		return fmt.Errorf("%s is older than this %s; going back takes the backup from before the upgrade (docs/operations.md#rolling-back-an-upgrade)", target, current)
	}

	tmp, err := os.MkdirTemp("", "armada-upgrade-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmp) }()

	archive := fmt.Sprintf("armada_%s_linux_%s.tar.gz", strings.TrimPrefix(target, "v"), u.goarch)
	for _, name := range []string{archive, "checksums.txt"} {
		if err := u.fetch(ctx, target, name, filepath.Join(tmp, name)); err != nil {
			return err
		}
	}
	if err := u.verifySignature(ctx, target, tmp); err != nil {
		return err
	}
	if err := verifyChecksum(filepath.Join(tmp, "checksums.txt"), filepath.Join(tmp, archive), archive); err != nil {
		return err
	}
	files, err := extractRelease(filepath.Join(tmp, archive), filepath.Join(tmp, "x"))
	if err != nil {
		return err
	}
	for _, bin := range []string{"armadad", "armada"} {
		if _, ok := files[bin]; !ok {
			return fmt.Errorf("the release has no %s", bin)
		}
	}

	// Everything is verified: install, armadad last.
	for _, bin := range []string{"armada", "armadad"} {
		if err := installFile(files[bin], filepath.Join(u.binDir, bin), 0o755, nil); err != nil {
			return err
		}
	}
	if err := u.installUnits(ctx, files); err != nil {
		return err
	}

	msg := fmt.Sprintf("Upgraded to %s (from %s)", target, current)
	if u.restart {
		for _, unit := range []string{"armada-server", "armada-agent"} {
			if !u.isActive(ctx, unit) {
				continue
			}
			if err := u.systemctl(ctx, "restart", unit); err != nil {
				return fmt.Errorf("installed %s, but restarting %s failed: %w", target, unit, err)
			}
			msg += "; restarted " + unit
			break
		}
	}
	_, err = fmt.Fprintln(u.out, msg+".")
	return err
}

// fetch downloads base/tag/name to dst over HTTPS (or from a file:// mirror).
func (u *upgrader) fetch(ctx context.Context, tag, name, dst string) error {
	src, err := url.Parse(u.base + "/" + tag + "/" + name)
	if err != nil {
		return err
	}
	var body io.ReadCloser
	switch src.Scheme {
	case "file":
		if body, err = os.Open(src.Path); err != nil {
			return fmt.Errorf("download %s: %w", name, err)
		}
	case "https":
		ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, src.String(), nil)
		if err != nil {
			return err
		}
		client := &http.Client{CheckRedirect: func(r *http.Request, _ []*http.Request) error {
			if r.URL.Scheme != "https" {
				return errors.New("redirect away from https")
			}
			return nil
		}}
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("download %s: %w", name, err)
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			return fmt.Errorf("download %s: %s", name, resp.Status)
		}
		body = resp.Body
	default:
		return fmt.Errorf("download base %q: want https:// or file://", u.base)
	}
	defer func() { _ = body.Close() }()
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // our temporary directory
	if err != nil {
		return err
	}
	n, err := io.Copy(f, io.LimitReader(body, maxDownload+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > maxDownload {
		err = errors.New("too large")
	}
	if err != nil {
		return fmt.Errorf("download %s: %w", name, err)
	}
	return nil
}

// verifySignature checks that the release workflow of this repository, for
// this tag, signed checksums.txt, as install.sh does.
func (u *upgrader) verifySignature(ctx context.Context, tag, dir string) error {
	if u.cosign == "" {
		if u.requireSig {
			return errors.New("cosign is not installed and a signature is required")
		}
		_, _ = fmt.Fprintln(u.warn, "warning: cosign not found: checking the checksum only")
		return nil
	}
	bundle := filepath.Join(dir, "checksums.txt.sigstore.json")
	if err := u.fetch(ctx, tag, "checksums.txt.sigstore.json", bundle); err != nil {
		return err
	}
	identity := "https://github.com/" + release.Repo + "/.github/workflows/release.yml@refs/tags/" + tag
	c := exec.CommandContext(ctx, u.cosign, "verify-blob", "--bundle", bundle, //nolint:gosec // cosign from PATH, fixed arguments
		"--certificate-identity", identity, "--certificate-oidc-issuer", oidcIssuer, filepath.Join(dir, "checksums.txt"))
	if out, err := c.CombinedOutput(); err != nil {
		return fmt.Errorf("signature verification of checksums.txt FAILED; not installing: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func verifyChecksum(sums, file, name string) error {
	f, err := os.Open(sums) //nolint:gosec // our temporary directory
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	want := ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if fields := strings.Fields(sc.Text()); len(fields) == 2 && strings.TrimPrefix(fields[1], "*") == name {
			want = fields[0]
		}
	}
	if want == "" {
		return fmt.Errorf("%s is not listed in checksums.txt", name)
	}
	a, err := os.Open(file) //nolint:gosec // our temporary directory
	if err != nil {
		return err
	}
	defer func() { _ = a.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, a); err != nil {
		return err
	}
	if hex.EncodeToString(h.Sum(nil)) != strings.ToLower(want) {
		return fmt.Errorf("checksum mismatch for %s; not installing", name)
	}
	return nil
}

// extractRelease takes the binaries and the systemd units out of a release
// archive into dir and returns them by name ("armadad", "armada",
// "armada-server.service", ...). Anything else in the archive is skipped.
func extractRelease(archive, dir string) (map[string]string, error) {
	f, err := os.Open(archive) //nolint:gosec // our temporary directory
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("release archive: %w", err)
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return nil, err
	}
	files := map[string]string{}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("release archive: %w", err)
		}
		name := strings.TrimPrefix(filepath.ToSlash(filepath.Clean(h.Name)), "./")
		var key string
		switch {
		case h.Typeflag != tar.TypeReg:
			continue
		case name == "armadad" || name == "armada":
			key = name
		case strings.HasPrefix(name, "deploy/systemd/armada-") && strings.HasSuffix(name, ".service") && !strings.Contains(name[len("deploy/systemd/"):], "/"):
			key = filepath.Base(name)
		default:
			continue
		}
		if h.Size > maxDownload {
			return nil, fmt.Errorf("release archive: %s is too large", name)
		}
		dst := filepath.Join(dir, key)
		out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // fixed names in our temporary directory
		if err != nil {
			return nil, err
		}
		_, err = io.Copy(out, io.LimitReader(tr, h.Size))
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return nil, err
		}
		files[key] = dst
	}
	return files, nil
}

// installUnits writes the release's units, pointed at this armadad, when
// the machine has a unit directory, and reloads systemd.
func (u *upgrader) installUnits(ctx context.Context, files map[string]string) error {
	if u.unitDir == "" {
		return nil
	}
	if fi, err := os.Stat(u.unitDir); err != nil || !fi.IsDir() {
		return nil
	}
	changed := false
	for key, src := range files {
		if !strings.HasSuffix(key, ".service") {
			continue
		}
		edit := func(b []byte) []byte {
			return []byte(strings.ReplaceAll(string(b), installedBinary, filepath.Join(u.binDir, "armadad")))
		}
		if err := installFile(src, filepath.Join(u.unitDir, key), 0o644, edit); err != nil {
			return err
		}
		changed = true
	}
	if changed {
		return u.systemctl(ctx, "daemon-reload")
	}
	return nil
}

// installFile replaces dst with src (changed by edit, if any) atomically.
func installFile(src, dst string, mode os.FileMode, edit func([]byte) []byte) error {
	b, err := os.ReadFile(src) //nolint:gosec // our temporary directory
	if err != nil {
		return err
	}
	if edit != nil {
		b = edit(b)
	}
	tmp := dst + ".new"
	if err := os.WriteFile(tmp, b, mode); err != nil { //nolint:gosec // binaries 0755, units 0644, as install.sh
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

func systemctl(ctx context.Context, args ...string) error {
	out, err := exec.CommandContext(ctx, "systemctl", args...).CombinedOutput() //nolint:gosec // fixed unit names
	if err != nil {
		return fmt.Errorf("systemctl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func unitActive(ctx context.Context, unit string) bool {
	return exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", unit).Run() == nil //nolint:gosec // fixed unit names
}
