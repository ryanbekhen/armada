package daemon

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// needrestartDir is where needrestart (Debian, Ubuntu) reads extra settings.
// After apt upgrades a library, or armadad upgrade replaces the binary that
// the containers' log processes still run, needrestart restarts the services
// it thinks need it, armada-runtime included. Restarting the runtime keeps
// containers running, but Armada's services restart only when Armada or its
// operator asks: armadad upgrade restarts what it upgraded.
const needrestartDir = "/etc/needrestart/conf.d"

// needrestartFile and needrestartConf keep needrestart from restarting any
// armada-* service on its own; it still lists them. install.sh writes the
// same file.
const (
	needrestartFile = "armada.conf"
	needrestartConf = "# Written by Armada: needrestart lists Armada's services but never restarts\n" +
		"# them; armadad upgrade restarts what it upgrades.\n" +
		"$nrconf{override_rc}{qr(^armada-)} = 0;\n"
)

// writeNeedrestart writes the setting into dir when needrestart is installed
// (dir exists) and the file differs. It reports whether it wrote.
func writeNeedrestart(dir string) (bool, error) {
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		return false, nil
	}
	p := filepath.Join(dir, needrestartFile)
	if b, err := os.ReadFile(p); err == nil && bytes.Equal(b, []byte(needrestartConf)) { //nolint:gosec // a fixed path
		return false, nil
	}
	tmp := p + ".new"
	if err := os.WriteFile(tmp, []byte(needrestartConf), 0o644); err != nil { //nolint:gosec // read by needrestart, like the files beside it
		return false, err
	}
	if err := os.Rename(tmp, p); err != nil {
		_ = os.Remove(tmp)
		return false, err
	}
	return true, nil
}

// needrestartState reports whether needrestart is installed (dir exists) and
// whether it holds Armada's setting.
func needrestartState(dir string) (installed, set bool) {
	if _, err := os.Stat(dir); errors.Is(err, fs.ErrNotExist) {
		return false, false
	}
	b, err := os.ReadFile(filepath.Join(dir, needrestartFile)) //nolint:gosec // a fixed path
	return true, err == nil && bytes.Contains(b, []byte("$nrconf{override_rc}{qr(^armada-)} = 0;"))
}
