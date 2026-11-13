package agent

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/fsutil"
	"github.com/ryanbekhen/armada/internal/runtime"
)

// replicaIDRe bounds replica IDs before they become directory names.
// Apps of other spaces than the default one have a dot in their ID, and
// so in their replicas' IDs (ADR 0026).
var replicaIDRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,126}[a-z0-9])?$`)

// errNoSecretsDir is reported for replicas with secret files on a node
// without a tmpfs secrets directory.
var errNoSecretsDir = errors.New("this node cannot mount secret files: the agent has no tmpfs secrets directory (see --secrets-dir)")

// writeSecretFiles writes a replica's secret files to its directory under
// the secrets dir (tmpfs, so plaintext stays in memory) and returns the
// mounts for its container.
func (a *Agent) writeSecretFiles(s *armadav1.ReplicaSpec) ([]runtime.FileMount, error) {
	files := s.GetSecretFiles()
	if len(files) == 0 {
		return nil, nil
	}
	if a.cfg.SecretsDir == "" {
		return nil, errNoSecretsDir
	}
	if !replicaIDRe.MatchString(s.GetId()) {
		return nil, fmt.Errorf("invalid replica id %q", s.GetId())
	}
	dir := filepath.Join(a.cfg.SecretsDir, s.GetId())
	if err := fsutil.MkdirPrivate(dir); err != nil {
		return nil, fmt.Errorf("secrets dir: %w", err)
	}
	mounts := make([]runtime.FileMount, 0, len(files))
	for i, f := range files {
		target := f.GetPath()
		if !filepath.IsAbs(target) || filepath.Clean(target) != target {
			return nil, fmt.Errorf("invalid secret file path %q", target)
		}
		src := filepath.Join(dir, strconv.Itoa(i))
		// World-readable so any container user can read it; the private
		// parent directories keep other users on the node out.
		if err := fsutil.WriteFileAtomic(src, f.GetData(), 0o444); err != nil {
			return nil, fmt.Errorf("write secret file: %w", err)
		}
		mounts = append(mounts, runtime.FileMount{Source: src, Target: target})
	}
	return mounts, nil
}

// cleanSecretFiles removes the secret directories of replicas this node no
// longer runs.
func (a *Agent) cleanSecretFiles(desired map[string]*armadav1.ReplicaSpec) {
	if a.cfg.SecretsDir == "" {
		return
	}
	entries, err := os.ReadDir(a.cfg.SecretsDir)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			a.log.Warn("read secrets dir failed", "err", err)
		}
		return
	}
	for _, e := range entries {
		// Only touch what this agent could have created.
		if !e.IsDir() || !replicaIDRe.MatchString(e.Name()) {
			continue
		}
		if s, ok := desired[e.Name()]; ok && len(s.GetSecretFiles()) > 0 {
			continue
		}
		if err := os.RemoveAll(filepath.Join(a.cfg.SecretsDir, e.Name())); err != nil {
			a.log.Warn("remove secret files failed", "replica", e.Name(), "err", err)
		}
	}
}

// registryAuth returns the pull credentials of a replica, if any.
func registryAuth(s *armadav1.ReplicaSpec) *runtime.RegistryAuth {
	r := s.GetRegistry()
	if r == nil {
		return nil
	}
	return &runtime.RegistryAuth{Username: r.GetUsername(), Password: r.GetPassword(), ServerAddress: r.GetServer()}
}
