package backup

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ryanbekhen/armada/internal/etcd"
	"github.com/ryanbekhen/armada/internal/pki"
	"github.com/ryanbekhen/armada/internal/store"
	"github.com/ryanbekhen/armada/internal/volbackup"
)

var bucketKey = bytes.Repeat([]byte("k"), 32)

func TestStageRestoreSnapshotRoundTrip(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	src, c := newDataDir(t)
	bucket := volbackup.NewMemory()
	tgt, err := volbackup.ParseTarget("https://AK:SK@s3.example.com/backups/armada")
	if err != nil {
		t.Fatal(err)
	}
	repo, err := volbackup.Open(ctx, bucket, volbackup.ControlPlaneRoot(tgt), bucketKey)
	if err != nil {
		t.Fatal(err)
	}
	var snap volbackup.Snapshot
	var staged []string
	m, err := Stage(ctx, src, c, func(dir string, _ Manifest) error {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, e := range entries {
			staged = append(staged, e.Name())
			if fi, _ := e.Info(); fi.Mode().Perm() != 0o600 {
				t.Errorf("%s staged with mode %o", e.Name(), fi.Mode().Perm())
			}
		}
		snap, _, err = repo.Backup(ctx, dir, "n1", time.Now())
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(staged, manifestName) || !slices.Contains(staged, FileState) || !slices.Contains(staged, FileCAKey) {
		t.Errorf("staged %v", staged)
	}
	// Staging leaves nothing behind in the data directory.
	entries, _ := os.ReadDir(src)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			t.Errorf("left %s in the data directory", e.Name())
		}
	}
	for _, k := range bucket.Keys() {
		if !strings.HasPrefix(k, "armada/_control-plane/") {
			t.Errorf("object outside the control plane's repository: %s", k)
		}
	}
	// Nothing in the bucket is readable without the key.
	caKey, _ := os.ReadFile(filepath.Join(src, FileCAKey))
	for _, k := range bucket.Keys() {
		b, _ := bucket.Get(ctx, k, 1<<30)
		if bytes.Contains(b, caKey[30:60]) {
			t.Errorf("%s holds the CA key in the clear", k)
		}
	}
	if info, err := repo.Info(ctx, snap.ID); err != nil || info.Node != "n1" || info.Files != len(m.Files)+1 {
		t.Errorf("info %+v %v (want %d files)", info, err, len(m.Files)+1)
	}

	dst := filepath.Join(t.TempDir(), "restored")
	cfg := member(t, "", "", nil)
	got, rsnap, err := RestoreSnapshot(ctx, repo, snap.ID, dst, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got.MasterKeyID != m.MasterKeyID || got.CAFingerprint != m.CAFingerprint || rsnap.ID != snap.ID {
		t.Errorf("manifest %+v, snapshot %+v", got, rsnap)
	}
	for name := range m.Files {
		if name == FileState {
			continue
		}
		a, _ := os.ReadFile(filepath.Join(src, name))
		b, err := os.ReadFile(filepath.Join(dst, name))
		if err != nil || !bytes.Equal(a, b) {
			t.Errorf("%s differs: %v", name, err)
		}
	}
	caPEM, _ := os.ReadFile(filepath.Join(dst, FileCACert))
	ca, err := pki.LoadCA(caPEM, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Dir, cfg.Name, cfg.CA = filepath.Join(dst, DirEtcd), "n1", ca
	em, err := etcd.Start(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer em.Close()
	st, err := store.NewEtcd(ctx, em.Client(), etcdPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := st.GetMeta(ctx, "cluster"); v != "test" {
		t.Errorf("cluster meta = %q", v)
	}

	// A restore never overwrites, and a wrong key reads nothing.
	if _, _, err := RestoreSnapshot(ctx, repo, snap.ID, dst, member(t, "", "", nil)); err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Errorf("restore over a data dir: %v", err)
	}
	if _, err := volbackup.Open(ctx, bucket, volbackup.ControlPlaneRoot(tgt), bytes.Repeat([]byte("x"), 32)); err == nil {
		t.Error("a wrong key opened the repository")
	}
}

// A snapshot holding anything but the backup's own files is refused before
// the data directory exists.
func TestRestoreSnapshotRefusesStrangeFiles(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo, err := volbackup.Open(ctx, volbackup.NewMemory(), "cp/", bucketKey)
	if err != nil {
		t.Fatal(err)
	}
	for name, build := range map[string]func(dir string){
		"unknown file": func(dir string) { _ = os.WriteFile(filepath.Join(dir, "authorized_keys"), []byte("x"), 0o600) },
		"directory":    func(dir string) { _ = os.Mkdir(filepath.Join(dir, "etcd"), 0o700) },
		"link":         func(dir string) { _ = os.Symlink("/etc/shadow", filepath.Join(dir, FileCAKey)) },
		"no manifest":  func(dir string) { _ = os.WriteFile(filepath.Join(dir, FileCACert), []byte("x"), 0o600) },
	} {
		dir := t.TempDir()
		build(dir)
		snap, _, err := repo.Backup(ctx, dir, "n1", time.Now())
		if err != nil {
			t.Fatal(err)
		}
		dst := filepath.Join(t.TempDir(), "restored")
		if _, _, err := RestoreSnapshot(ctx, repo, snap.ID, dst, member(t, "", "", nil)); err == nil {
			t.Errorf("%s: restored", name)
		}
		if _, err := os.Stat(dst); err == nil {
			t.Errorf("%s: the data directory was created", name)
		}
		if leftovers, _ := os.ReadDir(filepath.Dir(dst)); len(leftovers) != 0 {
			t.Errorf("%s: left %v", name, leftovers)
		}
	}
}
