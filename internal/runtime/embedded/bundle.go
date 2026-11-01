package embedded

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
)

// manifestName is the first entry of a pack: the SHA-256 of every file.
const manifestName = "MANIFEST.json"

// Limits for a pack, far above what the pinned artifacts need.
const (
	maxPackFiles = 32
	maxFileSize  = 256 << 20
)

// Manifest describes a pack.
type Manifest struct {
	Arch     string            `json:"arch"`
	Versions map[string]string `json:"versions"`
	Files    map[string]string `json:"files"` // name -> sha256
}

// Pack builds a pack (gzipped tar, manifest first) from files, which maps
// bundle names to their contents.
func Pack(arch string, versions map[string]string, files map[string][]byte) ([]byte, error) {
	m := Manifest{Arch: arch, Versions: versions, Files: map[string]string{}}
	names := make([]string, 0, len(files))
	for n, b := range files {
		if err := checkName(n); err != nil {
			return nil, err
		}
		sum := sha256.Sum256(b)
		m.Files[n] = hex.EncodeToString(sum[:])
		names = append(names, n)
	}
	slices.Sort(names)
	mj, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	add := func(name string, mode int64, b []byte) error {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: int64(len(b)), Typeflag: tar.TypeReg}); err != nil {
			return err
		}
		_, err := tw.Write(b)
		return err
	}
	if err := add(manifestName, 0o644, mj); err != nil {
		return nil, err
	}
	for _, n := range names {
		if err := add(n, 0o755, files[n]); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// checkName accepts only plain relative names such as "runc" or
// "cni/bridge".
func checkName(n string) error {
	if n == "" || n == manifestName || path.Clean(n) != n || path.IsAbs(n) ||
		strings.HasPrefix(n, "../") || n == ".." || strings.ContainsAny(n, "\\\x00") {
		return fmt.Errorf("bundle: invalid file name %q", n)
	}
	return nil
}

// Install extracts pack under root (created 0700) unless an identical,
// intact copy is there already, points root/current at it, and returns the
// directory holding the binaries (always root/current/bin, a stable path
// that keeps working across upgrades). Every file is checked against the
// pack's manifest on every call.
func Install(root string, pack []byte) (string, Manifest, error) {
	sum := sha256.Sum256(pack)
	id := hex.EncodeToString(sum[:8])
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", Manifest{}, err
	}
	if err := os.Chmod(root, 0o700); err != nil { //nolint:gosec // a directory
		return "", Manifest{}, err
	}
	m, err := readManifest(pack)
	if err != nil {
		return "", Manifest{}, err
	}
	dir := filepath.Join(root, id)
	if verify(filepath.Join(dir, "bin"), m) != nil {
		tmp, err := os.MkdirTemp(root, ".extract-")
		if err != nil {
			return "", Manifest{}, err
		}
		defer os.RemoveAll(tmp)
		if err := extract(pack, filepath.Join(tmp, "bin"), m); err != nil {
			return "", Manifest{}, err
		}
		if err := verify(filepath.Join(tmp, "bin"), m); err != nil {
			return "", Manifest{}, err
		}
		if err := os.RemoveAll(dir); err != nil {
			return "", Manifest{}, err
		}
		if err := os.Rename(tmp, dir); err != nil {
			return "", Manifest{}, err
		}
	}
	// Swap the link atomically: a symlink renamed over the old one.
	link := filepath.Join(root, "current")
	tmpLink := link + ".new"
	_ = os.Remove(tmpLink)
	if err := os.Symlink(id, tmpLink); err != nil {
		return "", Manifest{}, err
	}
	if err := os.Rename(tmpLink, link); err != nil {
		return "", Manifest{}, err
	}
	// Older packs are no longer referenced: running shims call runc through
	// the stable path, which now resolves to this pack.
	entries, err := os.ReadDir(root)
	if err != nil {
		return "", Manifest{}, err
	}
	for _, e := range entries {
		if e.IsDir() && e.Name() != id && !strings.HasPrefix(e.Name(), ".") {
			_ = os.RemoveAll(filepath.Join(root, e.Name()))
		}
	}
	return filepath.Join(link, "bin"), m, nil
}

func readManifest(pack []byte) (Manifest, error) {
	var m Manifest
	tr, closeFn, err := openPack(pack)
	if err != nil {
		return m, err
	}
	defer closeFn()
	h, err := tr.Next()
	if err != nil || h.Name != manifestName || h.Size > 1<<20 {
		return m, errors.New("bundle: pack does not start with a manifest")
	}
	if err := json.NewDecoder(io.LimitReader(tr, 1<<20)).Decode(&m); err != nil {
		return m, fmt.Errorf("bundle: manifest: %w", err)
	}
	if len(m.Files) == 0 || len(m.Files) > maxPackFiles {
		return m, errors.New("bundle: manifest lists no files or too many")
	}
	for n, s := range m.Files {
		if err := checkName(n); err != nil {
			return m, err
		}
		if b, err := hex.DecodeString(s); err != nil || len(b) != sha256.Size {
			return m, fmt.Errorf("bundle: bad checksum for %s", n)
		}
	}
	return m, nil
}

func openPack(pack []byte) (*tar.Reader, func(), error) {
	zr, err := gzip.NewReader(bytes.NewReader(pack))
	if err != nil {
		return nil, nil, fmt.Errorf("bundle: %w", err)
	}
	return tar.NewReader(zr), func() { _ = zr.Close() }, nil
}

// extract writes the files the manifest lists into dir.
func extract(pack []byte, dir string, m Manifest) error {
	tr, closeFn, err := openPack(pack)
	if err != nil {
		return err
	}
	defer closeFn()
	seen := map[string]bool{}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("bundle: %w", err)
		}
		if h.Name == manifestName {
			continue
		}
		if _, ok := m.Files[h.Name]; !ok || seen[h.Name] {
			return fmt.Errorf("bundle: unexpected entry %q", h.Name)
		}
		if h.Typeflag != tar.TypeReg || h.Size > maxFileSize {
			return fmt.Errorf("bundle: %s is not a regular file within limits", h.Name)
		}
		seen[h.Name] = true
		dst := filepath.Join(dir, filepath.FromSlash(h.Name))
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return err
		}
		f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755) //nolint:gosec // executables in a 0700 directory
		if err != nil {
			return err
		}
		_, err = io.Copy(f, io.LimitReader(tr, maxFileSize))
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
	}
	if len(seen) != len(m.Files) {
		return errors.New("bundle: pack is missing files from its manifest")
	}
	return nil
}

// verify checks that dir holds exactly the manifest's files, as regular
// files with matching checksums.
func verify(dir string, m Manifest) error {
	for n, want := range m.Files {
		p := filepath.Join(dir, filepath.FromSlash(n))
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		if !fi.Mode().IsRegular() {
			return fmt.Errorf("bundle: %s is not a regular file", n)
		}
		f, err := os.Open(p) //nolint:gosec // p is a checked name under the pack directory
		if err != nil {
			return err
		}
		h := sha256.New()
		_, err = io.Copy(h, f)
		_ = f.Close()
		if err != nil {
			return err
		}
		if hex.EncodeToString(h.Sum(nil)) != want {
			return fmt.Errorf("bundle: %s does not match its checksum", n)
		}
	}
	return nil
}

// Bundled returns the pack compiled into this binary, or nil if it was built
// without the bundle tag.
func Bundled() []byte { return bundledPack }

// UseBinDir points root/current at binaries in dir instead of an extracted
// pack (development builds without the bundle tag).
func UseBinDir(root, dir string) error {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	for _, n := range []string{BinContainerd, BinShim, BinRunc, BinTini, DirCNI} {
		if _, err := os.Stat(filepath.Join(abs, n)); err != nil {
			return fmt.Errorf("runtime binaries: %w", err)
		}
	}
	dev := filepath.Join(root, "dev")
	if err := os.MkdirAll(dev, 0o700); err != nil {
		return err
	}
	_ = os.Remove(filepath.Join(dev, "bin"))
	if err := os.Symlink(abs, filepath.Join(dev, "bin")); err != nil {
		return err
	}
	link := filepath.Join(root, "current")
	_ = os.Remove(link + ".new")
	if err := os.Symlink("dev", link+".new"); err != nil {
		return err
	}
	return os.Rename(link+".new", link)
}
