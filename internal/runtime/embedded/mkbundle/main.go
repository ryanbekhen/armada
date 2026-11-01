// Command mkbundle downloads the artifacts pinned in embedded.Lock, checks
// their SHA-256, and writes the runtime pack that release builds embed.
//
//	go run ./internal/runtime/embedded/mkbundle -arch amd64
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ryanbekhen/armada/internal/runtime/embedded"
)

const maxDownload = 512 << 20

func main() {
	arch := flag.String("arch", "amd64", "target architecture (amd64 or arm64)")
	out := flag.String("out", "", "output file (default internal/runtime/embedded/bundle/linux_<arch>.pack)")
	cache := flag.String("cache", ".cache/runtime", "download cache directory")
	flag.Parse()
	if *out == "" {
		*out = filepath.Join("internal", "runtime", "embedded", "bundle", "linux_"+*arch+".pack")
	}
	if err := run(context.Background(), *arch, *out, *cache); err != nil {
		fmt.Fprintln(os.Stderr, "mkbundle:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, arch, out, cache string) error {
	if arch != "amd64" && arch != "arm64" {
		return fmt.Errorf("unsupported architecture %q", arch)
	}
	files := map[string][]byte{}
	versions := map[string]string{}
	for _, a := range embedded.Lock {
		want := a.SHA256[arch]
		if want == "" {
			return fmt.Errorf("%s: no checksum for %s", a.Name, arch)
		}
		b, err := fetch(ctx, strings.ReplaceAll(a.URL, "{arch}", arch), want, cache)
		if err != nil {
			return fmt.Errorf("%s: %w", a.Name, err)
		}
		versions[a.Name] = a.Version
		if len(a.Files) == 0 {
			files[a.Name] = b
			continue
		}
		got, err := members(b, a.Files)
		if err != nil {
			return fmt.Errorf("%s: %w", a.Name, err)
		}
		maps.Copy(files, got)
	}
	pack, err := embedded.Pack(arch, versions, files)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil { //nolint:gosec // build output in the source tree
		return err
	}
	if err := os.WriteFile(out, pack, 0o644); err != nil { //nolint:gosec // build output, no secrets
		return err
	}
	sum := sha256.Sum256(pack)
	fmt.Printf("%s: %d files, %.1f MB, sha256 %x\n", out, len(files), float64(len(pack))/(1<<20), sum[:8])
	return nil
}

// fetch returns the artifact from the cache or the network, and only if its
// SHA-256 matches.
func fetch(ctx context.Context, url, want, cache string) ([]byte, error) {
	if !strings.HasPrefix(url, "https://") {
		return nil, fmt.Errorf("refusing non-HTTPS URL %s", url)
	}
	cached := filepath.Join(cache, want)
	if b, err := os.ReadFile(cached); err == nil && sumHex(b) == want { //nolint:gosec // cache path named by a checksum
		return b, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxDownload))
	if err != nil {
		return nil, err
	}
	if got := sumHex(b); got != want {
		return nil, fmt.Errorf("checksum mismatch for %s: got %s, want %s", url, got, want)
	}
	if err := os.MkdirAll(cache, 0o755); err == nil { //nolint:gosec // download cache of public artifacts
		_ = os.WriteFile(cached, b, 0o644) //nolint:gosec // public artifact
	}
	return b, nil
}

func sumHex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// members extracts the listed regular files from a gzipped tar.
func members(archive []byte, want map[string]string) (map[string][]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	out := map[string][]byte{}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		name, ok := want[h.Name]
		if !ok {
			continue
		}
		if h.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("%s is not a regular file", h.Name)
		}
		b, err := io.ReadAll(io.LimitReader(tr, maxDownload))
		if err != nil {
			return nil, err
		}
		out[name] = b
	}
	for m := range want {
		if _, ok := out[want[m]]; !ok {
			return nil, fmt.Errorf("archive has no %s", m)
		}
	}
	return out, nil
}
