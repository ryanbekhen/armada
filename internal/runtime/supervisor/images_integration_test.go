//go:build integration

package supervisor

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/core/remotes/docker"
	"github.com/containerd/containerd/v2/core/remotes/docker/config"
)

// TestImagesPullIntegration pulls the images in ARMADA_IMAGES (comma
// separated) into a store under ARMADA_IMAGES_DIR as root, mounts a root
// filesystem for each, and reports the memory the pulls took.
//
//	go test -c -tags integration ./internal/runtime/supervisor -o t
//	sudo ARMADA_IMAGES=docker.io/traefik/whoami:v1.10 ARMADA_IMAGES_DIR=/var/tmp/imgs ./t -test.run PullIntegration -test.v
func TestImagesPullIntegration(t *testing.T) {
	refs := os.Getenv("ARMADA_IMAGES")
	dir := os.Getenv("ARMADA_IMAGES_DIR")
	if refs == "" || dir == "" || os.Geteuid() != 0 {
		t.Skip("needs root, ARMADA_IMAGES, and ARMADA_IMAGES_DIR")
	}
	ctx := context.Background()
	runtime.GC()
	before := stats()
	var peak atomic.Uint64
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(20 * time.Millisecond):
			}
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			if v := m.HeapInuse + m.StackInuse; v > peak.Load() {
				peak.Store(v)
			}
		}
	}()
	s, err := OpenImages(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	resolver := docker.NewResolver(docker.ResolverOptions{Hosts: config.ConfigureHosts(ctx, config.HostOptions{DefaultScheme: "https"})})
	for _, ref := range strings.Split(refs, ",") {
		start := time.Now()
		img, err := s.Pull(ctx, ref, resolver, nil)
		if err != nil {
			t.Fatalf("%s: %v", ref, err)
		}
		t.Logf("%s: %s chain %s platforms %v in %v", ref, img.Target.Digest, img.ChainID, img.Platforms, time.Since(start).Round(time.Millisecond))
		key := "test-" + img.ChainID.Encoded()[:12]
		ms, err := s.Prepare(ctx, key, img)
		if err != nil {
			t.Fatal(err)
		}
		target := t.TempDir()
		if err := mount.All(ms, target); err != nil {
			t.Fatal(err)
		}
		entries, _ := os.ReadDir(target)
		_, etcErr := os.Stat(filepath.Join(target, "etc"))
		if err := mount.UnmountAll(target, 0); err != nil {
			t.Fatal(err)
		}
		if err := s.Release(ctx, key); err != nil {
			t.Fatal(err)
		}
		t.Logf("  root filesystem: %d entries, /etc: %v", len(entries), etcErr == nil)
	}
	close(stop)
	runtime.GC()
	after := stats()
	t.Logf("memory: before heap %.1f MiB anon %.1f MiB; peak heap+stacks %.1f MiB; after GC heap %.1f MiB anon %.1f MiB",
		mib(before.heap), mib(before.anon), mib(peak.Load()), mib(after.heap), mib(after.anon))

}

type memStats struct{ heap, anon uint64 }

func stats() memStats {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	out := memStats{heap: m.HeapInuse}
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var kb uint64
		if n, _ := fmt.Sscanf(sc.Text(), "RssAnon: %d kB", &kb); n == 1 {
			out.anon = kb << 10
		}
	}
	return out
}

func mib(b uint64) float64 { return float64(b) / (1 << 20) }
