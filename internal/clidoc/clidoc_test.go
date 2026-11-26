package clidoc_test

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ryanbekhen/armada/internal/cli"
	"github.com/ryanbekhen/armada/internal/clidoc"
)

var update = flag.Bool("update", false, "rewrite docs/cli")

// TestReferenceIsCurrent fails when armada's pages of docs/cli differ from
// Go's client: make docs writes them from the Rust client, which must
// document the same commands. armadad's pages are the Rust daemon's (ADR
// 0055, item 20), whose help differs from Go's where its server machines
// run etcd and the agent as units of their own (item 19).
func TestReferenceIsCurrent(t *testing.T) {
	dir := filepath.Join("..", "..", "docs", "cli")
	pages := clidoc.Pages(cli.NewRootCommand())
	ours := func(name string) bool {
		return name != "README.md" && (name == "armada.md" || strings.HasPrefix(name, "armada-"))
	}
	if *update {
		old, _ := filepath.Glob(filepath.Join(dir, "*.md"))
		for _, f := range old {
			if _, ok := pages[filepath.Base(f)]; !ok && ours(filepath.Base(f)) {
				_ = os.Remove(f)
			}
		}
		if err := clidoc.Write(dir, pages); err != nil {
			t.Fatal(err)
		}
		return
	}
	for name, want := range pages {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("docs/cli/%s is out of date: run make docs", name)
		}
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.md"))
	for _, f := range files {
		if _, ok := pages[filepath.Base(f)]; !ok && ours(filepath.Base(f)) {
			t.Errorf("docs/cli/%s names no command: run make docs", filepath.Base(f))
		}
	}
}
