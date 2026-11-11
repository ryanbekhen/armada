package clidoc_test

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/ryanbekhen/armada/internal/cli"
	"github.com/ryanbekhen/armada/internal/clidoc"
	"github.com/ryanbekhen/armada/internal/daemon"
)

var update = flag.Bool("update", false, "rewrite docs/cli")

// TestReferenceIsCurrent fails when docs/cli differs from the commands:
// run make docs.
func TestReferenceIsCurrent(t *testing.T) {
	dir := filepath.Join("..", "..", "docs", "cli")
	pages := clidoc.Pages(cli.NewRootCommand())
	for name, b := range clidoc.Pages(daemon.NewRootCommand()) {
		pages[name] = b
	}
	if *update {
		old, _ := filepath.Glob(filepath.Join(dir, "*.md"))
		for _, f := range old {
			if _, ok := pages[filepath.Base(f)]; !ok && filepath.Base(f) != "README.md" {
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
		if _, ok := pages[filepath.Base(f)]; !ok && filepath.Base(f) != "README.md" {
			t.Errorf("docs/cli/%s names no command: run make docs", filepath.Base(f))
		}
	}
}
