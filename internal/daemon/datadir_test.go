package daemon

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestLockDataDirRefusesSecondAgent(t *testing.T) {
	dir := t.TempDir()
	unlock, err := lockDataDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lockDataDir(dir); err == nil || !strings.Contains(err.Error(), "another agent") {
		t.Fatalf("second lock: %v", err)
	}
	unlock()
	again, err := lockDataDir(dir)
	if err != nil {
		t.Fatalf("lock after release: %v", err)
	}
	again()
	if _, err := lockDataDir(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("locked a directory that does not exist")
	}
}
