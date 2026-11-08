// Package conntrack reads and raises the limit of the kernel's connection
// tracking table on a node (ADR 0025). When the table is full the kernel drops
// the first packet of new connections, and clients wait for a retransmit: one
// second or more per request.
package conntrack

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	// Minimum is the limit a node gets when it has the memory for it.
	Minimum = 262144
	// memoryPerEntry keeps a full table to about 6% of the node's memory: an
	// entry takes about 256 bytes.
	memoryPerEntry = 4096
	// WarnPercent is how full the table is when armadad doctor warns.
	WarnPercent = 80

	procDir   = "/proc/sys/net/netfilter"
	fileCount = "nf_conntrack_count"
	fileMax   = "nf_conntrack_max"
)

// Table is the node's connection tracking table.
type Table struct {
	dir    string
	memory int64
}

// New returns the table of this machine.
func New() *Table {
	var si unix.Sysinfo_t
	if err := unix.Sysinfo(&si); err != nil {
		return &Table{dir: procDir}
	}
	return &Table{dir: procDir, memory: int64(si.Totalram) * int64(si.Unit)} //nolint:gosec // the size of this machine's memory
}

// At returns a table kept in dir, for tests.
func At(dir string, memory int64) *Table { return &Table{dir: dir, memory: memory} }

// Target is the limit a node with memory bytes should have at least.
func Target(memory int64) int64 { return min(Minimum, max(0, memory)/memoryPerEntry) }

// Read returns how many connections are tracked and the limit. ok is false
// while the kernel module is not loaded, which is not a problem: nothing is
// tracked then.
func (t *Table) Read() (entries, limit int64, ok bool) {
	entries, err := t.read(fileCount)
	if err != nil {
		return 0, 0, false
	}
	limit, err = t.read(fileMax)
	if err != nil || limit <= 0 {
		return 0, 0, false
	}
	return entries, limit, true
}

// Raise lifts the limit to Target if it is below, and never lowers it, so
// an operator's higher limit stands. It returns the previous limit if it
// changed anything. The kernel module may load after the agent starts, so
// callers repeat this; with no module it does nothing.
func (t *Table) Raise() (previous int64, err error) {
	limit, err := t.read(fileMax)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	target := Target(t.memory)
	if limit >= target {
		return 0, nil
	}
	path := filepath.Join(t.dir, fileMax)
	if err := os.WriteFile(path, []byte(strconv.FormatInt(target, 10)+"\n"), 0o600); err != nil {
		return 0, fmt.Errorf("raise the connection tracking limit: %w", err)
	}
	return limit, nil
}

func (t *Table) read(name string) (int64, error) {
	b, err := os.ReadFile(filepath.Join(t.dir, name)) //nolint:gosec // a fixed directory and name
	if err != nil {
		return 0, err
	}
	v, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("read %s: %w", name, err)
	}
	return v, nil
}
