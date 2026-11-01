package embedded

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ryanbekhen/armada/internal/runtime"
)

func readAll(t *testing.T, s runtime.LogStream) []runtime.LogFrame {
	t.Helper()
	var out []runtime.LogFrame
	for {
		f, err := s.Next()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, f)
	}
}

func TestWriteAndReadLogs(t *testing.T) {
	dir := t.TempDir()
	stdout := strings.NewReader("one\ntwo\n" + strings.Repeat("x", maxLogChunk+10) + "\n")
	stderr := strings.NewReader("oops\n")
	if err := WriteLogs(dir, "armada-web-1", stdout, stderr); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dir, "armada-web-1.log"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("log file: %v %v", fi, err)
	}

	s, err := ReadLogs(context.Background(), dir, "armada-web-1", runtime.LogOptions{})
	if err != nil {
		t.Fatal(err)
	}
	frames := readAll(t, s)
	_ = s.Close()
	var out, errOut string
	for _, f := range frames {
		if f.Stream == runtime.Stderr {
			errOut += string(f.Data)
		} else {
			out += string(f.Data)
		}
	}
	if !strings.HasPrefix(out, "one\ntwo\nxxx") || len(out) != 8+maxLogChunk+11 || errOut != "oops\n" {
		t.Errorf("stdout %d bytes (%q...), stderr %q", len(out), out[:min(len(out), 12)], errOut)
	}

	s, _ = ReadLogs(context.Background(), dir, "armada-web-1", runtime.LogOptions{Tail: 1})
	if frames := readAll(t, s); len(frames) != 1 {
		t.Errorf("tail 1 returned %d frames", len(frames))
	}
	_ = s.Close()
}

func TestLogRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.log")
	l, err := openLogFile(path, 200, 3)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		if err := l.write("stdout", []byte("line "+strings.Repeat("a", 30)+"\n")); err != nil {
			t.Fatal(err)
		}
	}
	_ = l.Close()
	for _, p := range []string{path, path + ".1", path + ".2"} {
		fi, err := os.Stat(p)
		if err != nil || fi.Size() > 200 {
			t.Errorf("%s: %v %v", p, fi, err)
		}
	}
	if _, err := os.Stat(path + ".3"); err == nil {
		t.Error("kept more than 3 files")
	}
	s, _ := ReadLogs(context.Background(), dir, "c", runtime.LogOptions{})
	frames := readAll(t, s)
	_ = s.Close()
	if len(frames) == 0 || len(frames) >= 20 {
		t.Errorf("read %d frames across rotated files", len(frames))
	}
	if err := RemoveLogs(dir, "c"); err != nil {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("left %d files", len(entries))
	}
}

func TestFollowLogs(t *testing.T) {
	old := followInterval
	followInterval = 10 * time.Millisecond
	t.Cleanup(func() { followInterval = old })
	dir := t.TempDir()
	l, err := openLogFile(filepath.Join(dir, "c.log"), 1<<20, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	_ = l.write("stdout", []byte("before\n"))
	s, err := ReadLogs(context.Background(), dir, "c", runtime.LogOptions{Follow: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if f, err := s.Next(); err != nil || string(f.Data) != "before\n" {
		t.Fatalf("first frame %q %v", f.Data, err)
	}
	_ = l.write("stderr", []byte("after\n"))
	got := make(chan runtime.LogFrame, 1)
	go func() {
		if f, err := s.Next(); err == nil {
			got <- f
		}
	}()
	select {
	case f := <-got:
		if string(f.Data) != "after\n" || f.Stream != runtime.Stderr {
			t.Errorf("followed frame %+v", f)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("follow did not deliver new output")
	}
}

func TestLogsRejectBadIDs(t *testing.T) {
	dir := t.TempDir()
	for _, id := range []string{"", "../x", "a/b", ".hidden", strings.Repeat("a", 200)} {
		if err := WriteLogs(dir, id, strings.NewReader(""), strings.NewReader("")); err == nil {
			t.Errorf("wrote logs for %q", id)
		}
		if _, err := ReadLogs(context.Background(), dir, id, runtime.LogOptions{}); err == nil {
			t.Errorf("read logs for %q", id)
		}
	}
	if _, err := ReadLogs(context.Background(), dir, "missing", runtime.LogOptions{}); !errors.Is(err, runtime.ErrNotFound) {
		t.Errorf("missing logs: %v", err)
	}
}
