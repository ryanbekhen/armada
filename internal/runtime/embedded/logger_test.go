package embedded

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// armada-log (logger/, Rust) must store exactly what WriteLogs stores. The
// test runs both on the same output and compares every file byte for byte,
// timestamps aside. CI sets ARMADA_LOG_BIN to the binary `make logger`
// built; without it the test is skipped.
func TestArmadaLogMatchesGo(t *testing.T) {
	bin := os.Getenv("ARMADA_LOG_BIN")
	if bin == "" {
		t.Skip("ARMADA_LOG_BIN is not set (make logger, then point it at logger/target/<triple>/release/armada-log)")
	}
	compareLoggers(t, func(t *testing.T, dir, id, stdout, stderr string, lim logLimits) {
		runArmadaLog(t, bin, dir, id, stdout, stderr, lim)
	})
}

// `armadad runtime-log` in Rust (ADR 0055, pull request 18b) must store
// exactly what WriteLogs stores too. ARMADA_DAEMON_BIN is a build of
// daemon/ with its test hooks (`make daemon-parity`), which takes the
// limits from ARMADA_DAEMON_TEST_LOG_LIMITS as writeLogs takes them here.
func TestRuntimeLogMatchesGo(t *testing.T) {
	bin := os.Getenv("ARMADA_DAEMON_BIN")
	if bin == "" {
		t.Skip("ARMADA_DAEMON_BIN is not set (make daemon-parity builds target/debug/armadad with its test hooks)")
	}
	compareLoggers(t, func(t *testing.T, dir, id, stdout, stderr string, lim logLimits) {
		runLogger(t, bin, []string{"runtime-log", dir}, []string{
			"CONTAINER_ID=" + id,
			fmt.Sprintf("ARMADA_DAEMON_TEST_LOG_LIMITS=%d,%d,%s,%s", lim.maxSize, lim.maxFiles,
				strconv.FormatFloat(lim.rate, 'f', 0, 64), strconv.FormatFloat(lim.burst, 'f', 0, 64)),
		}, stdout, stderr)
	})
}

// compareLoggers runs WriteLogs and another logger (run) on the same
// output and compares every file byte for byte, timestamps aside.
func compareLoggers(t *testing.T, run func(t *testing.T, dir, id, stdout, stderr string, lim logLimits)) {
	t.Helper()
	for _, c := range loggerCases() {
		t.Run(c.name, func(t *testing.T) {
			const id = loggerCaseID
			goDir, rustDir := t.TempDir(), t.TempDir()
			if c.meta {
				for _, d := range []string{goDir, rustDir} {
					if err := WriteLogMeta(d, id, LogMeta{App: "web", Replica: "web-r1"}); err != nil {
						t.Fatal(err)
					}
				}
			}
			start := time.Now()
			if err := writeLogs(goDir, id, strings.NewReader(c.stdout), strings.NewReader(c.stderr), c.lim); err != nil {
				t.Fatal(err)
			}
			run(t, rustDir, id, c.stdout, c.stderr, c.lim)
			goFiles, rustFiles := logFiles(t, goDir, start), logFiles(t, rustDir, start)
			if !slices.EqualFunc(goFiles, rustFiles, func(a, b logFileContent) bool { return a.name == b.name && a.body == b.body }) {
				t.Errorf("go:\n%s\nrust:\n%s", describe(goFiles), describe(rustFiles))
			}
		})
	}
}

// loggerCaseID is the container the logger cases write for.
const loggerCaseID = "web-r1-0a1b2c3d"

// loggerCase is one output a logger stores.
type loggerCase struct {
	name           string
	stdout, stderr string
	lim            logLimits
	meta           bool
}

// loggerCases are the outputs compareLoggers runs (and the recording for
// the Rust replay writes, logger_record_test.go).
func loggerCases() []loggerCase {
	long := strings.Repeat("x", 40000) + "\n"
	return []loggerCase{
		{
			name: "encoding and long lines",
			stdout: "plain\n" + `quotes " and \ and <tags> & ampersands` + "\n" +
				"ctrl \x00\x01\x08\x0c\t\r\x1f\x7f end\n" + "utf8 é € 😀     �\n" +
				"bad \xff \xc0\x80 \xe2\x82 \xed\xa0\x80 \xf4\x90\x80\x80 end\n" + long + "no newline at the end",
			lim: logLimits{maxSize: 10 << 20, maxFiles: 3},
		},
		{
			name:   "stderr",
			stderr: "one\ntwo\n",
			lim:    logLimits{maxSize: 10 << 20, maxFiles: 3},
		},
		{
			name:   "rotation without history",
			stdout: numbered(400),
			lim:    logLimits{maxSize: 4000, maxFiles: 3},
		},
		{
			name:   "rotation into history",
			stdout: numbered(400),
			lim:    logLimits{maxSize: 4000, maxFiles: 3},
			meta:   true,
		},
		{
			name:   "one file",
			stdout: numbered(100),
			lim:    logLimits{maxSize: 1000, maxFiles: 1},
			meta:   true,
		},
		{
			name:   "rate limit",
			stdout: numbered(200),
			lim:    logLimits{maxSize: 10 << 20, maxFiles: 3, rate: 1, burst: 500},
		},
	}
}

func numbered(n int) string {
	var b strings.Builder
	for i := range n {
		fmt.Fprintf(&b, "line %04d of the output\n", i)
	}
	return b.String()
}

// runArmadaLog starts bin the way the shim does: output on fds 3 and 4,
// fd 5 closed once ready, the container ID in the environment.
func runArmadaLog(t *testing.T, bin, dir, id, stdout, stderr string, lim logLimits) {
	t.Helper()
	args := []string{"runtime-log", dir,
		"max-size", strconv.FormatInt(lim.maxSize, 10), "max-files", strconv.Itoa(lim.maxFiles),
		"rate", strconv.FormatFloat(lim.rate, 'f', 0, 64), "burst", strconv.FormatFloat(lim.burst, 'f', 0, 64)}
	runLogger(t, bin, args, []string{"CONTAINER_ID=" + id, "CONTAINER_NAMESPACE=armada"}, stdout, stderr)
}

// runLogger runs a logger with args and env as the shim does: output on
// fds 3 and 4, fd 5 closed once ready.
func runLogger(t *testing.T, bin string, args, env []string, stdout, stderr string) {
	t.Helper()
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	readyR, readyW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, args...)
	cmd.Env = env
	cmd.ExtraFiles = []*os.File{outR, errR, readyW}
	var logged bytes.Buffer
	cmd.Stderr = &logged
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	for _, f := range []*os.File{outR, errR, readyW} {
		_ = f.Close()
	}
	if _, err := io.ReadAll(readyR); err != nil {
		t.Fatal(err)
	}
	_ = readyR.Close()
	done := make(chan error, 2)
	feed := func(w *os.File, s string) {
		_, err := io.WriteString(w, s)
		done <- errorsJoin(err, w.Close())
	}
	go feed(outW, stdout)
	go feed(errW, stderr)
	for range 2 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("armada-log: %v: %s", err, logged.String())
	}
}

func errorsJoin(a, b error) error {
	if a != nil {
		return a
	}
	return b
}

type logFileContent struct{ name, body string }

var timeField = regexp.MustCompile(`"time":"([^"]*)"`)

// logFiles reads every file under dir in a stable order: history files by
// their sequence (renamed to their position, since the sequence is a
// time), then the live files. Times must be valid and recent, and are then
// blanked.
func logFiles(t *testing.T, dir string, start time.Time) []logFileContent {
	t.Helper()
	var out []logFileContent
	hist, _ := filepath.Glob(filepath.Join(dir, historyDirName, "*.log"))
	slices.SortFunc(hist, func(a, b string) int {
		_, sa, _ := parseHistoryName(filepath.Base(a))
		_, sb, _ := parseHistoryName(filepath.Base(b))
		return int(sa - sb)
	})
	live, _ := filepath.Glob(filepath.Join(dir, "*.log*"))
	slices.Sort(live)
	for i, p := range slices.Concat(hist, live) {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range timeField.FindAllSubmatch(b, -1) {
			var ts time.Time
			if err := json.Unmarshal([]byte(`"`+string(m[1])+`"`), &ts); err != nil || ts.Before(start.Add(-time.Second)) || ts.After(time.Now().Add(time.Second)) || ts.Location() != time.UTC {
				t.Errorf("%s: time %q: %v", p, m[1], err)
			}
		}
		name := filepath.Base(p)
		if strings.HasPrefix(p, filepath.Join(dir, historyDirName)) {
			name = "history/" + strconv.Itoa(i)
		}
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: mode %v", p, fi.Mode().Perm())
		}
		out = append(out, logFileContent{name: name, body: timeField.ReplaceAllString(string(b), `"time":""`)})
	}
	if len(out) == 0 {
		t.Fatalf("%s: no log files", dir)
	}
	return out
}

func describe(fs []logFileContent) string {
	var b strings.Builder
	for _, f := range fs {
		body := f.body
		if len(body) > 600 {
			body = body[:300] + " … " + body[len(body)-300:]
		}
		fmt.Fprintf(&b, "== %s (%d bytes)\n%s\n", f.name, len(f.body), body)
	}
	return b.String()
}
