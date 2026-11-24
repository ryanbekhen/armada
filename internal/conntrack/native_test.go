package conntrack

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ryanbekhen/armada/internal/nodeprog"
)

// nodeBin is armada-node for the parity tests (ARMADA_NODE_BIN).
func nodeBin(t *testing.T) string {
	t.Helper()
	bin := os.Getenv("ARMADA_NODE_BIN")
	if bin == "" {
		t.Skip("ARMADA_NODE_BIN is not set (make node)")
	}
	return bin
}

// fixture makes a table directory with files: name → content; a value
// "DIR" makes a directory of that name.
func fixture(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, v := range files {
		p := filepath.Join(dir, name)
		if v == "DIR" {
			if err := os.Mkdir(p, 0o700); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.WriteFile(p, []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

var conntrackCases = []struct {
	name   string
	memory int64
	files  map[string]string
}{
	{"below", 4 * gib, map[string]string{fileCount: "12\n", fileMax: "65536\n"}},
	{"small machine", 512 << 20, map[string]string{fileCount: "1", fileMax: "16384"}},
	{"at the target", 4 * gib, map[string]string{fileCount: "1", fileMax: "262144\n"}},
	{"higher", 4 * gib, map[string]string{fileCount: "1", fileMax: "2000000"}},
	{"memory unknown", 0, map[string]string{fileCount: "1", fileMax: "65536"}},
	{"no module", 4 * gib, map[string]string{}},
	{"no count", 4 * gib, map[string]string{fileMax: "65536"}},
	{"zero limit", 4 * gib, map[string]string{fileCount: "3", fileMax: "0"}},
	{"negative limit", 4 * gib, map[string]string{fileCount: "3", fileMax: "-5"}},
	{"garbage limit", 4 * gib, map[string]string{fileCount: "3", fileMax: "lots\n"}},
	{"garbage count", 4 * gib, map[string]string{fileCount: "x", fileMax: "65536"}},
	{"signed", 4 * gib, map[string]string{fileCount: "+3", fileMax: "+65536"}},
	{"spaces", 4 * gib, map[string]string{fileCount: " \t3 \n", fileMax: "\v65536\r\n"}},
	{"out of range", 4 * gib, map[string]string{fileCount: "1", fileMax: "9223372036854775808"}},
	{"invalid UTF-8", 4 * gib, map[string]string{fileCount: "1", fileMax: "\xff12"}},
	{"a directory", 4 * gib, map[string]string{fileCount: "1", fileMax: "DIR"}},
	{"negative memory", -1, map[string]string{fileCount: "1", fileMax: "5"}},
}

// armada-node conntrack read|raise answer what Read and Raise answer,
// error texts included, and leave the same files.
func TestArmadaNodeConntrackMatchesGo(t *testing.T) {
	prog := nodeprog.New(nodeBin(t))
	for _, c := range conntrackCases {
		t.Run(c.name, func(t *testing.T) {
			goDir, rustDir := fixture(t, c.files), fixture(t, c.files)
			goT, rustT := At(goDir, c.memory), At(rustDir, c.memory).WithProgram(prog)

			ge, gl, gok := goT.Read()
			re, rl, rok := rustT.Read()
			if ge != re || gl != rl || gok != rok {
				t.Errorf("Read: Go %d %d %v, armada-node %d %d %v", ge, gl, gok, re, rl, rok)
			}
			gp, gerr := goT.Raise()
			rp, rerr := rustT.Raise()
			gtext := strings.ReplaceAll(errText(gerr), goDir, "DIR")
			rtext := strings.ReplaceAll(errText(rerr), rustDir, "DIR")
			if gp != rp || gtext != rtext {
				t.Errorf("Raise: Go %d %q, armada-node %d %q", gp, gtext, rp, rtext)
			}
			for name := range map[string]bool{fileCount: true, fileMax: true} {
				gb, _ := os.ReadFile(filepath.Join(goDir, name))
				rb, _ := os.ReadFile(filepath.Join(rustDir, name))
				if string(gb) != string(rb) {
					t.Errorf("%s: Go left %q, armada-node %q", name, gb, rb)
				}
			}
		})
	}
	if n := prog.StoodIn("conntrack raise") + prog.StoodIn("conntrack read"); n != 0 {
		t.Errorf("Go stood in %d times", n)
	}
}

// A limit file armada-node cannot write fails as Go's write fails.
func TestArmadaNodeConntrackUnwritable(t *testing.T) {
	prog := nodeprog.New(nodeBin(t))
	if os.Geteuid() == 0 {
		t.Skip("root writes read-only files")
	}
	files := map[string]string{fileCount: "1", fileMax: "65536"}
	goDir, rustDir := fixture(t, files), fixture(t, files)
	for _, d := range []string{goDir, rustDir} {
		if err := os.Chmod(filepath.Join(d, fileMax), 0o400); err != nil {
			t.Fatal(err)
		}
	}
	_, gerr := At(goDir, 4*gib).Raise()
	_, rerr := At(rustDir, 4*gib).WithProgram(prog).Raise()
	gtext := strings.ReplaceAll(errText(gerr), goDir, "DIR")
	rtext := strings.ReplaceAll(errText(rerr), rustDir, "DIR")
	if gtext == "" || gtext != rtext {
		t.Errorf("Go %q, armada-node %q", gtext, rtext)
	}
}

// A program that fails leaves the call to Go, which counts it.
func TestConntrackProgramFallsBack(t *testing.T) {
	t.Parallel()
	bin := filepath.Join(t.TempDir(), "armada-node")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\necho broken >&2\nexit 3\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	prog := nodeprog.New(bin)
	dir := fixture(t, map[string]string{fileCount: "2", fileMax: "65536"})
	tb := At(dir, 4*gib).WithProgram(prog)
	if e, l, ok := tb.Read(); e != 2 || l != 65536 || !ok {
		t.Errorf("Read: %d %d %v", e, l, ok)
	}
	if p, err := tb.Raise(); p != 65536 || err != nil {
		t.Errorf("Raise: %d %v", p, err)
	}
	if prog.StoodIn("conntrack read") != 1 || prog.StoodIn("conntrack raise") != 1 {
		t.Errorf("stood in: read %d, raise %d", prog.StoodIn("conntrack read"), prog.StoodIn("conntrack raise"))
	}
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
