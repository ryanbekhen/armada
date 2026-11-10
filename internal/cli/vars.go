package cli

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ryanbekhen/armada/internal/spec"
)

// maxVarsFile bounds a --vars file.
const maxVarsFile = 1 << 20

// loadVars reads the variables for spec.Substitute: NAME=VALUE lines from
// file (blank lines and # comments skipped, values taken as written), then
// each NAME=VALUE of list, which wins.
func loadVars(file string, list []string) (map[string]string, error) {
	vars := map[string]string{}
	if file != "" {
		f, err := os.Open(file) //nolint:gosec // user-chosen vars file
		if err != nil {
			return nil, err
		}
		defer f.Close()
		b, err := io.ReadAll(io.LimitReader(f, maxVarsFile+1))
		if err != nil {
			return nil, err
		}
		if len(b) > maxVarsFile {
			return nil, fmt.Errorf("%s is larger than %d bytes", file, maxVarsFile)
		}
		sc := bufio.NewScanner(bytes.NewReader(b))
		sc.Buffer(make([]byte, 0, 64<<10), maxVarsFile)
		seen := map[string]int{}
		for n := 1; sc.Scan(); n++ {
			line := strings.TrimSuffix(sc.Text(), "\r")
			if t := strings.TrimSpace(line); t == "" || t[0] == '#' {
				continue
			}
			name, value, err := splitVar(line)
			if err != nil {
				return nil, fmt.Errorf("%s line %d: %w", file, n, err)
			}
			if first, dup := seen[name]; dup {
				return nil, fmt.Errorf("%s line %d: %s was already set on line %d", file, n, name, first)
			}
			seen[name] = n
			vars[name] = value
		}
		if err := sc.Err(); err != nil {
			return nil, fmt.Errorf("%s: %w", file, err)
		}
	}
	for _, v := range list {
		name, value, err := splitVar(v)
		if err != nil {
			return nil, fmt.Errorf("--var: %w", err)
		}
		vars[name] = value
	}
	return vars, nil
}

func splitVar(s string) (name, value string, err error) {
	name, value, ok := strings.Cut(s, "=")
	if !ok || !spec.VarNameRe.MatchString(name) {
		return "", "", fmt.Errorf("want NAME=VALUE with NAME of letters, digits, and _")
	}
	if strings.ContainsRune(value, 0) {
		return "", "", fmt.Errorf("%s contains a NUL byte", name)
	}
	return name, value, nil
}
