package spec

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// varRe matches ${NAME}, and $${ which stands for a literal ${.
var varRe = regexp.MustCompile(`\$\$\{|\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// VarNameRe is what a spec variable may be called.
var VarNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Substitute replaces ${NAME} with vars[NAME] in the values of a spec
// (ADR 0029); $${ stays a literal ${. Each variable first becomes a plain
// placeholder, so ${NAME} needs no quotes even inside [..] or {..}; the
// values go in after parsing, so a value never changes the document's
// structure, and a plain value that is all one variable takes the
// variable's type (max: ${API_MAX} is a number). A variable the spec uses
// but vars lacks, or one in a key, is an error. Comments are dropped.
func Substitute(data []byte, vars map[string]string) ([]byte, error) {
	if len(data) > MaxSpecBytes {
		return nil, fmt.Errorf("spec is larger than %d bytes", MaxSpecBytes)
	}
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	prefix := "av" + hex.EncodeToString(nonce) + "n"
	var names []string
	marked := varRe.ReplaceAllStringFunc(string(data), func(m string) string {
		name := "$" // the literal ${
		if m != "$${" {
			name = m[2 : len(m)-1]
		}
		names = append(names, name)
		return prefix + strconv.Itoa(len(names)-1) + "e"
	})
	token := regexp.MustCompile(prefix + `([0-9]+)e`)

	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(marked), &doc); err != nil {
		return nil, fmt.Errorf("invalid spec: %w", err)
	}
	if doc.Kind == 0 {
		return nil, errors.New("spec is empty")
	}
	missing := map[string]bool{}
	set := func(n *yaml.Node) {
		if !strings.Contains(n.Value, prefix) {
			return
		}
		n.Value = token.ReplaceAllStringFunc(n.Value, func(m string) string {
			i, _ := strconv.Atoi(token.FindStringSubmatch(m)[1])
			if names[i] == "$" {
				return "${"
			}
			v, ok := vars[names[i]]
			if !ok {
				missing[names[i]] = true
			}
			return v
		})
		if n.Style == 0 {
			// Resolve the type again from the new value.
			n.Tag = ""
		}
	}
	inKey := false
	var walk func(n *yaml.Node)
	walk = func(n *yaml.Node) {
		n.HeadComment, n.LineComment, n.FootComment = "", "", ""
		switch n.Kind {
		case yaml.ScalarNode:
			set(n)
		case yaml.MappingNode:
			for i, c := range n.Content {
				if i%2 == 0 && strings.Contains(c.Value, prefix) {
					inKey = true
				}
				walk(c)
			}
		default:
			for _, c := range n.Content {
				walk(c)
			}
		}
	}
	walk(&doc)
	if inKey {
		return nil, errors.New("variables are only allowed in values, not in keys")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("the spec uses variables that are not set: %s (pass --var NAME=VALUE or --vars FILE)",
			strings.Join(slices.Sorted(maps.Keys(missing)), ", "))
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, err
	}
	if buf.Len() > MaxSpecBytes {
		return nil, fmt.Errorf("spec is larger than %d bytes once its variables are set", MaxSpecBytes)
	}
	return buf.Bytes(), nil
}
