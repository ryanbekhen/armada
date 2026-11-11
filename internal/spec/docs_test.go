package spec

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var (
	yamlBlock = regexp.MustCompile("(?s)```yaml\n(.*?)```")
	topName   = regexp.MustCompile(`(?m)^name: `)
	topImage  = regexp.MustCompile(`(?m)^image: `)
	varRef    = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)
)

// TestDocumentedSpecsParse parses every complete app or job spec in the
// documents (a YAML block with a top-level name and image), so examples
// never drift from what Armada accepts. Variables are filled in with a
// placeholder; a block that must not parse says so in a comment
// ("# invalid:").
func TestDocumentedSpecsParse(t *testing.T) {
	t.Parallel()
	var files []string
	for _, pattern := range []string{"../../README.md", "../../docs/*.md", "../../docs/guides/*.md"} {
		m, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, m...)
	}
	checked := 0
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range yamlBlock.FindAllStringSubmatch(string(b), -1) {
			block := m[1]
			if !topName.MatchString(block) || !topImage.MatchString(block) || strings.Contains(block, "# invalid:") {
				continue
			}
			vars := map[string]string{}
			for _, v := range varRef.FindAllStringSubmatch(block, -1) {
				vars[v[1]] = "1"
				switch {
				case strings.Contains(v[1], "DOMAIN") || strings.Contains(v[1], "HOST"):
					vars[v[1]] = "app.example.com"
				case strings.Contains(v[1], "MAX"):
					vars[v[1]] = "10"
				}
			}
			data := []byte(block)
			if len(vars) > 0 {
				if data, err = Substitute(data, vars); err != nil {
					t.Errorf("%s: substitute: %v\n%s", f, err, block)
					continue
				}
			}
			if _, err := Parse(data); err != nil {
				t.Errorf("%s: a documented spec does not parse: %v\n%s", f, err, block)
			}
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("no documented specs found")
	}
}
