package spec

import (
	"bytes"
	"slices"

	"go.yaml.in/yaml/v3"
)

// Export writes the spec the way a file holds it (ADR 0032): what envFrom
// added when it was deployed is left out, so importing it again resolves
// the app's secrets anew, and the space, which a file never names, too.
func (a *App) Export() ([]byte, error) {
	c := *a
	c.Space = ""
	if len(c.EnvFromAdded) > 0 {
		c.Env = slices.DeleteFunc(slices.Clone(c.Env), func(e EnvVar) bool { return slices.Contains(c.EnvFromAdded, e.Name) })
		c.EnvFromAdded = nil
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&c); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
