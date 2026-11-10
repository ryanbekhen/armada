package spec

import (
	"strings"
	"testing"
)

func TestSubstitute(t *testing.T) {
	in := `name: api
image: "ghcr.io/acme/api:${TAG}"
env:
  - { name: GREETING, value: "hi $${HOME} ${TAG}" }
  - { name: FLAG, value: "${ON}" }
ingress:
  type: external
  port: 3000
  domains: [${DOMAIN}, www.${DOMAIN}]
scale:
  min: 1
  max: ${MAX}
  rules:
    - { type: cpu, utilization: 80 }
`
	out, err := Substitute([]byte(in), map[string]string{"TAG": "sha-1", "DOMAIN": "example.com", "MAX": "4", "ON": "true", "UNUSED": "x"})
	if err != nil {
		t.Fatal(err)
	}
	a, err := Parse(out)
	if err != nil {
		t.Fatalf("parse %s: %v", out, err)
	}
	if a.Image != "ghcr.io/acme/api:sha-1" || *a.Scale.Max != 4 || a.Ingress.Domains[1] != "www.example.com" {
		t.Errorf("app = %+v", a)
	}
	if a.Env[0].Value != "hi ${HOME} sha-1" || a.Env[1].Value != "true" {
		t.Errorf("env = %+v", a.Env)
	}
}

func TestSubstituteMissing(t *testing.T) {
	_, err := Substitute([]byte("name: a\nimage: x:${B}\nenv:\n  - { name: A, value: \"${A}\" }\n"), map[string]string{})
	if err == nil || !strings.Contains(err.Error(), "not set: A, B") {
		t.Errorf("err = %v", err)
	}
}

// A value can never add fields or change the document's structure.
func TestSubstituteKeepsStructure(t *testing.T) {
	evil := "x\nkind: job\nprivileged: true"
	out, err := Substitute([]byte("name: a\nimage: nginx:1\nenv:\n  - { name: A, value: ${V} }\n"), map[string]string{"V": evil})
	if err != nil {
		t.Fatal(err)
	}
	a, err := Parse(out)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if a.IsJob() || a.Env[0].Value != evil {
		t.Errorf("structure changed: %+v", a)
	}
	// Keys are never substituted.
	if _, err := Substitute([]byte("name: a\n${K}: 1\n"), map[string]string{"K": "image"}); err == nil {
		t.Error("variable in a key accepted")
	}
}
