package spec

import (
	"strings"
	"testing"
)

func TestAppID(t *testing.T) {
	for _, c := range []struct{ space, name, id string }{
		{"", "web", "web"},
		{DefaultSpace, "web", "web"},
		{"staging", "web", "web.staging"},
	} {
		if got := AppID(c.space, c.name); got != c.id {
			t.Errorf("AppID(%q, %q) = %q, want %q", c.space, c.name, got, c.id)
		}
		wantSpace := c.space
		if wantSpace == "" {
			wantSpace = DefaultSpace
		}
		p, n, ok := SplitAppID(c.id)
		if !ok || p != wantSpace || n != c.name {
			t.Errorf("SplitAppID(%q) = %q, %q, %v", c.id, p, n, ok)
		}
	}
}

func TestSplitAppIDInvalid(t *testing.T) {
	for _, id := range []string{
		"", ".", "web.", ".staging", "web.default", "web.a.b", "Web", "web--x",
		"web.Staging", "web.st--g", "web." + strings.Repeat("a", 31),
		strings.Repeat("a", 64), "web/x", "web.x/y", "../web", "web.-x",
	} {
		if _, _, ok := SplitAppID(id); ok {
			t.Errorf("SplitAppID(%q) accepted", id)
		}
		if ValidAppID(id) {
			t.Errorf("ValidAppID(%q) = true", id)
		}
	}
}

func TestValidateSpace(t *testing.T) {
	a := &App{Kind: KindApp, Name: "web", Image: "nginx:1"}
	for _, p := range []string{"", DefaultSpace, "staging", strings.Repeat("a", 30)} {
		a.Space = p
		if err := a.Validate(); err != nil {
			t.Errorf("space %q: %v", p, err)
		}
	}
	for _, p := range []string{"Staging", "a--b", "-a", strings.Repeat("a", 31), "a.b"} {
		a.Space = p
		if err := a.Validate(); err == nil || !strings.Contains(err.Error(), "space") {
			t.Errorf("space %q: %v", p, err)
		}
	}
}

func TestParseRejectsSpace(t *testing.T) {
	if _, err := Parse([]byte("name: web\nimage: nginx:1\nspace: staging\n")); err == nil {
		t.Fatal("a space in the file was accepted")
	}
}

func TestInternalSearchDomain(t *testing.T) {
	t.Parallel()
	for id, want := range map[string]string{"web": "internal", "web.shop": "shop.internal", "web.default": "", "Web": "", "": ""} {
		if got := InternalSearchDomain(id); got != want {
			t.Errorf("%q: %q, want %q", id, got, want)
		}
		if want != "" && !ValidSearchDomain(want) {
			t.Errorf("%q not valid", want)
		}
	}
}
