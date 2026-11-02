package spec

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParsePlacement(t *testing.T) {
	t.Parallel()
	a, err := Parse([]byte("name: web\nimage: nginx:1\nplacement:\n  require:\n    region: sulawesi\n    kind: [raspi, small]\n"))
	if err != nil {
		t.Fatal(err)
	}
	p := a.Placement
	if got := p.String(); got != "kind=raspi|small, region=sulawesi" {
		t.Errorf("String() = %q", got)
	}
	// The spec is stored as JSON in revisions.
	b, _ := json.Marshal(a)
	var back App
	if err := json.Unmarshal(b, &back); err != nil || back.Placement.String() != p.String() {
		t.Errorf("JSON round trip: %v, %q", err, back.Placement.String())
	}

	node := map[string]string{"region": "sulawesi", "kind": "small", LabelArch: "arm64"}
	if !p.Matches(node) {
		t.Error("matching node rejected")
	}
	for name, labels := range map[string]map[string]string{
		"wrong value":   {"region": "papua", "kind": "raspi"},
		"missing key":   {"region": "sulawesi"},
		"no labels":     nil,
		"value in list": {"region": "sulawesi", "kind": "raspi|small"},
	} {
		if p.Matches(labels) {
			t.Errorf("%s: matched", name)
		}
	}
	var none *Placement
	if !none.Matches(nil) || none.Selects(map[string]string{"region": "x"}) {
		t.Error("nil placement must match every node and select none")
	}
	if !p.Selects(map[string]string{"kind": "other"}) {
		t.Error("a placement naming a node's label key selects it")
	}
	spread := &Placement{Require: map[string]LabelValues{"kind": {"small"}}, SpreadBy: "region"}
	if got := spread.String(); got != "kind=small, region=*" {
		t.Errorf("String() with spreadBy = %q", got)
	}
	if !spread.Matches(map[string]string{"kind": "small", "region": "java"}) || spread.Matches(map[string]string{"kind": "small"}) {
		t.Error("spreadBy must match only nodes that have its label")
	}
	if spread.Selects(map[string]string{"region": "java"}) {
		t.Error("spreadBy must not select restricted nodes")
	}
	onlySpread, err := Parse([]byte("name: web\nimage: nginx:1\nplacement:\n  spreadBy: example.org/rack\n"))
	if err != nil || onlySpread.Placement.String() != "example.org/rack=*" {
		t.Errorf("spreadBy alone: %v, %q", err, onlySpread.Placement.String())
	}
	if (&Placement{Require: map[string]LabelValues{"region": {"java", "papua"}}, SpreadBy: "region"}).String() != "region=java|papua" {
		t.Error("a spreadBy key named in require shows its values")
	}
	arch := &Placement{Require: map[string]LabelValues{LabelArch: {"arm64"}}}
	if arch.Selects(map[string]string{LabelArch: "arm64"}) {
		t.Error("armada.* labels must not select restricted nodes")
	}
}

func TestPlacementRejects(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct{ yaml, want string }{
		"empty":          {"placement: {}", "must set require or spreadBy"},
		"bad spreadBy":   {"placement:\n  spreadBy: Region", "label key"},
		"spreadBy list":  {"placement:\n  spreadBy: [region]", ""},
		"empty list":     {"placement:\n  require:\n    region: []", "between 1 and"},
		"upper key":      {"placement:\n  require:\n    Region: x", "label key"},
		"upper value":    {"placement:\n  require:\n    region: Sulawesi", "label value"},
		"space":          {"placement:\n  require:\n    region: \"a b\"", "label value"},
		"newline":        {"placement:\n  require:\n    region: \"a\\nb\"", "label value"},
		"slash in value": {"placement:\n  require:\n    region: a/b", "label value"},
		"long value":     {"placement:\n  require:\n    region: " + strings.Repeat("a", 64), "longer than 63"},
		"unknown field":  {"placement:\n  prefer: city", "prefer"},
		"nested value":   {"placement:\n  require:\n    region: {a: b}", ""},
	} {
		_, err := Parse([]byte("name: web\nimage: nginx:1\n" + tc.yaml + "\n"))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.want)
		}
	}
}

func TestCheckAdminLabel(t *testing.T) {
	t.Parallel()
	for _, kv := range [][2]string{{"region", "sulawesi"}, {"example.org/rack", "r-12"}, {"kind", "raspi_4"}, {"a", "1"}} {
		if err := CheckAdminLabel(kv[0], kv[1]); err != nil {
			t.Errorf("%s=%s: %v", kv[0], kv[1], err)
		}
	}
	for _, kv := range [][2]string{
		{"armada.arch", "arm64"}, // reserved
		{"armada.custom", "x"},   // reserved prefix
		{"", "x"}, {"k", ""},
		{"-k", "x"}, {"k-", "x"}, {"k", "-v"},
		{"a//b", "x"}, {"k", "v=w"}, {"k=v", "x"},
		{"k", "a\nb"}, {"k\x00", "x"}, {"ключ", "x"},
		{strings.Repeat("k", 64), "x"},
	} {
		if err := CheckAdminLabel(kv[0], kv[1]); err == nil {
			t.Errorf("%q=%q accepted", kv[0], kv[1])
		}
	}
}
