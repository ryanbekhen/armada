package cli

import "testing"

func TestParseLabel(t *testing.T) {
	t.Parallel()
	if k, v, err := parseLabel("region=sulawesi"); err != nil || k != "region" || v != "sulawesi" {
		t.Errorf("parseLabel = %q, %q, %v", k, v, err)
	}
	for _, s := range []string{"region", "region=", "=x", "Region=x", "armada.arch=arm64", "k=a b", "k=v=w"} {
		if _, _, err := parseLabel(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
	if got := formatLabels(map[string]string{"b": "2", "a": "1", "armada.arch": "arm64"}); got != "a=1,armada.arch=arm64,b=2" {
		t.Errorf("formatLabels = %q", got)
	}
}
