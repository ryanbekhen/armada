package spec

import (
	"strings"
	"testing"
)

func TestVolumes(t *testing.T) {
	t.Parallel()
	ok := "name: db\nimage: postgres\nvolumes:\n  - name: data\n    path: /var/lib/postgresql/data\n    owner: \"999:999\"\n  - name: logs\n    path: /logs\nscale:\n  min: 1\n  max: 1\n"
	a, err := Parse([]byte(ok))
	if err != nil {
		t.Fatal(err)
	}
	if !a.HasVolumes() || len(a.Volumes) != 2 || a.Volumes[0].Owner != "999:999" {
		t.Fatalf("parsed %+v", a.Volumes)
	}

	vol := func(entries string) string { return "name: db\nimage: postgres\nvolumes:\n" + entries }
	for name, c := range map[string]struct{ yaml, field string }{
		"bad name":           {vol("  - name: Data!\n    path: /data\n"), "volumes[0].name"},
		"duplicate name":     {vol("  - name: a\n    path: /a\n  - name: a\n    path: /b\n"), "volumes[1].name"},
		"relative path":      {vol("  - name: a\n    path: data\n"), "volumes[0].path"},
		"root":               {vol("  - name: a\n    path: /\n"), "volumes[0].path"},
		"proc":               {vol("  - name: a\n    path: /proc/x\n"), "volumes[0].path"},
		"dotdot":             {vol("  - name: a\n    path: /data/../etc\n"), "volumes[0].path"},
		"overlap":            {vol("  - name: a\n    path: /data\n  - name: b\n    path: /data/sub\n"), "volumes[1].path"},
		"same path":          {vol("  - name: a\n    path: /data\n  - name: b\n    path: /data\n"), "volumes[1].path"},
		"secret overlap":     {"name: db\nimage: p\nsecretFiles:\n  - path: /data/key\n    secretRef: k\nvolumes:\n  - name: a\n    path: /data\n", "volumes[0].path"},
		"bad owner":          {vol("  - name: a\n    path: /a\n    owner: postgres\n"), "volumes[0].owner"},
		"negative owner":     {vol("  - name: a\n    path: /a\n    owner: \"-1:0\"\n"), "volumes[0].owner"},
		"two replicas":       {vol("  - name: a\n    path: /a\n") + "scale:\n  min: 2\n  max: 2\n", "scale"},
		"scale to zero":      {vol("  - name: a\n    path: /a\n") + "ingress:\n  type: internal\n  port: 80\nscale:\n  min: 0\n  max: 1\n  rules:\n    - type: http\n      concurrent: 10\n", "scale"},
		"autoscaled":         {vol("  - name: a\n    path: /a\n") + "scale:\n  min: 1\n  max: 1\n  rules:\n    - type: cpu\n      utilization: 50\n", "scale"},
		"job":                {"kind: job\nname: x\nimage: y\nvolumes:\n  - name: a\n    path: /a\n", "volumes"},
		"unknown field":      {vol("  - name: a\n    path: /a\n    hostPath: /srv\n"), ""},
		"too many":           {vol(strings.Repeat("  - name: a\n    path: /a\n", MaxVolumes+1)), "volumes"},
		"multiple revisions": {vol("  - name: a\n    path: /a\n") + "ingress:\n  type: internal\n  port: 80\nrevisions:\n  mode: multiple\n  traffic:\n    - revision: latest\n      weight: 100\n", "revisions.mode"},
	} {
		_, err := Parse([]byte(c.yaml))
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if c.field != "" && !strings.Contains(err.Error(), c.field) {
			t.Errorf("%s: %v does not name %s", name, err, c.field)
		}
	}
}

func TestParseOwner(t *testing.T) {
	t.Parallel()
	if u, g, err := ParseOwner("999:1000"); err != nil || u != 999 || g != 1000 {
		t.Errorf("ParseOwner = %d %d %v", u, g, err)
	}
	for _, bad := range []string{"", "999", "a:b", "1:", ":1", "01:1", "+1:1", "1:2:3", "2147483648:0", " 1:1"} {
		if _, _, err := ParseOwner(bad); err == nil {
			t.Errorf("ParseOwner(%q) accepted", bad)
		}
	}
}
