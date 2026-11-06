package haproxy

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/ryanbekhen/armada/internal/proxy"
)

// serverLine is a replica slot in the configuration. Its address and weight
// change through the Runtime API, so they say nothing about the structure.
var serverLine = regexp.MustCompile(`(?m)^    server (s[0-9]+) .*$`)

// sameStructure reports whether two configurations differ only in what the
// Runtime API can change.
func sameStructure(a, b []byte) bool {
	return bytes.Equal(serverLine.ReplaceAll(a, []byte("    server $1")), serverLine.ReplaceAll(b, []byte("    server $1")))
}

// liveConfig prepares a new agent to take over a running proxy. It returns the
// configuration that proxy runs, with d.layout and d.applied set from its server
// slots, or false when this is not a new agent, the proxy cannot say, or its
// certificates differ, which a reload has to load.
func (d *Driver) liveConfig(ctx context.Context, cfg proxy.Config, opts renderOptions) ([]byte, bool) {
	if d.sig != "" {
		return nil, false
	}
	if running, err := d.cfg.Engine.Running(ctx); err != nil || !running {
		return nil, false
	}
	live, err := os.ReadFile(filepath.Join(etcDir(d.cfg.Dir), configFile)) //nolint:gosec // path under our own directory
	if err != nil {
		return nil, false
	}
	entries, err := os.ReadDir(filepath.Join(etcDir(d.cfg.Dir), certDir))
	if err != nil {
		return nil, false
	}
	var have, want []string
	for _, e := range entries {
		have = append(have, e.Name())
	}
	for _, c := range cfg.Certificates {
		want = append(want, c.FileName())
	}
	slices.Sort(have)
	slices.Sort(want)
	if !slices.Equal(have, want) {
		return nil, false
	}
	out, err := d.cfg.API.Command(ctx, "show servers state")
	if err != nil {
		d.log.Debug("read the running proxy's servers", "err", err)
		return nil, false
	}
	slots := parseServersState(out)
	if len(slots) == 0 {
		return nil, false
	}
	d.layout, d.applied = layoutFromSlots(slots, cfg, opts.node())
	return live, true
}

// parseServersState returns the slots of `show servers state` by backend, in
// slot order. A slot in maintenance serves nothing, whatever address it keeps.
func parseServersState(out string) map[string][]slot {
	col := map[string]int{}
	slots := map[string][]slot{}
	for line := range strings.Lines(out) {
		f := strings.Fields(line)
		if len(f) > 1 && f[0] == "#" {
			for i, name := range f[1:] {
				col[name] = i
			}
			continue
		}
		need := []string{"be_name", "srv_name", "srv_addr", "srv_admin_state", "srv_uweight", "srv_port"}
		ok := true
		for _, c := range need {
			if i, found := col[c]; !found || i >= len(f) {
				ok = false
			}
		}
		if !ok {
			continue
		}
		n, err := strconv.Atoi(strings.TrimPrefix(f[col["srv_name"]], "s"))
		if err != nil || n < 1 || n > maxLiveSlots {
			continue // not a replica slot
		}
		admin, err1 := strconv.Atoi(f[col["srv_admin_state"]])
		weight, err2 := strconv.Atoi(f[col["srv_uweight"]])
		if err1 != nil || err2 != nil {
			continue
		}
		be := f[col["be_name"]]
		for len(slots[be]) < n {
			slots[be] = append(slots[be], slot{})
		}
		s := slot{Weight: weight}
		if admin&adminMaintenance == 0 {
			s.Addr = f[col["srv_addr"]] + ":" + f[col["srv_port"]]
		}
		slots[be][n-1] = s
	}
	return slots
}

const (
	// maxLiveSlots bounds what a reply can make this allocate.
	maxLiveSlots = 1 << 16
	// adminMaintenance is HAProxy's flag for a server forced into maintenance.
	adminMaintenance = 1
)

// layoutFromSlots names each live slot after the replica at its address, so a
// replica keeps the slot it has. A slot serving an address no replica has stays
// in applied as it is, and the first update takes it out of service.
func layoutFromSlots(live map[string][]slot, cfg proxy.Config, n node) (Layout, map[string]slot) {
	layout, applied := Layout{}, map[string]slot{}
	for _, p := range pools(cfg, n) {
		byAddr := map[string]string{}
		for _, s := range p.servers {
			byAddr[s.Address] = s.Name
		}
		names := make([]string, len(live[p.name]))
		for i, s := range live[p.name] {
			if s.Addr != "" {
				names[i] = byAddr[s.Addr]
			}
			applied[p.name+"/"+slotName(i)] = s
		}
		layout[p.name] = names
	}
	return layout, applied
}
