package haproxy

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/ryanbekhen/armada/internal/proxy"
)

var _ proxy.LoadReader = (*Driver)(nil)

// Load implements proxy.LoadReader from the Runtime API's "show stat":
// each slot's current sessions plus its queue, and its total sessions,
// mapped back to the replica in that slot.
func (d *Driver) Load(ctx context.Context) (map[string]proxy.ServerLoad, error) {
	// Servers only: any proxy, type 4.
	out, err := d.cfg.API.Command(ctx, "show stat -1 4 -1")
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	layout := d.layout
	d.mu.Unlock()
	return parseLoad(out, layout)
}

// parseLoad reads "show stat" CSV. Only server rows of Armada's backends
// count; anything else (frontends, the stats backend, unknown slots) is
// skipped.
func parseLoad(out string, layout Layout) (map[string]proxy.ServerLoad, error) {
	r := csv.NewReader(strings.NewReader(strings.TrimPrefix(out, "# ")))
	r.FieldsPerRecord, r.LazyQuotes = -1, true
	header, err := r.Read()
	if err != nil {
		return nil, fmt.Errorf("show stat: %w", err)
	}
	col := map[string]int{}
	for i, h := range header {
		col[h] = i
	}
	px, sv, scur, qcur, stot := col["pxname"], col["svname"], col["scur"], col["qcur"], col["stot"]
	for _, c := range []string{"pxname", "svname", "scur", "qcur", "stot"} {
		if _, ok := col[c]; !ok {
			return nil, fmt.Errorf("show stat: no %s column", c)
		}
	}
	load := map[string]proxy.ServerLoad{}
	for {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			continue // one malformed row; the rest still count
		}
		if len(rec) <= max(px, sv, scur, qcur, stot) {
			continue
		}
		// be_<app> and lo_<app> (ADR 0026) serve the same replicas; a
		// replica's load is the sum of both.
		if !strings.HasPrefix(rec[px], "be_") && !strings.HasPrefix(rec[px], "lo_") {
			continue
		}
		slot, ok := strings.CutPrefix(rec[sv], "s")
		if !ok {
			continue
		}
		i, err := strconv.Atoi(slot)
		slots := layout[rec[px]]
		if err != nil || i < 1 || i > len(slots) || slots[i-1] == "" {
			continue
		}
		cur, _ := strconv.ParseInt(rec[scur], 10, 64)
		q, _ := strconv.ParseInt(rec[qcur], 10, 64)
		total, _ := strconv.ParseInt(rec[stot], 10, 64)
		l := load[slots[i-1]]
		l.InFlight += max(0, cur) + max(0, q)
		l.Total += max(0, total)
		load[slots[i-1]] = l
	}
	return load, nil
}
