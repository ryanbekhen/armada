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
// each slot's current sessions plus its queue, mapped back to the replica
// in that slot.
func (d *Driver) Load(ctx context.Context) (map[string]int64, error) {
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
func parseLoad(out string, layout Layout) (map[string]int64, error) {
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
	px, sv, scur, qcur := col["pxname"], col["svname"], col["scur"], col["qcur"]
	if _, ok := col["scur"]; !ok {
		return nil, errors.New("show stat: no scur column")
	}
	load := map[string]int64{}
	for {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			continue // one malformed row; the rest still count
		}
		if len(rec) <= max(px, sv, scur, qcur) {
			continue
		}
		app, ok := strings.CutPrefix(rec[px], "be_")
		slot, ok2 := strings.CutPrefix(rec[sv], "s")
		if !ok || !ok2 {
			continue
		}
		i, err := strconv.Atoi(slot)
		slots := layout[app]
		if err != nil || i < 1 || i > len(slots) || slots[i-1] == "" {
			continue
		}
		cur, _ := strconv.ParseInt(rec[scur], 10, 64)
		q, _ := strconv.ParseInt(rec[qcur], 10, 64)
		load[slots[i-1]] = max(0, cur) + max(0, q)
	}
	return load, nil
}
