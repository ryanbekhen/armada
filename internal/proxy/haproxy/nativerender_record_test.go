package haproxy

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"flag"
	"os"
	"testing"

	"github.com/ryanbekhen/armada/internal/proxy"
)

// Recording the render cases for the Rust replay (ADR 0055, item 20). With
// -record-fixtures, TestArmadaNodeRenderMatchesGo renders every
// configuration it compares (the named ones on every node, the unsafe one,
// and the random ones) with the Go renderer alone and writes
// node/tests/testdata/render.jsonl.gz: each line the request
// `armada-node proxy render` reads (certificates by name, as renderNative
// sends it) and Go's files, or that it rendered nothing. node/tests/
// render.rs renders each request with armada-node's renderer and compares,
// so the check keeps running once Go is gone.

var recordFixtures = flag.Bool("record-fixtures", false,
	"write node/tests/testdata/render.jsonl.gz (each render request and Go's files) for the Rust replay")

const renderFixtures = "../../../node/tests/testdata/render.jsonl.gz"

type renderRecorder struct{ lines [][]byte }

func newRenderRecorder() *renderRecorder {
	if !*recordFixtures {
		return nil
	}
	return &renderRecorder{}
}

func (r *renderRecorder) add(t *testing.T, what string, cfg proxy.Config, layout Layout, opts renderOptions, want rendered) {
	t.Helper()
	certs := make([]proxy.Certificate, len(cfg.Certificates))
	for i, c := range cfg.Certificates {
		certs[i] = proxy.Certificate{Name: c.Name}
	}
	cfg.Certificates = certs
	line := map[string]any{
		"name":    what,
		"request": renderRequest{Config: cfg, Layout: layout, Options: opts},
		"unsafe":  want.config == nil,
	}
	if want.config != nil {
		routes := map[string]string{}
		for k, v := range want.routes {
			routes[k] = string(v)
		}
		line["config"], line["routes"], line["local"] = string(want.config), routes, string(want.local)
	}
	b, err := json.Marshal(line)
	if err != nil {
		t.Fatal(err)
	}
	r.lines = append(r.lines, b)
}

func (r *renderRecorder) write(t *testing.T) {
	if r == nil {
		return
	}
	t.Helper()
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	for _, l := range r.lines {
		_, _ = zw.Write(l)
		_, _ = zw.Write([]byte("\n"))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(renderFixtures, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("recorded %d renders into %s (%d bytes)", len(r.lines), renderFixtures, buf.Len())
}
