package agent

import (
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/ryanbekhen/armada/internal/logexport"
	"github.com/ryanbekhen/armada/internal/runtime"
	"github.com/ryanbekhen/armada/internal/runtime/fake"
)

// encodingDriver renders its tail itself, as the embedded runtime does with
// armada-log.
type encodingDriver struct {
	*fake.Driver
	bodies    [][]byte
	enc       runtime.LogEncoding
	committed bool
}

func (d *encodingDriver) TailLogsEncoded(_ context.Context, _ string, _ int64, enc runtime.LogEncoding) (runtime.LogTail, error) {
	d.enc = enc
	return runtime.LogTail{Bodies: d.bodies, Size: 5, Commit: func() error { d.committed = true; return nil }}, nil
}

func TestExportSendsRenderedBodies(t *testing.T) {
	t.Parallel()
	var (
		mu  sync.Mutex
		got []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		zr, err := gzip.NewReader(r.Body)
		if err != nil || r.Header.Get("Content-Encoding") != "gzip" {
			http.Error(w, "not gzip", http.StatusBadRequest)
			return
		}
		b, _ := io.ReadAll(zr)
		mu.Lock()
		got = append(got, string(b))
		mu.Unlock()
	}))
	defer srv.Close()
	client, err := logexport.NewClient(logexport.Config{Format: logexport.OTLP, Endpoint: srv.URL + "/v1/logs"}, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	d := &encodingDriver{Driver: fake.New(), bodies: [][]byte{[]byte(`{"resourceLogs":[1]}`), []byte(`{"resourceLogs":[2]}`)}}
	a := &Agent{cfg: Config{NodeID: "n1"}}
	more, err := a.exportOnce(context.Background(), d, client, "t")
	if err != nil || more {
		t.Fatalf("exportOnce: %v %v", more, err)
	}
	if !d.committed || len(got) != 2 || got[0] != `{"resourceLogs":[1]}` || got[1] != `{"resourceLogs":[2]}` {
		t.Fatalf("committed %v, sent %q", d.committed, got)
	}
	if d.enc.Format != logexport.OTLP || d.enc.Node != "n1" || d.enc.BatchRecords != exportBatchRecords ||
		d.enc.BatchBytes != exportBatchBytes || d.enc.Split == nil {
		t.Errorf("encoding %+v", d.enc)
	}
	if space, name, ok := d.enc.Split("web.shop"); !ok || space != "shop" || name != "web" {
		t.Errorf("split: %q %q %v", space, name, ok)
	}

	// A refused request leaves the output for the next round.
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "full", http.StatusServiceUnavailable)
	})
	d.committed = false
	if _, err := a.exportOnce(context.Background(), d, client, "t"); err == nil || d.committed {
		t.Fatalf("refused push: committed %v, err %v", d.committed, err)
	}
}
