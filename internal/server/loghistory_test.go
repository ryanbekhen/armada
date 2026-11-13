package server

import (
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/runtime"
)

// searchLogs runs a log search and returns its lines as "replica|data".
func (c *cluster) searchLogs(req *armadav1.LogsRequest) ([]string, error) {
	stream, err := c.admin.Logs(c.ctx, req)
	if err != nil {
		return nil, err
	}
	var got []string
	for {
		e, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return got, nil
		}
		if err != nil {
			return got, err
		}
		got = append(got, e.Replica+"|"+strings.TrimSuffix(string(e.Data), "\n"))
	}
}

func TestLogHistorySearch(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	d1 := c.addNode("n1", "127.0.0.1")
	d2 := c.addNode("n2", "127.0.0.2")
	c.deploy(webSpec("nginx:1", 2))
	c.eventually("2 running", func() bool { return len(c.running("web")) == 2 })

	base := time.Now().Add(-time.Hour)
	rec := func(sec int, replica, text string) runtime.LogRecord {
		return runtime.LogRecord{Time: base.Add(time.Duration(sec) * time.Second), Stream: runtime.Stdout, Data: []byte(text + "\n"), Replica: replica}
	}
	// web-gone ran on n2 before it was replaced; only history knows it.
	d1.SetLogHistory("web", []runtime.LogRecord{rec(1, "web-a", "a start"), rec(3, "web-a", "a ERROR db"), rec(5, "web-a", "a done")})
	d2.SetLogHistory("web", []runtime.LogRecord{rec(2, "web-gone", "gone ERROR panic"), rec(4, "web-b", "b ok")})
	d2.SetLogHistory("api", []runtime.LogRecord{rec(1, "api-x", "api")})

	got, err := c.searchLogs(&armadav1.LogsRequest{App: "web", Since: timestamppb.New(base)})
	if err != nil {
		t.Fatal(err)
	}
	want := "web-a|a start,web-gone|gone ERROR panic,web-a|a ERROR db,web-b|b ok,web-a|a done"
	if strings.Join(got, ",") != want {
		t.Errorf("merged by time:\n got %v\nwant %s", got, want)
	}
	got, _ = c.searchLogs(&armadav1.LogsRequest{App: "web", Since: timestamppb.New(base), Grep: "error", Limit: 1})
	if strings.Join(got, ",") != "web-a|a ERROR db" {
		t.Errorf("grep with limit 1 keeps the newest: %v", got)
	}
	// A replica that no longer exists can be searched.
	got, _ = c.searchLogs(&armadav1.LogsRequest{App: "web", Replica: "web-gone", Since: timestamppb.New(base)})
	if strings.Join(got, ",") != "web-gone|gone ERROR panic" {
		t.Errorf("gone replica: %v", got)
	}
	// Every node was asked with the window, the text, and the limit.
	qs := d2.LogSearches()
	q := qs[len(qs)-1]
	if q.App != "web" || q.Replica != "web-gone" || q.Since.Sub(base).Abs() > time.Millisecond || q.Limit != defaultSearchLimit {
		t.Errorf("query %+v", q)
	}

	for name, req := range map[string]*armadav1.LogsRequest{
		"until before since": {App: "web", Since: timestamppb.New(base), Until: timestamppb.New(base.Add(-time.Second))},
		"grep alone":         {App: "web", Grep: "x"},
	} {
		if _, err := c.searchLogs(req); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestLogSettings(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	d := c.addNode("n1", "127.0.0.1")
	c.eventually("pruned with defaults", func() bool {
		return len(d.LogPruneCalls()) > 0
	})
	cc, err := c.admin.SetClusterConfig(c.ctx, &armadav1.SetClusterConfigRequest{
		Config:          &armadav1.ClusterConfig{LogRetentionSeconds: 3 * 86400, LogMaxBytes: 1 << 30},
		SetLogRetention: true, SetLogMaxBytes: true,
	})
	if err != nil || cc.LogRetentionSeconds != 3*86400 || cc.LogMaxBytes != 1<<30 {
		t.Fatalf("set: %v %v", cc, err)
	}
	c.eventually("agent prunes with the cluster's settings", func() bool {
		p := d.LogPruneCalls()
		return len(p) > 0 && p[len(p)-1] == [2]int64{int64(3 * 24 * time.Hour), 1 << 30}
	})
	for _, cfg := range []*armadav1.ClusterConfig{{LogRetentionSeconds: 60}, {LogMaxBytes: 1 << 10}} {
		_, err := c.admin.SetClusterConfig(c.ctx, &armadav1.SetClusterConfigRequest{Config: cfg, SetLogRetention: cfg.LogRetentionSeconds != 0, SetLogMaxBytes: cfg.LogMaxBytes != 0})
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("%v: %v", cfg, err)
		}
	}
}
