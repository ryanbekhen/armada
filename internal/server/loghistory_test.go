package server

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/agent"
	"github.com/ryanbekhen/armada/internal/runtime"
	"github.com/ryanbekhen/armada/internal/runtime/embedded"
	"github.com/ryanbekhen/armada/internal/runtime/fake"
	"github.com/ryanbekhen/armada/internal/secrets"
	"github.com/ryanbekhen/armada/internal/store"
)

// replicasOnTwoNodes waits for app's two replicas to run, one on n1 and
// one on n2, and returns their IDs.
func (c *cluster) replicasOnTwoNodes(app string) (onN1, onN2 string) {
	c.t.Helper()
	c.eventually("one replica on each node", func() bool {
		onN1, onN2 = "", ""
		for _, r := range c.running(app) {
			switch r.NodeId {
			case "n1":
				onN1 = r.Id
			case "n2":
				onN2 = r.Id
			}
		}
		return onN1 != "" && onN2 != ""
	})
	return onN1, onN2
}

// goneReplica records a replica of app on node and removes it again, as
// one that ran there before it was replaced, and returns its ID.
func (c *cluster) goneReplica(app, node string) string {
	c.t.Helper()
	a, err := c.store.GetApp(c.ctx, app)
	if err != nil {
		c.t.Fatal(err)
	}
	id := app + "-r99-gone0"
	if err := c.store.CreateReplica(c.ctx, store.Replica{ID: id, App: app, Revision: a.ActiveRevision, NodeID: node}); err != nil {
		c.t.Fatal(err)
	}
	if err := c.store.DeleteReplica(c.ctx, id); err != nil {
		c.t.Fatal(err)
	}
	return id
}

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
	ra, rb := c.replicasOnTwoNodes("web")
	gone := c.goneReplica("web", "n2")

	base := time.Now().Add(-time.Hour)
	rec := func(sec int, replica, text string) runtime.LogRecord {
		return runtime.LogRecord{Time: base.Add(time.Duration(sec) * time.Second), Stream: runtime.Stdout, Data: []byte(text + "\n"), Replica: replica}
	}
	// gone ran on n2 before it was replaced; only history knows it.
	d1.SetLogHistory("web", []runtime.LogRecord{rec(1, ra, "a start"), rec(3, ra, "a ERROR db"), rec(5, ra, "a done")})
	d2.SetLogHistory("web", []runtime.LogRecord{rec(2, gone, "gone ERROR panic"), rec(4, rb, "b ok")})
	d2.SetLogHistory("api", []runtime.LogRecord{rec(1, "api-x", "api")})

	got, err := c.searchLogs(&armadav1.LogsRequest{App: "web", Since: timestamppb.New(base)})
	if err != nil {
		t.Fatal(err)
	}
	want := ra + "|a start," + gone + "|gone ERROR panic," + ra + "|a ERROR db," + rb + "|b ok," + ra + "|a done"
	if strings.Join(got, ",") != want {
		t.Errorf("merged by time:\n got %v\nwant %s", got, want)
	}
	got, _ = c.searchLogs(&armadav1.LogsRequest{App: "web", Since: timestamppb.New(base), Grep: "error", Limit: 1})
	if strings.Join(got, ",") != ra+"|a ERROR db" {
		t.Errorf("grep with limit 1 keeps the newest: %v", got)
	}
	// A replica that no longer exists can be searched.
	got, _ = c.searchLogs(&armadav1.LogsRequest{App: "web", Replica: gone, Since: timestamppb.New(base)})
	if strings.Join(got, ",") != gone+"|gone ERROR panic" {
		t.Errorf("gone replica: %v", got)
	}
	// Every node was asked with the window, the text, and the limit.
	qs := d2.LogSearches()
	q := qs[len(qs)-1]
	if q.App != "web" || q.Replica != gone || q.Since.Sub(base).Abs() > time.Millisecond || q.Limit != defaultSearchLimit {
		t.Errorf("query %+v", q)
	}

	for name, req := range map[string]*armadav1.LogsRequest{
		"until before since": {App: "web", Since: timestamppb.New(base), Until: timestamppb.New(base.Add(-time.Second))},
		"until alone":        {App: "web", Until: timestamppb.New(base)},
		"limit alone":        {App: "web", Limit: 3},
	} {
		if _, err := c.searchLogs(req); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A node answers a search only for the app's replicas that ran on it: a node
// that never ran the app cannot add entries, under invented replica IDs or
// the ID of a real replica on another node, nor push genuine ones out.
func TestLogHistoryFromForeignNode(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	nodes := map[string]*fake.Driver{"n1": c.addNode("n1", "127.0.0.1"), "n2": c.addNode("n2", "127.0.0.2")}
	c.deploy(webSpec("nginx:1", 1))
	var real store.Replica
	c.eventually("1 running", func() bool {
		rs := c.running("web")
		if len(rs) != 1 {
			return false
		}
		real = store.Replica{ID: rs[0].Id, NodeID: rs[0].NodeId}
		return true
	})
	foreign := "n1"
	if real.NodeID == "n1" {
		foreign = "n2"
	}
	base := time.Now().Add(-time.Hour)
	rec := func(d time.Duration, replica, text string) runtime.LogRecord {
		return runtime.LogRecord{Time: base.Add(d), Stream: runtime.Stdout, Data: []byte(text + "\n"), Replica: replica}
	}
	nodes[real.NodeID].SetLogHistory("web", []runtime.LogRecord{
		rec(10*time.Minute, real.ID, "GENUINE first"), rec(20*time.Minute, real.ID, "GENUINE second"),
	})
	nodes[foreign].SetLogHistory("web", []runtime.LogRecord{
		rec(time.Hour-2*time.Second, real.ID, "SPOOF a"), rec(time.Hour-time.Second, "web-r7-inven", "SPOOF b"),
	})
	for _, limit := range []int32{2, 10} {
		got, err := c.searchLogs(&armadav1.LogsRequest{App: "web", Since: timestamppb.New(base), Limit: limit})
		if err != nil {
			t.Fatal(err)
		}
		want := real.ID + "|GENUINE first," + real.ID + "|GENUINE second"
		if strings.Join(got, ",") != want {
			t.Errorf("limit %d:\n got %v\nwant %s", limit, got, want)
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

// lokiSink is a log endpoint that records what it is sent.
type lokiSink struct {
	mu     sync.Mutex
	status int
	auth   []string
	lines  []string
}

func (k *lokiSink) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.status != 0 && k.status != http.StatusNoContent {
		w.WriteHeader(k.status)
		return
	}
	zr, err := gzip.NewReader(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var push struct {
		Streams []struct {
			Stream map[string]string `json:"stream"`
			Values [][]any           `json:"values"`
		} `json:"streams"`
	}
	if err := json.NewDecoder(zr).Decode(&push); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	k.auth = append(k.auth, r.Header.Get("Authorization"))
	for _, s := range push.Streams {
		for _, v := range s.Values {
			k.lines = append(k.lines, fmt.Sprintf("%s/%s/%s|%v", s.Stream["space"], s.Stream["app"], s.Stream["node"], v[1]))
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (k *lokiSink) got() ([]string, []string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return slices.Clone(k.lines), slices.Clone(k.auth)
}

func (k *lokiSink) answer(code int) {
	k.mu.Lock()
	k.status = code
	k.mu.Unlock()
}

func TestLogExport(t *testing.T) {
	t.Parallel()
	keys, err := secrets.NewKeyring(bytes.Repeat([]byte{5}, 32))
	if err != nil {
		t.Fatal(err)
	}
	sink := &lokiSink{}
	srv := httptest.NewServer(sink)
	defer srv.Close()
	c := newCluster(t, func(cfg *Config) { cfg.Secrets = keys })
	c.agentConfig = func(_ string, cfg *agent.Config) { cfg.LogExport = 20 * time.Millisecond }
	d := c.addNode("n1", "127.0.0.1")
	rec := func(app, text string) runtime.LogRecord {
		return runtime.LogRecord{Time: time.Now(), Stream: runtime.Stdout, Data: []byte(text + "\n"), App: app, Replica: "x", Revision: "r"}
	}
	d.AddLogOutput(rec("web", "one"), rec("api.shop", "two"))

	set := func(req *armadav1.SetClusterConfigRequest) (*armadav1.ClusterConfig, error) {
		return c.admin.SetClusterConfig(c.ctx, req)
	}
	endpoint := srv.URL + "/loki/api/v1/push"
	for name, req := range map[string]*armadav1.SetClusterConfigRequest{
		"no endpoint":     {Config: &armadav1.ClusterConfig{LogExport: "loki"}, SetLogExport: true},
		"public http":     {Config: &armadav1.ClusterConfig{LogExport: "loki", LogEndpoint: "http://logs.example.com/push"}, SetLogExport: true},
		"format":          {Config: &armadav1.ClusterConfig{LogExport: "syslog", LogEndpoint: endpoint}, SetLogExport: true},
		"token, no sink":  {SetLogToken: true, LogToken: []byte("tok")},
		"user, no token":  {Config: &armadav1.ClusterConfig{LogExport: "loki", LogEndpoint: endpoint, LogExportUser: "u"}, SetLogExport: true},
		"multiline token": {Config: &armadav1.ClusterConfig{LogExport: "loki", LogEndpoint: endpoint}, SetLogExport: true, SetLogToken: true, LogToken: []byte("a\nb")},
	} {
		if _, err := set(req); status.Code(err) != codes.InvalidArgument && status.Code(err) != codes.FailedPrecondition {
			t.Errorf("%s: %v", name, err)
		}
	}
	cc, err := set(&armadav1.SetClusterConfigRequest{Config: &armadav1.ClusterConfig{LogExport: "loki", LogEndpoint: endpoint},
		SetLogExport: true, SetLogToken: true, LogToken: []byte(" tok-9\n")})
	if err != nil || cc.LogExport != "loki" || cc.LogEndpoint != endpoint || !cc.LogTokenSet {
		t.Fatalf("set: %v %v", cc, err)
	}
	c.eventually("output sent with the token", func() bool {
		lines, auth := sink.got()
		return len(lines) == 2 && d.LogOutputLeft() == 0 && auth[0] == "Bearer tok-9"
	})
	if lines, _ := sink.got(); !slices.Contains(lines, "default/web/n1|one") || !slices.Contains(lines, "shop/api/n1|two") {
		t.Errorf("lines %v", lines)
	}

	// While the endpoint refuses, output waits and the node says so.
	sink.answer(http.StatusInternalServerError)
	d.AddLogOutput(rec("web", "three"))
	c.eventually("failing event", func() bool {
		evs, _ := c.store.ListEvents(c.ctx, time.Time{})
		return slices.ContainsFunc(evs, func(e store.Event) bool {
			return e.Reason == "LogExportFailing" && e.Node == "n1" && strings.Contains(e.Message, "500") && !strings.Contains(e.Message, "tok-9")
		})
	})
	if d.LogOutputLeft() != 1 {
		t.Errorf("output dropped while failing")
	}
	sink.answer(http.StatusNoContent)
	c.eventually("sent once the endpoint is back", func() bool {
		lines, _ := sink.got()
		return d.LogOutputLeft() == 0 && slices.Contains(lines, "default/web/n1|three")
	})

	cc, err = set(&armadav1.SetClusterConfigRequest{Config: &armadav1.ClusterConfig{LogExport: "none"}, SetLogExport: true})
	if err != nil || cc.LogExport != "" || cc.LogTokenSet || cc.LogEndpoint != "" {
		t.Fatalf("none: %v %v", cc, err)
	}
	audit, _ := c.store.ListAudit(c.ctx, 100)
	for _, e := range audit {
		if strings.Contains(fmt.Sprint(e), "tok-9") {
			t.Errorf("token in the audit log: %v", e)
		}
	}
}

// A node's search answer counts only for the query it was asked: the
// app's replicas (the asked one, if any), inside the window.
func TestSearchMatch(t *testing.T) {
	t.Parallel()
	now := time.Now()
	q := &armadav1.LogQuery{App: "web.a", Since: timestamppb.New(now.Add(-time.Hour)), Until: timestamppb.New(now)}
	at := func(r string, d time.Duration) *armadav1.LogPush {
		return &armadav1.LogPush{Replica: r, Time: timestamppb.New(now.Add(d)), Data: []byte("x")}
	}
	for _, c := range []struct {
		m    *armadav1.LogPush
		want bool
	}{
		{at("web.a-r1-abcde", -time.Minute), true},
		{at("billing.b-r9-zzzzz", -time.Minute), false},
		{at("web.a-api-r1-abcde", -time.Minute), false}, // web.a-api's, not web.a's
		{at("web.a-j3-abcde", -time.Minute), true},      // a job attempt
		{at("web.a-", -time.Minute), false},
		{at("web.a-r1-abcde", -2*time.Hour), false},
		{at("web.a-r1-abcde", time.Minute), false},
	} {
		if got := searchMatch(q, c.m, now); got != c.want {
			t.Errorf("%s at %v: %v, want %v", c.m.GetReplica(), c.m.GetTime().AsTime().Sub(now), got, c.want)
		}
	}
	q.Until = nil
	if !searchMatch(q, at("web.a-r1-abcde", 30*time.Second), now) || searchMatch(q, at("web.a-r1-abcde", 2*time.Minute), now) {
		t.Error("without --until, entries may be at most a minute ahead")
	}
	q.Replica = "web.a-r2-fghij"
	if searchMatch(q, at("web.a-r1-abcde", -time.Minute), now) {
		t.Error("an entry of another replica than the asked one")
	}
}

// The leader runs a bounded number of searches, in total and per caller.
func TestSearchSlots(t *testing.T) {
	t.Parallel()
	s := newCallerSlots(maxSearches, maxSearchesPerCaller, "busy")
	var release []func()
	for range maxSearchesPerCaller {
		r, err := s.take("user:a")
		if err != nil {
			t.Fatal(err)
		}
		release = append(release, r)
	}
	if _, err := s.take("user:a"); status.Code(err) != codes.ResourceExhausted {
		t.Errorf("caller over its limit: %v", err)
	}
	for i := maxSearchesPerCaller; i < maxSearches; i++ {
		r, err := s.take("user:b" + strconv.Itoa(i))
		if err != nil {
			t.Fatal(err)
		}
		release = append(release, r)
	}
	if _, err := s.take("user:c"); status.Code(err) != codes.ResourceExhausted {
		t.Errorf("over the total: %v", err)
	}
	release[0]()
	if _, err := s.take("user:c"); err != nil {
		t.Errorf("after a release: %v", err)
	}
}

// The leader keeps placement records as long as nodes keep history.
func TestDefaultLogRetention(t *testing.T) {
	t.Parallel()
	if defaultLogRetention != embedded.DefaultLogRetention {
		t.Errorf("default log retention %s, nodes keep %s", defaultLogRetention, embedded.DefaultLogRetention)
	}
}
