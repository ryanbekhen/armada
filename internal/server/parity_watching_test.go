package server

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/pki"
	"github.com/ryanbekhen/armada/internal/store"
)

// Scenarios of watching (ADR 0055, pull request 15, first part), run
// against both servers by runParity: Top with the usage counted per
// space, ClusterStatus with its runtime and control plane backup views,
// alert channels with every kind of channel delivering to stand-ins in
// the test (a webhook, Slack, Discord, the Telegram Bot API, and an SMTP
// server), the metrics endpoint with its text compared line by line
// (Go's runtime metrics left out), and the metrics credentials. They move
// what top_test.go, alerts_test.go, metrics_test.go, and the ClusterStatus
// tests check onto both servers; those tests stay.

// alertSinks are the stand-ins alert channels deliver to: one HTTP server
// for webhooks, Slack, Discord, and the Telegram Bot API (by path), and
// one SMTP server.
type alertSinks struct {
	t    *testing.T
	http *httptest.Server
	smtp net.Listener

	mu sync.Mutex
	// got holds what each path or the SMTP server received, normalized.
	got map[string][]string
	// fail answers a path with 401 and a body naming the secret.
	fail map[string]bool
}

var (
	sinkTime  = regexp.MustCompile(`\d{4}-\d\d-\d\d \d\d:\d\d:\d\d UTC`)
	sinkDate  = regexp.MustCompile(`(?m)^Date: .*\r$`)
	sinkTimeQ = regexp.MustCompile(`\d{4}-\d\d-\d\d =?\r?\n?\d\d:\d\d:\d\d UTC`)
)

func newAlertSinks(t *testing.T) *alertSinks {
	t.Helper()
	s := &alertSinks{t: t, got: map[string][]string{}, fail: map[string]bool{}}
	s.http = httptest.NewServer(http.HandlerFunc(s.serveHTTP))
	t.Cleanup(s.http.Close)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.smtp = l
	t.Cleanup(func() { _ = l.Close() })
	go s.serveSMTP()
	return s
}

func (s *alertSinks) serveHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	path := r.URL.Path
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail[path] {
		w.WriteHeader(http.StatusUnauthorized)
		// The whole URL, the channel's secret, which errors never repeat.
		_, _ = fmt.Fprintf(w, "no access for http://%s%s", r.Host, r.URL.RequestURI())
		return
	}
	var v map[string]any
	_ = json.Unmarshal(body, &v)
	for k, x := range v {
		if str, ok := x.(string); ok {
			v[k] = sinkTime.ReplaceAllString(str, "<time> UTC")
		}
	}
	b, _ := json.Marshal(map[string]any{"method": r.Method, "type": r.Header.Get("Content-Type"),
		"agent": r.Header.Get("User-Agent"), "query": r.URL.RawQuery, "body": v})
	s.got[path] = append(s.got[path], string(b))
	w.WriteHeader(http.StatusOK)
}

// serveSMTP answers as a plain SMTP server on a private address: no
// STARTTLS and no authentication offered.
func (s *alertSinks) serveSMTP() {
	for {
		c, err := s.smtp.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(time.Minute))
			r := bufio.NewReader(c)
			say := func(line string) { _, _ = io.WriteString(c, line+"\r\n") }
			var lines []string
			say("220 standin ESMTP")
			for {
				line, err := r.ReadString('\n')
				if err != nil {
					return
				}
				line = strings.TrimRight(line, "\r\n")
				lines = append(lines, line)
				switch cmd := strings.ToUpper(strings.SplitN(line, " ", 2)[0]); cmd {
				case "EHLO":
					say("250-standin")
					say("250 SIZE 1000000")
				case "HELO", "MAIL", "RCPT", "RSET", "NOOP":
					say("250 ok")
				case "DATA":
					say("354 go on")
					var data strings.Builder
					for {
						l, err := r.ReadString('\n')
						if err != nil {
							return
						}
						if l == ".\r\n" {
							break
						}
						data.WriteString(l)
					}
					msg := sinkDate.ReplaceAllString(data.String(), "Date: <date>\r")
					msg = sinkTimeQ.ReplaceAllString(msg, "<time> UTC")
					lines = append(lines, msg)
					say("250 queued")
				case "QUIT":
					say("221 bye")
					s.mu.Lock()
					s.got["smtp"] = append(s.got["smtp"], strings.Join(lines, "\n"))
					s.mu.Unlock()
					return
				default:
					say("502 not here")
				}
			}
		}()
	}
}

// url is a channel URL on the HTTP stand-in.
func (s *alertSinks) url(path string) string { return s.http.URL + path }

// telegramAPI is the Bot API's address on the HTTP stand-in.
func (s *alertSinks) telegramAPI() string { return s.http.URL + "/telegram" }

// client is Go's server's HTTP client for alerts: requests to the Bot API
// go to the stand-in, the others where they are addressed.
func (s *alertSinks) client() *http.Client {
	base, _ := url.Parse(s.telegramAPI())
	return &http.Client{
		Timeout:       30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
			if r.URL.Host == "api.telegram.org" {
				r = r.Clone(r.Context())
				r.URL.Scheme, r.URL.Host, r.URL.Path = base.Scheme, base.Host, base.Path+r.URL.Path
				r.Host = base.Host
			}
			return http.DefaultTransport.RoundTrip(r)
		}),
	}
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// wait waits until path (or "smtp") received n notices, and returns them
// sorted: channels deliver on their own.
func (s *alertSinks) wait(sc *scenario, path string, n int) []string {
	sc.t.Helper()
	var got []string
	deadline := time.Now().Add(15 * time.Second)
	for {
		s.mu.Lock()
		got = slices.Clone(s.got[path])
		s.mu.Unlock()
		if len(got) >= n {
			break
		}
		if time.Now().After(deadline) {
			sc.t.Fatalf("%s: %d notices at %s, want %d: %v", sc.sut.kind(), len(got), path, n, got)
		}
		time.Sleep(10 * time.Millisecond)
	}
	sort.Strings(got)
	return got
}

func (s *alertSinks) setFail(path string, on bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fail[path] = on
}

// away records a node whose agent last reported now and is not
// connected: lost once the node-lost timeout passed.
func (sc *scenario) away(id, ip string) {
	sc.t.Helper()
	sc.node(id, ip, 1000, 1<<30, nil)
	if err := sc.st.SetNodeStatus(sc.ctx, id, store.NodeStatus{State: store.NodeUnknown, LastSeen: sc.clock.now(), CPUMillis: 1000, MemoryBytes: 1 << 30, Containers: true}); err != nil {
		sc.t.Fatal(err)
	}
}

// clusterStatus records ClusterStatus.
func (sc *scenario) clusterStatus(label string) {
	sc.t.Helper()
	resp, err := sc.admin.ClusterStatus(sc.ctx, &armadav1.ClusterStatusRequest{})
	sc.answer(label, resp, err)
}

// top records Top for app ("" for all) as c.
func (sc *scenario) top(label string, c armadav1.AdminServiceClient, app string) {
	sc.t.Helper()
	resp, err := c.Top(sc.ctx, &armadav1.TopRequest{App: app})
	sc.answer(label, resp, err)
}

// user records a user with roles and returns its client.
func (sc *scenario) user(name string, roles ...store.Grant) armadav1.AdminServiceClient {
	sc.t.Helper()
	if _, err := sc.st.CreateUser(sc.ctx, store.Principal{Name: name, Since: sc.clock.now().Add(-time.Hour), Roles: roles}, "user:ryan"); err != nil {
		sc.t.Fatal(err)
	}
	return sc.adminClient(pki.Identity{Kind: pki.KindUser, Name: name})
}

// TestTop, TestTopSpaces, TestTopSpacesScope, and TestUsageStoreCountsSpaces
// on both servers: usage only from a replica's own node, reservations and
// limits, nodes' allocatable capacity and connection tracking, the spaces
// a caller may manage with requests from every node's proxy and egress
// from a replica's own node, the counting start, samples that grow old,
// and a removed space's counters.
func TestParityTop(t *testing.T) {
	runParity(t, parityConfig{}, func(sc *scenario) {
		for _, name := range []string{"shop", "other"} {
			resp, err := sc.admin.CreateSpace(sc.ctx, &armadav1.CreateSpaceRequest{Name: name})
			sc.answer("space "+name, resp, err)
		}
		vera := sc.user("vera", store.Grant{Role: store.RoleViewer, Space: "shop"})
		agents := sc.scaleAgents("n1", "n2")
		sc.deploy("web", webYAML("1", 2)+"resources:\n  cpu: 250m\n  memory: 128Mi\n")
		resp, err := sc.admin.Deploy(sc.ctx, &armadav1.DeployRequest{Spec: []byte("name: api\nimage: api:1\nresources:\n  cpu: 100m\n  memory: 64Mi\n"), Space: "shop"})
		sc.answer("api.shop", resp, err)
		sc.top("before a pass", sc.admin, "")
		sc.pass("placed")
		sc.serve("web")
		sc.serve("api.shop")
		// A pass tells the usage store whose replicas are whose.
		sc.pass("running")
		sc.top("unmeasured", sc.admin, "")
		sc.top("ghost", sc.admin, "ghost")

		web1, web2 := sc.onNode("web", "n1"), sc.onNode("web", "n2")
		api := sc.replicaOf("api.shop-")
		own := map[string][]*armadav1.ReplicaUsage{}
		for _, id := range web1 {
			own["n1"] = append(own["n1"], &armadav1.ReplicaUsage{Id: id, CpuMillis: 120, MemoryBytes: 50 << 20, EgressBytes: 1000})
		}
		for _, id := range web2 {
			own["n2"] = append(own["n2"], &armadav1.ReplicaUsage{Id: id, CpuMillis: 80, MemoryBytes: 40 << 20, EgressBytes: 500})
		}
		own[api.NodeID] = append(own[api.NodeID], &armadav1.ReplicaUsage{Id: api.ID, CpuMillis: 30, MemoryBytes: 20 << 20, EgressBytes: 7000})
		var everyone []*armadav1.ReplicaLoad
		for _, id := range append(append(slices.Clone(web1), web2...), api.ID) {
			everyone = append(everyone, &armadav1.ReplicaLoad{Id: id, InFlight: 1, Requests: 10})
		}
		sc.advance(time.Second)
		sc.usage(agents["n1"], &armadav1.UsageReport{Replicas: own["n1"], Load: everyone, LoadMeasured: true, ConntrackEntries: 7, ConntrackMax: 262144})
		sc.usage(agents["n2"], &armadav1.UsageReport{Replicas: own["n2"], Load: everyone, LoadMeasured: true})
		sc.top("measured", sc.admin, "")
		// Status's last seen follows the samples (TestStatusLastSeenFollowsUsage).
		sc.status("status", "")
		sc.top("one app", sc.admin, "web")
		sc.top("a viewer of shop", vera, "")
		sc.top("a viewer, another app", vera, "web")

		// n2 reports n1's replicas: nothing changes.
		var forged []*armadav1.ReplicaUsage
		for _, r := range own["n1"] {
			forged = append(forged, &armadav1.ReplicaUsage{Id: r.GetId(), CpuMillis: 9000, MemoryBytes: 1 << 40, EgressBytes: 1 << 50})
		}
		sc.usage(agents["n2"], &armadav1.UsageReport{Replicas: append(forged, own["n2"]...)})
		sc.top("forged", sc.admin, "")
		del, err := sc.admin.DeleteSpace(sc.ctx, &armadav1.DeleteSpaceRequest{Name: "other"})
		sc.answer("other removed", del, err)
		sc.advance(40 * time.Second)
		sc.top("samples grown old", sc.admin, "")
		sc.clusterStatus("status")
	})
}

// The ClusterStatus tests on both servers: counts of apps and jobs, the
// apps that need attention (rolling out, failing), nodes not ready or
// lost, cluster-admin only, where the nodes' move to armada-node stands,
// and the control plane backups' status read from their records.
func TestParityClusterStatus(t *testing.T) {
	runParity(t, parityConfig{progress: time.Minute}, func(sc *scenario) {
		sc.clusterStatus("empty")
		agents := sc.scaleAgents("n1", "n2")
		sc.away("n3", "10.0.0.13")
		vera := sc.user("vera", store.Grant{Role: store.RoleViewer, Space: "default"})
		resp, err := vera.ClusterStatus(sc.ctx, &armadav1.ClusterStatusRequest{})
		sc.answer("a viewer", resp, err)
		sc.deploy("web", webYAML("1", 2))
		sc.deploy("bad", "name: bad\nimage: bad:1\n")
		sc.deploy("slow", "name: slow\nimage: slow:1\n")
		sc.deploy("job", "kind: job\nname: nightly\nimage: busybox\nschedule: \"0 3 * * *\"\n")
		sc.pass("placed")
		sc.serve("web")
		sc.clusterStatus("rolling out")
		sc.later("bad stuck", 2*time.Minute)
		sc.serve("slow")
		sc.clusterStatus("one failing")
		// What the nodes run (ADR 0054).
		sc.usage(agents["n1"], &armadav1.UsageReport{Runtime: &armadav1.RuntimeStatus{Agent: "supervisor-rust"}})
		sc.usage(agents["n2"], &armadav1.UsageReport{Runtime: &armadav1.RuntimeStatus{Agent: AgentContainerdName, MoveError: "drain\nfirst"}})
		sc.pass("runtimes")
		sc.clusterStatus("runtimes")
		sc.status("each node's runtime", "")
		// Control plane backups as the backup loop records them.
		sealed := `{"KeyID":"k","WrappedKey":"AA==","Ciphertext":"AA=="}`
		for k, v := range map[string]string{
			metaCPBackup:      `{"everySeconds":3600,"keep":{"last":3},"bucket":"https://minio.lab/cp","url":` + sealed + `,"urlVersion":1,"key":` + sealed + `,"keyVersion":1}`,
			metaCPBackupState: `{"urlVersion":1,"keyVersion":1,"lastAt":"2026-11-20T09:30:00Z","lastId":"s1","lastServer":"cp-1","lastBytes":4096,"stored":8192,"snapshots":2,"failedAt":"2026-11-20T09:45:00Z","error":"bucket: put: AccessDenied (HTTP 403)"}`,
		} {
			if err := sc.st.SetMeta(sc.ctx, k, v); err != nil {
				t.Fatal(err)
			}
		}
		sc.clusterStatus("with backups")
		sc.later("nodes lost", 6*time.Minute)
		sc.clusterStatus("lost")
	})
}

// TestAlerts on both servers, with every kind of channel: refusals of bad
// channels, a test notice, warnings sent once, a repeat and a normal
// event not, conditions that end told as resolved, filters by space and
// reason, a failing channel saying why without its secret, the counts
// each channel keeps, the audit log, and deletion.
func TestParityAlerts(t *testing.T) {
	runParity(t, parityConfig{masterKey: true, alerts: true, nodeLost: 30 * time.Second}, func(sc *scenario) {
		sinks := sc.sinks
		sc.alias(sinks.smtp.Addr().String(), "<smtp>")
		create := func(label string, ch *armadav1.AlertChannel, secret string) {
			sc.t.Helper()
			resp, err := sc.admin.CreateAlertChannel(sc.ctx, &armadav1.AlertChannelRequest{Channel: ch, SetSecret: secret != "", Secret: []byte(secret)})
			sc.answer(label, resp, err)
		}
		hook := sinks.url("/hook?key=s3cret")
		for _, c := range []struct {
			label string
			ch    *armadav1.AlertChannel
		}{
			{"no type", &armadav1.AlertChannel{Name: "a"}},
			{"bad name", &armadav1.AlertChannel{Name: "A!", Type: "webhook"}},
			{"chat id", &armadav1.AlertChannel{Name: "a", Type: "webhook", ChatId: "1"}},
			{"email bad to", &armadav1.AlertChannel{Name: "a", Type: "email", SmtpHost: "127.0.0.1:25", From: "a@b.c", To: []string{"Name <x@y>"}}},
			{"email no host", &armadav1.AlertChannel{Name: "a", Type: "email", From: "a@b.c", To: []string{"x@y"}}},
			{"telegram no id", &armadav1.AlertChannel{Name: "a", Type: "telegram"}},
			{"bad space", &armadav1.AlertChannel{Name: "a", Type: "webhook", Spaces: []string{"Bad"}}},
		} {
			create(c.label, c.ch, hook)
		}
		create("no secret", &armadav1.AlertChannel{Name: "a", Type: "slack"}, "")
		create("public http", &armadav1.AlertChannel{Name: "a", Type: "webhook"}, "http://example.com/x")
		create("bad token", &armadav1.AlertChannel{Name: "a", Type: "telegram", ChatId: "-1001234567890"}, "nope")
		create("two lines", &armadav1.AlertChannel{Name: "a", Type: "webhook"}, hook+"\nx")

		create("ops", &armadav1.AlertChannel{Name: "ops", Type: "webhook"}, hook+"\n")
		create("ops twice", &armadav1.AlertChannel{Name: "ops", Type: "webhook"}, hook)
		create("slack", &armadav1.AlertChannel{Name: "chat", Type: "slack", Reasons: []string{"Started", "OutOfMemory"}, Spaces: []string{"shop"}}, sinks.url("/slack"))
		create("discord", &armadav1.AlertChannel{Name: "dc", Type: "discord", Reasons: []string{"OutOfMemory", "Started"}}, sinks.url("/discord"))
		create("telegram", &armadav1.AlertChannel{Name: "tg", Type: "telegram", ChatId: " -1001234567890 ", Reasons: []string{"Lost"}}, "123456:ABCDEFGHIJKLMNOPQRSTUVWX")
		create("email", &armadav1.AlertChannel{Name: "mail", Type: "email", SmtpHost: sinks.smtp.Addr().String(), From: "armada@example.com",
			To: []string{"ops@example.com", " ops@example.com", "dev@example.com"}, Reasons: []string{"Lost", "OutOfMemory"}}, "")
		test, err := sc.admin.TestAlertChannel(sc.ctx, &armadav1.TestAlertChannelRequest{Name: "ops"})
		sc.answer("test ops", test, err)
		sc.note("test notice", sinks.wait(sc, "/hook", 1))

		// Events: a deploy (Started, a normal event), an out-of-memory kill twice
		// (a warning, the repeat folded), and a node lost and back.
		space, err := sc.admin.CreateSpace(sc.ctx, &armadav1.CreateSpaceRequest{Name: "shop"})
		sc.answer("space", space, err)
		agents := sc.scaleAgents("n1")
		resp, err := sc.admin.Deploy(sc.ctx, &armadav1.DeployRequest{Spec: []byte("name: web\nimage: web:1\n"), Space: "shop"})
		sc.answer("deploy web.shop", resp, err)
		sc.pass("placed")
		sc.serve("web.shop")
		// A pass tells the usage store whose replicas are whose.
		sc.pass("running")
		r := sc.replicaOf("web.shop-")
		oom := &armadav1.UsageReport{Replicas: []*armadav1.ReplicaUsage{{Id: r.ID, MemoryBytes: 1 << 20, OomKills: 2}}}
		sc.usage(agents["n1"], oom)
		sc.usage(agents["n1"], oom)
		sc.note("oom events", sc.eventCount(r.ID, "OutOfMemory"))
		sc.away("n9", "10.0.0.99")
		sc.later("n9 lost", time.Minute)
		if err := sc.st.SetNodeStatus(sc.ctx, "n9", store.NodeStatus{State: store.NodeReady, LastSeen: sc.clock.now(), CPUMillis: 1000, MemoryBytes: 1 << 30, Containers: true}); err != nil {
			t.Fatal(err)
		}
		sc.pass("n9 back")

		sc.note("webhook", sinks.wait(sc, "/hook", 4))
		sc.note("slack", sinks.wait(sc, "/slack", 2))
		sc.note("discord", sinks.wait(sc, "/discord", 2))
		sc.note("telegram", sinks.wait(sc, "/telegram/bot123456:ABCDEFGHIJKLMNOPQRSTUVWX/sendMessage", 2))
		sc.note("email", sinks.wait(sc, "smtp", 3))

		// Filters: only Started of space shop.
		upd, err := sc.admin.UpdateAlertChannel(sc.ctx, &armadav1.AlertChannelRequest{
			Channel: &armadav1.AlertChannel{Name: "ops", Spaces: []string{"shop"}, Reasons: []string{"Started"}}, SetSpaces: true, SetReasons: true})
		sc.answer("filter ops", upd, err)
		upd, err = sc.admin.UpdateAlertChannel(sc.ctx, &armadav1.AlertChannelRequest{Channel: &armadav1.AlertChannel{Name: "ops", Type: "slack"}})
		sc.answer("another type", upd, err)
		upd, err = sc.admin.UpdateAlertChannel(sc.ctx, &armadav1.AlertChannelRequest{Channel: &armadav1.AlertChannel{Name: "ghost"}})
		sc.answer("update ghost", upd, err)
		sc.deploy("deploy web", "name: web\nimage: web:1\n")
		resp, err = sc.admin.Deploy(sc.ctx, &armadav1.DeployRequest{Spec: []byte("name: api\nimage: api:1\n"), Space: "shop"})
		sc.answer("deploy api.shop", resp, err)
		sc.note("filtered", sinks.wait(sc, "/hook", 5))

		// A failing channel says why, without its secret.
		sinks.setFail("/hook", true)
		test, err = sc.admin.TestAlertChannel(sc.ctx, &armadav1.TestAlertChannelRequest{Name: "ops"})
		sc.answer("failing", test, err)
		sinks.setFail("/hook", false)
		// Every notice so far delivered, and counted: test notices are not.
		var list *armadav1.ListAlertChannelsResponse
		sc.eventually("every notice counted", func() bool {
			l, err := sc.admin.ListAlertChannels(sc.ctx, &armadav1.ListAlertChannelsRequest{})
			if err != nil {
				return false
			}
			sent := 0
			for _, c := range l.GetChannels() {
				sent += int(c.GetSent())
			}
			list = l
			return sent == 16
		})
		sc.note("list", list)
		del, err := sc.admin.DeleteAlertChannel(sc.ctx, &armadav1.DeleteAlertChannelRequest{Name: "ops"})
		sc.answer("delete", del, err)
		test, err = sc.admin.TestAlertChannel(sc.ctx, &armadav1.TestAlertChannelRequest{Name: "ops"})
		sc.answer("deleted", test, err)
		del, err = sc.admin.DeleteAlertChannel(sc.ctx, &armadav1.DeleteAlertChannelRequest{Name: "ops"})
		sc.answer("deleted twice", del, err)
		sc.keyspace("keyspace")
	})
}

// scrape gets /metrics with a client certificate (none without one), and
// returns the status and body with Go's runtime metrics left out.
func (sc *scenario) scrape(certPEM, keyPEM []byte, method, path string) (int, string, error) {
	sc.t.Helper()
	cfg, err := pki.ClientTLS(sc.fx.ca.CertPEM, certPEM, keyPEM)
	if err != nil {
		sc.t.Fatal(err)
	}
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 10 * time.Second}
	req, _ := http.NewRequestWithContext(sc.ctx, method, "https://"+sc.metricsAddr+path, nil)
	resp, err := hc.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var keep []string
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "go_") || strings.HasPrefix(l, "# HELP go_") || strings.HasPrefix(l, "# TYPE go_") {
			continue
		}
		keep = append(keep, l)
	}
	return resp.StatusCode, strings.Join(keep, "\n"), nil
}

// noteScrape records a scrape: its status and its lines.
func (sc *scenario) noteScrape(label string, certPEM, keyPEM []byte) {
	sc.t.Helper()
	// The cluster's metrics are gathered again once the clock moved.
	sc.advance(time.Millisecond)
	code, body, err := sc.scrape(certPEM, keyPEM, http.MethodGet, "/metrics")
	if err != nil {
		sc.note(label, map[string]any{"error": true})
		return
	}
	sc.note(label, map[string]any{"status": code, "lines": strings.Split(body, "\n")})
}

// TestMetrics, TestRevisionInfoDuringRollout,
// TestIssueMetricsCertificateRefusesBadInput, and
// TestMetricsCertificatesRevoke on both servers: every metric of the
// cluster, the leader's counters (events, job runs), who may scrape, what
// a metrics certificate may not do, and its revocation.
func TestParityMetrics(t *testing.T) {
	runParity(t, parityConfig{metrics: true, drain: 30 * time.Second, warmup: time.Second}, func(sc *scenario) {
		sc.node("n1", "10.0.0.11", 2000, 4<<30, map[string]string{"name": "n1"}, "containers", "jobs")
		n1 := sc.jobAgent("n1", "10.0.0.11", false)
		sc.node("n2", "10.0.0.12", 2000, 4<<30, map[string]string{"name": "n2"}, "containers", "jobs")
		n2 := sc.jobAgent("n2", "10.0.0.12", false)
		sc.deploy("web", webYAML("1", 2)+"drain: 30s\nresources:\n  cpu: 250m\n  memory: 128Mi\n")
		sc.deploy("scaled", strings.Replace(scaledYAML("1", 1, "    - type: http\n      concurrent: 10\n"), "name: web", "name: scaled", 1))
		sc.deploy("job", "kind: job\nname: once\nimage: busybox\n")
		sc.pass("placed")
		sc.serve("web")
		sc.serve("scaled")
		sc.runJob("run", "once")
		sc.jobPass("run placed")
		sc.exit(sc.attempt("once", 1, -1), 0)
		sc.jobPass("run done")
		var mine []*armadav1.ReplicaUsage
		for _, id := range sc.onNode("web", "n1") {
			mine = append(mine, &armadav1.ReplicaUsage{Id: id, CpuMillis: 100, MemoryBytes: 50 << 20})
		}
		sc.usage(n1, &armadav1.UsageReport{Replicas: mine, ConntrackEntries: 7, ConntrackMax: 262144, Load: sc.load("scaled", 4, 9).GetLoad(), LoadMeasured: true})
		sc.usage(n2, &armadav1.UsageReport{})
		sc.evaluate("evaluated", "scaled")

		// A metrics certificate from the caller's own key, and refusals.
		keyPEM, csr, err := pki.NewCSR(pki.Identity{Kind: pki.KindMetrics, Name: "prometheus"})
		if err != nil {
			t.Fatal(err)
		}
		issued, err := sc.admin.IssueMetricsCertificate(sc.ctx, &armadav1.IssueMetricsCertificateRequest{Name: "prometheus", Csr: csr})
		sc.answer("issued", issued, err)
		bad, err := sc.admin.IssueMetricsCertificate(sc.ctx, &armadav1.IssueMetricsCertificateRequest{Name: "bad name!", Csr: csr})
		sc.answer("bad name", bad, err)
		bad, err = sc.admin.IssueMetricsCertificate(sc.ctx, &armadav1.IssueMetricsCertificateRequest{Name: "prometheus", Csr: []byte("nope")})
		sc.answer("bad CSR", bad, err)
		sc.noteScrape("metrics", issued.GetCert(), keyPEM)

		// A rollout: both revisions are exported with their images, the
		// old replicas draining.
		sc.deploy("web v2", webYAML("2", 2)+"drain: 30s\nresources:\n  cpu: 250m\n  memory: 128Mi\n")
		sc.pass("surge")
		sc.serve("web")
		sc.later("warmed up", 2*time.Second)
		sc.noteScrape("during the rollout", issued.GetCert(), keyPEM)

		// cluster-admin users may scrape too; nodes may not.
		adminCert, adminKey, _ := sc.fx.ca.Issue(pki.IssueRequest{Identity: pki.Identity{Kind: pki.KindAdmin, Name: "ryan"}, Client: true})
		sc.noteScrape("as an admin", adminCert, adminKey)
		nodeCert, nodeKey, _ := sc.fx.ca.Issue(pki.IssueRequest{Identity: pki.Identity{Kind: pki.KindNode, Name: "n1"}, Client: true})
		sc.noteScrape("as a node", nodeCert, nodeKey)
		code, body, err := sc.scrape(issued.GetCert(), keyPEM, http.MethodGet, "/other")
		sc.note("another path", map[string]any{"status": code, "body": body, "error": err != nil})
		code, body, err = sc.scrape(issued.GetCert(), keyPEM, http.MethodPost, "/metrics")
		sc.note("a POST", map[string]any{"status": code, "body": body, "error": err != nil})
		other, _ := pki.NewCA("other")
		otherCert, otherKey, _ := other.Issue(pki.IssueRequest{Identity: pki.Identity{Kind: pki.KindMetrics, Name: "prometheus"}, Client: true})
		_, _, err = sc.scrape(otherCert, otherKey, http.MethodGet, "/metrics")
		sc.note("another CA fails", err != nil)
		pool, _ := pki.ClientTLS(sc.fx.ca.CertPEM, issued.GetCert(), keyPEM)
		noCert := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool.RootCAs, ServerName: pki.ServerName}
		if resp, err := (&http.Client{Transport: &http.Transport{TLSClientConfig: noCert}, Timeout: 5 * time.Second}).Get("https://" + sc.metricsAddr + "/metrics"); err == nil {
			_ = resp.Body.Close()
			sc.note("no certificate", resp.StatusCode)
		} else {
			sc.note("no certificate", "refused")
		}

		// The metrics certificate cannot call the API.
		api := armadav1.NewAdminServiceClient(sc.dialPEM(issued.GetCert(), keyPEM))
		st, err := api.Status(sc.ctx, &armadav1.StatusRequest{})
		sc.answer("metrics certificate on the API", st, err)

		list, err := sc.admin.ListMetricsCredentials(sc.ctx, &armadav1.ListMetricsCredentialsRequest{})
		sc.answer("credentials", list, err)
		rev, err := sc.admin.RevokeMetricsCredentials(sc.ctx, &armadav1.RevokeMetricsCredentialsRequest{Name: "prometheus"})
		sc.answer("revoked", rev, err)
		rev, err = sc.admin.RevokeMetricsCredentials(sc.ctx, &armadav1.RevokeMetricsCredentialsRequest{Name: "Bad Name"})
		sc.answer("revoke a bad name", rev, err)
		list, err = sc.admin.ListMetricsCredentials(sc.ctx, &armadav1.ListMetricsCredentialsRequest{})
		sc.answer("credentials after", list, err)
		sc.noteScrape("revoked", issued.GetCert(), keyPEM)
		sc.keyspace("keyspace")
	})
}
