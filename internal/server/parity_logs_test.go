package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/pki"
	"github.com/ryanbekhen/armada/internal/store"
	"github.com/ryanbekhen/armada/internal/store/storetest"
)

// Pull request 15 of ADR 0055, second part: logs, log history, exec,
// placement records, and the log settings on both servers. Fake agents
// (watchAgent) answer the log requests and exec requests their Connect
// stream carries on PushLogs and ExecSession, as a node's agent does.

// watchAgent is a fake agent that serves logs and exec sessions.
type watchAgent struct {
	*parityAgent
	client armadav1.AgentServiceClient
	mu     sync.Mutex
	// history holds the entries the node's log history answers searches
	// with; live the lines each replica's live logs send (errs: an error
	// instead).
	history []*armadav1.LogPush
	live    map[string][]string
	errs    map[string]string
	// seen are the requests the node got, one line each; queries the
	// searches' queries; cancels the cancels by request ID.
	seen    []string
	queries []*armadav1.LogQuery
	cancels map[string]bool
	open    map[string]context.CancelFunc
	// execs are the exec requests the node got.
	execs []string
	// attachAs, when set, attaches exec sessions with another node's
	// client; attached what that attach answered.
	attachAs armadav1.AgentServiceClient
	attached chan error
}

// watchAgent connects node id's fake agent; history says whether its
// runtime keeps a log history.
func (sc *scenario) watchAgent(id, ip string, history bool) *watchAgent {
	sc.t.Helper()
	sc.node(id, ip, 4000, 8<<30, nil)
	client := sc.nodeAgent(id)
	a, err := sc.connectAgent(id, client, &armadav1.Hello{PrivateIp: ip, CpuMillis: 4000, MemoryBytes: 8 << 30, Containers: true, Jobs: true, LogHistory: history})
	if err != nil {
		sc.t.Fatal(err)
	}
	w := &watchAgent{parityAgent: a, client: client, live: map[string][]string{}, errs: map[string]string{}, cancels: map[string]bool{},
		open: map[string]context.CancelFunc{}, attached: make(chan error, 4)}
	sc.rec.skip("log and exec sessions of fake agents")
	logs := w.serveLogs
	a.logs.Store(&logs)
	exec := w.serveExec
	a.exec.Store(&exec)
	return w
}

// liveAt is when live lines are stamped: a minute apart from the fixture
// clock's start.
func (sc *scenario) liveAt(i int) *timestamppb.Timestamp {
	return timestamppb.New(sc.fx.start.Add(time.Duration(i) * time.Minute))
}

func (w *watchAgent) serveLogs(m *armadav1.ServerMessage) {
	if c := m.GetLogCancel(); c != nil {
		w.mu.Lock()
		w.cancels[c.GetRequestId()] = true
		if f := w.open[c.GetRequestId()]; f != nil {
			f()
		}
		w.mu.Unlock()
		return
	}
	req := m.GetLogRequest()
	ctx, cancel := context.WithCancel(w.sc.ctx)
	w.mu.Lock()
	w.open[req.GetRequestId()] = cancel
	if q := req.GetQuery(); q != nil {
		w.queries = append(w.queries, q)
		w.seen = append(w.seen, fmt.Sprintf("search %s replica=%q container=%q grep=%q limit=%d until=%t", q.GetApp(), q.GetReplica(), q.GetContainer(), q.GetGrep(), q.GetLimit(), q.GetUntil() != nil))
	} else {
		w.seen = append(w.seen, fmt.Sprintf("live %s follow=%t tail=%d container=%q grep=%q", req.GetReplicaId(), req.GetFollow(), req.GetTail(), req.GetContainer(), req.GetGrep()))
	}
	w.mu.Unlock()
	go func() {
		defer cancel()
		stream, err := w.client.PushLogs(ctx)
		if err != nil {
			return
		}
		send := func(p *armadav1.LogPush) bool {
			p.RequestId = req.GetRequestId()
			return stream.Send(p) == nil
		}
		if q := req.GetQuery(); q != nil {
			// The node's own search: the app's entries holding the text,
			// the newest limit of them.
			w.mu.Lock()
			var got []*armadav1.LogPush
			for _, h := range w.history {
				if strings.HasPrefix(h.GetReplica(), q.GetApp()+"-") && strings.Contains(strings.ToLower(string(h.GetData())), strings.ToLower(q.GetGrep())) &&
					(q.GetReplica() == "" || h.GetReplica() == q.GetReplica()) {
					got = append(got, h)
				}
			}
			w.mu.Unlock()
			if n := int(q.GetLimit()); n > 0 && len(got) > n {
				got = got[len(got)-n:]
			}
			if !send(&armadav1.LogPush{}) {
				return
			}
			for _, h := range got {
				if !send(&armadav1.LogPush{Replica: h.GetReplica(), Stream: h.GetStream(), Data: h.GetData(), Time: h.GetTime()}) {
					return
				}
			}
			_, _ = stream.CloseAndRecv()
			return
		}
		w.mu.Lock()
		lines, fail := w.live[req.GetReplicaId()], w.errs[req.GetReplicaId()]
		w.mu.Unlock()
		if fail != "" {
			send(&armadav1.LogPush{Error: fail})
		}
		if !send(&armadav1.LogPush{}) {
			return
		}
		for i, l := range lines {
			if !send(&armadav1.LogPush{Stream: armadav1.Stream_STREAM_STDOUT, Data: []byte(l + "\n"), Time: w.sc.liveAt(i)}) {
				return
			}
		}
		if req.GetFollow() {
			<-ctx.Done()
			return
		}
		_, _ = stream.CloseAndRecv()
	}()
}

func (w *watchAgent) serveExec(er *armadav1.ExecRequest) {
	w.mu.Lock()
	w.execs = append(w.execs, fmt.Sprintf("%s %s tty=%t stdin=%t container=%q size=%v", er.GetReplicaId(), strings.Join(er.GetCmd(), " "), er.GetTty(), er.GetStdin(), er.GetContainer(), er.GetSize() != nil))
	client := w.client
	if w.attachAs != nil {
		client = w.attachAs
	}
	w.mu.Unlock()
	stream, err := client.ExecSession(w.sc.ctx)
	if err != nil {
		return
	}
	first := &armadav1.ExecSessionOutput{RequestId: er.GetRequestId()}
	if er.GetCmd()[0] == "missing" {
		first.Output = &armadav1.ExecSessionOutput_Error{Error: `exec: "missing": executable file not found in $PATH`}
	}
	if err := stream.Send(first); err != nil {
		return
	}
	if w.attachAs != nil {
		_, err := stream.Recv()
		w.attached <- err
		return
	}
	out := func(o *armadav1.ExecSessionOutput) { _ = stream.Send(o) }
	switch er.GetCmd()[0] {
	case "missing":
	case "cat":
		// Echoes its input once it ends.
		var in []byte
		for {
			m, err := stream.Recv()
			if err != nil || m.GetCloseStdin() {
				break
			}
			in = append(in, m.GetStdin()...)
		}
		out(&armadav1.ExecSessionOutput{Output: &armadav1.ExecSessionOutput_Stdout{Stdout: in}})
		out(&armadav1.ExecSessionOutput{Output: &armadav1.ExecSessionOutput_Stderr{Stderr: []byte("cat")}})
		out(&armadav1.ExecSessionOutput{Output: &armadav1.ExecSessionOutput_ExitCode{ExitCode: 2}})
	case "boom":
		out(&armadav1.ExecSessionOutput{Output: &armadav1.ExecSessionOutput_Stdout{Stdout: []byte("partial")}})
		out(&armadav1.ExecSessionOutput{Output: &armadav1.ExecSessionOutput_Error{Error: "the container went away"}})
	case "gone":
		// The node ends its session without an exit code.
		_ = stream.CloseSend()
		return
	default:
		out(&armadav1.ExecSessionOutput{Output: &armadav1.ExecSessionOutput_Stdout{Stdout: []byte(er.GetCmd()[0])}})
		out(&armadav1.ExecSessionOutput{Output: &armadav1.ExecSessionOutput_ExitCode{ExitCode: 0}})
	}
	_ = stream.CloseSend()
	for {
		if _, err := stream.Recv(); err != nil {
			return
		}
	}
}

// requests records and clears what each agent was asked.
func (sc *scenario) requests(label string, agents ...*watchAgent) {
	sc.t.Helper()
	out := map[string]any{}
	for _, w := range agents {
		w.mu.Lock()
		seen := slices.Clone(w.seen)
		slices.Sort(seen)
		execs := slices.Clone(w.execs)
		w.seen, w.execs = nil, nil
		w.mu.Unlock()
		out[w.id] = map[string]any{"logs": seen, "exec": execs}
	}
	sc.note(label, out)
}

// readLogs runs Logs and returns its entries as "replica|stream|data"
// lines in the order they came, and its error.
func (sc *scenario) readLogs(c armadav1.AdminServiceClient, req *armadav1.LogsRequest) ([]string, error) {
	stream, err := c.Logs(sc.ctx, req)
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
		got = append(got, fmt.Sprintf("%s|%s|%s", e.GetReplica(), e.GetStream(), strings.TrimSuffix(string(e.GetData()), "\n")))
	}
}

// logs records Logs as c, its lines sorted (relays of several replicas
// interleave) unless ordered.
func (sc *scenario) logs(label string, c armadav1.AdminServiceClient, req *armadav1.LogsRequest, ordered bool) {
	sc.t.Helper()
	got, err := sc.readLogs(c, req)
	if !ordered {
		slices.Sort(got)
	}
	sc.note(label, map[string]any{"lines": got, "error": errText(err)})
}

func errText(err error) any {
	if err == nil {
		return nil
	}
	st := status.Convert(err)
	return map[string]any{"code": st.Code().String(), "message": st.Message()}
}

// running reports app's replicas running and ready and finishes their
// rollout.
func (sc *scenario) running(app string) {
	sc.t.Helper()
	sc.pass("placed " + app)
	sc.serve(app)
	sc.later("rolled out "+app, 10*time.Second)
}

// shortsOf are the short names of app's replicas by node.
func (sc *scenario) shortsOf(app string) map[string]string {
	sc.t.Helper()
	rs, err := sc.st.ListReplicas(sc.ctx, store.ReplicaFilter{App: app})
	if err != nil {
		sc.t.Fatal(err)
	}
	out := map[string]string{}
	for _, r := range rs {
		out[r.NodeID] = r.ID
	}
	return out
}

// TestLogs, TestLogsFollowGrep, TestLogsOfSilentReplica,
// TestLogsFromDisconnectedNode, and TestLogsFollowEndsWithAccess on both
// servers: live output of every replica or one by its short name, the
// checks of containers and replicas, lines holding a text, the agent's
// error as a notice, a node that is not connected, a follow that picks up
// replicas the app gets later, the slots per caller, and the requests
// each node got and the cancels that end them.
func TestParityLogs(t *testing.T) {
	runParity(t, parityConfig{warmup: time.Second}, func(sc *scenario) {
		n1 := sc.watchAgent("n1", "10.0.0.11", false)
		n2 := sc.watchAgent("n2", "10.0.0.12", false)
		sc.deploy("web", webYAML("1", 2))
		sc.deploy("pod", "name: pod\nimage: nginx:1\nscale:\n  min: 1\ninitContainers:\n  - name: init\n    image: busybox\nsidecars:\n  - name: side\n    image: busybox\n")
		sc.running("web")
		sc.running("pod")
		on := sc.shortsOf("web")
		for node, id := range on {
			w := map[string]*watchAgent{"n1": n1, "n2": n2}[node]
			w.mu.Lock()
			w.live[id] = []string{"start of " + node, "An ERROR on " + node, "fine on " + node}
			w.mu.Unlock()
		}
		sc.logs("all replicas", sc.admin, &armadav1.LogsRequest{App: "web"}, false)
		sc.requests("asked", n1, n2)
		sc.logs("one replica by its short name", sc.admin, &armadav1.LogsRequest{App: "web", Replica: shortReplica(on["n2"]), Tail: 20000}, true)
		sc.logs("lines holding a text", sc.admin, &armadav1.LogsRequest{App: "web", Grep: "eRRor", Tail: 5}, false)
		sc.requests("asked again", n1, n2)
		for _, req := range []*armadav1.LogsRequest{
			{App: "web", Replica: "zzzzz"},
			{App: "web", Container: "Bad Name"},
			{App: "web", Container: "side"},
			{App: "web", Until: timestamppb.New(sc.fx.start)},
			{App: "web", Limit: 3},
			{App: "web", Run: 1},
			{App: "ghost"},
			{App: "pod", Container: "nope"},
		} {
			sc.logs(fmt.Sprintf("refused: %v", req), sc.admin, req, true)
		}
		sc.logs("an init container", sc.admin, &armadav1.LogsRequest{App: "pod", Container: "init"}, false)
		sc.logs("a sidecar", sc.admin, &armadav1.LogsRequest{App: "pod", Container: "side"}, false)

		// The node's error is a notice; a replica on a node that is not
		// connected is one too.
		n1.mu.Lock()
		n1.errs[on["n1"]] = "no such container"
		n1.mu.Unlock()
		sc.node("n3", "10.0.0.13", 4000, 8<<30, nil)
		web, err := sc.st.GetApp(sc.ctx, "web")
		if err != nil {
			t.Fatal(err)
		}
		if err := sc.st.CreateReplica(sc.ctx, store.Replica{ID: "web-r9-away0", App: "web", Revision: web.ActiveRevision, NodeID: "n3"}); err != nil {
			t.Fatal(err)
		}
		sc.logs("an error and a node away", sc.admin, &armadav1.LogsRequest{App: "web"}, false)
		if err := sc.st.DeleteReplica(sc.ctx, "web-r9-away0"); err != nil {
			t.Fatal(err)
		}
		if err := sc.st.SetNodeCordoned(sc.ctx, "n3", true, "user:ryan"); err != nil {
			t.Fatal(err)
		}
		n1.mu.Lock()
		delete(n1.errs, on["n1"])
		n1.mu.Unlock()
		sc.requests("asked with an error", n1, n2)

		// A job's logs need a run.
		sc.deploy("job", "kind: job\nname: once\nimage: busybox\n")
		sc.logs("a job with no runs", sc.admin, &armadav1.LogsRequest{App: "once"}, true)
		sc.logs("a job's run that does not exist", sc.admin, &armadav1.LogsRequest{App: "once", Run: 4}, true)

		// A node cannot push logs nobody asked for.
		push, err := n1.client.PushLogs(sc.ctx)
		if err == nil {
			_ = push.Send(&armadav1.LogPush{RequestId: "unknown"})
			_, err = push.CloseAndRecv()
		}
		sc.note("unknown push", err)

		// Following the whole app: the replicas it gets later follow too.
		ctx, cancel := context.WithCancel(sc.ctx)
		stream, err := sc.admin.Logs(ctx, &armadav1.LogsRequest{App: "web", Follow: true, Tail: 2})
		if err != nil {
			t.Fatal(err)
		}
		lines := make(chan string, 64)
		go func() {
			defer close(lines)
			for {
				e, err := stream.Recv()
				if err != nil {
					return
				}
				lines <- fmt.Sprintf("%s|%s", e.GetReplica(), strings.TrimSuffix(string(e.GetData()), "\n"))
			}
		}()
		take := func(n int) []string {
			var got []string
			for len(got) < n {
				select {
				case l := <-lines:
					got = append(got, l)
				case <-time.After(15 * time.Second):
					t.Fatalf("%s: %d of %d lines: %v", sc.sut.kind(), len(got), n, got)
				}
			}
			slices.Sort(got)
			return got
		}
		sc.note("followed", take(6))
		sc.deploy("web scaled", webYAML("1", 3))
		sc.pass("third placed")
		third := ""
		for node, id := range sc.shortsOf("web") {
			if id != on[node] {
				third = id
			}
		}
		for _, w := range []*watchAgent{n1, n2} {
			w.mu.Lock()
			w.live[third] = []string{"third"}
			w.mu.Unlock()
		}
		sc.serve("web")
		// Which ID the third replica gets depends on when each server
		// allocated IDs before it, so the note names it by its role.
		later := take(1)
		for i, l := range later {
			later[i] = strings.Replace(l, third, "THIRD", 1)
		}
		sc.note("a replica the app got later", later)
		cancel()
		for range lines {
		}
		sc.eventually("cancels", func() bool {
			for _, w := range []*watchAgent{n1, n2} {
				w.mu.Lock()
				open := 0
				for id := range w.open {
					if !w.cancels[id] {
						open++
					}
				}
				w.mu.Unlock()
				if open > 0 {
					return false
				}
			}
			return true
		})
		sc.requests("asked to follow", n1, n2)

		// Eight live calls per caller at once.
		ctx, cancel = context.WithCancel(sc.ctx)
		defer cancel()
		for i := range 8 {
			s, err := sc.admin.Logs(ctx, &armadav1.LogsRequest{App: "web", Replica: on["n1"], Follow: true})
			if err == nil {
				_, err = s.Recv()
			}
			if err != nil {
				t.Fatalf("%s: follow %d: %v", sc.sut.kind(), i, err)
			}
		}
		sc.logs("a ninth", sc.admin, &armadav1.LogsRequest{App: "web", Replica: on["n1"], Follow: true}, true)
		cancel()
	})
}

// TestLogHistorySearch, TestLogHistoryFromForeignNode, and the space's
// earlier history on both servers: entries of every node that keeps a
// history merged by time and cut to the newest limit, a replica that is
// gone, entries only from the node a replica ran on and inside the
// window, the query each node got, the checks of the window, no node with
// a history, a search followed by live output, and a space's history
// from before it was created left out for its own users.
func TestParityLogHistory(t *testing.T) {
	runParity(t, parityConfig{warmup: time.Second}, func(sc *scenario) {
		n3 := sc.watchAgent("n3", "10.0.0.13", false)
		sc.deploy("web", webYAML("1", 2))
		since := timestamppb.New(sc.fx.start.Add(-time.Hour))
		sc.logs("no node keeps a history", sc.admin, &armadav1.LogsRequest{App: "web", Since: since}, true)
		n1 := sc.watchAgent("n1", "10.0.0.11", true)
		n2 := sc.watchAgent("n2", "10.0.0.12", true)
		// Cordoned: the app's replicas run on n1 and n2.
		if err := sc.st.SetNodeCordoned(sc.ctx, "n3", true, "user:ryan"); err != nil {
			t.Fatal(err)
		}
		sc.running("web")
		on := sc.shortsOf("web")
		web, err := sc.st.GetApp(sc.ctx, "web")
		if err != nil {
			t.Fatal(err)
		}
		// A replica that ran on n2 before it was replaced.
		gone := "web-r99-gone0"
		if err := sc.st.CreateReplica(sc.ctx, store.Replica{ID: gone, App: "web", Revision: web.ActiveRevision, NodeID: "n2"}); err != nil {
			t.Fatal(err)
		}
		if err := sc.st.DeleteReplica(sc.ctx, gone); err != nil {
			t.Fatal(err)
		}
		base := sc.fx.start.Add(-time.Hour)
		rec := func(d time.Duration, replica, text string) *armadav1.LogPush {
			return &armadav1.LogPush{Replica: replica, Stream: armadav1.Stream_STREAM_STDOUT, Data: []byte(text + "\n"), Time: timestamppb.New(base.Add(d))}
		}
		n1.history = []*armadav1.LogPush{rec(1*time.Second, on["n1"], "a start"), rec(3*time.Second, on["n1"], "a ERROR db"), rec(5*time.Second, on["n1"], "a done"),
			// Not n1's to answer for: another node's replica, an invented
			// one, one outside the window, and one in the future.
			rec(6*time.Second, on["n2"], "SPOOF other"), rec(7*time.Second, "web-r7-inven", "SPOOF invented"),
			rec(-time.Minute, on["n1"], "before the window"), rec(time.Since(base)+time.Hour, on["n1"], "SPOOF future")}
		n2.history = []*armadav1.LogPush{rec(2*time.Second, gone, "gone ERROR panic"), rec(4*time.Second, on["n2"], "b ok"), rec(time.Second, "api-r1-x", "api")}
		n3.history = []*armadav1.LogPush{rec(time.Second, on["n1"], "never asked")}

		sc.logs("merged by time", sc.admin, &armadav1.LogsRequest{App: "web", Since: since}, true)
		sc.logs("a text, the newest one", sc.admin, &armadav1.LogsRequest{App: "web", Since: since, Grep: "error", Limit: 1}, true)
		sc.logs("a replica that is gone", sc.admin, &armadav1.LogsRequest{App: "web", Replica: gone, Since: since}, true)
		sc.logs("by its short name", sc.admin, &armadav1.LogsRequest{App: "web", Replica: shortReplica(on["n2"]), Since: since}, true)
		sc.logs("until", sc.admin, &armadav1.LogsRequest{App: "web", Since: since, Until: timestamppb.New(base.Add(3 * time.Second))}, true)
		sc.logs("limits", sc.admin, &armadav1.LogsRequest{App: "web", Since: since, Limit: 9000}, true)
		sc.logs("until before since", sc.admin, &armadav1.LogsRequest{App: "web", Since: since, Until: timestamppb.New(base.Add(-time.Second))}, true)
		sc.requests("queries", n1, n2, n3)

		// A search, then live output from now on.
		n1.live[on["n1"]] = []string{"live ok one"}
		n2.live[on["n2"]] = []string{"live ok two"}
		ctx, cancel := context.WithCancel(sc.ctx)
		stream, err := sc.admin.Logs(ctx, &armadav1.LogsRequest{App: "web", Since: since, Grep: "ok", Follow: true})
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for len(got) < 3 {
			e, err := stream.Recv()
			if err != nil {
				t.Fatalf("%s: %v after %v", sc.sut.kind(), err, got)
			}
			got = append(got, e.GetReplica()+"|"+strings.TrimSuffix(string(e.GetData()), "\n"))
		}
		cancel()
		slices.Sort(got[1:])
		sc.note("searched, then followed", got)
		sc.eventually("follows cancelled", func() bool {
			for _, w := range []*watchAgent{n1, n2} {
				w.mu.Lock()
				n := len(w.cancels)
				w.mu.Unlock()
				if n < 2 {
					return false
				}
			}
			return true
		})
		sc.requests("asked to search and follow", n1, n2, n3)

		// A space's own users never see what an earlier space of its name
		// left: their window starts when the space was created.
		sc.advance(time.Hour)
		_, err = sc.admin.CreateSpace(sc.ctx, &armadav1.CreateSpaceRequest{Name: "team"})
		sc.note("space", err)
		created := sc.clock.now()
		resp, err := sc.admin.Deploy(sc.ctx, &armadav1.DeployRequest{Spec: []byte("name: api\nimage: nginx:1\nscale:\n  min: 1\n"), Space: "team"})
		sc.answer("api in team", resp, err)
		sc.running("api.team")
		viewer := sc.user("vera", store.Grant{Role: "viewer", Space: "team"})
		before := timestamppb.New(created.Add(-2 * time.Hour))
		n1.mu.Lock()
		n1.queries = nil
		n1.mu.Unlock()
		sc.logs("a viewer of team", viewer, &armadav1.LogsRequest{App: "api.team", Since: before}, true)
		sc.logs("an admin", sc.admin, &armadav1.LogsRequest{App: "api.team", Since: before}, true)
		n1.mu.Lock()
		var windows []bool
		for _, q := range n1.queries {
			windows = append(windows, q.GetSince().AsTime().Equal(created))
		}
		n1.mu.Unlock()
		sc.note("windows start when the space was created", windows)
		sc.logs("a viewer of another space", viewer, &armadav1.LogsRequest{App: "web", Since: since}, true)
		sc.requests("asked for team", n1, n2, n3)
	})
}

// placements are the placement records' keys.
func (sc *scenario) placements() []string {
	sc.t.Helper()
	resp, err := storetest.Client().Get(sc.ctx, sc.pfx+"placements/", clientv3.WithPrefix(), clientv3.WithKeysOnly())
	if err != nil {
		sc.t.Fatal(err)
	}
	var out []string
	for _, kv := range resp.Kvs {
		out = append(out, strings.TrimPrefix(string(kv.Key), sc.pfx))
	}
	if sc.rec != nil {
		step := sc.rec.add(map[string]any{"op": "keys", "prefix": "placements/"})
		sc.rec.expect(step, "expect", out)
	}
	return out
}

// The pruning of placement records (placementLoop): kept for the log
// retention (the default seven days, or the cluster's) and a day more.
func TestParityPlacementsPruned(t *testing.T) {
	runParity(t, parityConfig{}, func(sc *scenario) {
		sc.deploy("web", webYAML("1", 1))
		web, err := sc.st.GetApp(sc.ctx, "web")
		if err != nil {
			t.Fatal(err)
		}
		sc.node("n1", "10.0.0.11", 1000, 1<<30, nil)
		add := func(id string) {
			if err := sc.st.CreateReplica(sc.ctx, store.Replica{ID: id, App: "web", Revision: web.TargetRevision, NodeID: "n1"}); err != nil {
				t.Fatal(err)
			}
			if err := sc.st.DeleteReplica(sc.ctx, id); err != nil {
				t.Fatal(err)
			}
		}
		add("web-r1-first")
		sc.advance(24 * time.Hour)
		add("web-r2-second")
		prune := func(label string, d time.Duration) {
			sc.advance(d)
			sc.sut.prunePlacements(t)
			sc.note(label, sc.placements())
		}
		prune("within the retention", 7*24*time.Hour)
		prune("the first past the retention and a day", 24*time.Hour+time.Minute)
		_, err = sc.admin.SetClusterConfig(sc.ctx, &armadav1.SetClusterConfigRequest{Config: &armadav1.ClusterConfig{LogRetentionSeconds: 3600}, SetLogRetention: true})
		sc.note("retention of an hour", err)
		add("web-r3-third")
		prune("within an hour and a day", 25*time.Hour-time.Minute)
		prune("past an hour and a day", 2*time.Minute)
	})
}

// TestLogSettings and TestLogExport's settings on both servers: the
// bounds of the history, the export's checks, the token sealed and opened
// into every assignment, none clearing the export, and the audit log.
func TestParityLogSettings(t *testing.T) {
	runParity(t, parityConfig{masterKey: true}, func(sc *scenario) {
		n1 := sc.watchAgent("n1", "10.0.0.11", true)
		set := func(label string, req *armadav1.SetClusterConfigRequest) {
			cc, err := sc.admin.SetClusterConfig(sc.ctx, req)
			if err != nil {
				sc.note(label, err)
				return
			}
			sc.note(label, map[string]any{"retention": cc.GetLogRetentionSeconds(), "maxBytes": cc.GetLogMaxBytes(), "export": cc.GetLogExport(),
				"endpoint": cc.GetLogEndpoint(), "user": cc.GetLogExportUser(), "tenant": cc.GetLogExportTenant(), "token": cc.GetLogTokenSet()})
		}
		cfg := func(c *armadav1.ClusterConfig) *armadav1.ClusterConfig { return c }
		set("history", &armadav1.SetClusterConfigRequest{Config: cfg(&armadav1.ClusterConfig{LogRetentionSeconds: 3 * 86400, LogMaxBytes: 1 << 30}), SetLogRetention: true, SetLogMaxBytes: true})
		sc.pass("pass")
		sc.note("assignment", n1.assignment().GetLogs())
		endpoint := "https://logs.example.com/loki/api/v1/push"
		for _, tc := range []struct {
			name string
			req  *armadav1.SetClusterConfigRequest
		}{
			{"a minute of history", &armadav1.SetClusterConfigRequest{Config: cfg(&armadav1.ClusterConfig{LogRetentionSeconds: 60}), SetLogRetention: true}},
			{"91 days", &armadav1.SetClusterConfigRequest{Config: cfg(&armadav1.ClusterConfig{LogRetentionSeconds: 91 * 86400}), SetLogRetention: true}},
			{"a KiB", &armadav1.SetClusterConfigRequest{Config: cfg(&armadav1.ClusterConfig{LogMaxBytes: 1 << 10}), SetLogMaxBytes: true}},
			{"no endpoint", &armadav1.SetClusterConfigRequest{Config: cfg(&armadav1.ClusterConfig{LogExport: "loki"}), SetLogExport: true}},
			{"public http", &armadav1.SetClusterConfigRequest{Config: cfg(&armadav1.ClusterConfig{LogExport: "loki", LogEndpoint: "http://logs.example.com/push"}), SetLogExport: true}},
			{"credentials in the URL", &armadav1.SetClusterConfigRequest{Config: cfg(&armadav1.ClusterConfig{LogExport: "loki", LogEndpoint: "https://u:p@logs.example.com/push"}), SetLogExport: true}},
			{"a query", &armadav1.SetClusterConfigRequest{Config: cfg(&armadav1.ClusterConfig{LogExport: "loki", LogEndpoint: endpoint + "?a=b"}), SetLogExport: true}},
			{"format", &armadav1.SetClusterConfigRequest{Config: cfg(&armadav1.ClusterConfig{LogExport: "syslog", LogEndpoint: endpoint}), SetLogExport: true}},
			{"token, no sink", &armadav1.SetClusterConfigRequest{SetLogToken: true, LogToken: []byte("tok")}},
			{"user, no token", &armadav1.SetClusterConfigRequest{Config: cfg(&armadav1.ClusterConfig{LogExport: "loki", LogEndpoint: endpoint, LogExportUser: "u"}), SetLogExport: true}},
			{"user with a colon", &armadav1.SetClusterConfigRequest{Config: cfg(&armadav1.ClusterConfig{LogExport: "loki", LogEndpoint: endpoint, LogExportUser: "u:x"}), SetLogExport: true, SetLogToken: true, LogToken: []byte("t")}},
			{"a tenant for otlp", &armadav1.SetClusterConfigRequest{Config: cfg(&armadav1.ClusterConfig{LogExport: "otlp", LogEndpoint: endpoint, LogExportTenant: "t1"}), SetLogExport: true}},
			{"multiline token", &armadav1.SetClusterConfigRequest{Config: cfg(&armadav1.ClusterConfig{LogExport: "loki", LogEndpoint: endpoint}), SetLogExport: true, SetLogToken: true, LogToken: []byte("a\nb")}},
		} {
			set("refused: "+tc.name, tc.req)
		}
		set("loki with a token", &armadav1.SetClusterConfigRequest{Config: cfg(&armadav1.ClusterConfig{LogExport: " loki ", LogEndpoint: endpoint, LogExportUser: "u", LogExportTenant: "t1"}),
			SetLogExport: true, SetLogToken: true, LogToken: []byte(" tok-9\n")})
		sc.pass("pass with the export")
		sc.note("assignment with the export", n1.assignment().GetLogs())
		set("otlp to a private address", &armadav1.SetClusterConfigRequest{Config: cfg(&armadav1.ClusterConfig{LogExport: "otlp", LogEndpoint: "http://10.0.0.9:4318/v1/logs"}), SetLogExport: true, SetLogToken: true})
		set("none", &armadav1.SetClusterConfigRequest{Config: cfg(&armadav1.ClusterConfig{LogExport: "none"}), SetLogExport: true})
		sc.pass("pass without")
		sc.note("assignment without", n1.assignment().GetLogs())
		sc.keyspace("keyspace")
	})
}

// TestExec and TestExecAuthorization on both servers: a command in the
// serving revision's replica or one named, its input and output, the
// audit log naming only the command, the checks of commands, replicas,
// and containers, the node's errors, a node that is not connected or ends
// the session, input after the start and before it, who may exec, and a
// session attached only by the node it was sent to.
func TestParityExec(t *testing.T) {
	runParity(t, parityConfig{warmup: time.Second}, func(sc *scenario) {
		n1 := sc.watchAgent("n1", "10.0.0.11", false)
		n2 := sc.watchAgent("n2", "10.0.0.12", false)
		sc.deploy("web", webYAML("1", 2))
		sc.deploy("pod", "name: pod\nimage: nginx:1\nscale:\n  min: 1\ninitContainers:\n  - name: init\n    image: busybox\nsidecars:\n  - name: side\n    image: busybox\n")
		sc.running("web")
		sc.running("pod")
		on := sc.shortsOf("web")
		run := func(label string, c armadav1.AdminServiceClient, start *armadav1.ExecStart, stdin string) {
			sc.t.Helper()
			stream, err := c.Exec(sc.ctx)
			if err != nil {
				sc.note(label, err)
				return
			}
			var r struct {
				Replica, Stdout, Stderr string
				Exit                    int32
				Error                   any
			}
			if err := stream.Send(&armadav1.ExecClientMessage{Msg: &armadav1.ExecClientMessage_Start{Start: start}}); err == nil && start.GetStdin() {
				_ = stream.Send(&armadav1.ExecClientMessage{Msg: &armadav1.ExecClientMessage_Input{Input: &armadav1.ExecInput{Input: &armadav1.ExecInput_Stdin{Stdin: []byte(stdin)}}}})
				_ = stream.Send(&armadav1.ExecClientMessage{Msg: &armadav1.ExecClientMessage_Input{Input: &armadav1.ExecInput{Input: &armadav1.ExecInput_CloseStdin{CloseStdin: true}}}})
			}
			_ = stream.CloseSend()
			for {
				m, err := stream.Recv()
				if err != nil {
					if !errors.Is(err, io.EOF) {
						r.Error = errText(err)
					}
					break
				}
				switch o := m.GetMsg().(type) {
				case *armadav1.ExecServerMessage_Replica:
					r.Replica = o.Replica
				case *armadav1.ExecServerMessage_Stdout:
					r.Stdout += string(o.Stdout)
				case *armadav1.ExecServerMessage_Stderr:
					r.Stderr += string(o.Stderr)
				case *armadav1.ExecServerMessage_ExitCode:
					r.Exit = o.ExitCode
				}
			}
			sc.note(label, r)
		}
		run("stdin", sc.admin, &armadav1.ExecStart{App: "web", Cmd: []string{"cat", "-", "--secret=hunter2"}, Stdin: true}, "hello")
		run("a terminal", sc.admin, &armadav1.ExecStart{App: "web", Cmd: []string{"/bin/sh"}, Tty: true, Size: &armadav1.TermSize{Rows: 24, Cols: 80}}, "")
		for _, node := range []string{"n1", "n2"} {
			run("by ID on "+node, sc.admin, &armadav1.ExecStart{App: "web", Replica: on[node], Cmd: []string{"true"}}, "")
			run("by short name on "+node, sc.admin, &armadav1.ExecStart{App: "web", Replica: shortReplica(on[node]), Cmd: []string{"true"}}, "")
		}
		run("a sidecar", sc.admin, &armadav1.ExecStart{App: "pod", Container: "side", Cmd: []string{"ls"}}, "")
		run("the app's own", sc.admin, &armadav1.ExecStart{App: "pod", Container: "app", Cmd: []string{"ls"}}, "")
		run("the node's error", sc.admin, &armadav1.ExecStart{App: "web", Cmd: []string{"missing"}}, "")
		run("an error after output", sc.admin, &armadav1.ExecStart{App: "web", Cmd: []string{"boom"}}, "")
		run("the node ends the session", sc.admin, &armadav1.ExecStart{App: "web", Cmd: []string{"gone"}}, "")
		for _, tc := range []struct {
			name  string
			start *armadav1.ExecStart
		}{
			{"unknown app", &armadav1.ExecStart{App: "ghost", Cmd: []string{"sh"}}},
			{"unknown replica", &armadav1.ExecStart{App: "web", Replica: "ghost", Cmd: []string{"sh"}}},
			{"empty command", &armadav1.ExecStart{App: "web"}},
			{"NUL byte", &armadav1.ExecStart{App: "web", Cmd: []string{"sh", "a\x00b"}}},
			{"too many args", &armadav1.ExecStart{App: "web", Cmd: make([]string, 65)}},
			{"a long argument", &armadav1.ExecStart{App: "web", Cmd: []string{"sh", strings.Repeat("x", 4097)}}},
			{"an init container", &armadav1.ExecStart{App: "pod", Container: "init", Cmd: []string{"sh"}}},
			{"no such container", &armadav1.ExecStart{App: "pod", Container: "nope", Cmd: []string{"sh"}}},
			{"a bad container name", &armadav1.ExecStart{App: "pod", Container: "Bad Name", Cmd: []string{"sh"}}},
		} {
			run("refused: "+tc.name, sc.admin, tc.start, "")
		}

		// A second start, oversized input, and input first.
		stream, err := sc.admin.Exec(sc.ctx)
		if err != nil {
			t.Fatal(err)
		}
		start := &armadav1.ExecClientMessage{Msg: &armadav1.ExecClientMessage_Start{Start: &armadav1.ExecStart{App: "web", Replica: on["n1"], Cmd: []string{"cat"}, Stdin: true}}}
		_ = stream.Send(start)
		m, err := stream.Recv()
		sc.note("first message", map[string]any{"replica": m.GetReplica(), "error": errText(err)})
		_ = stream.Send(start)
		for {
			if _, err := stream.Recv(); err != nil {
				sc.note("a second start", err)
				break
			}
		}
		stream, _ = sc.admin.Exec(sc.ctx)
		_ = stream.Send(start)
		_, _ = stream.Recv()
		_ = stream.Send(&armadav1.ExecClientMessage{Msg: &armadav1.ExecClientMessage_Input{Input: &armadav1.ExecInput{Input: &armadav1.ExecInput_Stdin{Stdin: make([]byte, 32<<10+1)}}}})
		for {
			if _, err := stream.Recv(); err != nil {
				sc.note("oversized input", err)
				break
			}
		}
		stream, _ = sc.admin.Exec(sc.ctx)
		_ = stream.Send(&armadav1.ExecClientMessage{Msg: &armadav1.ExecClientMessage_Input{Input: &armadav1.ExecInput{}}})
		_, err = stream.Recv()
		sc.note("input first", err)

		// A replica that is not running, and one on a node away.
		sc.node("n3", "10.0.0.13", 4000, 8<<30, nil)
		web, err := sc.st.GetApp(sc.ctx, "web")
		if err != nil {
			t.Fatal(err)
		}
		r := store.Replica{ID: "web-r9-away0", App: "web", Revision: web.ActiveRevision, NodeID: "n3"}
		if err := sc.st.CreateReplica(sc.ctx, r); err != nil {
			t.Fatal(err)
		}
		run("a pending replica", sc.admin, &armadav1.ExecStart{App: "web", Replica: "away0", Cmd: []string{"sh"}}, "")
		sc.report(r, store.ReplicaRunning, true, "")
		run("a node that is not connected", sc.admin, &armadav1.ExecStart{App: "web", Replica: "away0", Cmd: []string{"sh"}}, "")
		if err := sc.st.DeleteReplica(sc.ctx, r.ID); err != nil {
			t.Fatal(err)
		}

		// Who may exec.
		viewer := sc.user("vera", store.Grant{Role: "viewer", Space: ""})
		run("a viewer", viewer, &armadav1.ExecStart{App: "web", Cmd: []string{"sh"}}, "")
		node := armadav1.NewAdminServiceClient(sc.dial(pki.Identity{Kind: pki.KindNode, Name: "n1"}))
		run("a node", node, &armadav1.ExecStart{App: "web", Cmd: []string{"sh"}}, "")
		admin := armadav1.NewAgentServiceClient(sc.dial(pki.Identity{Kind: pki.KindAdmin, Name: "ryan"}))
		sess, err := admin.ExecSession(sc.ctx)
		if err == nil {
			_ = sess.Send(&armadav1.ExecSessionOutput{RequestId: "x"})
			_, err = sess.Recv()
		}
		sc.note("an admin opening a session", err)
		sess, err = n1.client.ExecSession(sc.ctx)
		if err == nil {
			_ = sess.Send(&armadav1.ExecSessionOutput{RequestId: "unknown"})
			_, err = sess.Recv()
		}
		sc.note("an unknown session", err)
		// n1's request attached by n2: refused, and the exec waits for its
		// node in vain.
		n1.mu.Lock()
		n1.attachAs = n2.client
		n1.mu.Unlock()
		run("attached by another node", sc.admin, &armadav1.ExecStart{App: "web", Replica: on["n1"], Cmd: []string{"sh"}}, "")
		sc.note("the other node's attach", <-n1.attached)
		sc.requests("execs", n1, n2)
		sc.keyspace("keyspace")
	})
}
