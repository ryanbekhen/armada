package agent

import (
	"bufio"
	"bytes"
	"context"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/runtime/fake"
)

// fakeRedis answers AUTH with the password pw and LLEN of any list with
// length; it returns its address.
func fakeRedis(t *testing.T, pw string, length *atomic.Int64) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				r := bufio.NewReader(conn)
				for {
					line, err := r.ReadString('\n')
					if err != nil || len(line) < 2 {
						return
					}
					n, _ := strconv.Atoi(strings.TrimSpace(line[1:]))
					args := make([]string, n)
					for i := range args {
						_, _ = r.ReadString('\n')
						a, _ := r.ReadString('\n')
						args[i] = strings.TrimSuffix(a, "\r\n")
					}
					switch {
					case len(args) == 2 && args[0] == "AUTH" && args[1] == pw:
						_, _ = conn.Write([]byte("+OK\r\n"))
					case len(args) == 2 && args[0] == "LLEN":
						_, _ = conn.Write([]byte(":" + strconv.FormatInt(length.Load(), 10) + "\r\n"))
					default:
						_, _ = conn.Write([]byte("-ERR\r\n"))
					}
				}
			}()
		}
	}()
	return l.Addr().String()
}

// lockedLog is a log destination tests read.
type lockedLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *lockedLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *lockedLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func sandboxAgent(t *testing.T, d *fake.Driver) (*Agent, *recordingNet, *lockedLog) {
	t.Helper()
	nw := &recordingNet{}
	logs := &lockedLog{}
	a := New(Config{NodeID: "n1", PrivateIP: "10.0.0.2", Driver: d, Unpublished: true, Network: nw, SandboxInterval: time.Millisecond,
		Logger: slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))})
	a.setNetwork(&armadav1.NetworkConfig{Mode: "plain", ClusterCidr: "10.120.0.0/16"})
	return a, nw, logs
}

// A node keeps a network sandbox for each job queue the leader gives it,
// adopts the ones it already has, removes the others, reads each queue from
// its sandbox, and reports the length with the sandbox's address; the
// firewall knows the address as the job's (ADR 0040).
func TestSandboxLifecycle(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	var length atomic.Int64
	length.Store(7)
	addr := fakeRedis(t, "s3cret-pw", &length)
	d := fake.New()
	d.BridgeIPs = "10.120.0."
	// Left by the agent before a restart: one still wanted, one not.
	kept, _ := d.EnsureSandbox(ctx, "mailer.shop")
	if _, err := d.EnsureSandbox(ctx, "gone"); err != nil {
		t.Fatal(err)
	}
	a, nw, logs := sandboxAgent(t, d)
	if !a.sandboxesOn() {
		t.Fatal("sandboxes off on a node of a cluster network")
	}

	// Before the first assignment nothing is removed.
	a.syncSandboxes(ctx)
	if got := d.Sandboxes(); !slices.Equal(got, []string{"gone", "mailer.shop"}) {
		t.Fatalf("before an assignment: %v", got)
	}

	probe := &armadav1.QueueProbe{Type: "redis", Url: "redis://:s3cret-pw@" + addr, UrlRef: "redis-url@v1", Name: "mail:outbox"}
	a.setSandboxes([]*armadav1.QueueSandbox{
		{Job: "mailer.shop", Probe: probe, IntervalSeconds: 30},
		{Job: "../etc", Probe: probe},                            // not an ID
		{Job: "cmd", Probe: &armadav1.QueueProbe{Type: "queue"}}, // not read from a sandbox
	})
	a.syncSandboxes(ctx)
	if got := d.Sandboxes(); !slices.Equal(got, []string{"mailer.shop"}) {
		t.Fatalf("sandboxes = %v", got)
	}
	if d.SandboxCreates != 2 {
		t.Errorf("made %d sandboxes, want only the two before the restart (adopted, not made again)", d.SandboxCreates)
	}
	ip := netip.MustParseAddr(kept.IP)
	nw.mu.Lock()
	app, known := nw.local[ip]
	nw.mu.Unlock()
	if !known || app != "mailer.shop" {
		t.Errorf("the firewall knows %s as %q (%v)", ip, app, known)
	}
	rep := a.sandboxReport(time.Now())
	if len(rep) != 1 || rep[0].GetJob() != "mailer.shop" || rep[0].GetIp() != kept.IP || !rep[0].GetMeasured() || rep[0].GetLength() != 7 || rep[0].GetReading() != 1 {
		t.Fatalf("report = %v", rep)
	}
	if !slices.ContainsFunc(d.SandboxDials, func(s string) bool { return s == "mailer.shop "+addr }) {
		t.Errorf("dials = %v", d.SandboxDials)
	}

	// Every interval a new reading.
	length.Store(120)
	time.Sleep(5 * time.Millisecond)
	a.syncSandboxes(ctx)
	rep = a.sandboxReport(time.Now())
	if len(rep) != 1 || rep[0].GetLength() != 120 || rep[0].GetReading() != 2 {
		t.Fatalf("second reading: %v", rep)
	}
	// A reading ages out of reports; the sandbox's address stays.
	if rep := a.sandboxReport(time.Now().Add(time.Minute)); len(rep) != 1 || rep[0].GetMeasured() || rep[0].GetIp() != kept.IP {
		t.Errorf("stale reading reported: %v", rep)
	}

	// listLocal finds the sandbox on every pass.
	local, err := a.listLocal(ctx)
	if err != nil || local[ip] != "mailer.shop" {
		t.Errorf("listLocal = %v, %v", local, err)
	}

	// A broker that refuses: the reading is not taken, and the URL with its
	// password stays out of the log.
	bad := &armadav1.QueueProbe{Type: "redis", Url: "redis://:wrong-pw@" + addr, UrlRef: "redis-url@v2", Name: "mail:outbox"}
	a.setSandboxes([]*armadav1.QueueSandbox{{Job: "mailer.shop", Probe: bad, IntervalSeconds: 30}})
	time.Sleep(5 * time.Millisecond)
	a.syncSandboxes(ctx)
	if rep := a.sandboxReport(time.Now()); len(rep) != 1 || rep[0].GetMeasured() {
		t.Errorf("a refused reading, or the length of the old URL, reported: %v", rep)
	}
	if out := logs.String(); !strings.Contains(out, "job queue not read") || strings.Contains(out, "wrong-pw") || strings.Contains(out, "s3cret-pw") {
		t.Errorf("log:\n%s", out)
	}

	// Gone from the assignment: removed, and no longer the job's address.
	a.setSandboxes(nil)
	a.syncSandboxes(ctx)
	if got := d.Sandboxes(); len(got) != 0 {
		t.Errorf("after removal: %v", got)
	}
	if rep := a.sandboxReport(time.Now()); len(rep) != 0 {
		t.Errorf("report after removal: %v", rep)
	}
	a.mu.Lock()
	_, still := a.local[ip]
	a.mu.Unlock()
	if still {
		t.Error("a removed sandbox's address is still the job's")
	}
}

// Sandboxes are only kept on a node of a cluster network: never from the
// host's own network, which would bypass the firewall.
func TestSandboxesNeedClusterNetwork(t *testing.T) {
	t.Parallel()
	d := fake.New()
	a := New(Config{NodeID: "n1", PrivateIP: "10.0.0.2", Driver: d})
	if a.sandboxesOn() {
		t.Error("sandboxes without a cluster network")
	}
	b := New(Config{NodeID: "n1", PrivateIP: "10.0.0.2", Driver: d, Unpublished: true, Network: &recordingNet{}})
	d.NoSandboxes = true
	if b.sandboxesOn() {
		t.Error("sandboxes on a runtime without them")
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	a.sandboxLoop(ctx) // returns at once
	if len(d.Sandboxes()) != 0 {
		t.Error("made a sandbox")
	}
}
