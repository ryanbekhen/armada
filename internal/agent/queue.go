package agent

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/queuelen"
	"github.com/ryanbekhen/armada/internal/runtime"
	"github.com/ryanbekhen/armada/internal/spec"
)

const (
	defaultQueueInterval = 15 * time.Second
	// queueTimeout bounds one run of a queue rule's command.
	queueTimeout = 10 * time.Second
	// maxQueueOutput is the most a queue command may print: a number.
	maxQueueOutput = 64
	// maxQueueLength bounds the length an agent reports.
	maxQueueLength = 1 << 40
	// maxQueueApps bounds the queue commands one pass runs.
	maxQueueApps = 32
)

// queueLengths holds the latest length read for each queue rule of the
// apps on the node, by the replica it was read from (ADR 0034).
type queueLengths struct {
	mu sync.Mutex
	m  map[queueKey]queueLength // latest reading
}

// queueKey names one queue rule: an app has at most one of each type.
type queueKey struct{ app, typ string }

type queueLength struct {
	replica string
	length  int64
	at      time.Time
}

func (q *queueLengths) set(k queueKey, l queueLength) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.m == nil {
		q.m = map[queueKey]queueLength{}
	}
	q.m[k] = l
}

// keep drops readings of rules no app on the node has anymore.
func (q *queueLengths) keep(rules map[queueKey]bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for k := range q.m {
		if !rules[k] {
			delete(q.m, k)
		}
	}
}

// fresh returns the readings taken within maxAge of now, for a usage report.
func (q *queueLengths) fresh(now time.Time, maxAge time.Duration) []*armadav1.QueueLength {
	q.mu.Lock()
	defer q.mu.Unlock()
	var out []*armadav1.QueueLength
	for k, l := range q.m {
		if now.Sub(l.at) <= maxAge {
			out = append(out, &armadav1.QueueLength{Id: l.replica, Length: l.length, Type: k.typ})
		}
	}
	slices.SortFunc(out, func(a, b *armadav1.QueueLength) int {
		return cmp.Or(cmp.Compare(a.GetId(), b.GetId()), cmp.Compare(a.GetType(), b.GetType()))
	})
	return out
}

// queueLoop reads every queue rule of the apps on the node from one ready
// replica of each app, every QueueInterval, and keeps the lengths for the
// next usage report (ADR 0034).
func (a *Agent) queueLoop(ctx context.Context) {
	if !runtime.CanExec(a.cfg.Driver) && !runtime.CanDial(a.cfg.Driver) {
		return
	}
	t := time.NewTicker(a.cfg.QueueInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		a.measureQueues(ctx)
	}
}

// queueTarget is the replica a queue rule is read from.
type queueTarget struct {
	app, replica, container string
	probe                   *armadav1.QueueProbe
}

func (a *Agent) measureQueues(ctx context.Context) {
	targets := a.queueTargets(ctx)
	rules := map[queueKey]bool{}
	for _, t := range targets {
		rules[queueKey{t.app, t.probe.GetType()}] = true
	}
	a.queues.keep(rules)
	for _, t := range targets {
		n, err := a.readQueue(ctx, t.container, t.probe)
		if err != nil {
			// The command's arguments and the broker's URL stay out of logs.
			a.log.Debug("queue rule", "app", t.app, "type", t.probe.GetType(), "replica", t.replica, "err", err)
			continue
		}
		a.queues.set(queueKey{t.app, t.probe.GetType()}, queueLength{replica: t.replica, length: n, at: time.Now()})
	}
}

// queueTargets picks, for every app with queue rules, the ready replica on
// this node with the lowest ID, once per rule.
func (a *Agent) queueTargets(ctx context.Context) []queueTarget {
	a.mu.Lock()
	specs := map[string]*armadav1.ReplicaSpec{}
	for id, s := range a.desired {
		if len(s.GetQueues()) > 0 && s.GetJob() == nil {
			specs[id] = s
		}
	}
	a.mu.Unlock()
	if len(specs) == 0 {
		return nil
	}
	cs, err := a.cfg.Driver.List(ctx, map[string]string{runtime.LabelManaged: "true"})
	if err != nil {
		return nil
	}
	type pick struct {
		replica, container string
		s                  *armadav1.ReplicaSpec
	}
	best := map[string]pick{}
	for _, c := range cs {
		id := c.Labels[runtime.LabelReplica]
		s := specs[id]
		if s == nil || c.State != runtime.StateRunning || !a.replicaReady(id, c.ID) {
			continue
		}
		if cur, ok := best[s.GetApp()]; !ok || id < cur.replica {
			best[s.GetApp()] = pick{replica: id, container: c.ID, s: s}
		}
	}
	var out []queueTarget
	for app, p := range best {
		for _, q := range p.s.GetQueues() {
			out = append(out, queueTarget{app: app, replica: p.replica, container: p.container, probe: q})
		}
	}
	slices.SortFunc(out, func(x, y queueTarget) int {
		return cmp.Or(cmp.Compare(x.app, y.app), cmp.Compare(x.probe.GetType(), y.probe.GetType()))
	})
	if len(out) > maxQueueApps {
		out = out[:maxQueueApps]
	}
	return out
}

// replicaReady reports whether the probes of replica's container passed.
func (a *Agent) replicaReady(replica, container string) bool {
	a.mu.Lock()
	w := a.probes[replica]
	a.mu.Unlock()
	if w == nil || w.containerID != container {
		return false
	}
	ready, _ := w.status()
	return ready
}

// limitedBuffer keeps at most max bytes and notes whether more came.
type limitedBuffer struct {
	buf  bytes.Buffer
	max  int
	over bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := b.max - b.buf.Len(); len(p) > room {
		b.over = true
		p = p[:max(room, 0)]
	}
	b.buf.Write(p)
	return len(p), nil
}

// readQueue reads one queue rule from the container: by running its
// command, or by dialling the broker from the container's network
// namespace.
func (a *Agent) readQueue(ctx context.Context, container string, p *armadav1.QueueProbe) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, queueTimeout)
	defer cancel()
	switch p.GetType() {
	case spec.ScaleRedis:
		return queuelen.RedisListLength(ctx, a.containerDialer(container), p.GetUrl(), p.GetName())
	case spec.ScaleRabbitMQ:
		return queuelen.RabbitMQQueueLength(ctx, a.containerDialer(container), p.GetUrl(), p.GetName())
	case spec.ScaleQueue:
		return a.runQueueCommand(ctx, container, p.GetCommand())
	}
	return 0, errors.New("unknown queue rule " + strconv.Quote(p.GetType()))
}

// runQueueCommand runs cmd in the container with its own security settings
// and reads the number it prints. Its error output is dropped.
func (a *Agent) runQueueCommand(ctx context.Context, container string, cmd []string) (int64, error) {
	ex, ok := a.cfg.Driver.(runtime.Execer)
	if !ok || !runtime.CanExec(a.cfg.Driver) {
		return 0, errors.New("this node's runtime cannot run commands in containers")
	}
	if err := runtime.CheckExecCommand(cmd); err != nil {
		return 0, err
	}
	out := &limitedBuffer{max: maxQueueOutput}
	code, err := ex.ExecApp(ctx, container, runtime.ExecOptions{Cmd: cmd, Stdout: out, Stderr: io.Discard})
	switch {
	case ctx.Err() != nil:
		return 0, errors.New("command timed out")
	case err != nil:
		return 0, errors.New("could not run the command; is the program in the image?")
	case code != 0:
		return 0, errors.New("command exited with code " + strconv.Itoa(code))
	case out.over:
		return 0, errors.New("command printed more than a number")
	}
	n, err := strconv.ParseInt(string(bytes.TrimSpace(out.buf.Bytes())), 10, 64)
	if err != nil || n < 0 || n > maxQueueLength {
		return 0, errors.New("command did not print a whole number between 0 and 2^40")
	}
	return n, nil
}

// containerDialer dials from the container's network namespace. Names are
// resolved there too, through the nameserver the container uses.
func (a *Agent) containerDialer(container string) queuelen.Dialer {
	return a.namespaceDialer(func(ctx context.Context, network, address string) (net.Conn, error) {
		cd, ok := a.cfg.Driver.(runtime.ContainerDialer)
		if !ok || !runtime.CanDial(a.cfg.Driver) {
			return nil, errors.New("this node's runtime cannot dial from containers")
		}
		return cd.DialContainer(ctx, container, network, address)
	})
}

// namespaceDialer dials through dial, which dials IP addresses from one
// network namespace, and resolves names from there too, through the
// nameserver containers use.
func (a *Agent) namespaceDialer(dial queuelen.Dialer) queuelen.Dialer {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		if _, err := netip.ParseAddr(host); err == nil {
			return dial(ctx, network, address)
		}
		ns := a.containerNameserver()
		if ns == "" {
			return nil, errors.New("no nameserver to resolve the broker's name")
		}
		r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, nw, _ string) (net.Conn, error) {
			return dial(ctx, nw, ns)
		}}
		ips, err := r.LookupNetIP(ctx, "ip", host)
		if err != nil || len(ips) == 0 {
			return nil, errors.New("cannot resolve the broker's name from the namespace")
		}
		var last error
		for _, ip := range ips {
			c, err := dial(ctx, network, net.JoinHostPort(ip.Unmap().String(), port))
			if err == nil {
				return c, nil
			}
			last = err
		}
		return nil, last
	}
}

// containerNameserver is host:53 of the resolver containers use: the
// node's internal DNS, else the host's first nameserver.
func (a *Agent) containerNameserver() string {
	if a.cfg.DNS != nil {
		if addr := a.cfg.DNS.Address(); addr != "" {
			return net.JoinHostPort(addr, "53")
		}
	}
	b, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return ""
	}
	for line := range strings.Lines(string(b)) {
		if f := strings.Fields(line); len(f) >= 2 && f[0] == "nameserver" {
			if ip, err := netip.ParseAddr(f[1]); err == nil && !ip.IsLoopback() {
				return net.JoinHostPort(ip.String(), "53")
			}
		}
	}
	return ""
}
