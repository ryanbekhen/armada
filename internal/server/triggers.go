package server

import (
	"context"
	"fmt"
	"hash/fnv"
	"strconv"
	"sync"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/spec"
	"github.com/ryanbekhen/armada/internal/store"
)

// queueTriggers is what the leader keeps about jobs that a queue starts
// (ADR 0040), in memory only: a new leader picks the same nodes and has a
// reading again after one polling interval.
type queueTriggers struct {
	mu sync.Mutex
	// nodes is the node that reads each job's queue, from the latest pass;
	// empty when no node can.
	nodes map[string]string
	// acted is the reading runs were last started for, by job: each reading
	// starts runs once, so runs that end between two readings are not
	// replaced on the strength of a length that is already out of date.
	acted map[string]actedReading
}

type actedReading struct {
	node    string
	reading int64
}

func newQueueTriggers() *queueTriggers {
	return &queueTriggers{nodes: map[string]string{}, acted: map[string]actedReading{}}
}

func (q *queueTriggers) node(job string) string {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.nodes[job]
}

// keep forgets jobs that no longer have a queue trigger.
func (q *queueTriggers) keep(jobs map[string]bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for j := range q.nodes {
		if !jobs[j] {
			delete(q.nodes, j)
		}
	}
	for j := range q.acted {
		if !jobs[j] {
			delete(q.acted, j)
		}
	}
}

// sandboxNodes returns the connected nodes whose agents read job queues from
// network sandboxes.
func (s *Server) sandboxNodes() map[string]bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]bool{}
	for id, sess := range s.sessions {
		if sess.sandboxes {
			out[id] = true
		}
	}
	return out
}

// probeNode picks the node that reads a job's queue: one the job may run on
// (eligible), with a subnet of the cluster network, connected, not lost,
// and whose agent keeps sandboxes. Of those it takes the one whose hash with
// the job is highest, so a job stays on its node while that node fits, jobs
// spread over the nodes, and every leader picks the same node.
func probeNode(job string, nodes []store.Node, rev store.Revision, lost, sandboxes map[string]bool) (string, bool) {
	best, bestHash := "", uint64(0)
	for _, n := range eligible(nodes, rev) {
		if n.Subnet == "" || !n.Jobs || lost[n.ID] || !sandboxes[n.ID] {
			continue
		}
		h := fnv.New64a()
		_, _ = h.Write([]byte(job + "\x00" + n.ID))
		if v := h.Sum64(); best == "" || v > bestHash || (v == bestHash && n.ID < best) {
			best, bestHash = n.ID, v
		}
	}
	return best, best != ""
}

// queueReading returns what node last reported of job's sandbox, if the
// node's sample is recent; fresh says the length is too: read within two
// polling intervals.
func (s *Server) queueReading(job, node string, every time.Duration, now time.Time) (r sandboxReading, fresh bool) {
	n, ok := s.usage.node(node, now)
	if !ok {
		return sandboxReading{}, false
	}
	r, ok = n.sandboxes[job]
	if !ok {
		return sandboxReading{}, false
	}
	return r, r.measured && now.Sub(r.at) <= 2*every+usageMaxAge
}

// triggerJob keeps the job's queue read from a network sandbox on one node
// and starts runs for what waits in it: ⌈length ÷ perRun⌉ runs at most
// trigger.parallelism, less the active ones, once per reading. Without a
// recent reading it starts nothing.
func (s *Server) triggerJob(ctx context.Context, rc *reconcileRun, job store.App, runs []store.JobRun, nodes []store.Node, revs *revisionCache) []store.JobRun {
	rev, err := revs.get(ctx, job.ActiveRevision)
	if err != nil {
		return runs
	}
	t := rev.Spec.Trigger
	q := rev.Spec.QueueTrigger()
	if q == nil {
		return runs
	}
	rc.triggered[job.Name] = true
	node, ok := probeNode(job.Name, nodes, rev, rc.lost, rc.sandboxNodes)
	s.condition(ctx, "job-queue:"+job.Name, !ok, store.Event{Kind: eventJob, Object: job.Name, App: job.Name, Reason: "QueueUnread",
		Message: "no node can read the queue: it needs a connected node the job may run on, in the cluster network, whose agent reads queues"})
	s.triggers.mu.Lock()
	s.triggers.nodes[job.Name] = node
	s.triggers.mu.Unlock()
	if !ok {
		return runs
	}
	vals, err := revs.secrets(ctx, rev)
	v, has := vals[q.URLSecretRef]
	if err != nil || !has {
		// The job keeps its runs; the queue is not read until the secret opens.
		s.log.Error("job queue URL", "job", job.Name, "err", err)
		return runs
	}
	every := t.PollEvery()
	rc.sandboxes[node] = append(rc.sandboxes[node], &armadav1.QueueSandbox{
		Job: job.Name,
		Probe: &armadav1.QueueProbe{
			Type: q.Type, Url: string(v.Bytes()), Name: q.Name(),
			UrlRef: q.URLSecretRef + "@v" + strconv.Itoa(rev.Secrets[q.URLSecretRef]),
		},
		IntervalSeconds: int64(every / time.Second),
	})
	r, fresh := s.queueReading(job.Name, node, every, rc.now)
	if r.ip != "" {
		// The firewalls of every node know the sandbox as the job's.
		rc.sandboxAddrs = append(rc.sandboxAddrs, store.Replica{ID: "sandbox:" + job.Name, App: job.Name, NodeID: node, IP: r.ip})
	}
	if !fresh {
		return runs
	}
	key := actedReading{node: node, reading: r.reading}
	s.triggers.mu.Lock()
	acted := s.triggers.acted[job.Name] == key
	s.triggers.acted[job.Name] = key
	s.triggers.mu.Unlock()
	if acted {
		return runs
	}
	active := 0
	for _, x := range runs {
		if x.Active() {
			active++
		}
	}
	start := min(t.RunsWanted(r.length)-active, spec.MaxJobParallelism)
	if start <= 0 {
		return runs
	}
	started := 0
	for range start {
		run, err := s.store.CreateJobRun(ctx, job.Name, store.TriggerQueue, time.Time{}, "")
		if err != nil {
			s.log.Error("start a run for the job's queue", "job", job.Name, "err", err)
			break
		}
		runs = append(runs, run)
		started++
	}
	if started > 0 {
		s.log.Info("job runs started for its queue", "job", job.Name, "runs", started, "length", r.length)
		s.record(ctx, store.Event{Kind: eventJob, Object: job.Name, App: job.Name, Reason: "QueueTriggered",
			Message: fmt.Sprintf("%d run(s) started: %d message(s) waiting, %d per run, %d already active, at most %d", started, r.length, q.PerRun, active, t.MaxRuns())})
	}
	return runs
}

// jobTrigger describes a job's queue trigger with what was last read.
func (s *Server) jobTrigger(a store.App) *armadav1.JobTrigger {
	t, q := a.Spec.Trigger, a.Spec.QueueTrigger()
	if q == nil {
		return nil
	}
	out := &armadav1.JobTrigger{
		Type: q.Type, Name: q.Name(), PerRun: q.PerRun,
		Parallelism:            int32(t.MaxRuns()), //nolint:gosec // validated to at most spec.MaxJobParallelism
		PollingIntervalSeconds: int64(t.PollEvery() / time.Second),
		Node:                   s.triggers.node(a.Name),
	}
	if out.Node == "" {
		return out
	}
	if r, fresh := s.queueReading(a.Name, out.Node, t.PollEvery(), s.now()); fresh {
		out.Measured, out.Length, out.MeasuredAt = true, r.length, timestamppb.New(r.at)
	}
	return out
}
