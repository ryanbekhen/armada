package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/ryanbekhen/armada/internal/secrets"
	"github.com/ryanbekhen/armada/internal/spec"
)

// Etcd stores cluster state in etcd. Every record is a JSON value under
// Prefix; see the key layout below.
//
// Transactions are optimistic and serializable: a transaction reads a
// consistent snapshot at one etcd revision, buffers its writes, and commits
// them atomically only if no other transaction committed in between, which
// it detects through a single commit key that every write updates. On a
// conflict the transaction runs again. The control plane writes rarely, so
// serializing all writes costs nothing and keeps the semantics simple: every
// multi-record invariant (unique host+path routes, single-use join tokens,
// revision pruning) holds as if there were one writer.
type Etcd struct {
	c      *clientv3.Client
	prefix string
	now    func() time.Time
	// fenceKey and fenceRev, if set, guard every commit: see Fenced.
	fenceKey string
	fenceRev int64
	leases   *eventLeases
}

// Key layout below the prefix.
const (
	keyCommit   = "commit"
	keyAuditSeq = "auditseq"
	keySchema   = "schema"
	pfxMeta     = "meta/"
	pfxNodes    = "nodes/"
	pfxCerts    = "nodecerts/" // nodecerts/<node>/<serial>
	pfxTokens   = "tokens/"
	pfxApps     = "apps/"
	pfxRevs     = "revs/" // revs/<app>/<seq, 10 digits>
	pfxReplicas = "replicas/"
	pfxSecrets  = "secrets/" // secrets/<app>/<name>/<version, 10 digits>
	pfxDomains  = "domains/"
	pfxAudit    = "audit/" // audit/<id, 20 digits>
	pfxServers  = "servers/"
	pfxRuns     = "runs/"    // runs/<job>/<seq, 10 digits>
	pfxVolumes  = "volumes/" // volumes/<app>/<name>
	// Apps are keyed by their ID (spec.AppID): the name in the default
	// project, <name>.<project> in others (ADR 0026). Projects live under
	// pfxProjects (projects.go).
	// pfxEvents (events.go) holds expiring events; older binaries ignore
	// the prefix, so it needs no schema step.

	// etcdSchema is the version of the key layout. Bump it with a step in
	// migrations when records change incompatibly. Records under servers/
	// and meta/ are read and written by every server, whatever its schema,
	// so they only ever gain optional fields.
	etcdSchema = 8

	maxTxnRetries = 100
	// auditKeep is how many audit events are retained.
	auditKeep = 10_000
)

// NewEtcd returns a store using c under prefix (e.g. "/armada/"), after
// checking the stored schema version.
func NewEtcd(ctx context.Context, c *clientv3.Client, prefix string) (*Etcd, error) {
	if !strings.HasSuffix(prefix, "/") {
		return nil, errors.New("store: etcd prefix must end with /")
	}
	s := &Etcd{c: c, prefix: prefix, now: time.Now, leases: &eventLeases{}}
	err := s.tx(ctx, func(t *etx) error {
		var v int
		ok, err := t.get(keySchema, &v)
		if err != nil {
			return err
		}
		switch {
		case !ok:
			return t.put(keySchema, etcdSchema)
		case v > etcdSchema:
			return fmt.Errorf("the state was written by a newer Armada (schema %d, this binary knows %d); run the newer version (downgrades are not supported)", v, etcdSchema)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return s, nil
}

// SetNow replaces the clock used for timestamps. It is meant for tests that
// drive time by hand and must be called before concurrent use.
func (s *Etcd) SetNow(now func() time.Time) { s.now = now }

// Fenced returns a store whose writes commit only while the etcd key exists
// with the given creation revision: the leader election key of one
// leadership term. A leader that lost its term (a network partition, a
// paused process) cannot overwrite what the new leader decides; its writes
// fail with ErrNotLeader.
func (s *Etcd) Fenced(key string, rev int64) *Etcd {
	f := *s
	f.fenceKey, f.fenceRev = key, rev
	return &f
}

// fenceHolds reports whether the fence key still has its revision.
func (s *Etcd) fenceHolds(ctx context.Context) (bool, error) {
	resp, err := s.c.Get(ctx, s.fenceKey)
	if err != nil {
		return false, err
	}
	return len(resp.Kvs) == 1 && resp.Kvs[0].CreateRevision == s.fenceRev, nil
}

// Close does nothing: the client belongs to the caller.
func (s *Etcd) Close() error { return nil }

// etx is one optimistic transaction.
type etx struct {
	ctx context.Context
	s   *Etcd
	rev int64
	// ops holds buffered writes by key; a nil value is a delete.
	ops map[string][]byte
	del map[string]bool
}

type kv struct {
	key string // without the store prefix
	val []byte
}

func (t *etx) full(k string) string { return t.s.prefix + k }

func (t *etx) getRaw(k string) ([]byte, bool, error) {
	if t.del[k] {
		return nil, false, nil
	}
	if v, ok := t.ops[k]; ok {
		return v, true, nil
	}
	resp, err := t.s.c.Get(t.ctx, t.full(k), clientv3.WithRev(t.rev))
	if err != nil {
		return nil, false, err
	}
	if len(resp.Kvs) == 0 {
		return nil, false, nil
	}
	return resp.Kvs[0].Value, true, nil
}

// readBatch is how many keys one read asks for: etcd allows 128 operations in
// a transaction unless configured otherwise.
const readBatch = 128

// getMany returns the records at keys that exist, by key, in as few round trips
// as the batch size allows, including writes buffered in this transaction.
func (t *etx) getMany(keys []string) (map[string][]byte, error) {
	out := make(map[string][]byte, len(keys))
	var remote []string
	for _, k := range keys {
		if t.del[k] {
			continue
		}
		if v, ok := t.ops[k]; ok {
			out[k] = v
			continue
		}
		remote = append(remote, k)
	}
	for batch := range slices.Chunk(remote, readBatch) {
		ops := make([]clientv3.Op, 0, len(batch))
		for _, k := range batch {
			ops = append(ops, clientv3.OpGet(t.full(k), clientv3.WithRev(t.rev)))
		}
		resp, err := t.s.c.Txn(t.ctx).Then(ops...).Commit()
		if err != nil {
			return nil, err
		}
		for i, r := range resp.Responses {
			if kvs := r.GetResponseRange().GetKvs(); len(kvs) > 0 {
				out[batch[i]] = kvs[0].Value
			}
		}
	}
	return out, nil
}

// get decodes the record at k into v and reports whether it exists.
func (t *etx) get(k string, v any) (bool, error) {
	b, ok, err := t.getRaw(k)
	if err != nil || !ok {
		return false, err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return false, fmt.Errorf("decode %s: %w", k, err)
	}
	return true, nil
}

// list returns the records under prefix in key order, including writes
// buffered in this transaction.
func (t *etx) list(prefix string) ([]kv, error) {
	resp, err := t.s.c.Get(t.ctx, t.full(prefix), clientv3.WithPrefix(), clientv3.WithRev(t.rev))
	if err != nil {
		return nil, err
	}
	m := make(map[string][]byte, len(resp.Kvs))
	for _, e := range resp.Kvs {
		m[strings.TrimPrefix(string(e.Key), t.s.prefix)] = e.Value
	}
	for k, v := range t.ops {
		if strings.HasPrefix(k, prefix) {
			m[k] = v
		}
	}
	for k := range t.del {
		if strings.HasPrefix(k, prefix) {
			delete(m, k)
		}
	}
	out := make([]kv, 0, len(m))
	for k, v := range m {
		out = append(out, kv{k, v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key < out[j].key })
	return out, nil
}

// listInto decodes every record under prefix with fn.
func listInto[T any](t *etx, prefix string, fn func(key string, rec T) error) error {
	kvs, err := t.list(prefix)
	if err != nil {
		return err
	}
	for _, e := range kvs {
		var rec T
		if err := json.Unmarshal(e.val, &rec); err != nil {
			return fmt.Errorf("decode %s: %w", e.key, err)
		}
		if err := fn(e.key, rec); err != nil {
			return err
		}
	}
	return nil
}

func (t *etx) put(k string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	delete(t.del, k)
	t.ops[k] = b
	return nil
}

func (t *etx) delete(k string) {
	delete(t.ops, k)
	t.del[k] = true
}

func (t *etx) dirty() bool { return len(t.ops) > 0 || len(t.del) > 0 }

// tx runs fn in a transaction, retrying on conflicts. fn may run more than
// once and must not have side effects outside t.
func (s *Etcd) tx(ctx context.Context, fn func(*etx) error) error {
	commit := s.prefix + keyCommit
	for attempt := 0; attempt < maxTxnRetries; attempt++ {
		resp, err := s.c.Get(ctx, commit)
		if err != nil {
			return err
		}
		var mod int64
		if len(resp.Kvs) > 0 {
			mod = resp.Kvs[0].ModRevision
		}
		t := &etx{ctx: ctx, s: s, rev: resp.Header.Revision, ops: map[string][]byte{}, del: map[string]bool{}}
		if err := fn(t); err != nil {
			return err
		}
		if !t.dirty() {
			return nil
		}
		ops := make([]clientv3.Op, 0, len(t.ops)+len(t.del)+1)
		for _, k := range slices.Sorted(maps.Keys(t.ops)) {
			ops = append(ops, clientv3.OpPut(t.full(k), string(t.ops[k])))
		}
		for _, k := range slices.Sorted(maps.Keys(t.del)) {
			ops = append(ops, clientv3.OpDelete(t.full(k)))
		}
		ops = append(ops, clientv3.OpPut(commit, ""))
		cmps := []clientv3.Cmp{clientv3.Compare(clientv3.ModRevision(commit), "=", mod)}
		if s.fenceKey != "" {
			cmps = append(cmps, clientv3.Compare(clientv3.CreateRevision(s.fenceKey), "=", s.fenceRev))
		}
		tr, err := s.c.Txn(ctx).If(cmps...).Then(ops...).Commit()
		if err != nil {
			return err
		}
		if tr.Succeeded {
			return nil
		}
		if s.fenceKey != "" {
			if ok, err := s.fenceHolds(ctx); err != nil {
				return err
			} else if !ok {
				return ErrNotLeader
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(attempt+1) * time.Millisecond):
		}
	}
	return errors.New("store: too many concurrent changes; try again")
}

// view runs fn on a consistent snapshot without writing.
func (s *Etcd) view(ctx context.Context, fn func(*etx) error) error {
	return s.tx(ctx, func(t *etx) error {
		if err := fn(t); err != nil {
			return err
		}
		if t.dirty() {
			return errors.New("store: write in a read-only view")
		}
		return nil
	})
}

func notFoundf(format string, args ...any) error {
	return fmt.Errorf(format+": %w", append(args, ErrNotFound)...)
}

// Records.

type nodeRec struct {
	ID          string `json:"id"`
	PrivateIP   string `json:"privateIp"`
	CPUMillis   int64  `json:"cpuMillis"`
	MemoryBytes int64  `json:"memoryBytes"`
	State       string `json:"state"`
	LastSeen    int64  `json:"lastSeen"`
	CreatedAt   int64  `json:"createdAt"`
	Cordoned    bool   `json:"cordoned"`
	Version     string `json:"version,omitempty"`
	// LegacyCerts accepts any CA-signed certificate for the node until its
	// first renewal (nodes created before certificates were recorded).
	LegacyCerts bool              `json:"legacyCerts,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Restricted  bool              `json:"restricted,omitempty"`
	OS          string            `json:"os,omitempty"`
	Arch        string            `json:"arch,omitempty"`
	Jobs        bool              `json:"jobs,omitempty"`
	Volumes     bool              `json:"volumes,omitempty"`
	// Subnet is the node's container subnet in the cluster network
	// (ADR 0025); empty in clusters without one.
	Subnet string `json:"subnet,omitempty"`
	// NetworkKey is the node's WireGuard public key.
	NetworkKey string `json:"networkKey,omitempty"`
}

type certRec struct {
	Serial    string `json:"serial"`
	Node      string `json:"node"`
	NotAfter  int64  `json:"notAfter"`
	CreatedAt int64  `json:"createdAt"`
}

type tokenRec struct {
	ID         string            `json:"id"`
	SecretHash string            `json:"secretHash"`
	ExpiresAt  int64             `json:"expiresAt"`
	CreatedAt  int64             `json:"createdAt"`
	CreatedBy  string            `json:"createdBy"`
	UsedAt     int64             `json:"usedAt"`
	UsedBy     string            `json:"usedBy"`
	Server     bool              `json:"server,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
}

type serverRec struct {
	Name      string `json:"name"`
	PrivateIP string `json:"privateIp"`
	APIAddr   string `json:"apiAddr"`
	JoinAddr  string `json:"joinAddr,omitempty"`
	MemberID  uint64 `json:"memberId"`
	Schema    int    `json:"schema,omitempty"`
	Version   string `json:"version,omitempty"`
	CreatedAt int64  `json:"createdAt"`
}

type appRec struct {
	Name              string `json:"name"`
	ActiveRevision    string `json:"activeRevision"`
	TargetRevision    string `json:"targetRevision"`
	Replicas          int    `json:"replicas"`
	RolloutState      string `json:"rolloutState"`
	RolloutMessage    string `json:"rolloutMessage"`
	RolloutProgressAt int64  `json:"rolloutProgressAt"`
	CreatedAt         int64  `json:"createdAt"`
	UpdatedAt         int64  `json:"updatedAt"`
	// LastScheduled is the latest time a job's schedule fired (ADR 0019).
	LastScheduled int64 `json:"lastScheduled,omitempty"`
	// LastRun is the number of a job's newest run, kept after the run
	// itself is pruned so numbers are never reused.
	LastRun int64 `json:"lastRun,omitempty"`
	// Traffic is how an app in multiple revision mode splits requests,
	// with "latest" resolved (ADR 0022). It stays while such an app rolls
	// out to single mode, so its revisions serve until the new one does.
	Traffic []spec.TrafficTarget `json:"traffic,omitempty"`
	// Removing marks an app whose replicas are draining before it goes.
	Removing bool `json:"removing,omitempty"`
}

type revRec struct {
	Name        string          `json:"name"`
	App         string          `json:"app"`
	Seq         int             `json:"seq"`
	Spec        json.RawMessage `json:"spec"`
	ImageDigest string          `json:"imageDigest"`
	Platforms   []string        `json:"platforms,omitempty"`
	Secrets     map[string]int  `json:"secrets"`
	CreatedAt   int64           `json:"createdAt"`
}

type replicaRec struct {
	ID            string `json:"id"`
	App           string `json:"app"`
	Revision      string `json:"revision"`
	NodeID        string `json:"nodeId"`
	State         string `json:"state"`
	ContainerID   string `json:"containerId"`
	Address       string `json:"address"`
	IP            string `json:"ip,omitempty"`
	Message       string `json:"message"`
	Ready         bool   `json:"ready"`
	ReadySince    int64  `json:"readySince"`
	DrainingSince int64  `json:"drainingSince"`
	MovingSince   int64  `json:"movingSince,omitempty"`
	UpdatedAt     int64  `json:"updatedAt"`
	CreatedAt     int64  `json:"createdAt,omitempty"`
	// Container recreations by the agent (Replica.Restarts).
	Restarts      int    `json:"restarts,omitempty"`
	LastRestartAt int64  `json:"lastRestartAt,omitempty"`
	LastRestart   string `json:"lastRestart,omitempty"`
	// Job attempts (ADR 0019).
	Run      int64 `json:"run,omitempty"`
	Done     bool  `json:"done,omitempty"`
	Finished bool  `json:"finished,omitempty"`
	ExitCode int   `json:"exitCode,omitempty"`
}

type secretRec struct {
	KeyID      string `json:"keyId"`
	WrappedKey []byte `json:"wrappedKey"`
	Ciphertext []byte `json:"ciphertext"`
	CreatedAt  int64  `json:"createdAt"`
	CreatedBy  string `json:"createdBy"`
}

type domainRec struct {
	Name       string `json:"name"`
	Token      string `json:"token"`
	Verified   bool   `json:"verified"`
	VerifiedAt int64  `json:"verifiedAt"`
	Message    string `json:"message"`
	CreatedAt  int64  `json:"createdAt"`
	// Project owns the domain (ADR 0026); empty is the default project.
	Project string `json:"project,omitempty"`
}

type auditRec struct {
	ID     int64  `json:"id"`
	At     int64  `json:"at"`
	Actor  string `json:"actor"`
	Action string `json:"action"`
	Target string `json:"target"`
	Detail string `json:"detail"`
}

func seqKey(n int) string { return fmt.Sprintf("%010d", n) }

func revKey(app string, seq int) string { return pfxRevs + app + "/" + seqKey(seq) }

func secretKey(app, name string, version int) string {
	return pfxSecrets + app + "/" + name + "/" + seqKey(version)
}

// parseRevisionName splits "<app>--r<seq>". App names never contain "--".
func parseRevisionName(name string) (string, int, bool) {
	i := strings.LastIndex(name, "--r")
	if i <= 0 {
		return "", 0, false
	}
	seq, err := strconv.Atoi(name[i+3:])
	if err != nil || seq < 1 {
		return "", 0, false
	}
	return name[:i], seq, true
}

func (t *etx) audit(at time.Time, actor, action, target, detail string) error {
	var seq int64
	if _, err := t.get(keyAuditSeq, &seq); err != nil {
		return err
	}
	seq++
	if err := t.put(keyAuditSeq, seq); err != nil {
		return err
	}
	if seq > auditKeep && seq%100 == 0 {
		// Drop the oldest events in batches.
		kvs, err := t.list(pfxAudit)
		if err != nil {
			return err
		}
		for _, e := range kvs[:max(0, len(kvs)-auditKeep)] {
			t.delete(e.key)
		}
	}
	return t.put(fmt.Sprintf("%s%020d", pfxAudit, seq), auditRec{ID: seq, At: at.UnixMilli(), Actor: actor, Action: action, Target: target, Detail: detail})
}

// Meta.

// GetMeta returns a cluster-level setting.
func (s *Etcd) GetMeta(ctx context.Context, key string) (string, error) {
	var v string
	err := s.view(ctx, func(t *etx) error {
		ok, err := t.get(pfxMeta+key, &v)
		if err == nil && !ok {
			return notFoundf("meta %s", key)
		}
		return err
	})
	return v, err
}

// SetMeta stores a cluster-level setting.
func (s *Etcd) SetMeta(ctx context.Context, key, value string) error {
	return s.tx(ctx, func(t *etx) error { return t.put(pfxMeta+key, value) })
}

// Nodes.

func (t *etx) node(id string) (nodeRec, bool, error) {
	var n nodeRec
	ok, err := t.get(pfxNodes+id, &n)
	return n, ok, err
}

func (t *etx) toNode(n nodeRec) (Node, error) {
	out := Node{ID: n.ID, PrivateIP: n.PrivateIP, CPUMillis: n.CPUMillis, MemoryBytes: n.MemoryBytes, State: n.State,
		LastSeen: fromMS(n.LastSeen), CreatedAt: fromMS(n.CreatedAt), Cordoned: n.Cordoned, Version: n.Version,
		Labels: n.Labels, OS: n.OS, Arch: n.Arch, Restricted: n.Restricted,
		Jobs: n.Jobs, Volumes: n.Volumes, Subnet: n.Subnet, NetworkKey: n.NetworkKey}
	var latest int64
	err := listInto(t, pfxCerts+n.ID+"/", func(_ string, c certRec) error {
		latest = max(latest, c.NotAfter)
		return nil
	})
	out.CertNotAfter = fromMS(latest)
	return out, err
}

// UpsertNode creates or replaces a node record. A new node gets a subnet
// when the cluster has a network (ADR 0025).
func (s *Etcd) UpsertNode(ctx context.Context, n Node) error {
	if n.CreatedAt.IsZero() {
		n.CreatedAt = s.now()
	}
	if n.State == "" {
		n.State = NodeUnknown
	}
	return s.tx(ctx, func(t *etx) error {
		cur, ok, err := t.node(n.ID)
		if err != nil {
			return err
		}
		rec := nodeRec{ID: n.ID, PrivateIP: n.PrivateIP, CPUMillis: n.CPUMillis, MemoryBytes: n.MemoryBytes, State: n.State,
			LastSeen: ms(n.LastSeen), CreatedAt: ms(n.CreatedAt)}
		if ok {
			rec.CreatedAt, rec.Cordoned, rec.LegacyCerts, rec.Version = cur.CreatedAt, cur.Cordoned, cur.LegacyCerts, cur.Version
			rec.Labels, rec.Restricted, rec.OS, rec.Arch = cur.Labels, cur.Restricted, cur.OS, cur.Arch
			rec.Subnet, rec.NetworkKey = cur.Subnet, cur.NetworkKey
		} else {
			if rec.Subnet, err = t.newNodeNetwork(n.PrivateIP); err != nil {
				return err
			}
		}
		if n.Labels != nil {
			rec.Labels = n.Labels
		}
		if n.OS != "" || n.Arch != "" {
			rec.OS, rec.Arch = n.OS, n.Arch
		}
		rec.Restricted = rec.Restricted || n.Restricted
		return t.put(pfxNodes+n.ID, rec)
	})
}

// GetNode returns one node.
func (s *Etcd) GetNode(ctx context.Context, id string) (Node, error) {
	var out Node
	err := s.view(ctx, func(t *etx) error {
		n, ok, err := t.node(id)
		if err != nil {
			return err
		}
		if !ok {
			return notFoundf("node %s", id)
		}
		out, err = t.toNode(n)
		return err
	})
	return out, err
}

// ListNodes returns all nodes ordered by ID.
func (s *Etcd) ListNodes(ctx context.Context) ([]Node, error) {
	var out []Node
	err := s.view(ctx, func(t *etx) error {
		out = nil
		return listInto(t, pfxNodes, func(_ string, n nodeRec) error {
			node, err := t.toNode(n)
			out = append(out, node)
			return err
		})
	})
	return out, err
}

// SetNodeStatus updates runtime information for an existing node.
func (s *Etcd) SetNodeStatus(ctx context.Context, id string, st NodeStatus) error {
	return s.tx(ctx, func(t *etx) error {
		n, ok, err := t.node(id)
		if err != nil {
			return err
		}
		if !ok {
			return notFoundf("node %s", id)
		}
		n.State, n.LastSeen, n.CPUMillis, n.MemoryBytes = st.State, ms(st.LastSeen), st.CPUMillis, st.MemoryBytes
		n.Jobs, n.Volumes = st.Jobs, st.Volumes
		if st.Version != "" {
			n.Version = st.Version
		}
		if st.OS != "" {
			n.OS = st.OS
		}
		if st.Arch != "" {
			n.Arch = st.Arch
		}
		if st.NetworkKey != "" && st.NetworkKey != n.NetworkKey {
			taken := false
			err := listInto(t, pfxNodes, func(_ string, r nodeRec) error {
				taken = taken || (r.ID != id && r.NetworkKey == st.NetworkKey)
				return nil
			})
			if err != nil {
				return err
			}
			if taken {
				return fmt.Errorf("node %s: network key already used by another node: %w", id, ErrConflict)
			}
			n.NetworkKey = st.NetworkKey
		}
		return t.put(pfxNodes+id, n)
	})
}

// SetNodeCordoned marks a node (un)schedulable. See Store.
func (s *Etcd) SetNodeCordoned(ctx context.Context, id string, cordoned bool, actor string) error {
	now := s.now()
	return s.tx(ctx, func(t *etx) error {
		n, ok, err := t.node(id)
		if err != nil {
			return err
		}
		if !ok {
			return notFoundf("node %s", id)
		}
		n.Cordoned = cordoned
		if err := t.put(pfxNodes+id, n); err != nil {
			return err
		}
		action := "node.uncordon"
		if cordoned {
			action = "node.cordon"
		}
		return t.audit(now, actor, action, id, "")
	})
}

// SetNodeLabels sets and removes a node's admin labels. See Store.
func (s *Etcd) SetNodeLabels(ctx context.Context, id string, set map[string]string, remove []string, actor string) (map[string]string, error) {
	now := s.now()
	var out map[string]string
	err := s.tx(ctx, func(t *etx) error {
		n, ok, err := t.node(id)
		if err != nil {
			return err
		}
		if !ok {
			return notFoundf("node %s", id)
		}
		labels := make(map[string]string, len(n.Labels)+len(set))
		for k, v := range n.Labels {
			labels[k] = v
		}
		for _, k := range remove {
			delete(labels, k)
		}
		for k, v := range set {
			labels[k] = v
		}
		if len(labels) > spec.MaxNodeLabels {
			return fmt.Errorf("node %s would have %d labels (at most %d): %w", id, len(labels), spec.MaxNodeLabels, ErrPrecondition)
		}
		if len(labels) == 0 {
			labels = nil
		}
		n.Labels, out = labels, labels
		if err := t.put(pfxNodes+id, n); err != nil {
			return err
		}
		return t.audit(now, actor, "node.label", id, labelString(labels))
	})
	return out, err
}

// SetNodeRestricted makes a node restricted or open. See Store.
func (s *Etcd) SetNodeRestricted(ctx context.Context, id string, restricted bool, actor string) error {
	now := s.now()
	return s.tx(ctx, func(t *etx) error {
		n, ok, err := t.node(id)
		if err != nil {
			return err
		}
		if !ok {
			return notFoundf("node %s", id)
		}
		n.Restricted = restricted
		if err := t.put(pfxNodes+id, n); err != nil {
			return err
		}
		action := "node.open"
		if restricted {
			action = "node.restrict"
		}
		return t.audit(now, actor, action, id, "")
	})
}

// labelString renders labels as "k=v,k2=v2", sorted by key.
func labelString(labels map[string]string) string {
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k + "=" + labels[k]
	}
	return strings.Join(parts, ",")
}

// RemoveNode deletes a node and its certificates. See Store.
func (s *Etcd) RemoveNode(ctx context.Context, id string, force bool, actor string) error {
	now := s.now()
	return s.tx(ctx, func(t *etx) error {
		var onNode []string
		err := listInto(t, pfxReplicas, func(k string, r replicaRec) error {
			if r.NodeID == id {
				onNode = append(onNode, k)
			}
			return nil
		})
		if err != nil {
			return err
		}
		if len(onNode) > 0 && !force {
			return fmt.Errorf("node %s still runs %d replicas: %w", id, len(onNode), ErrPrecondition)
		}
		// Volume records stay, so `armada volume restore --node` can bind
		// them elsewhere (ADR 0023).
		var vols []string
		err = listInto(t, pfxVolumes, func(_ string, v volumeRec) error {
			if v.Node == id {
				vols = append(vols, v.App+"/"+v.Name)
			}
			return nil
		})
		if err != nil {
			return err
		}
		if len(vols) > 0 && !force {
			return fmt.Errorf("node %s holds volumes %s; back them up and restore them on another node first, or remove the node with --force: %w", id, strings.Join(vols, ", "), ErrPrecondition)
		}
		if _, ok, err := t.node(id); err != nil {
			return err
		} else if !ok {
			return notFoundf("node %s", id)
		}
		for _, k := range onNode {
			t.delete(k)
		}
		certs, err := t.list(pfxCerts + id + "/")
		if err != nil {
			return err
		}
		for _, c := range certs {
			t.delete(c.key)
		}
		t.delete(pfxNodes + id)
		detail := ""
		if len(onNode) > 0 {
			detail = fmt.Sprintf("forced, %d replicas deleted", len(onNode))
		}
		return t.audit(now, actor, "node.remove", id, detail)
	})
}

// CreateJoinToken stores a join token. See Store.
func (s *Etcd) CreateJoinToken(ctx context.Context, tok JoinToken) error {
	now := s.now()
	return s.tx(ctx, func(t *etx) error {
		// Expired and used tokens are of no further use.
		err := listInto(t, pfxTokens, func(k string, r tokenRec) error {
			if r.ExpiresAt < now.UnixMilli() || r.UsedAt != 0 {
				t.delete(k)
			}
			return nil
		})
		if err != nil {
			return err
		}
		if _, ok, err := t.getRaw(pfxTokens + tok.ID); err != nil {
			return err
		} else if ok {
			return fmt.Errorf("join token %s exists: %w", tok.ID, ErrConflict)
		}
		if err := t.put(pfxTokens+tok.ID, tokenRec{ID: tok.ID, SecretHash: tok.SecretHash, ExpiresAt: tok.ExpiresAt.UnixMilli(),
			CreatedAt: now.UnixMilli(), CreatedBy: tok.CreatedBy, Server: tok.Server, Labels: tok.Labels}); err != nil {
			return err
		}
		detail := "expires " + tok.ExpiresAt.UTC().Format("2006-01-02T15:04Z")
		if tok.Server {
			detail = "server, " + detail
		}
		if len(tok.Labels) > 0 {
			detail += ", labels " + labelString(tok.Labels)
		}
		return t.audit(now, tok.CreatedBy, "token.create", tok.ID, detail)
	})
}

// RedeemJoinToken consumes a token and registers a node. See Store.
func (s *Etcd) RedeemJoinToken(ctx context.Context, id string, check func(string) bool, n Node, issue func() (NodeCert, error)) error {
	return s.redeem(ctx, id, check, nil, n, issue)
}

// RedeemServerToken consumes a server token and registers a control plane
// node. See Store.
func (s *Etcd) RedeemServerToken(ctx context.Context, id string, check func(string) bool, srv Server, n Node, issue func() (NodeCert, error)) error {
	return s.redeem(ctx, id, check, &srv, n, issue)
}

func (s *Etcd) redeem(ctx context.Context, id string, check func(string) bool, srv *Server, n Node, issue func() (NodeCert, error)) error {
	now := s.now()
	return s.tx(ctx, func(t *etx) error {
		var tok tokenRec
		ok, err := t.get(pfxTokens+id, &tok)
		if err != nil {
			return err
		}
		// Check the secret first, so a guessed ID alone reveals nothing. A
		// node token cannot add a server, nor a server token a node.
		if !ok || !check(tok.SecretHash) || tok.UsedAt != 0 || now.UnixMilli() >= tok.ExpiresAt || tok.Server != (srv != nil) {
			return errBadToken
		}
		if _, exists, err := t.node(n.ID); err != nil {
			return err
		} else if exists {
			return fmt.Errorf("node %s already exists; remove it first or pick another name: %w", n.ID, ErrConflict)
		}
		// Only after the token checks out, so unauthenticated callers cannot
		// probe which IPs are in use.
		taken := false
		err = listInto(t, pfxNodes, func(_ string, other nodeRec) error {
			taken = taken || other.PrivateIP == n.PrivateIP
			return nil
		})
		if err != nil {
			return err
		}
		if taken {
			return fmt.Errorf("private IP %s is already used by another node: %w", n.PrivateIP, ErrConflict)
		}
		subnet, err := t.newNodeNetwork(n.PrivateIP)
		if err != nil {
			return err
		}
		if srv != nil {
			if _, exists, err := t.getRaw(pfxServers + srv.Name); err != nil {
				return err
			} else if exists {
				return fmt.Errorf("server %s already exists: %w", srv.Name, ErrConflict)
			}
			if err := t.putServer(*srv, now); err != nil {
				return err
			}
		}
		tok.UsedAt, tok.UsedBy = now.UnixMilli(), n.ID
		if err := t.put(pfxTokens+id, tok); err != nil {
			return err
		}
		cert, err := issue()
		if err != nil {
			return err
		}
		if n.State == "" {
			n.State = NodeUnknown
		}
		if err := t.put(pfxNodes+n.ID, nodeRec{ID: n.ID, PrivateIP: n.PrivateIP, State: n.State, CreatedAt: now.UnixMilli(), Labels: tok.Labels, Subnet: subnet}); err != nil {
			return err
		}
		if err := t.putCert(n.ID, cert, now); err != nil {
			return err
		}
		action := "node.join"
		if srv != nil {
			action = "server.join"
		}
		return t.audit(now, "token:"+id, action, n.ID, networkDetail(n.PrivateIP, subnet))
	})
}

func (t *etx) putServer(srv Server, now time.Time) error {
	created := now.UnixMilli()
	var old serverRec
	if ok, err := t.get(pfxServers+srv.Name, &old); err != nil {
		return err
	} else if ok {
		created = old.CreatedAt
	}
	return t.put(pfxServers+srv.Name, serverRec{Name: srv.Name, PrivateIP: srv.PrivateIP, APIAddr: srv.APIAddr, JoinAddr: srv.JoinAddr,
		MemberID: srv.MemberID, Schema: srv.Schema, Version: srv.Version, CreatedAt: created})
}

// UpsertServer records a control plane node. See Store.
func (s *Etcd) UpsertServer(ctx context.Context, srv Server) error {
	now := s.now()
	return s.tx(ctx, func(t *etx) error {
		var old serverRec
		if ok, err := t.get(pfxServers+srv.Name, &old); err != nil {
			return err
		} else if ok && old.PrivateIP == srv.PrivateIP && old.APIAddr == srv.APIAddr && old.JoinAddr == srv.JoinAddr && old.MemberID == srv.MemberID &&
			old.Schema == srv.Schema && old.Version == srv.Version {
			return nil
		}
		return t.putServer(srv, now)
	})
}

// ListServers lists the control plane nodes. See Store.
func (s *Etcd) ListServers(ctx context.Context) ([]Server, error) {
	var out []Server
	err := s.view(ctx, func(t *etx) error {
		out = nil
		return listInto(t, pfxServers, func(_ string, r serverRec) error {
			out = append(out, Server{Name: r.Name, PrivateIP: r.PrivateIP, APIAddr: r.APIAddr, JoinAddr: r.JoinAddr,
				MemberID: r.MemberID, Schema: max(r.Schema, 1), Version: r.Version, CreatedAt: fromMS(r.CreatedAt)})
			return nil
		})
	})
	return out, err
}

// RemoveServer deletes a control plane node's record. See Store.
func (s *Etcd) RemoveServer(ctx context.Context, name, actor string) error {
	now := s.now()
	return s.tx(ctx, func(t *etx) error {
		if _, ok, err := t.getRaw(pfxServers + name); err != nil {
			return err
		} else if !ok {
			return notFoundf("server %s", name)
		}
		t.delete(pfxServers + name)
		return t.audit(now, actor, "server.remove", name, "")
	})
}

func (t *etx) putCert(node string, c NodeCert, now time.Time) error {
	return t.put(pfxCerts+node+"/"+c.Serial, certRec{Serial: c.Serial, Node: node, NotAfter: c.NotAfter.UnixMilli(), CreatedAt: now.UnixMilli()})
}

// RecordNodeCert records a renewed certificate. See Store.
func (s *Etcd) RecordNodeCert(ctx context.Context, node string, c NodeCert, keep string) error {
	now := s.now()
	return s.tx(ctx, func(t *etx) error {
		n, ok, err := t.node(node)
		if err != nil {
			return err
		}
		if !ok {
			return notFoundf("node %s", node)
		}
		if n.LegacyCerts {
			n.LegacyCerts = false
			if err := t.put(pfxNodes+node, n); err != nil {
				return err
			}
		}
		err = listInto(t, pfxCerts+node+"/", func(k string, rec certRec) error {
			// Expired certificates are pruned; a renewal revokes every other
			// certificate of the node, so at most the renewing one and the
			// new one stay valid and a stolen one dies at the next renewal.
			if rec.NotAfter < now.UnixMilli() || (keep != "" && rec.Serial != keep) {
				t.delete(k)
			}
			return nil
		})
		if err != nil {
			return err
		}
		return t.putCert(node, c, now)
	})
}

// NodeCertAllowed checks a node certificate against the record. See Store.
func (s *Etcd) NodeCertAllowed(ctx context.Context, node, serial string) (bool, error) {
	allowed := false
	err := s.view(ctx, func(t *etx) error {
		n, ok, err := t.node(node)
		if err != nil || !ok {
			allowed = false
			return err
		}
		if n.LegacyCerts {
			allowed = true
			return nil
		}
		var c certRec
		ok, err = t.get(pfxCerts+node+"/"+serial, &c)
		allowed = ok && c.NotAfter > s.now().UnixMilli()
		return err
	})
	return allowed, err
}

// setLegacyCerts marks every node as accepting legacy certificates; tests
// use it to model nodes created before certificates were recorded.
func (s *Etcd) setLegacyCerts(ctx context.Context) error {
	return s.tx(ctx, func(t *etx) error {
		return listInto(t, pfxNodes, func(k string, n nodeRec) error {
			n.LegacyCerts = true
			return t.put(k, n)
		})
	})
}

// Apps and revisions.

func (t *etx) app(name string) (appRec, bool, error) {
	var a appRec
	ok, err := t.get(pfxApps+name, &a)
	return a, ok, err
}

func (t *etx) revision(name string) (Revision, error) {
	app, seq, ok := parseRevisionName(name)
	if !ok {
		return Revision{}, notFoundf("revision %s", name)
	}
	var r revRec
	found, err := t.get(revKey(app, seq), &r)
	if err != nil {
		return Revision{}, err
	}
	if !found {
		return Revision{}, notFoundf("revision %s", name)
	}
	return decodeRev(r)
}

// revisions returns the revisions that exist among names, by name.
func (t *etx) revisions(names []string) (map[string]Revision, error) {
	keys := make([]string, 0, len(names))
	byKey := make(map[string]string, len(names))
	for _, name := range names {
		app, seq, ok := parseRevisionName(name)
		if !ok {
			continue
		}
		k := revKey(app, seq)
		if _, seen := byKey[k]; !seen {
			byKey[k] = name
			keys = append(keys, k)
		}
	}
	raw, err := t.getMany(keys)
	if err != nil {
		return nil, err
	}
	out := make(map[string]Revision, len(raw))
	for k, b := range raw {
		var r revRec
		if err := json.Unmarshal(b, &r); err != nil {
			return nil, fmt.Errorf("decode %s: %w", k, err)
		}
		rev, err := decodeRev(r)
		if err != nil {
			return nil, err
		}
		out[byKey[k]] = rev
	}
	return out, nil
}

func decodeRev(r revRec) (Revision, error) {
	out := Revision{Name: r.Name, App: r.App, Seq: r.Seq, ImageDigest: r.ImageDigest, Platforms: r.Platforms, Secrets: r.Secrets, CreatedAt: fromMS(r.CreatedAt), Spec: new(spec.App)}
	if out.Secrets == nil {
		out.Secrets = map[string]int{}
	}
	if err := json.Unmarshal(r.Spec, out.Spec); err != nil {
		return out, fmt.Errorf("decode revision %s: %w", r.Name, err)
	}
	return out, nil
}

func (t *etx) toApp(a appRec) (App, error) {
	rev, err := t.revision(a.ActiveRevision)
	if err != nil {
		return App{}, err
	}
	return appFrom(a, rev), nil
}

// appFrom builds an app from its record and active revision.
func appFrom(a appRec, rev Revision) App {
	return App{Name: a.Name, ActiveRevision: a.ActiveRevision, TargetRevision: a.TargetRevision, Replicas: a.Replicas,
		Spec: rev.Spec, RolloutState: a.RolloutState, RolloutMessage: a.RolloutMessage,
		Removing: a.Removing, RolloutProgressAt: fromMS(a.RolloutProgressAt), CreatedAt: fromMS(a.CreatedAt), UpdatedAt: fromMS(a.UpdatedAt),
		LastScheduled: fromMS(a.LastScheduled), Traffic: slices.Clone(a.Traffic)}
}

// Deploy records a new revision. See Store.
func (s *Etcd) Deploy(ctx context.Context, sp *spec.App, actor string) (Revision, bool, error) {
	var rev Revision
	var created bool
	err := s.tx(ctx, func(t *etx) error {
		var err error
		rev, created, err = s.deploy(t, sp, sp.Replicas(), actor, "deploy")
		return err
	})
	return rev, created, err
}

// deploy implements Deploy inside t. replicas is the desired count to set.
func (s *Etcd) deploy(t *etx, sp *spec.App, replicas int, actor, action string) (Revision, bool, error) {
	// Traffic is not part of a revision: changing only the weights moves
	// traffic without a new revision (ADR 0022).
	var traffic []spec.TrafficTarget
	multiple := sp.MultipleRevisions()
	if multiple {
		traffic = sp.Revisions.Traffic
		c, r := *sp, *sp.Revisions
		r.Traffic = nil
		c.Revisions = &r
		sp = &c
	}
	body, err := json.Marshal(sp)
	if err != nil {
		return Revision{}, false, err
	}
	pins, err := t.pinSecrets(sp)
	if err != nil {
		return Revision{}, false, err
	}
	now := s.now()

	id := sp.ID()
	if err := t.projectExists(sp.Project); err != nil {
		return Revision{}, false, err
	}
	same := func(r Revision) bool { return sameRevision(r, body, pins) }
	a, exists, err := t.app(id)
	if err != nil {
		return Revision{}, false, err
	}
	if exists && a.Removing {
		return Revision{}, false, fmt.Errorf("%s is being removed; deploy again once it is gone: %w", id, ErrPrecondition)
	}
	if exists && sp.Autoscaled() {
		// The autoscaler's count carries over, within the new bounds.
		replicas = keptReplicas(sp, a.Replicas)
	}
	if exists {
		cur, err := t.revision(a.ActiveRevision)
		if err != nil {
			return Revision{}, false, err
		}
		if cur.Spec.IsJob() != sp.IsJob() {
			what := "an app"
			if cur.Spec.IsJob() {
				what = "a job"
			}
			return Revision{}, false, fmt.Errorf("%s is %s; choose another name: %w", id, what, ErrConflict)
		}
		tgt := cur
		if a.TargetRevision != a.ActiveRevision {
			if tgt, err = t.revision(a.TargetRevision); err != nil {
				return Revision{}, false, err
			}
		}
		switch {
		case multiple && same(tgt):
			return tgt, false, t.activateTraffic(a, tgt.Name, traffic, replicas, now, actor, action+".unchanged")
		case multiple && same(cur):
			return cur, false, t.activateTraffic(a, cur.Name, traffic, replicas, now, actor, action+".unchanged")
		case same(tgt):
			a.Replicas, a.UpdatedAt = replicas, now.UnixMilli()
			if err := t.put(pfxApps+a.Name, a); err != nil {
				return Revision{}, false, err
			}
			return tgt, false, t.audit(now, actor, action+".unchanged", id, tgt.Name)
		case same(cur):
			// Deploying what is already serving cancels the rollout.
			target := a.TargetRevision
			if err := t.setTarget(a, cur.Name, replicas, now); err != nil {
				return Revision{}, false, err
			}
			if err := t.pruneDomains(); err != nil {
				return Revision{}, false, err
			}
			return cur, false, t.audit(now, actor, action+".cancel", id, target)
		}
	}

	if err := t.claimDomains(sp, now); err != nil {
		return Revision{}, false, err
	}
	seq := 1
	revs, err := t.list(pfxRevs + id + "/")
	if err != nil {
		return Revision{}, false, err
	}
	if len(revs) > 0 {
		last := revs[len(revs)-1].key
		n, err := strconv.Atoi(last[strings.LastIndex(last, "/")+1:])
		if err != nil {
			return Revision{}, false, fmt.Errorf("bad revision key %s", last)
		}
		seq = n + 1
	}
	rev := Revision{Name: fmt.Sprintf("%s--r%d", id, seq), App: id, Seq: seq, Spec: sp, Secrets: pins, CreatedAt: now}
	if !exists {
		// Nothing serves yet, so the first revision is active at once.
		a = appRec{Name: id, ActiveRevision: rev.Name, TargetRevision: rev.Name, CreatedAt: now.UnixMilli()}
	}
	if err := t.put(revKey(id, seq), revRec{Name: rev.Name, App: rev.App, Seq: seq, Spec: body, Secrets: pins, CreatedAt: now.UnixMilli()}); err != nil {
		return Revision{}, false, err
	}
	if multiple {
		return rev, true, t.activateTraffic(a, rev.Name, traffic, replicas, now, actor, action)
	}
	if sp.IsJob() {
		// Jobs have no rollouts: new runs use the new revision.
		a.ActiveRevision = rev.Name
	}
	if err := t.setTarget(a, rev.Name, replicas, now); err != nil {
		return Revision{}, false, err
	}
	if err := t.pruneRevisions(id); err != nil {
		return Revision{}, false, err
	}
	if err := t.pruneDomains(); err != nil {
		return Revision{}, false, err
	}
	return rev, true, t.audit(now, actor, action, id, rev.Name)
}

// activateTraffic makes latest the app's current revision in multiple
// revision mode, with no rollout: traffic, with "latest" resolved to it,
// decides which revisions run and serve (ADR 0022). Every revision named
// must be one of the app's.
func (t *etx) activateTraffic(a appRec, latest string, traffic []spec.TrafficTarget, replicas int, now time.Time, actor, action string) error {
	resolved, err := t.resolveTraffic(a.Name, latest, traffic)
	if err != nil {
		return err
	}
	a.ActiveRevision, a.TargetRevision, a.Traffic = latest, latest, resolved
	a.RolloutState, a.RolloutMessage, a.Replicas = RolloutNone, "", replicas
	a.RolloutProgressAt, a.UpdatedAt = now.UnixMilli(), now.UnixMilli()
	if err := t.put(pfxApps+a.Name, a); err != nil {
		return err
	}
	if err := t.pruneRevisions(a.Name); err != nil {
		return err
	}
	if err := t.pruneDomains(); err != nil {
		return err
	}
	return t.audit(now, actor, action, a.Name, trafficString(resolved))
}

// resolveTraffic replaces "latest" with latest and checks every revision
// exists, belongs to app, and is listed once.
func (t *etx) resolveTraffic(app, latest string, traffic []spec.TrafficTarget) ([]spec.TrafficTarget, error) {
	out := make([]spec.TrafficTarget, 0, len(traffic))
	seen := map[string]bool{}
	for _, tt := range traffic {
		if tt.Revision == spec.LatestRevision {
			tt.Revision = latest
		}
		if seen[tt.Revision] {
			return nil, fmt.Errorf("revisions.traffic lists %s twice (latest is %s): %w", tt.Revision, latest, ErrPrecondition)
		}
		seen[tt.Revision] = true
		rev, err := t.revision(tt.Revision)
		if errors.Is(err, ErrNotFound) || (err == nil && rev.App != app) {
			return nil, fmt.Errorf("revisions.traffic: %s is not a revision of %s (see armada revisions %s): %w", tt.Revision, app, app, ErrPrecondition)
		}
		if err != nil {
			return nil, err
		}
		out = append(out, tt)
	}
	return out, nil
}

// trafficString is traffic for the audit log: "web--r3=90,web--r4=10".
func trafficString(traffic []spec.TrafficTarget) string {
	parts := make([]string, 0, len(traffic))
	for _, tt := range traffic {
		parts = append(parts, fmt.Sprintf("%s=%d", tt.Revision, tt.Weight))
	}
	return strings.Join(parts, ",")
}

// SetTraffic changes the weights of an app in multiple revision mode until
// its next deploy (ADR 0022). Each target keeps the label it has; a
// revision not listed stops serving.
func (s *Etcd) SetTraffic(ctx context.Context, app string, weights []spec.TrafficTarget, actor string) ([]spec.TrafficTarget, error) {
	now := s.now()
	var out []spec.TrafficTarget
	err := s.tx(ctx, func(t *etx) error {
		a, ok, err := t.app(app)
		if err != nil {
			return err
		}
		if !ok {
			return notFoundf("app %s", app)
		}
		cur, err := t.revision(a.ActiveRevision)
		if err != nil {
			return err
		}
		if !cur.Spec.MultipleRevisions() || a.TargetRevision != a.ActiveRevision {
			return fmt.Errorf("%s does not split traffic; set revisions.mode: multiple in its spec: %w", app, ErrPrecondition)
		}
		labels := map[string]string{}
		for _, tt := range a.Traffic {
			labels[tt.Revision] = tt.Label
		}
		next := make([]spec.TrafficTarget, 0, len(weights))
		for _, w := range weights {
			next = append(next, spec.TrafficTarget{Revision: w.Revision, Weight: w.Weight, Label: labels[w.Revision]})
		}
		if errs := spec.CheckTraffic(app, next, false); len(errs) > 0 {
			return fmt.Errorf("%w: %w", errors.Join(fieldErrs(errs)...), ErrPrecondition)
		}
		if out, err = t.resolveTraffic(app, a.ActiveRevision, next); err != nil {
			return err
		}
		a.Traffic, a.UpdatedAt = out, now.UnixMilli()
		if err := t.put(pfxApps+app, a); err != nil {
			return err
		}
		if err := t.pruneRevisions(app); err != nil {
			return err
		}
		return t.audit(now, actor, "traffic", app, trafficString(out))
	})
	return out, err
}

func fieldErrs(errs []*spec.FieldError) []error {
	out := make([]error, len(errs))
	for i, e := range errs {
		out[i] = e
	}
	return out
}

// setTarget points a at target and resets the rollout state: progressing if
// target differs from the active revision, none otherwise.
func (t *etx) setTarget(a appRec, target string, replicas int, now time.Time) error {
	a.RolloutState = RolloutNone
	if target != a.ActiveRevision {
		a.RolloutState = RolloutProgressing
	}
	a.TargetRevision, a.Replicas, a.RolloutMessage = target, replicas, ""
	a.RolloutProgressAt, a.UpdatedAt = now.UnixMilli(), now.UnixMilli()
	return t.put(pfxApps+a.Name, a)
}

// pruneRevisions deletes old revisions beyond RevisionsToKeep that are
// neither active, targeted, nor still running, then secret versions nothing
// pins any more.
func (t *etx) pruneRevisions(app string) error {
	a, ok, err := t.app(app)
	if err != nil || !ok {
		return err
	}
	running := map[string]bool{}
	err = listInto(t, pfxReplicas, func(_ string, r replicaRec) error {
		if r.App == app {
			running[r.Revision] = true
		}
		return nil
	})
	if err != nil {
		return err
	}
	// A job's pending runs start with the revision they were created with.
	err = listInto(t, pfxRuns+app+"/", func(_ string, r jobRunRec) error {
		if r.State == RunPending || r.State == RunRunning {
			running[r.Revision] = true
		}
		return nil
	})
	if err != nil {
		return err
	}
	var recs []revRec
	if err := listInto(t, pfxRevs+app+"/", func(_ string, r revRec) error { recs = append(recs, r); return nil }); err != nil {
		return err
	}
	if len(recs) == 0 {
		return nil
	}
	for _, tt := range a.Traffic {
		running[tt.Revision] = true
	}
	maxSeq := recs[len(recs)-1].Seq
	for _, r := range recs {
		if r.Name == a.ActiveRevision || r.Name == a.TargetRevision || running[r.Name] || r.Seq > maxSeq-RevisionsToKeep {
			continue
		}
		t.delete(revKey(app, r.Seq))
	}
	return t.pruneSecrets(app)
}

// Rollback targets an existing revision. See Store.
func (s *Etcd) Rollback(ctx context.Context, app, revision, actor string) (Revision, error) {
	now := s.now()
	var rev Revision
	err := s.tx(ctx, func(t *etx) error {
		a, ok, err := t.app(app)
		if err != nil {
			return err
		}
		if !ok {
			return notFoundf("app %s", app)
		}
		rev, err = t.revision(revision)
		if err != nil {
			return err
		}
		if rev.App != app {
			return notFoundf("revision %s of app %s", revision, app)
		}
		if rev.Spec.IsJob() {
			return fmt.Errorf("%s is a job; jobs have no rollouts (deploy the spec you want its next runs to use): %w", app, ErrPrecondition)
		}
		if len(a.Traffic) > 0 || rev.Spec.MultipleRevisions() {
			return fmt.Errorf("%s splits traffic between revisions; change the weights with armada traffic %s or in its spec: %w", app, app, ErrPrecondition)
		}
		if err := t.checkPins(rev); err != nil {
			return err
		}
		kept := keptReplicas(rev.Spec, a.Replicas)
		// The old revision may route domains that were dropped or taken by
		// another app since.
		if err := t.claimDomains(rev.Spec, now); err != nil {
			return err
		}
		if err := t.setTarget(a, revision, kept, now); err != nil {
			return err
		}
		if err := t.pruneDomains(); err != nil {
			return err
		}
		return t.audit(now, actor, "rollback", app, revision)
	})
	return rev, err
}

// CompleteRollout promotes revision to active. See Store.
func (s *Etcd) CompleteRollout(ctx context.Context, app, revision string) error {
	now := s.now()
	return s.tx(ctx, func(t *etx) error {
		a, ok, err := t.app(app)
		if err != nil {
			return err
		}
		if !ok || a.TargetRevision != revision {
			return notFoundf("rollout of %s to %s", app, revision)
		}
		a.ActiveRevision, a.RolloutState, a.RolloutMessage, a.UpdatedAt = a.TargetRevision, RolloutNone, "", now.UnixMilli()
		if cur, err := t.revision(revision); err == nil && !cur.Spec.MultipleRevisions() {
			a.Traffic = nil // the app has left multiple revision mode
		}
		if err := t.put(pfxApps+app, a); err != nil {
			return err
		}
		if err := t.pruneRevisions(app); err != nil {
			return err
		}
		if err := t.pruneDomains(); err != nil {
			return err
		}
		return t.audit(now, "system", "rollout.complete", app, revision)
	})
}

// FailRollout aborts a rollout. See Store.
func (s *Etcd) FailRollout(ctx context.Context, app, revision, message string) error {
	now := s.now()
	return s.tx(ctx, func(t *etx) error {
		a, ok, err := t.app(app)
		if err != nil {
			return err
		}
		if !ok || a.TargetRevision != revision || a.TargetRevision == a.ActiveRevision {
			return notFoundf("rollout of %s to %s", app, revision)
		}
		a.TargetRevision, a.RolloutState, a.RolloutMessage, a.UpdatedAt = a.ActiveRevision, RolloutFailed, message, now.UnixMilli()
		if err := t.put(pfxApps+app, a); err != nil {
			return err
		}
		if err := t.pruneDomains(); err != nil {
			return err
		}
		return t.audit(now, "system", "rollout.fail", app, revision+": "+message)
	})
}

// MarkRolloutProgress restarts the progress deadline. See Store.
func (s *Etcd) MarkRolloutProgress(ctx context.Context, app string) error {
	return s.tx(ctx, func(t *etx) error {
		a, ok, err := t.app(app)
		if err != nil {
			return err
		}
		if !ok {
			return notFoundf("app %s", app)
		}
		a.RolloutProgressAt = s.now().UnixMilli()
		return t.put(pfxApps+app, a)
	})
}

// GetApp returns an app with its active spec.
func (s *Etcd) GetApp(ctx context.Context, name string) (App, error) {
	var out App
	err := s.view(ctx, func(t *etx) error {
		a, ok, err := t.app(name)
		if err != nil {
			return err
		}
		if !ok {
			return notFoundf("app %s", name)
		}
		out, err = t.toApp(a)
		return err
	})
	return out, err
}

// ListApps returns all apps ordered by name.
func (s *Etcd) ListApps(ctx context.Context) ([]App, error) {
	var out []App
	err := s.view(ctx, func(t *etx) error {
		var recs []appRec
		if err := listInto(t, pfxApps, func(_ string, a appRec) error {
			recs = append(recs, a)
			return nil
		}); err != nil {
			return err
		}
		names := make([]string, len(recs))
		for i, a := range recs {
			names[i] = a.ActiveRevision
		}
		revs, err := t.revisions(names)
		if err != nil {
			return err
		}
		out = make([]App, 0, len(recs))
		for _, a := range recs {
			rev, ok := revs[a.ActiveRevision]
			if !ok {
				return notFoundf("revision %s", a.ActiveRevision)
			}
			out = append(out, appFrom(a, rev))
		}
		return nil
	})
	return out, err
}

// SetReplicas changes the desired replica count until the next deploy.
func (s *Etcd) SetReplicas(ctx context.Context, app string, n int, actor string) error {
	if n < 1 || n > spec.MaxReplicas {
		return fmt.Errorf("replicas must be between 1 and %d", spec.MaxReplicas)
	}
	now := s.now()
	return s.tx(ctx, func(t *etx) error {
		a, ok, err := t.app(app)
		if err != nil {
			return err
		}
		if !ok {
			return notFoundf("app %s", app)
		}
		if cur, err := t.revision(a.ActiveRevision); err != nil {
			return err
		} else if cur.Spec.IsJob() {
			return fmt.Errorf("%s is a job; it runs one container per run: %w", app, ErrPrecondition)
		} else if cur.Spec.Autoscaled() {
			lo, hi := cur.Spec.ScaleBounds()
			return fmt.Errorf("%s scales itself between %d and %d replicas; change scale.min and scale.max in its spec: %w", app, lo, hi, ErrPrecondition)
		}
		if tgt, err := t.revision(a.TargetRevision); err != nil {
			return err
		} else if tgt.Spec.HasVolumes() && n != 1 {
			return fmt.Errorf("%s has volumes and runs exactly one replica (ADR 0023): %w", app, ErrPrecondition)
		}
		a.Replicas, a.UpdatedAt = n, now.UnixMilli()
		if err := t.put(pfxApps+app, a); err != nil {
			return err
		}
		return t.audit(now, actor, "scale", app, strconv.Itoa(n))
	})
}

// keptReplicas is the count an app keeps when sp becomes its target: the
// current count within sp's bounds if sp is autoscaled, else unchanged.
func keptReplicas(sp *spec.App, cur int) int {
	if sp.HasVolumes() {
		return 1 // volumes: exactly one replica (ADR 0023)
	}
	if !sp.Autoscaled() {
		return cur
	}
	lo, hi := sp.ScaleBounds()
	return min(max(cur, lo), hi)
}

// AutoscaleReplicas sets an autoscaled app's replica count to n if it is
// still from and the app is not rolling out (ErrConflict otherwise), so a
// decision made on stale state is dropped (ADR 0020).
func (s *Etcd) AutoscaleReplicas(ctx context.Context, app string, from, n int, actor string) error {
	now := s.now()
	return s.tx(ctx, func(t *etx) error {
		a, ok, err := t.app(app)
		if err != nil {
			return err
		}
		if !ok {
			return notFoundf("app %s", app)
		}
		cur, err := t.revision(a.ActiveRevision)
		if err != nil {
			return err
		}
		lo, hi := cur.Spec.ScaleBounds()
		if !cur.Spec.Autoscaled() || a.Replicas != from || a.TargetRevision != a.ActiveRevision || n < lo || n > hi {
			return fmt.Errorf("app %s changed since the autoscaler looked: %w", app, ErrConflict)
		}
		a.Replicas, a.UpdatedAt = n, now.UnixMilli()
		if err := t.put(pfxApps+app, a); err != nil {
			return err
		}
		return t.audit(now, actor, "autoscale", app, fmt.Sprintf("%d->%d", from, n))
	})
}

// GetRevision returns one revision.
func (s *Etcd) GetRevision(ctx context.Context, name string) (Revision, error) {
	var out Revision
	err := s.view(ctx, func(t *etx) error {
		var err error
		out, err = t.revision(name)
		return err
	})
	return out, err
}

// GetRevisions returns the revisions that exist among names, by name.
func (s *Etcd) GetRevisions(ctx context.Context, names []string) (map[string]Revision, error) {
	var out map[string]Revision
	err := s.view(ctx, func(t *etx) error {
		var err error
		out, err = t.revisions(names)
		return err
	})
	return out, err
}

// ListRevisions returns an app's revisions, newest first.
func (s *Etcd) ListRevisions(ctx context.Context, app string) ([]Revision, error) {
	var out []Revision
	err := s.view(ctx, func(t *etx) error {
		out = nil
		return listInto(t, pfxRevs+app+"/", func(_ string, r revRec) error {
			rev, err := decodeRev(r)
			out = append(out, rev)
			return err
		})
	})
	slices.Reverse(out)
	return out, err
}

// SetRevisionDigest records the pinned image once.
func (s *Etcd) SetRevisionDigest(ctx context.Context, revision, digest string) error {
	return s.tx(ctx, func(t *etx) error {
		app, seq, ok := parseRevisionName(revision)
		if !ok {
			return nil
		}
		var r revRec
		found, err := t.get(revKey(app, seq), &r)
		if err != nil || !found || r.ImageDigest != "" {
			return err
		}
		r.ImageDigest = digest
		return t.put(revKey(app, seq), r)
	})
}

// SetRevisionPlatforms records the image's platforms once. A server that
// predates the field drops it if it records the digest afterwards; agents
// report the platforms with every replica state, so they are learned again
// and no schema change is needed.
func (s *Etcd) SetRevisionPlatforms(ctx context.Context, revision string, platforms []string) error {
	return s.tx(ctx, func(t *etx) error {
		app, seq, ok := parseRevisionName(revision)
		if !ok {
			return nil
		}
		var r revRec
		found, err := t.get(revKey(app, seq), &r)
		if err != nil || !found || len(r.Platforms) > 0 {
			return err
		}
		r.Platforms = slices.Clone(platforms)
		return t.put(revKey(app, seq), r)
	})
}

// Replicas.

// CreateReplica schedules a replica.
func (s *Etcd) CreateReplica(ctx context.Context, r Replica) error {
	if r.State == "" {
		r.State = ReplicaPending
	}
	return s.tx(ctx, func(t *etx) error {
		if _, ok, err := t.getRaw(pfxReplicas + r.ID); err != nil {
			return err
		} else if ok {
			return fmt.Errorf("replica %s exists: %w", r.ID, ErrConflict)
		}
		if _, ok, err := t.app(r.App); err != nil {
			return err
		} else if !ok {
			return notFoundf("app %s", r.App)
		}
		rev, err := t.revision(r.Revision)
		if err != nil {
			return err
		}
		if _, ok, err := t.node(r.NodeID); err != nil {
			return err
		} else if !ok {
			return notFoundf("node %s", r.NodeID)
		}
		if err := t.bindVolumes(rev, r.NodeID, s.now()); err != nil {
			return err
		}
		return t.put(pfxReplicas+r.ID, replicaRec{ID: r.ID, App: r.App, Revision: r.Revision, NodeID: r.NodeID, State: r.State, UpdatedAt: s.now().UnixMilli(), CreatedAt: s.now().UnixMilli(), Run: r.Run})
	})
}

// DeleteReplica removes a replica from desired state.
func (s *Etcd) DeleteReplica(ctx context.Context, id string) error {
	return s.tx(ctx, func(t *etx) error {
		if _, ok, err := t.getRaw(pfxReplicas + id); err != nil {
			return err
		} else if !ok {
			return notFoundf("replica %s", id)
		}
		t.delete(pfxReplicas + id)
		return nil
	})
}

// DrainReplica marks a replica as draining. See Store.
func (s *Etcd) DrainReplica(ctx context.Context, id string) error {
	return s.tx(ctx, func(t *etx) error {
		var r replicaRec
		ok, err := t.get(pfxReplicas+id, &r)
		if err != nil {
			return err
		}
		if !ok {
			return notFoundf("replica %s", id)
		}
		if r.DrainingSince != 0 {
			return nil
		}
		r.DrainingSince = s.now().UnixMilli()
		return t.put(pfxReplicas+id, r)
	})
}

// SetReplicaMoving marks or unmarks a replica as moving. See Store.
func (s *Etcd) SetReplicaMoving(ctx context.Context, id string, moving bool) error {
	return s.tx(ctx, func(t *etx) error {
		var r replicaRec
		ok, err := t.get(pfxReplicas+id, &r)
		if err != nil {
			return err
		}
		if !ok {
			return notFoundf("replica %s", id)
		}
		switch {
		case moving && r.MovingSince == 0:
			r.MovingSince = s.now().UnixMilli()
		case !moving && r.MovingSince != 0:
			r.MovingSince = 0
		default:
			return nil
		}
		return t.put(pfxReplicas+id, r)
	})
}

// ListReplicas returns replicas matching f ordered by ID.
func (s *Etcd) ListReplicas(ctx context.Context, f ReplicaFilter) ([]Replica, error) {
	var out []Replica
	err := s.view(ctx, func(t *etx) error {
		out = nil
		return listInto(t, pfxReplicas, func(_ string, r replicaRec) error {
			if (f.App == "" || r.App == f.App) && (f.NodeID == "" || r.NodeID == f.NodeID) {
				out = append(out, Replica{ID: r.ID, App: r.App, Revision: r.Revision, NodeID: r.NodeID, State: r.State,
					ContainerID: r.ContainerID, Address: r.Address, IP: r.IP, Message: r.Message, Ready: r.Ready,
					ReadySince: fromMS(r.ReadySince), DrainingSince: fromMS(r.DrainingSince), MovingSince: fromMS(r.MovingSince), UpdatedAt: fromMS(r.UpdatedAt),
					CreatedAt: fromMS(r.CreatedAt), Restarts: r.Restarts, LastRestartAt: fromMS(r.LastRestartAt), LastRestart: r.LastRestart,
					Run: r.Run, Done: r.Done, Finished: r.Finished, ExitCode: r.ExitCode})
			}
			return nil
		})
	})
	return out, err
}

// UpdateReplicaStatus applies an agent report scoped to its node. A replica
// only counts as ready while running; ReadySince keeps the moment it last
// became ready.
func (s *Etcd) UpdateReplicaStatus(ctx context.Context, nodeID string, st ReplicaStatus) error {
	now := s.now().UnixMilli()
	return s.tx(ctx, func(t *etx) error {
		var r replicaRec
		ok, err := t.get(pfxReplicas+st.ID, &r)
		if err != nil {
			return err
		}
		if !ok || r.NodeID != nodeID {
			return notFoundf("replica %s on node %s", st.ID, nodeID)
		}
		ready := st.Ready && st.State == ReplicaRunning
		switch {
		case !ready:
			r.ReadySince = 0
		case r.Ready && r.ReadySince != 0:
		default:
			r.ReadySince = now
		}
		if r.Run == 0 && r.ContainerID != "" && st.ContainerID != "" && st.ContainerID != r.ContainerID {
			// The agent recreated the container.
			r.Restarts++
			r.LastRestartAt, r.LastRestart = now, ""
		}
		if r.Restarts > 0 && r.LastRestart == "" {
			// The agent prefixes a recreated container's messages with
			// why, until it is ready; the first report may come earlier.
			if why, ok := strings.CutPrefix(st.Message, RestartNote); ok {
				r.LastRestart = why
			}
		}
		r.State, r.ContainerID, r.Address, r.IP, r.Message, r.UpdatedAt, r.Ready = st.State, st.ContainerID, st.Address, st.IP, st.Message, now, ready
		if r.Run != 0 && !r.Finished {
			// A job attempt's result is kept once known: the container of
			// a done attempt is stopped and reports another exit code.
			r.Finished, r.ExitCode = st.Finished, st.ExitCode
		}
		return t.put(pfxReplicas+st.ID, r)
	})
}

// Audit.

// RecordAudit appends an audit event.
func (s *Etcd) RecordAudit(ctx context.Context, actor, action, target, detail string) error {
	now := s.now()
	return s.tx(ctx, func(t *etx) error { return t.audit(now, actor, action, target, detail) })
}

// ListAudit returns the newest audit events first.
func (s *Etcd) ListAudit(ctx context.Context, limit int) ([]AuditEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	resp, err := s.c.Get(ctx, s.prefix+pfxAudit, clientv3.WithPrefix(),
		clientv3.WithSort(clientv3.SortByKey, clientv3.SortDescend), clientv3.WithLimit(int64(limit)))
	if err != nil {
		return nil, err
	}
	out := make([]AuditEvent, 0, len(resp.Kvs))
	for _, e := range resp.Kvs {
		var a auditRec
		if err := json.Unmarshal(e.Value, &a); err != nil {
			return nil, fmt.Errorf("decode %s: %w", e.Key, err)
		}
		out = append(out, AuditEvent{ID: a.ID, At: fromMS(a.At), Actor: a.Actor, Action: a.Action, Target: a.Target, Detail: a.Detail})
	}
	return out, nil
}

// Domains.

// claimDomains rejects host+path collisions with other apps and registers
// sp's new domains with a fresh verification token. During a rollout an app
// has two live specs (active and target); both count.
func (t *etx) claimDomains(sp *spec.App, now time.Time) error {
	taken := map[string]string{}
	project := projectOf(sp.ID())
	// Domains in use by apps of other projects: a domain serves one project
	// only, so no project routes a path of another's verified domain.
	foreign := map[string]string{}
	err := t.liveSpecs(func(app string, other *spec.App) {
		if app == sp.ID() {
			return
		}
		for _, k := range routeKeys(other) {
			taken[k] = app
		}
		if p := projectOf(app); p != project && other.Ingress != nil {
			for _, d := range other.Ingress.Domains {
				foreign[d] = p
			}
		}
	})
	if err != nil {
		return err
	}
	for _, k := range routeKeys(sp) {
		if owner, ok := taken[k]; ok {
			return fmt.Errorf("%s is already routed to app %s: %w", k, owner, ErrConflict)
		}
	}
	if sp.Ingress == nil {
		return nil
	}
	for _, d := range sp.Ingress.Domains {
		if p, ok := foreign[d]; ok {
			return fmt.Errorf("domain %s is used by project %s: %w", d, p, ErrConflict)
		}
		var r domainRec
		ok, err := t.get(pfxDomains+d, &r)
		if err != nil {
			return err
		}
		owner := r.Project
		if owner == "" {
			owner = spec.DefaultProject
		}
		if ok && owner == project {
			continue
		}
		// New, or left behind by another project: this project proves
		// ownership afresh with a new token.
		token, err := randomToken()
		if err != nil {
			return err
		}
		rec := domainRec{Name: d, Token: token, CreatedAt: now.UnixMilli()}
		if project != spec.DefaultProject {
			rec.Project = project
		}
		if err := t.put(pfxDomains+d, rec); err != nil {
			return err
		}
	}
	return nil
}

// projectOf returns the project of an app ID.
func projectOf(id string) string {
	p, _, ok := spec.SplitAppID(id)
	if !ok {
		return ""
	}
	return p
}

// pruneDomains deletes domains that no live spec references any more.
func (t *etx) pruneDomains() error {
	inUse := map[string]bool{}
	err := t.liveSpecs(func(_ string, sp *spec.App) {
		if sp.Ingress != nil {
			for _, d := range sp.Ingress.Domains {
				inUse[d] = true
			}
		}
	})
	if err != nil {
		return err
	}
	return listInto(t, pfxDomains, func(k string, d domainRec) error {
		if !inUse[d.Name] {
			t.delete(k)
		}
		return nil
	})
}

// liveSpecs calls fn with the active and (if different) target spec of
// every app.
func (t *etx) liveSpecs(fn func(app string, sp *spec.App)) error {
	var apps []appRec
	var names []string
	err := listInto(t, pfxApps, func(_ string, a appRec) error {
		apps = append(apps, a)
		names = append(names, a.ActiveRevision, a.TargetRevision)
		return nil
	})
	if err != nil {
		return err
	}
	revs, err := t.revisions(names)
	if err != nil {
		return err
	}
	for _, a := range apps {
		for _, name := range slices.Compact([]string{a.ActiveRevision, a.TargetRevision}) {
			rev, ok := revs[name]
			if !ok {
				return notFoundf("revision %s", name)
			}
			fn(a.Name, rev.Spec)
		}
	}
	return nil
}

func toDomain(d domainRec) Domain {
	return Domain{Name: d.Name, Token: d.Token, Verified: d.Verified, VerifiedAt: fromMS(d.VerifiedAt), Message: d.Message, CreatedAt: fromMS(d.CreatedAt)}
}

// ListDomains returns all registered custom domains ordered by name.
func (s *Etcd) ListDomains(ctx context.Context) ([]Domain, error) {
	var out []Domain
	err := s.view(ctx, func(t *etx) error {
		out = nil
		return listInto(t, pfxDomains, func(_ string, d domainRec) error {
			out = append(out, toDomain(d))
			return nil
		})
	})
	return out, err
}

// GetDomain returns one domain.
func (s *Etcd) GetDomain(ctx context.Context, name string) (Domain, error) {
	var out Domain
	err := s.view(ctx, func(t *etx) error {
		var d domainRec
		ok, err := t.get(pfxDomains+name, &d)
		if err != nil {
			return err
		}
		if !ok {
			return notFoundf("domain %s", name)
		}
		out = toDomain(d)
		return nil
	})
	return out, err
}

// SetDomainVerification records the outcome of an ownership check. A domain
// that was verified once stays verified.
func (s *Etcd) SetDomainVerification(ctx context.Context, name string, verified bool, message string) error {
	return s.tx(ctx, func(t *etx) error {
		var d domainRec
		ok, err := t.get(pfxDomains+name, &d)
		if err != nil {
			return err
		}
		if !ok {
			return notFoundf("domain %s", name)
		}
		switch {
		case verified:
			if !d.Verified {
				d.VerifiedAt = s.now().UnixMilli()
			}
			d.Verified, d.Message = true, ""
		case d.Verified:
			return nil
		default:
			d.Message = message
		}
		return t.put(pfxDomains+name, d)
	})
}

// Secrets.

// latestVersions returns the newest version of every secret of app.
func (t *etx) latestVersions(app string) (map[string]int, error) {
	out := map[string]int{}
	kvs, err := t.list(pfxSecrets + app + "/")
	if err != nil {
		return nil, err
	}
	for _, e := range kvs {
		name, v, ok := splitSecretKey(e.key, app)
		if ok && v > out[name] {
			out[name] = v
		}
	}
	return out, nil
}

func splitSecretKey(key, app string) (string, int, bool) {
	rest := strings.TrimPrefix(key, pfxSecrets+app+"/")
	name, ver, ok := strings.Cut(rest, "/")
	if !ok {
		return "", 0, false
	}
	v, err := strconv.Atoi(ver)
	return name, v, err == nil
}

// pinSecrets resolves the latest version of every secret sp references.
func (t *etx) pinSecrets(sp *spec.App) (map[string]int, error) {
	latest, err := t.latestVersions(sp.ID())
	if err != nil {
		return nil, err
	}
	pins := map[string]int{}
	var missing []string
	for _, name := range sp.SecretRefs() {
		v, ok := latest[name]
		if !ok {
			missing = append(missing, name)
			continue
		}
		pins[name] = v
	}
	if len(missing) > 0 {
		cmd := "armada secret set " + sp.Name + " NAME"
		if sp.ID() != sp.Name {
			cmd += " --project " + sp.Project
		}
		return nil, fmt.Errorf("app %s references secrets that are not set: %s (set them with `%s`): %w",
			sp.ID(), strings.Join(missing, ", "), cmd, ErrPrecondition)
	}
	return pins, nil
}

// checkPins verifies that every secret version rev pins still exists.
func (t *etx) checkPins(rev Revision) error {
	for _, name := range slices.Sorted(maps.Keys(rev.Secrets)) {
		_, ok, err := t.getRaw(secretKey(rev.App, name, rev.Secrets[name]))
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("revision %s uses secret %s version %d, which was deleted: %w", rev.Name, name, rev.Secrets[name], ErrPrecondition)
		}
	}
	return nil
}

// pruneSecrets deletes secret versions that are neither the latest nor
// pinned by a retained revision of app.
func (t *etx) pruneSecrets(app string) error {
	pinned := map[string]bool{}
	err := listInto(t, pfxRevs+app+"/", func(_ string, r revRec) error {
		for name, v := range r.Secrets {
			pinned[secretKey(app, name, v)] = true
		}
		return nil
	})
	if err != nil {
		return err
	}
	latest, err := t.latestVersions(app)
	if err != nil {
		return err
	}
	kvs, err := t.list(pfxSecrets + app + "/")
	if err != nil {
		return err
	}
	for _, e := range kvs {
		name, v, ok := splitSecretKey(e.key, app)
		if ok && v < latest[name] && !pinned[e.key] {
			t.delete(e.key)
		}
	}
	return nil
}

// SetSecret stores a new secret version. See Store.
func (s *Etcd) SetSecret(ctx context.Context, app, name string, seal func(int) (secrets.Sealed, error), rollout bool, actor string) (int, string, error) {
	now := s.now()
	var version int
	var revision string
	project, _, ok := spec.SplitAppID(app)
	if !ok {
		return 0, "", fmt.Errorf("invalid app %q", app)
	}
	err := s.tx(ctx, func(t *etx) error {
		revision = ""
		if err := t.projectExists(project); err != nil {
			return err
		}
		latest, err := t.latestVersions(app)
		if err != nil {
			return err
		}
		version = latest[name] + 1
		sealed, err := seal(version)
		if err != nil {
			return err
		}
		if err := t.put(secretKey(app, name, version), secretRec{KeyID: sealed.KeyID, WrappedKey: sealed.WrappedKey, Ciphertext: sealed.Ciphertext,
			CreatedAt: now.UnixMilli(), CreatedBy: actor}); err != nil {
			return err
		}
		if err := t.audit(now, actor, "secret.set", app, name+" v"+strconv.Itoa(version)); err != nil {
			return err
		}
		if rollout {
			a, ok, err := t.app(app)
			if err != nil {
				return err
			}
			if ok {
				rev, err := t.revision(a.TargetRevision)
				if err != nil {
					return err
				}
				if slices.Contains(rev.Spec.SecretRefs(), name) {
					next, created, err := s.deploy(t, rev.Spec, a.Replicas, actor, "secret.rollout")
					if err != nil {
						return err
					}
					if created {
						revision = next.Name
					}
				}
			}
		}
		return t.pruneSecrets(app)
	})
	return version, revision, err
}

// GetSecret returns one encrypted secret version. See Store.
func (s *Etcd) GetSecret(ctx context.Context, app, name string, version int) (secrets.Sealed, error) {
	var out secrets.Sealed
	err := s.view(ctx, func(t *etx) error {
		var r secretRec
		ok, err := t.get(secretKey(app, name, version), &r)
		if err != nil {
			return err
		}
		if !ok {
			return notFoundf("secret %s/%s v%d", app, name, version)
		}
		out = secrets.Sealed{KeyID: r.KeyID, WrappedKey: r.WrappedKey, Ciphertext: r.Ciphertext}
		return nil
	})
	return out, err
}

// ListSecrets describes an app's secrets. See Store.
func (s *Etcd) ListSecrets(ctx context.Context, app string) ([]SecretInfo, error) {
	var out []SecretInfo
	err := s.view(ctx, func(t *etx) error {
		out = nil
		latest, err := t.latestVersions(app)
		if err != nil {
			return err
		}
		for _, name := range slices.Sorted(maps.Keys(latest)) {
			var r secretRec
			if _, err := t.get(secretKey(app, name, latest[name]), &r); err != nil {
				return err
			}
			out = append(out, SecretInfo{App: app, Name: name, Version: latest[name], UpdatedAt: fromMS(r.CreatedAt), UpdatedBy: r.CreatedBy})
		}
		var revs []revRec
		if err := listInto(t, pfxRevs+app+"/", func(_ string, r revRec) error { revs = append(revs, r); return nil }); err != nil {
			return err
		}
		slices.Reverse(revs) // newest first
		for _, r := range revs {
			for i := range out {
				if _, ok := r.Secrets[out[i].Name]; ok {
					out[i].UsedBy = append(out[i].UsedBy, r.Name)
				}
			}
		}
		return nil
	})
	return out, err
}

// DeleteSecret removes a secret. See Store.
func (s *Etcd) DeleteSecret(ctx context.Context, app, name, actor string) error {
	now := s.now()
	return s.tx(ctx, func(t *etx) error {
		a, ok, err := t.app(app)
		if err != nil {
			return err
		}
		if ok {
			for _, revName := range slices.Compact([]string{a.ActiveRevision, a.TargetRevision}) {
				rev, err := t.revision(revName)
				if err != nil {
					return err
				}
				if _, ok := rev.Secrets[name]; ok {
					return fmt.Errorf("secret %s is used by revision %s; deploy a spec without it first: %w", name, revName, ErrPrecondition)
				}
			}
		}
		kvs, err := t.list(pfxSecrets + app + "/" + name + "/")
		if err != nil {
			return err
		}
		if len(kvs) == 0 {
			return notFoundf("secret %s/%s", app, name)
		}
		for _, e := range kvs {
			t.delete(e.key)
		}
		return t.audit(now, actor, "secret.delete", app, name)
	})
}

var _ Store = (*Etcd)(nil)

// SchemaVersion is the newest state layout this binary understands.
func SchemaVersion() int { return etcdSchema }

// migration moves the keyspace one schema forward inside a transaction.
type migration func(*etx) error

// migrations[i] moves schema i+1 to i+2; len(migrations) == etcdSchema-1.
var migrations = []migration{
	// 1 -> 2: node records gain labels, restricted, os, and arch (ADR
	// 0014). Nothing to rewrite; the step exists so that servers that would
	// drop those fields when they rewrite a node can no longer lead.
	func(*etx) error { return nil },
	// 2 -> 3: jobs (ADR 0019): apps of kind job, runs under runs/, and
	// replicas that run to completion. Nothing to rewrite; servers that
	// would treat a job as an app can no longer lead.
	func(*etx) error { return nil },
	// 3 -> 4: traffic splitting (ADR 0022): app records gain traffic.
	// Nothing to rewrite; servers that would drop it when they rewrite an
	// app, and run one revision only, can no longer lead.
	func(*etx) error { return nil },
	// 4 -> 5: volumes (ADR 0023) under volumes/, bound to nodes. Nothing to
	// rewrite; servers that would start a replica without its volume, or on
	// another node, can no longer lead.
	func(*etx) error { return nil },
	// 5 -> 6: the cluster network (ADR 0025): the network record and node
	// subnets. Nothing to rewrite (upgraded clusters have no network yet);
	// servers that would register a node without a subnet can no longer
	// lead.
	func(*etx) error { return nil },
	// 6 -> 7: projects (ADR 0026) under projects/, and apps of other
	// projects keyed <name>.<project>. Nothing to rewrite (the default
	// project's apps keep their keys); servers that would treat such a key
	// as an app name, or deploy into a project that does not exist, can no
	// longer lead.
	func(*etx) error { return nil },
	// 7 -> 8: administrators on record (ADR 0028) under admins/. Nothing to
	// rewrite; servers that would accept a removed administrator's
	// certificate can no longer lead.
	func(*etx) error { return nil },
}

// StoredSchema returns the schema the keyspace is written in.
func (s *Etcd) StoredSchema(ctx context.Context) (int, error) {
	v := 0
	err := s.view(ctx, func(t *etx) error {
		_, err := t.get(keySchema, &v)
		return err
	})
	return v, err
}

// Migrate brings the keyspace to this binary's schema, one step per
// transaction, and returns the schema it started from. Only the leader may
// call it, on a store fenced to its term, and only once every server
// understands the new schema (ADR 0012).
func (s *Etcd) Migrate(ctx context.Context) (int, error) {
	return s.migrate(ctx, etcdSchema, migrations)
}

func (s *Etcd) migrate(ctx context.Context, target int, steps []migration) (int, error) {
	if len(steps) != target-1 {
		return 0, fmt.Errorf("store: %d migrations for schema %d", len(steps), target)
	}
	from, err := s.StoredSchema(ctx)
	if err != nil {
		return 0, err
	}
	if from > target {
		return from, fmt.Errorf("the state was written by a newer Armada (schema %d, this binary knows %d)", from, target)
	}
	for v := from; v < target; v++ {
		err := s.tx(ctx, func(t *etx) error {
			var cur int
			if _, err := t.get(keySchema, &cur); err != nil {
				return err
			}
			if cur != v {
				return fmt.Errorf("store: schema changed to %d during migration from %d", cur, v)
			}
			if err := steps[v-1](t); err != nil {
				return fmt.Errorf("migrate schema %d to %d: %w", v, v+1, err)
			}
			return t.put(keySchema, v+1)
		})
		if err != nil {
			return from, err
		}
	}
	return from, nil
}
