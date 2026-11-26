package store

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/netip"
	"os"
	"os/exec"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/client/v3/concurrency"

	"github.com/ryanbekhen/armada/internal/etcd"
	"github.com/ryanbekhen/armada/internal/secrets"
	"github.com/ryanbekhen/armada/internal/spec"
)

// The parity tests of the Rust port (ADR 0055): armada-store-parity, built
// with `cargo build -p armada-store --features parity`, runs the same
// operations as this package's store on the same etcd member, each under
// its own prefix. After every operation the answers (values, error kinds,
// and texts) and the two keyspaces must be equal; every record either
// side wrote must read and encode again to the same bytes on the other
// side; and Go and Rust write concurrently, fence each other, and
// campaign in one election.

func storeBin(t *testing.T) string {
	t.Helper()
	bin := os.Getenv("ARMADA_STORE_BIN")
	if bin == "" {
		t.Skip("ARMADA_STORE_BIN is not set (cargo build -p armada-store --features parity)")
	}
	return bin
}

type rustReply struct {
	ID    int64           `json:"id"`
	Value json.RawMessage `json:"value"`
	Error string          `json:"error"`
	Kind  string          `json:"kind"`
}

// rustProc is one armada-store-parity process: requests go in as lines,
// answers come back by ID, in any order.
type rustProc struct {
	t       *testing.T
	in      io.WriteCloser
	mu      sync.Mutex
	next    int64
	waiting map[int64]chan rustReply
}

func startRust(t *testing.T) *rustProc {
	t.Helper()
	cmd := exec.Command(storeBin(t))
	cmd.Env = append(os.Environ(), "TZ=UTC")
	cmd.Stderr = os.Stderr
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	p := &rustProc{t: t, in: in, waiting: map[int64]chan rustReply{}}
	go func() {
		sc := bufio.NewScanner(out)
		sc.Buffer(nil, 64<<20)
		for sc.Scan() {
			var r rustReply
			if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
				panic(fmt.Sprintf("armada-store-parity answered %q: %v", sc.Text(), err))
			}
			p.mu.Lock()
			ch := p.waiting[r.ID]
			delete(p.waiting, r.ID)
			p.mu.Unlock()
			ch <- r
		}
	}()
	t.Cleanup(func() {
		_ = in.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	return p
}

// send writes a request and returns where its answer arrives.
func (p *rustProc) send(req map[string]any) <-chan rustReply {
	p.mu.Lock()
	p.next++
	id := p.next
	ch := make(chan rustReply, 1)
	p.waiting[id] = ch
	req["id"] = id
	b, err := json.Marshal(req)
	if err != nil {
		p.mu.Unlock()
		p.t.Fatal(err)
	}
	_, err = p.in.Write(append(b, '\n'))
	p.mu.Unlock()
	if err != nil {
		p.t.Fatal(err)
	}
	return ch
}

func (p *rustProc) do(req map[string]any) rustReply {
	p.t.Helper()
	select {
	case r := <-p.send(req):
		return r
	case <-time.After(2 * time.Minute):
		p.t.Fatalf("armada-store-parity did not answer %v", req)
		return rustReply{}
	}
}

func (p *rustProc) ok(req map[string]any) json.RawMessage {
	p.t.Helper()
	r := p.do(req)
	if r.Error != "" {
		p.t.Fatalf("armada-store-parity %v: %s", req["op"], r.Error)
	}
	return r.Value
}

func memberEndpoint() string { return testMember.Client().Endpoints()[0] }

func (p *rustProc) conn(req map[string]any) map[string]any {
	req["endpoint"] = memberEndpoint()
	req["dir"] = testEtcdDir
	return req
}

// errKind names a store error as armada-store-parity does.
func errKind(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrNotFound):
		return "notFound"
	case errors.Is(err, ErrConflict):
		return "conflict"
	case errors.Is(err, ErrPrecondition):
		return "precondition"
	case errors.Is(err, ErrNotLeader):
		return "notLeader"
	}
	return "other"
}

// parityRandom is the random source both sides follow: call n fills byte j
// with n*31+j.
func parityRandom() func([]byte) {
	var n atomic.Uint64
	return func(b []byte) {
		c := n.Add(1)
		for j := range b {
			b[j] = byte(c*31 + uint64(j))
		}
	}
}

// pair is a Go store and a Rust store on two prefixes of one member.
type pair struct {
	t    *testing.T
	g    *Etcd
	gNow atomic.Int64
	r    *rustProc
	h    string
	rPfx string
	ops  int
}

var parityHandles atomic.Int64

func newPair(t *testing.T, r *rustProc, start time.Time) *pair {
	t.Helper()
	p := &pair{t: t, r: r}
	p.gNow.Store(start.UnixMilli())
	gPfx := fmt.Sprintf("/test/%d/", testPrefix.Add(1))
	p.rPfx = fmt.Sprintf("/test/%d/", testPrefix.Add(1))
	g, err := NewEtcd(context.Background(), testMember.Client(), gPfx)
	if err != nil {
		t.Fatal(err)
	}
	g.SetNow(func() time.Time { return time.UnixMilli(p.gNow.Load()).UTC() })
	g.random = parityRandom()
	p.g = g
	p.h = fmt.Sprintf("s%d", parityHandles.Add(1))
	r.ok(r.conn(map[string]any{"op": "open", "handle": p.h, "prefix": p.rPfx, "ms": start.UnixMilli()}))
	return p
}

func (p *pair) setNow(at time.Time) {
	p.gNow.Store(at.UnixMilli())
	p.r.ok(map[string]any{"op": "setNow", "handle": p.h, "ms": at.UnixMilli()})
}

// normalize makes two answers comparable: times as UTC instants, and nil
// and empty lists and maps alike.
func normalize(v any) any {
	switch x := v.(type) {
	case map[string]any:
		if len(x) == 0 {
			return nil
		}
		out := map[string]any{}
		for k, e := range x {
			out[k] = normalize(e)
		}
		return out
	case []any:
		if len(x) == 0 {
			return nil
		}
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = normalize(e)
		}
		return out
	case string:
		if len(x) >= 20 && x[4] == '-' && x[10] == 'T' {
			if tm, err := time.Parse(time.RFC3339Nano, x); err == nil {
				return tm.UTC().Format(time.RFC3339Nano)
			}
		}
	}
	return v
}

func decodeAny(t *testing.T, b []byte) any {
	t.Helper()
	if len(b) == 0 {
		return nil
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("decode %s: %v", b, err)
	}
	return normalize(v)
}

// dump returns every key under prefix (without it) and its value.
func dump(t *testing.T, prefix string) map[string]string {
	t.Helper()
	resp, err := testMember.Client().Get(context.Background(), prefix, clientv3.WithPrefix())
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, kv := range resp.Kvs {
		out[strings.TrimPrefix(string(kv.Key), prefix)] = string(kv.Value)
	}
	return out
}

func diffKeyspaces(gk, rk map[string]string) []string {
	var d []string
	for _, k := range slices.Sorted(maps.Keys(gk)) {
		rv, ok := rk[k]
		switch {
		case !ok:
			d = append(d, fmt.Sprintf("only Go wrote %s = %s", k, gk[k]))
		case rv != gk[k]:
			d = append(d, fmt.Sprintf("%s:\n  go   %s\n  rust %s", k, gk[k], rv))
		}
	}
	for _, k := range slices.Sorted(maps.Keys(rk)) {
		if _, ok := gk[k]; !ok {
			d = append(d, fmt.Sprintf("only Rust wrote %s = %s", k, rk[k]))
		}
	}
	return d
}

// keyspaces fails the test unless both prefixes hold the same records.
func (p *pair) keyspaces(what string) {
	p.t.Helper()
	if d := diffKeyspaces(dump(p.t, p.g.prefix), dump(p.t, p.rPfx)); len(d) > 0 {
		p.t.Fatalf("after %s the keyspaces differ:\n%s", what, strings.Join(d, "\n"))
	}
}

// call runs method on both stores and compares answers and keyspaces. It
// returns Go's answer and error.
func (p *pair) call(method string, args map[string]any) (any, error) {
	p.t.Helper()
	p.ops++
	gv, gerr := goCall(context.Background(), p.g, method, args)
	if args == nil {
		args = map[string]any{}
	}
	rr := p.r.do(map[string]any{"op": "call", "handle": p.h, "method": method, "args": args})
	what := fmt.Sprintf("%s %s", method, compactArgs(args))
	if errKind(gerr) != rr.Kind || (gerr != nil && gerr.Error() != rr.Error) {
		p.t.Fatalf("%s:\n  go   %q (%s)\n  rust %q (%s)", what, errText(gerr), errKind(gerr), rr.Error, rr.Kind)
	}
	if gerr == nil {
		b, err := json.Marshal(gv)
		if err != nil {
			p.t.Fatal(err)
		}
		g, r := decodeAny(p.t, b), decodeAny(p.t, rr.Value)
		if !reflect.DeepEqual(g, r) {
			gj, _ := json.Marshal(g)
			rj, _ := json.Marshal(r)
			p.t.Fatalf("%s answers differ:\n  go   %s\n  rust %s", what, gj, rj)
		}
	}
	p.keyspaces(what)
	return gv, gerr
}

// must is call for an operation that succeeds.
func (p *pair) must(method string, args map[string]any) any {
	p.t.Helper()
	v, err := p.call(method, args)
	if err != nil {
		p.t.Fatalf("%s: %v", method, err)
	}
	return v
}

// fails is call for an operation that fails.
func (p *pair) fails(method string, args map[string]any) {
	p.t.Helper()
	if _, err := p.call(method, args); err == nil {
		p.t.Fatalf("%s %s succeeded", method, compactArgs(args))
	}
}

// reencode checks that every record of both prefixes reads and encodes
// again to the bytes stored, in Rust.
func (p *pair) reencode() {
	p.t.Helper()
	reencodeOK(p.t, p.r, p.h)
}

func reencodeOK(t *testing.T, r *rustProc, h string) {
	t.Helper()
	var diffs []struct{ Key, Stored, Encoded string }
	if err := json.Unmarshal(r.ok(map[string]any{"op": "reencode", "handle": h}), &diffs); err != nil {
		t.Fatal(err)
	}
	for _, d := range diffs {
		t.Errorf("%s encodes differently in Rust:\n  stored  %s\n  encoded %s", d.Key, d.Stored, d.Encoded)
	}
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func compactArgs(args map[string]any) string {
	b, _ := json.Marshal(args)
	if len(b) > 300 {
		b = append(b[:300], "..."...)
	}
	return string(b)
}

func arg[T any](args map[string]any, k string) T {
	v, _ := args[k].(T)
	return v
}

func sealFor(value string) func(int) (secrets.Sealed, error) {
	return func(v int) (secrets.Sealed, error) {
		return secrets.Sealed{KeyID: "k", WrappedKey: []byte(strconv.Itoa(v)), Ciphertext: []byte(value)}, nil
	}
}

// goCall is armada-store-parity's call on the Go store.
func goCall(ctx context.Context, s *Etcd, method string, a map[string]any) (any, error) {
	str := func(k string) string { return arg[string](a, k) }
	b := func(k string) bool { return arg[bool](a, k) }
	n := func(k string) int { return arg[int](a, k) }
	tm := func(k string) time.Time { return arg[time.Time](a, k) }
	switch method {
	case "GetMeta":
		return s.GetMeta(ctx, str("key"))
	case "SetMeta":
		return nil, s.SetMeta(ctx, str("key"), str("value"))
	case "GetNetwork":
		return s.GetNetwork(ctx)
	case "InitNetwork":
		return nil, s.InitNetwork(ctx, Network{Mode: str("Mode"), ClusterCIDR: arg[netip.Prefix](a, "ClusterCIDR"),
			IsolateDefault: b("IsolateDefault"), MeshCIDR: arg[netip.Prefix](a, "MeshCIDR")})
	case "SetDefaultIsolation":
		return nil, s.SetDefaultIsolation(ctx, b("on"), str("actor"))
	case "StartNetworkSwitch":
		return nil, s.StartNetworkSwitch(ctx, str("to"), str("actor"))
	case "AdvanceNetworkSwitch":
		return nil, s.AdvanceNetworkSwitch(ctx, str("to"), str("from"))
	case "UpsertNode":
		return nil, s.UpsertNode(ctx, arg[Node](a, "node"))
	case "SetNodeSite":
		return nil, s.SetNodeSite(ctx, str("id"), str("site"), str("actor"))
	case "SetNodeRelay":
		return s.SetNodeRelay(ctx, str("id"), b("on"), str("actor"))
	case "SetNodeNetworkKey":
		return nil, s.SetNodeNetworkKey(ctx, str("id"), str("key"))
	case "GetNode":
		return s.GetNode(ctx, str("id"))
	case "ListNodes":
		return s.ListNodes(ctx)
	case "SetNodeStatus":
		return nil, s.SetNodeStatus(ctx, str("id"), arg[NodeStatus](a, "status"))
	case "SetNodeCordoned":
		return nil, s.SetNodeCordoned(ctx, str("id"), b("on"), str("actor"))
	case "SetNodeLabels":
		return s.SetNodeLabels(ctx, str("id"), arg[map[string]string](a, "set"), arg[[]string](a, "remove"), str("actor"))
	case "SetNodeRestricted":
		return nil, s.SetNodeRestricted(ctx, str("id"), b("on"), str("actor"))
	case "RemoveNode":
		return nil, s.RemoveNode(ctx, str("id"), b("force"), str("actor"))
	case "CreateJoinToken":
		return nil, s.CreateJoinToken(ctx, arg[JoinToken](a, "token"))
	case "OpenJoinTokens":
		return s.OpenJoinTokens(ctx)
	case "FreeMeshAddress":
		return s.FreeMeshAddress(ctx)
	case "SetMeshCIDR":
		return nil, s.SetMeshCIDR(ctx, arg[netip.Prefix](a, "prefix"), str("actor"))
	case "RedeemJoinToken", "RedeemServerToken":
		hash := str("hash")
		check := func(h string) bool { return h == hash }
		issue := func() (NodeCert, error) {
			if e := str("issueError"); e != "" {
				return NodeCert{}, errors.New(e)
			}
			return arg[NodeCert](a, "cert"), nil
		}
		if method == "RedeemJoinToken" {
			return nil, s.RedeemJoinToken(ctx, str("id"), check, arg[Node](a, "node"), issue)
		}
		return nil, s.RedeemServerToken(ctx, str("id"), check, arg[Server](a, "server"), arg[Node](a, "node"), issue)
	case "RecordNodeCert":
		return nil, s.RecordNodeCert(ctx, str("node"), arg[NodeCert](a, "cert"), str("keep"))
	case "NodeCertAllowed":
		return s.NodeCertAllowed(ctx, str("node"), str("serial"))
	case "StoredSchema":
		return s.StoredSchema(ctx)
	case "UpsertServer":
		return nil, s.UpsertServer(ctx, arg[Server](a, "server"))
	case "ListServers":
		return s.ListServers(ctx)
	case "RemoveServer":
		return nil, s.RemoveServer(ctx, str("name"), str("actor"))
	case "CreateSpace":
		return s.CreateSpace(ctx, str("name"), str("actor"), arg[*Principal](a, "by"))
	case "GetSpace":
		return s.GetSpace(ctx, str("name"))
	case "ListSpaces":
		return s.ListSpaces(ctx)
	case "DeleteSpace":
		return nil, s.DeleteSpace(ctx, str("name"), str("actor"))
	case "CreateUser":
		return s.CreateUser(ctx, arg[Principal](a, "principal"), str("actor"))
	case "KnowUser":
		return nil, s.KnowUser(ctx, str("name"))
	case "SetUserSince":
		return nil, s.SetUserSince(ctx, str("name"), tm("since"), str("serial"), str("actor"))
	case "RenewedUser":
		return nil, s.RenewedUser(ctx, str("name"), tm("notBefore"), str("callerSerial"), str("serial"))
	case "CreateService":
		return s.CreateService(ctx, arg[Principal](a, "principal"), str("actor"))
	case "GetPrincipal":
		return s.GetPrincipal(ctx, str("kind"), str("name"))
	case "ListPrincipals":
		return s.ListPrincipals(ctx, str("kind"))
	case "SetPrincipalLabels":
		return s.SetPrincipalLabels(ctx, str("kind"), str("name"), arg[map[string][]string](a, "labels"), str("actor"))
	case "Assign":
		return s.Assign(ctx, str("kind"), str("name"), arg[Grant](a, "grant"), str("actor"))
	case "Unassign":
		return s.Unassign(ctx, str("kind"), str("name"), arg[Grant](a, "grant"), str("actor"))
	case "DeletePrincipal":
		return nil, s.DeletePrincipal(ctx, str("kind"), str("name"), str("actor"))
	case "RecordServiceCert":
		return nil, s.RecordServiceCert(ctx, str("name"), arg[NodeCert](a, "cert"), str("keep"), str("actor"))
	case "UserAccess":
		p, ok, err := s.UserAccess(ctx, str("name"), tm("notBefore"), str("serial"))
		return map[string]any{"Principal": p, "Allowed": ok}, err
	case "ServiceAccess":
		p, ok, err := s.ServiceAccess(ctx, str("name"), str("serial"))
		return map[string]any{"Principal": p, "Allowed": ok}, err
	case "RecordMetricsCert":
		return nil, s.RecordMetricsCert(ctx, str("name"), arg[NodeCert](a, "cert"), str("actor"))
	case "RevokeMetricsCerts":
		return nil, s.RevokeMetricsCerts(ctx, str("name"), str("actor"))
	case "ListMetricsCerts":
		return s.ListMetricsCerts(ctx)
	case "MetricsAccess":
		return s.MetricsAccess(ctx, str("name"), tm("notBefore"), str("serial"))
	case "Deploy", "DeployWith":
		rev, created, err := s.DeployWith(ctx, arg[*spec.App](a, "spec"), str("actor"), arg[DeployOptions](a, "opts"))
		return map[string]any{"Rev": rev, "Created": created}, err
	case "Rollback":
		return s.Rollback(ctx, str("app"), str("revision"), str("actor"))
	case "RestartApp":
		return s.RestartApp(ctx, str("app"), str("actor"))
	case "CompleteRollout":
		return nil, s.CompleteRollout(ctx, str("app"), str("revision"))
	case "FailRollout":
		return nil, s.FailRollout(ctx, str("app"), str("revision"), str("message"))
	case "MarkRolloutProgress":
		return nil, s.MarkRolloutProgress(ctx, str("app"))
	case "GetApp":
		return s.GetApp(ctx, str("name"))
	case "ListApps":
		return s.ListApps(ctx)
	case "GetApps":
		return s.GetApps(ctx, arg[[]string](a, "names"))
	case "ListAppIDs":
		return s.ListAppIDs(ctx)
	case "SetReplicas":
		return nil, s.SetReplicas(ctx, str("app"), n("n"), str("actor"))
	case "SetTraffic":
		return s.SetTraffic(ctx, str("app"), arg[[]spec.TrafficTarget](a, "weights"), str("actor"))
	case "AutoscaleReplicas":
		return nil, s.AutoscaleReplicas(ctx, str("app"), n("from"), n("n"), str("actor"))
	case "GetRevision":
		return s.GetRevision(ctx, str("name"))
	case "GetRevisions":
		return s.GetRevisions(ctx, arg[[]string](a, "names"))
	case "ListRevisions":
		return s.ListRevisions(ctx, str("app"))
	case "SetRevisionDigest":
		return nil, s.SetRevisionDigest(ctx, str("revision"), str("digest"))
	case "SetRevisionPlatforms":
		return nil, s.SetRevisionPlatforms(ctx, str("revision"), arg[[]string](a, "platforms"))
	case "CreateReplica":
		return nil, s.CreateReplica(ctx, arg[Replica](a, "replica"))
	case "ReplicaPlacements":
		return s.ReplicaPlacements(ctx, str("app"))
	case "PrunePlacements":
		return s.PrunePlacements(ctx, tm("before"))
	case "DeleteReplica":
		return nil, s.DeleteReplica(ctx, str("id"))
	case "DrainReplica":
		return nil, s.DrainReplica(ctx, str("id"))
	case "SetReplicaMoving":
		return nil, s.SetReplicaMoving(ctx, str("id"), b("on"))
	case "ReleaseReplica":
		return nil, s.ReleaseReplica(ctx, str("id"))
	case "SetReplicaDone":
		return nil, s.SetReplicaDone(ctx, str("id"))
	case "ListReplicas":
		return s.ListReplicas(ctx, arg[ReplicaFilter](a, "filter"))
	case "UpdateReplicaStatus":
		return nil, s.UpdateReplicaStatus(ctx, str("node"), arg[ReplicaStatus](a, "status"))
	case "ListVolumes":
		return s.ListVolumes(ctx, str("app"))
	case "GetVolume":
		return s.GetVolume(ctx, str("app"), str("name"))
	case "DeleteVolume":
		return nil, s.DeleteVolume(ctx, str("app"), str("name"), str("actor"))
	case "BindVolume":
		return nil, s.BindVolume(ctx, str("app"), str("name"), str("node"), str("actor"))
	case "RecordVolumeBackup":
		return nil, s.RecordVolumeBackup(ctx, str("app"), str("name"), str("id"), int64(n("stored")), n("snapshots"), str("error"))
	case "PutEvent":
		return s.PutEvent(ctx, arg[Event](a, "event"), str("replace"))
	case "ListEvents":
		return s.ListEvents(ctx, tm("since"))
	case "TrimEvents":
		return nil, s.TrimEvents(ctx, n("keep"))
	case "CreateJobRun":
		return s.CreateJobRun(ctx, str("job"), str("trigger"), tm("at"), str("actor"))
	case "SkipJobSchedule":
		return nil, s.SkipJobSchedule(ctx, str("job"), tm("at"))
	case "UpdateJobRun":
		return nil, s.UpdateJobRun(ctx, arg[JobRun](a, "run"))
	case "ListJobRuns":
		return s.ListJobRuns(ctx, str("job"))
	case "DeleteJobRun":
		return nil, s.DeleteJobRun(ctx, str("job"), int64(n("seq")))
	case "CancelJobRuns":
		return s.CancelJobRuns(ctx, str("job"), str("actor"))
	case "DeleteJob":
		return nil, s.DeleteJob(ctx, str("job"), str("actor"))
	case "MarkAppRemoving":
		return nil, s.MarkAppRemoving(ctx, str("app"), str("actor"))
	case "DeleteApp":
		return nil, s.DeleteApp(ctx, str("app"))
	case "ListAudit":
		return s.ListAudit(ctx, n("limit"))
	case "RecordAudit":
		return nil, s.RecordAudit(ctx, str("actor"), str("action"), str("target"), str("detail"))
	case "SetSecret":
		v, revs, err := s.SetSecret(ctx, str("secret"), str("key"), sealFor(str("value")), b("rollout"), str("actor"))
		return map[string]any{"Version": v, "Revisions": revs}, err
	case "GetSecret":
		return s.GetSecret(ctx, str("secret"), str("key"), n("version"))
	case "ListSecrets":
		return s.ListSecrets(ctx, str("secret"))
	case "ListSpaceSecrets":
		return s.ListSpaceSecrets(ctx, str("space"))
	case "DeleteSecret":
		return nil, s.DeleteSecret(ctx, str("secret"), str("key"), str("actor"))
	case "ListDomains":
		return s.ListDomains(ctx)
	case "GetDomain":
		return s.GetDomain(ctx, str("name"))
	case "SetDomainVerification":
		return nil, s.SetDomainVerification(ctx, str("name"), b("verified"), str("message"))
	case "Migrate":
		return s.Migrate(ctx)
	case "MigrateTo":
		return s.migrate(ctx, n("target"), migrations[:n("target")-1])
	case "SetLegacyCerts":
		return nil, s.setLegacyCerts(ctx)
	}
	return nil, fmt.Errorf("goCall: unknown method %s", method)
}

func paritySpec(t *testing.T, space, y string) *spec.App {
	t.Helper()
	sp, err := spec.ParseIn([]byte(y), space)
	if err != nil {
		t.Fatalf("spec %q: %v", y, err)
	}
	return sp
}

// pargs is shorthand for an argument map.
type pargs = map[string]any

var parityStart = time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)

func TestArmadaStoreNodesAndNetwork(t *testing.T) {
	t.Parallel()
	p := newPair(t, startRust(t), parityStart)
	now := parityStart
	p.must("SetMeta", pargs{"key": "settings", "value": "{\"tls\":true}<&>"})
	p.must("GetMeta", pargs{"key": "settings"})
	p.fails("GetMeta", pargs{"key": "nope"})
	p.fails("GetNetwork", nil)
	p.fails("InitNetwork", pargs{"Mode": "weird", "ClusterCIDR": netip.MustParsePrefix("10.120.0.0/16")})
	p.fails("InitNetwork", pargs{"Mode": NetworkPlain, "ClusterCIDR": netip.MustParsePrefix("10.120.0.1/16")})
	p.fails("InitNetwork", pargs{"Mode": NetworkPlain, "ClusterCIDR": netip.MustParsePrefix("10.120.0.0/24")})
	p.fails("InitNetwork", pargs{"Mode": NetworkPlain, "ClusterCIDR": netip.MustParsePrefix("8.0.0.0/16")})
	p.fails("InitNetwork", pargs{"Mode": NetworkPlain})
	p.fails("InitNetwork", pargs{"Mode": NetworkPlain, "ClusterCIDR": netip.MustParsePrefix("10.120.0.0/16"), "MeshCIDR": netip.MustParsePrefix("10.122.0.0/16")})
	p.fails("SetDefaultIsolation", pargs{"on": true, "actor": "user:a"})
	p.fails("FreeMeshAddress", nil)
	p.must("InitNetwork", pargs{"Mode": NetworkPlain, "ClusterCIDR": netip.MustParsePrefix("10.120.0.0/16")})
	p.fails("InitNetwork", pargs{"Mode": NetworkPlain, "ClusterCIDR": netip.MustParsePrefix("10.120.0.0/16")})
	p.must("GetNetwork", nil)
	p.must("SetDefaultIsolation", pargs{"on": true, "actor": "user:a"})
	p.must("SetDefaultIsolation", pargs{"on": true, "actor": "user:a"})

	p.must("UpsertNode", pargs{"node": Node{ID: "n1", PrivateIP: "10.0.0.1", CPUMillis: 2000, MemoryBytes: 4 << 30,
		Labels: map[string]string{"zone": "a", "disk": "ssd"}, OS: "linux", Arch: "amd64", Restricted: true, NetworkKey: "key1"}})
	p.must("UpsertNode", pargs{"node": Node{ID: "n2", PrivateIP: "10.0.0.2", State: NodeReady, LastSeen: now}})
	p.must("UpsertNode", pargs{"node": Node{ID: "n1", PrivateIP: "10.0.0.1", CPUMillis: 4000, Labels: map[string]string{}}})
	p.fails("UpsertNode", pargs{"node": Node{ID: "n3", PrivateIP: "10.120.0.9"}})
	p.fails("UpsertNode", pargs{"node": Node{ID: "n3", PrivateIP: "fd00::1"}})
	p.fails("UpsertNode", pargs{"node": Node{ID: "n3", PrivateIP: "10.0.0.3", MeshAddress: true}})
	p.must("GetNode", pargs{"id": "n1"})
	p.fails("GetNode", pargs{"id": "nope"})
	p.must("ListNodes", nil)

	st := NodeStatus{State: NodeReady, LastSeen: now, CPUMillis: 1000, MemoryBytes: 1 << 30, Version: "v1", OS: "linux", Arch: "arm64",
		Jobs: true, Volumes: true, Containers: true, NFS: true, NetworkKey: "key2", Endpoint: "203.0.113.2"}
	p.must("SetNodeStatus", pargs{"id": "n2", "status": st})
	st.LastSeen = now.Add(10 * time.Second)
	p.must("SetNodeStatus", pargs{"id": "n2", "status": st}) // a heartbeat only: nothing written
	st.LastSeen = now.Add(40 * time.Second)
	p.must("SetNodeStatus", pargs{"id": "n2", "status": st})
	st.NetworkKey = "key1"
	p.fails("SetNodeStatus", pargs{"id": "n2", "status": st})
	st.NetworkKey, st.BehindNAT = "", true
	p.must("SetNodeStatus", pargs{"id": "n2", "status": st})
	p.fails("SetNodeStatus", pargs{"id": "nope", "status": st})
	p.must("SetNodeNetworkKey", pargs{"id": "n2", "key": "key3"})
	p.must("SetNodeNetworkKey", pargs{"id": "n2", "key": "key3"})
	p.fails("SetNodeNetworkKey", pargs{"id": "n2", "key": "key1"})
	p.fails("SetNodeNetworkKey", pargs{"id": "nope", "key": "k"})

	p.must("SetNodeCordoned", pargs{"id": "n1", "on": true, "actor": "user:a"})
	p.must("SetNodeCordoned", pargs{"id": "n1", "on": false, "actor": "user:a"})
	p.fails("SetNodeCordoned", pargs{"id": "nope", "on": true, "actor": "user:a"})
	p.must("SetNodeLabels", pargs{"id": "n1", "set": map[string]string{"pool": "gpu", "zone": "b"}, "remove": []string{"disk"}, "actor": "user:a"})
	p.must("SetNodeLabels", pargs{"id": "n1", "remove": []string{"pool", "zone"}, "actor": "user:a"})
	many := map[string]string{}
	for i := range spec.MaxNodeLabels + 1 {
		many[fmt.Sprintf("k%d", i)] = "v"
	}
	p.fails("SetNodeLabels", pargs{"id": "n1", "set": many, "actor": "user:a"})
	p.must("SetNodeRestricted", pargs{"id": "n1", "on": false, "actor": "user:a"})
	p.must("SetNodeRestricted", pargs{"id": "n1", "on": true, "actor": "user:a"})

	p.fails("SetNodeSite", pargs{"id": "n1", "site": "Not Valid!", "actor": "user:a"})
	p.must("SetNodeSite", pargs{"id": "n1", "site": "west", "actor": "user:a"})
	p.must("SetNodeSite", pargs{"id": "n1", "site": "west", "actor": "user:a"})
	p.fails("SetNodeRelay", pargs{"id": "n2", "on": true, "actor": "user:a"}) // behind NAT
	p.must("SetNodeRelay", pargs{"id": "n1", "on": true, "actor": "user:a"})
	p.must("SetNodeRelay", pargs{"id": "n1", "on": true, "actor": "user:a"})
	p.must("UpsertNode", pargs{"node": Node{ID: "n4", PrivateIP: "10.0.0.4", Site: "west"}})
	p.must("SetNodeRelay", pargs{"id": "n4", "on": true, "actor": "user:a"})
	p.must("SetNodeRelay", pargs{"id": "n4", "on": false, "actor": "user:a"})
	p.fails("StartNetworkSwitch", pargs{"to": NetworkWireGuard, "actor": "user:a"}) // a node in another site
	p.must("SetNodeSite", pargs{"id": "n1", "site": "", "actor": "user:a"})
	p.must("SetNodeSite", pargs{"id": "n4", "site": "", "actor": "user:a"})
	p.fails("StartNetworkSwitch", pargs{"to": NetworkMesh, "actor": "user:a"})
	p.must("StartNetworkSwitch", pargs{"to": NetworkPlain, "actor": "user:a"})
	p.must("StartNetworkSwitch", pargs{"to": NetworkWireGuard, "actor": "user:a"})
	p.fails("StartNetworkSwitch", pargs{"to": NetworkWireGuard, "actor": "user:a"})
	p.fails("SetNodeSite", pargs{"id": "n1", "site": "east", "actor": "user:a"})
	p.must("GetNetwork", nil)
	p.must("StartNetworkSwitch", pargs{"to": NetworkPlain, "actor": "user:a"}) // gives it up
	p.must("StartNetworkSwitch", pargs{"to": NetworkWireGuard, "actor": "user:a"})
	p.fails("AdvanceNetworkSwitch", pargs{"to": NetworkWireGuard, "from": SwitchMove})
	p.setNow(now.Add(time.Minute))
	p.must("AdvanceNetworkSwitch", pargs{"to": NetworkWireGuard, "from": SwitchPrepare})
	p.must("SetDefaultIsolation", pargs{"on": false, "actor": "user:a"})
	p.fails("StartNetworkSwitch", pargs{"to": NetworkPlain, "actor": "user:a"}) // move step: no giving up
	p.must("AdvanceNetworkSwitch", pargs{"to": NetworkWireGuard, "from": SwitchMove})
	p.must("GetNetwork", nil)

	// Mesh addresses outside the mesh mode.
	p.fails("SetMeshCIDR", pargs{"prefix": netip.MustParsePrefix("10.122.0.0/25"), "actor": "user:a"})
	p.fails("SetMeshCIDR", pargs{"prefix": netip.MustParsePrefix("10.120.0.0/16"), "actor": "user:a"})
	p.fails("SetMeshCIDR", pargs{"prefix": netip.MustParsePrefix("10.0.0.0/16"), "actor": "user:a"})
	p.must("SetMeshCIDR", pargs{"prefix": netip.MustParsePrefix("10.123.0.0/16"), "actor": "user:a"})
	p.must("SetMeshCIDR", pargs{"prefix": netip.MustParsePrefix("10.123.0.0/16"), "actor": "user:a"})
	p.must("FreeMeshAddress", nil)
	p.fails("UpsertNode", pargs{"node": Node{ID: "n5", PrivateIP: "10.123.0.7"}})
	p.must("UpsertNode", pargs{"node": Node{ID: "n5", PrivateIP: "10.123.0.1", MeshAddress: true, Endpoint: "198.51.100.5"}})
	p.must("FreeMeshAddress", nil)
	p.fails("SetMeshCIDR", pargs{"prefix": netip.MustParsePrefix("10.124.0.0/16"), "actor": "user:a"})

	// Tokens and joins.
	exp := now.Add(time.Hour)
	p.fails("CreateJoinToken", pargs{"token": JoinToken{ID: "t0", Site: "Bad Site", ExpiresAt: exp}})
	p.must("CreateJoinToken", pargs{"token": JoinToken{ID: "t1", SecretHash: "h1", ExpiresAt: exp, CreatedBy: "user:a"}})
	p.must("CreateJoinToken", pargs{"token": JoinToken{ID: "t2", SecretHash: "h2", ExpiresAt: exp, CreatedBy: "user:a",
		Labels: map[string]string{"role": "edge"}, From: "198.51.100.9", Site: "east"}})
	p.must("CreateJoinToken", pargs{"token": JoinToken{ID: "ts", SecretHash: "hs", ExpiresAt: exp, CreatedBy: "user:a", Server: true}})
	p.must("CreateJoinToken", pargs{"token": JoinToken{ID: "told", SecretHash: "ho", ExpiresAt: now.Add(-time.Minute), CreatedBy: "user:a"}})
	p.fails("CreateJoinToken", pargs{"token": JoinToken{ID: "t1", SecretHash: "h1", ExpiresAt: exp}})
	p.must("OpenJoinTokens", nil)
	cert := NodeCert{Serial: "s1", NotAfter: now.Add(30 * 24 * time.Hour)}
	p.fails("RedeemJoinToken", pargs{"id": "t1", "hash": "wrong", "node": Node{ID: "n6", PrivateIP: "10.0.0.6"}, "cert": cert})
	p.fails("RedeemJoinToken", pargs{"id": "nope", "hash": "h1", "node": Node{ID: "n6", PrivateIP: "10.0.0.6"}, "cert": cert})
	p.fails("RedeemJoinToken", pargs{"id": "ts", "hash": "hs", "node": Node{ID: "n6", PrivateIP: "10.0.0.6"}, "cert": cert})
	p.fails("RedeemJoinToken", pargs{"id": "t1", "hash": "h1", "node": Node{ID: "n1", PrivateIP: "10.0.0.6"}, "cert": cert})
	p.fails("RedeemJoinToken", pargs{"id": "t1", "hash": "h1", "node": Node{ID: "n6", PrivateIP: "10.0.0.1"}, "cert": cert})
	p.fails("RedeemJoinToken", pargs{"id": "t1", "hash": "h1", "node": Node{ID: "n6", PrivateIP: "10.0.0.6", NetworkKey: "key1"}, "cert": cert})
	p.fails("RedeemJoinToken", pargs{"id": "t1", "hash": "h1", "node": Node{ID: "n6", PrivateIP: "10.0.0.6"}, "issueError": "cannot sign"})
	p.must("RedeemJoinToken", pargs{"id": "t1", "hash": "h1", "node": Node{ID: "n6", PrivateIP: "10.0.0.6", NetworkKey: "key6"}, "cert": cert})
	p.fails("RedeemJoinToken", pargs{"id": "t1", "hash": "h1", "node": Node{ID: "n7", PrivateIP: "10.0.0.7"}, "cert": cert})
	p.must("RedeemJoinToken", pargs{"id": "t2", "hash": "h2", "node": Node{ID: "n7", PrivateIP: "10.0.0.7", BehindNAT: true}, "cert": NodeCert{Serial: "s7", NotAfter: exp}})
	srv := Server{Name: "srv1", PrivateIP: "10.0.0.8", APIAddr: "10.0.0.8:7443", JoinAddr: "10.0.0.8:7444", MemberID: 18446744073709551615, Schema: 15, Version: "v0.1.0"}
	p.must("RedeemServerToken", pargs{"id": "ts", "hash": "hs", "server": srv, "node": Node{ID: "n8", PrivateIP: "10.0.0.8"}, "cert": NodeCert{Serial: "s8", NotAfter: exp}})
	p.setNow(now.Add(2 * time.Hour))
	p.must("CreateJoinToken", pargs{"token": JoinToken{ID: "t3", SecretHash: "h3", ExpiresAt: now.Add(3 * time.Hour), CreatedBy: "user:a"}}) // prunes
	p.must("OpenJoinTokens", nil)
	p.must("RecordNodeCert", pargs{"node": "n6", "cert": NodeCert{Serial: "s1b", NotAfter: now.Add(60 * 24 * time.Hour)}})
	p.must("RecordNodeCert", pargs{"node": "n6", "cert": NodeCert{Serial: "s1c", NotAfter: now.Add(90 * 24 * time.Hour)}, "keep": "s1b"})
	p.fails("RecordNodeCert", pargs{"node": "nope", "cert": cert})
	for _, s := range []string{"s1", "s1b", "s1c", "zz"} {
		p.must("NodeCertAllowed", pargs{"node": "n6", "serial": s})
	}
	p.must("NodeCertAllowed", pargs{"node": "nope", "serial": "s1"})
	p.must("SetLegacyCerts", nil)
	p.must("NodeCertAllowed", pargs{"node": "n2", "serial": "any"})
	p.must("RecordNodeCert", pargs{"node": "n2", "cert": cert})
	p.must("ListNodes", nil)

	// Servers.
	p.must("UpsertServer", pargs{"server": srv})
	p.must("UpsertServer", pargs{"server": Server{Name: "srv2", PrivateIP: "10.0.0.9", APIAddr: "10.0.0.9:7443", MemberID: 7}})
	srv.Version = "v0.1.1"
	p.must("UpsertServer", pargs{"server": srv})
	p.must("ListServers", nil)
	p.must("RemoveServer", pargs{"name": "srv2", "actor": "user:a"})
	p.fails("RemoveServer", pargs{"name": "srv2", "actor": "user:a"})
	p.must("StoredSchema", nil)

	// Removing nodes.
	p.must("RemoveNode", pargs{"id": "n7", "actor": "user:a"})
	p.fails("RemoveNode", pargs{"id": "n7", "actor": "user:a"})
	p.must("ListAudit", pargs{"limit": 0})
	p.must("ListAudit", pargs{"limit": 3})
	p.reencode()
}

// The mesh mode.
func TestArmadaStoreMesh(t *testing.T) {
	t.Parallel()
	p := newPair(t, startRust(t), parityStart)
	p.fails("InitNetwork", pargs{"Mode": NetworkMesh, "ClusterCIDR": netip.MustParsePrefix("10.120.0.0/16"), "MeshCIDR": netip.MustParsePrefix("10.120.0.0/20")})
	p.fails("InitNetwork", pargs{"Mode": NetworkMesh, "ClusterCIDR": netip.MustParsePrefix("10.120.0.0/16")})
	p.must("InitNetwork", pargs{"Mode": NetworkMesh, "ClusterCIDR": netip.MustParsePrefix("10.120.0.0/16"), "MeshCIDR": netip.MustParsePrefix("10.122.0.0/24")})
	p.must("FreeMeshAddress", nil)
	p.fails("UpsertNode", pargs{"node": Node{ID: "m0", PrivateIP: "10.0.0.1"}})
	p.must("UpsertNode", pargs{"node": Node{ID: "m1", PrivateIP: "10.122.0.1", Endpoint: "203.0.113.1"}})
	p.must("UpsertNode", pargs{"node": Node{ID: "m2", PrivateIP: "10.122.0.2", Endpoint: "203.0.113.2"}})
	p.must("FreeMeshAddress", nil)
	p.fails("SetMeshCIDR", pargs{"prefix": netip.MustParsePrefix("10.123.0.0/16"), "actor": "user:a"})
	p.fails("StartNetworkSwitch", pargs{"to": NetworkPlain, "actor": "user:a"})
	p.must("GetNetwork", nil)
	p.reencode()
}

func TestArmadaStoreApps(t *testing.T) {
	t.Parallel()
	p := newPair(t, startRust(t), parityStart)
	now := parityStart
	p.must("InitNetwork", pargs{"Mode": NetworkWireGuard, "ClusterCIDR": netip.MustParsePrefix("10.120.0.0/16")})
	p.must("UpsertNode", pargs{"node": Node{ID: "n1", PrivateIP: "10.0.0.1"}})
	p.must("UpsertNode", pargs{"node": Node{ID: "n2", PrivateIP: "10.0.0.2"}})
	p.fails("CreateSpace", pargs{"name": "default", "actor": "user:a"})
	p.fails("CreateSpace", pargs{"name": "Bad_Name", "actor": "user:a"})
	p.must("CreateSpace", pargs{"name": "shop", "actor": "user:a"})
	p.fails("CreateSpace", pargs{"name": "shop", "actor": "user:a"})
	p.must("ListSpaces", nil)
	p.must("GetSpace", pargs{"name": "default"})
	p.must("GetSpace", pargs{"name": "shop"})
	p.fails("GetSpace", pargs{"name": "nope"})

	web := func(img string) *spec.App {
		return paritySpec(t, "", "name: web\nimage: "+img+"\ningress:\n  type: external\n  port: 8080\n  domains: [shop.example.com, www.example.com]\n  routes:\n    - path: /\n    - path: /api\nscale:\n  min: 2\n  max: 2\n")
	}
	deploy := func(sp *spec.App, opts DeployOptions) (any, error) {
		return p.call("DeployWith", pargs{"spec": sp, "actor": "user:a", "opts": opts})
	}
	if _, err := deploy(web("nginx:1"), DeployOptions{MustExist: true}); err == nil {
		t.Fatal("MustExist deployed")
	}
	if _, err := deploy(web("nginx:1"), DeployOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := deploy(web("nginx:1"), DeployOptions{MustCreate: true}); err == nil {
		t.Fatal("MustCreate deployed twice")
	}
	p.setNow(now.Add(time.Minute))
	_, _ = deploy(web("nginx:1"), DeployOptions{}) // unchanged
	_, _ = deploy(web("nginx:2"), DeployOptions{BaseRevision: "web--r1"})
	if _, err := deploy(web("nginx:3"), DeployOptions{BaseRevision: "web--r1"}); err == nil {
		t.Fatal("stale base revision deployed")
	}
	_, _ = deploy(web("nginx:1"), DeployOptions{}) // cancels the rollout
	_, _ = deploy(web("nginx:3"), DeployOptions{})
	p.must("MarkRolloutProgress", pargs{"app": "web"})
	p.fails("MarkRolloutProgress", pargs{"app": "nope"})
	p.must("FailRollout", pargs{"app": "web", "revision": "web--r3", "message": "probe <failed> & gave up"})
	p.fails("FailRollout", pargs{"app": "web", "revision": "web--r3", "message": "x"})
	p.must("Rollback", pargs{"app": "web", "revision": "web--r3", "actor": "user:a"})
	p.fails("Rollback", pargs{"app": "web", "revision": "web--r9", "actor": "user:a"})
	p.fails("Rollback", pargs{"app": "nope", "revision": "web--r1", "actor": "user:a"})
	p.must("CompleteRollout", pargs{"app": "web", "revision": "web--r3"})
	p.fails("CompleteRollout", pargs{"app": "web", "revision": "web--r2"})
	p.must("RestartApp", pargs{"app": "web", "actor": "user:a"})
	p.must("GetApp", pargs{"name": "web"})
	p.fails("GetApp", pargs{"name": "nope"})

	// Domains and routes in conflict, TCP ports, other spaces.
	other := paritySpec(t, "", "name: other\nimage: nginx\ningress:\n  type: external\n  port: 80\n  domains: [shop.example.com]\n  routes:\n    - path: /api\n")
	p.fails("Deploy", pargs{"spec": other, "actor": "user:a"})
	other = paritySpec(t, "", "name: other\nimage: nginx\ningress:\n  type: external\n  port: 80\n  domains: [shop.example.com]\n  routes:\n    - path: /admin\n")
	p.must("Deploy", pargs{"spec": other, "actor": "user:a"})
	p.fails("Deploy", pargs{"spec": paritySpec(t, "shop", "name: shopweb\nimage: nginx\ningress:\n  type: external\n  port: 80\n  domains: [shop.example.com]\n  routes:\n    - path: /x\n"), "actor": "user:a"})
	p.fails("Deploy", pargs{"spec": paritySpec(t, "nospace", "name: x\nimage: nginx\n"), "actor": "user:a"})
	p.must("Deploy", pargs{"spec": paritySpec(t, "shop", "name: db\nimage: postgres\ningress:\n  type: internal\n  protocol: tcp\n  port: 5432\n"), "actor": "user:a"})
	p.fails("Deploy", pargs{"spec": paritySpec(t, "shop", "name: db2\nimage: postgres\ningress:\n  type: internal\n  protocol: tcp\n  port: 5432\n"), "actor": "user:a"})
	p.must("Deploy", pargs{"spec": paritySpec(t, "", "name: db2\nimage: postgres\ningress:\n  type: internal\n  protocol: tcp\n  port: 5432\n"), "actor": "user:a"})
	p.must("Deploy", pargs{"spec": paritySpec(t, "shop", "name: shopweb\nimage: nginx\ningress:\n  type: external\n  port: 80\n  domains: [shop.example.net]\n"), "actor": "user:a"})
	p.must("ListDomains", nil)
	p.must("GetDomain", pargs{"name": "shop.example.com"})
	p.fails("GetDomain", pargs{"name": "nope.example.com"})
	p.must("SetDomainVerification", pargs{"name": "shop.example.com", "verified": false, "message": "no TXT record"})
	p.must("SetDomainVerification", pargs{"name": "shop.example.com", "verified": true})
	p.must("SetDomainVerification", pargs{"name": "shop.example.com", "verified": false, "message": "gone"})
	p.fails("SetDomainVerification", pargs{"name": "nope.example.com", "verified": true})

	// A job of the same name, an app of a job's name.
	p.fails("Deploy", pargs{"spec": paritySpec(t, "", "kind: job\nname: web\nimage: busybox\n"), "actor": "user:a"})

	// Replicas.
	p.fails("CreateReplica", pargs{"replica": Replica{ID: "bad-1", App: "web", Revision: "web--r4", NodeID: "n1"}})
	p.fails("CreateReplica", pargs{"replica": Replica{ID: "web-r4-a", App: "web", Revision: "web--r4", NodeID: "nope"}})
	p.fails("CreateReplica", pargs{"replica": Replica{ID: "web-r4-a", App: "web", Revision: "web--r99", NodeID: "n1"}})
	p.fails("CreateReplica", pargs{"replica": Replica{ID: "nope-r1-a", App: "nope", Revision: "web--r4", NodeID: "n1"}})
	p.must("CreateReplica", pargs{"replica": Replica{ID: "web-r4-a", App: "web", Revision: "web--r4", NodeID: "n1"}})
	p.fails("CreateReplica", pargs{"replica": Replica{ID: "web-r4-a", App: "web", Revision: "web--r4", NodeID: "n1"}})
	p.must("CreateReplica", pargs{"replica": Replica{ID: "web-r4-b", App: "web", Revision: "web--r4", NodeID: "n2", State: ReplicaPulling}})
	p.must("CreateReplica", pargs{"replica": Replica{ID: "other-r1-a", App: "other", Revision: "other--r1", NodeID: "n2", Held: true}})
	p.must("ListReplicas", pargs{"filter": ReplicaFilter{}})
	p.must("ListReplicas", pargs{"filter": ReplicaFilter{App: "web"}})
	p.must("ListReplicas", pargs{"filter": ReplicaFilter{NodeID: "n2"}})
	p.setNow(now.Add(2 * time.Minute))
	rs := ReplicaStatus{ID: "web-r4-a", State: ReplicaRunning, ContainerID: "c1", Address: "10.120.0.5:8080", IP: "10.120.0.5", Ready: true}
	p.must("UpdateReplicaStatus", pargs{"node": "n1", "status": rs})
	p.fails("UpdateReplicaStatus", pargs{"node": "n2", "status": rs})
	rs.ContainerID, rs.Message, rs.Ready = "c2", RestartNote+"out of memory", false
	p.must("UpdateReplicaStatus", pargs{"node": "n1", "status": rs})
	rs.Ready, rs.Message = true, ""
	p.must("UpdateReplicaStatus", pargs{"node": "n1", "status": rs})
	p.must("DrainReplica", pargs{"id": "web-r4-a"})
	p.must("DrainReplica", pargs{"id": "web-r4-a"})
	p.fails("DrainReplica", pargs{"id": "nope"})
	p.must("SetReplicaMoving", pargs{"id": "web-r4-b", "on": true})
	p.must("SetReplicaMoving", pargs{"id": "web-r4-b", "on": true})
	p.must("SetReplicaMoving", pargs{"id": "web-r4-b", "on": false})
	p.must("ReleaseReplica", pargs{"id": "other-r1-a"})
	p.must("ReleaseReplica", pargs{"id": "other-r1-a"})
	p.must("SetReplicaDone", pargs{"id": "other-r1-a"})
	p.fails("SetReplicaDone", pargs{"id": "nope"})
	p.must("ReplicaPlacements", pargs{"app": "web"})
	p.must("DeleteReplica", pargs{"id": "web-r4-a"})
	p.fails("DeleteReplica", pargs{"id": "web-r4-a"})
	p.must("ReplicaPlacements", pargs{"app": "web"})
	p.must("PrunePlacements", pargs{"before": now.Add(90 * time.Second)})
	p.must("PrunePlacements", pargs{"before": now.Add(time.Hour)})
	p.fails("RemoveNode", pargs{"id": "n2", "actor": "user:a"})

	// Replica counts.
	p.fails("SetReplicas", pargs{"app": "web", "n": 0, "actor": "user:a"})
	p.must("SetReplicas", pargs{"app": "web", "n": 3, "actor": "user:a"})
	p.fails("SetReplicas", pargs{"app": "nope", "n": 3, "actor": "user:a"})
	auto := paritySpec(t, "", "name: auto\nimage: nginx\ningress:\n  type: internal\n  port: 80\nscale:\n  min: 1\n  max: 5\n  rules:\n    - type: cpu\n      utilization: 70\n")
	p.must("Deploy", pargs{"spec": auto, "actor": "user:a"})
	p.fails("SetReplicas", pargs{"app": "auto", "n": 3, "actor": "user:a"})
	p.must("AutoscaleReplicas", pargs{"app": "auto", "from": 1, "n": 4, "actor": "autoscaler"})
	p.fails("AutoscaleReplicas", pargs{"app": "auto", "from": 1, "n": 2, "actor": "autoscaler"})
	p.fails("AutoscaleReplicas", pargs{"app": "auto", "from": 4, "n": 9, "actor": "autoscaler"})
	p.fails("AutoscaleReplicas", pargs{"app": "web", "from": 3, "n": 2, "actor": "autoscaler"})
	p.must("Deploy", pargs{"spec": paritySpec(t, "", "name: auto\nimage: nginx:2\ningress:\n  type: internal\n  port: 80\nscale:\n  min: 1\n  max: 3\n  rules:\n    - type: cpu\n      utilization: 70\n"), "actor": "user:a"})

	// Volumes.
	vol := paritySpec(t, "", "name: pg\nimage: postgres\nvolumes:\n  - name: data\n    path: /var/lib/postgresql\n  - name: share\n    path: /share\n    nfs:\n      server: 10.0.0.50\n      path: /exports/share\n")
	p.must("Deploy", pargs{"spec": vol, "actor": "user:a"})
	p.fails("SetReplicas", pargs{"app": "pg", "n": 2, "actor": "user:a"})
	p.must("CreateReplica", pargs{"replica": Replica{ID: "pg-r1-a", App: "pg", Revision: "pg--r1", NodeID: "n1"}})
	p.fails("CreateReplica", pargs{"replica": Replica{ID: "pg-r1-b", App: "pg", Revision: "pg--r1", NodeID: "n2"}})
	p.must("ListVolumes", pargs{"app": ""})
	p.must("ListVolumes", pargs{"app": "pg"})
	p.must("GetVolume", pargs{"app": "pg", "name": "data"})
	p.fails("GetVolume", pargs{"app": "pg", "name": "nope"})
	p.must("RecordVolumeBackup", pargs{"app": "pg", "name": "data", "id": "snap1", "stored": 1 << 20, "snapshots": 3})
	p.must("RecordVolumeBackup", pargs{"app": "pg", "name": "data", "error": strings.Repeat("é", 300)})
	p.fails("RecordVolumeBackup", pargs{"app": "pg", "name": "nope", "id": "x"})
	p.fails("DeleteVolume", pargs{"app": "pg", "name": "data", "actor": "user:a"})
	p.fails("BindVolume", pargs{"app": "Bad", "name": "data", "node": "n2", "actor": "user:a"})
	p.fails("BindVolume", pargs{"app": "pg", "name": "data", "node": "nope", "actor": "user:a"})
	p.must("BindVolume", pargs{"app": "pg", "name": "data", "node": "n1", "actor": "user:a"})
	p.must("BindVolume", pargs{"app": "pg", "name": "data", "node": "n2", "actor": "user:a"})
	p.must("BindVolume", pargs{"app": "pg", "name": "old", "node": "n2", "actor": "user:a"})
	p.must("DeleteVolume", pargs{"app": "pg", "name": "old", "actor": "user:a"})
	p.fails("DeleteVolume", pargs{"app": "pg", "name": "old", "actor": "user:a"})
	p.fails("RemoveNode", pargs{"id": "n1", "actor": "user:a"})

	// Traffic splitting.
	split := func(img, traffic string) *spec.App {
		return paritySpec(t, "", "name: split\nimage: "+img+"\ningress:\n  type: external\n  port: 80\nrevisions:\n  mode: multiple\n  traffic:\n"+traffic)
	}
	p.must("Deploy", pargs{"spec": split("nginx:1", "    - revision: latest\n      weight: 100\n"), "actor": "user:a"})
	p.must("Deploy", pargs{"spec": split("nginx:2", "    - revision: split--r1\n      weight: 90\n      label: old\n    - revision: latest\n      weight: 10\n      label: canary\n"), "actor": "user:a"})
	p.fails("Deploy", pargs{"spec": split("nginx:3", "    - revision: split--r9\n      weight: 100\n"), "actor": "user:a"})
	p.must("Deploy", pargs{"spec": split("nginx:2", "    - revision: latest\n      weight: 100\n"), "actor": "user:a"})
	p.must("SetTraffic", pargs{"app": "split", "weights": []spec.TrafficTarget{{Revision: "split--r1", Weight: 50}, {Revision: "split--r2", Weight: 50}}, "actor": "user:a"})
	p.fails("SetTraffic", pargs{"app": "split", "weights": []spec.TrafficTarget{{Revision: "split--r1", Weight: 70}}, "actor": "user:a"})
	p.fails("SetTraffic", pargs{"app": "split", "weights": []spec.TrafficTarget{{Revision: "split--r1", Weight: 50}, {Revision: "split--r1", Weight: 50}}, "actor": "user:a"})
	p.fails("SetTraffic", pargs{"app": "web", "weights": []spec.TrafficTarget{{Revision: "web--r1", Weight: 100}}, "actor": "user:a"})
	p.fails("Rollback", pargs{"app": "split", "revision": "split--r1", "actor": "user:a"})
	p.fails("RestartApp", pargs{"app": "split", "actor": "user:a"})
	p.must("Deploy", pargs{"spec": paritySpec(t, "", "name: split\nimage: nginx:4\ningress:\n  type: external\n  port: 80\n"), "actor": "user:a"})
	p.must("CompleteRollout", pargs{"app": "split", "revision": "split--r3"})

	// Revisions: many deploys prune the old ones.
	for i := range 13 {
		p.must("Deploy", pargs{"spec": paritySpec(t, "", fmt.Sprintf("name: many\nimage: nginx:%d\n", i)), "actor": "user:a"})
	}
	p.must("CreateReplica", pargs{"replica": Replica{ID: "many-r13-a", App: "many", Revision: "many--r13", NodeID: "n1"}})
	p.must("CompleteRollout", pargs{"app": "many", "revision": "many--r13"})
	p.must("ListRevisions", pargs{"app": "many"})
	p.must("GetRevision", pargs{"name": "many--r13"})
	p.fails("GetRevision", pargs{"name": "many--r1"})
	p.fails("GetRevision", pargs{"name": "badname"})
	p.must("GetRevisions", pargs{"names": []string{"many--r13", "many--r12", "many--r1", "x", "web--r4", "web--r4"}})
	p.must("SetRevisionDigest", pargs{"revision": "many--r13", "digest": "nginx@sha256:" + strings.Repeat("a", 64)})
	p.must("SetRevisionDigest", pargs{"revision": "many--r13", "digest": "nginx@sha256:" + strings.Repeat("b", 64)})
	p.must("SetRevisionDigest", pargs{"revision": "bad", "digest": "x"})
	p.must("SetRevisionPlatforms", pargs{"revision": "many--r13", "platforms": []string{"linux/amd64", "linux/arm64"}})
	p.must("SetRevisionPlatforms", pargs{"revision": "many--r13", "platforms": []string{"linux/riscv64"}})
	p.must("ListApps", nil)
	p.must("GetApps", pargs{"names": []string{"web", "nope", "many", "db.shop"}})
	p.must("ListAppIDs", nil)

	// Removing apps.
	p.must("MarkAppRemoving", pargs{"app": "other", "actor": "user:a"})
	p.must("MarkAppRemoving", pargs{"app": "other", "actor": "user:a"})
	p.fails("MarkAppRemoving", pargs{"app": "nope", "actor": "user:a"})
	p.fails("DeleteApp", pargs{"app": "other"})
	p.fails("DeleteApp", pargs{"app": "web"})
	p.fails("Deploy", pargs{"spec": other, "actor": "user:a"})
	p.fails("RestartApp", pargs{"app": "other", "actor": "user:a"})
	p.must("DeleteReplica", pargs{"id": "other-r1-a"})
	p.must("DeleteApp", pargs{"app": "other"})
	p.must("DeleteApp", pargs{"app": "other"})
	p.must("ListDomains", nil)
	p.fails("DeleteSpace", pargs{"name": "shop", "actor": "user:a"})
	p.fails("DeleteSpace", pargs{"name": "default", "actor": "user:a"})
	p.fails("DeleteSpace", pargs{"name": "nope", "actor": "user:a"})
	p.must("RemoveNode", pargs{"id": "n1", "force": true, "actor": "user:a"})
	p.must("ListAudit", pargs{"limit": 1000})
	p.reencode()
}

func TestArmadaStoreSecrets(t *testing.T) {
	t.Parallel()
	p := newPair(t, startRust(t), parityStart)
	p.must("CreateSpace", pargs{"name": "shop", "actor": "user:a"})
	p.fails("SetSecret", pargs{"secret": "Bad..id", "key": "k", "value": "v", "actor": "user:a"})
	p.fails("SetSecret", pargs{"secret": "db.nospace", "key": "url", "value": "v", "actor": "user:a"})
	p.must("SetSecret", pargs{"secret": "api.shop", "key": "token", "value": "t1", "actor": "user:a"})
	p.must("SetSecret", pargs{"secret": "db.shop", "key": "url", "value": "pg://1", "actor": "user:a"})
	p.must("SetSecret", pargs{"secret": "db.shop", "key": "password", "value": "p1", "actor": "user:a"})
	app := paritySpec(t, "shop", "name: api\nimage: nginx\nenv:\n  - name: TOKEN\n    secretRef: token\n  - name: DB\n    secretRef: db/url\n")
	p.fails("Deploy", pargs{"spec": paritySpec(t, "shop", "name: api\nimage: nginx\nenv:\n  - name: X\n    secretRef: missing\n  - name: Y\n    secretRef: db/missing\n"), "actor": "user:a"})
	p.must("Deploy", pargs{"spec": app, "actor": "user:a"})
	p.must("Deploy", pargs{"spec": paritySpec(t, "shop", "name: worker\nimage: nginx\nenvFrom:\n  - secret: db\nenv:\n  - name: TOKEN\n    secretRef: api/token\n"), "actor": "user:a"})
	p.fails("Deploy", pargs{"spec": paritySpec(t, "shop", "name: w2\nimage: nginx\nenvFrom:\n  - secret: empty\n"), "actor": "user:a"})
	p.must("Deploy", pargs{"spec": paritySpec(t, "shop", "name: w3\nimage: nginx\nenvFrom: secrets\n"), "actor": "user:a"})
	p.must("SetSecret", pargs{"secret": "db.shop", "key": "url", "value": "pg://2", "rollout": true, "actor": "user:a"})
	p.must("SetSecret", pargs{"secret": "api.shop", "key": "token", "value": "t2", "rollout": true, "actor": "user:a"})
	p.must("SetSecret", pargs{"secret": "api.shop", "key": "token", "value": "t3", "actor": "user:a"})
	p.must("GetSecret", pargs{"secret": "api.shop", "key": "token", "version": 3})
	p.must("GetSecret", pargs{"secret": "api.shop", "key": "token", "version": 1})
	p.fails("GetSecret", pargs{"secret": "api.shop", "key": "token", "version": 99})
	p.must("ListSecrets", pargs{"secret": "db.shop"})
	p.must("ListSecrets", pargs{"secret": "api.shop"})
	p.must("ListSpaceSecrets", pargs{"space": "shop"})
	p.fails("ListSpaceSecrets", pargs{"space": "nope"})
	p.fails("DeleteSecret", pargs{"secret": "db.shop", "key": "url", "actor": "user:a"})
	p.fails("DeleteSecret", pargs{"secret": "db.shop", "key": "", "actor": "user:a"})
	p.fails("DeleteSecret", pargs{"secret": "db.shop", "key": "nope", "actor": "user:a"})
	p.fails("DeleteSecret", pargs{"secret": "nope.shop", "key": "", "actor": "user:a"})
	p.must("Deploy", pargs{"spec": paritySpec(t, "shop", "name: worker\nimage: nginx\n"), "actor": "user:a"})
	worker, err := p.g.GetApp(context.Background(), "worker.shop")
	if err != nil {
		t.Fatal(err)
	}
	p.must("CompleteRollout", pargs{"app": "worker.shop", "revision": worker.TargetRevision})
	p.must("DeleteSecret", pargs{"secret": "db.shop", "key": "password", "actor": "user:a"})
	p.must("SetSecret", pargs{"secret": "db.shop", "key": "password", "value": "p2", "actor": "user:a"})
	p.must("RestartApp", pargs{"app": "api.shop", "actor": "user:a"})
	p.must("ListSecrets", pargs{"secret": "db.shop"})
	p.must("MarkAppRemoving", pargs{"app": "api.shop", "actor": "user:a"})
	p.must("DeleteApp", pargs{"app": "api.shop"})
	p.must("MarkAppRemoving", pargs{"app": "w3.shop", "actor": "user:a"})
	p.must("DeleteApp", pargs{"app": "w3.shop"})
	p.must("ListSpaceSecrets", pargs{"space": "shop"})
	p.reencode()
}

func TestArmadaStoreJobs(t *testing.T) {
	t.Parallel()
	p := newPair(t, startRust(t), parityStart)
	now := parityStart
	p.must("UpsertNode", pargs{"node": Node{ID: "n1", PrivateIP: "10.0.0.1"}})
	p.must("Deploy", pargs{"spec": paritySpec(t, "", "kind: job\nname: report\nimage: busybox\nschedule: \"0 * * * *\"\n"), "actor": "user:a"})
	p.must("Deploy", pargs{"spec": paritySpec(t, "", "kind: job\nname: batch\nimage: busybox\ntasks: 3\nparallelism: 2\n"), "actor": "user:a"})
	p.must("Deploy", pargs{"spec": paritySpec(t, "", "name: web\nimage: nginx\n"), "actor": "user:a"})
	p.fails("Deploy", pargs{"spec": paritySpec(t, "", "name: report\nimage: nginx\n"), "actor": "user:a"})
	p.fails("CreateJobRun", pargs{"job": "web", "trigger": TriggerManual, "actor": "user:a"})
	p.fails("CreateJobRun", pargs{"job": "nope", "trigger": TriggerManual, "actor": "user:a"})
	p.must("CreateJobRun", pargs{"job": "report", "trigger": TriggerSchedule, "at": now, "actor": "scheduler"})
	p.fails("CreateJobRun", pargs{"job": "report", "trigger": TriggerSchedule, "at": now, "actor": "scheduler"})
	p.must("SkipJobSchedule", pargs{"job": "report", "at": now.Add(time.Hour)})
	p.must("SkipJobSchedule", pargs{"job": "report", "at": now})
	p.must("CreateJobRun", pargs{"job": "report", "trigger": TriggerManual, "actor": "user:a"})
	run := p.must("CreateJobRun", pargs{"job": "batch", "trigger": TriggerQueue, "actor": "queue"}).(JobRun)
	p.must("Rollback", pargs{"app": "web", "revision": "web--r1", "actor": "user:a"})
	p.fails("Rollback", pargs{"app": "report", "revision": "report--r1", "actor": "user:a"})
	p.fails("RestartApp", pargs{"app": "report", "actor": "user:a"})
	p.fails("SetReplicas", pargs{"app": "report", "n": 2, "actor": "user:a"})
	p.fails("MarkAppRemoving", pargs{"app": "report", "actor": "user:a"})
	p.must("CreateReplica", pargs{"replica": Replica{ID: "batch-j1-t0-a", App: "batch", Revision: run.Revision, NodeID: "n1", Run: run.Seq, Task: 0}})
	p.must("CreateReplica", pargs{"replica": Replica{ID: "batch-j1-t1-a", App: "batch", Revision: run.Revision, NodeID: "n1", Run: run.Seq, Task: 1}})
	p.must("UpdateReplicaStatus", pargs{"node": "n1", "status": ReplicaStatus{ID: "batch-j1-t0-a", State: ReplicaExited, ContainerID: "c1", Finished: true, ExitCode: 3}})
	p.must("UpdateReplicaStatus", pargs{"node": "n1", "status": ReplicaStatus{ID: "batch-j1-t0-a", State: ReplicaExited, ContainerID: "c2", Finished: true, ExitCode: 137}})
	run.State, run.Attempts, run.Replica, run.Node, run.StartedAt, run.AttemptAt = RunRunning, 2, "batch-j1-t1-a", "n1", now, now.Add(time.Second)
	run.Tasks[0].State, run.Tasks[0].Attempts, run.Tasks[0].ExitCode, run.Tasks[0].Message, run.Tasks[0].FinishedAt = RunFailed, 1, 3, "exit 3", now
	run.Tasks[1].State, run.Tasks[1].Attempts, run.Tasks[1].Replica, run.Tasks[1].WaitingSince = RunRunning, 1, "batch-j1-t1-a", now
	p.must("UpdateJobRun", pargs{"run": run})
	p.fails("UpdateJobRun", pargs{"run": JobRun{Job: "batch", Seq: 99}})
	p.must("ListJobRuns", pargs{"job": "batch"})
	p.must("ListJobRuns", pargs{"job": ""})
	p.setNow(now.Add(time.Minute))
	p.must("CancelJobRuns", pargs{"job": "batch", "actor": "user:a"})
	p.must("CancelJobRuns", pargs{"job": "batch", "actor": "user:a"})
	p.fails("CancelJobRuns", pargs{"job": "web", "actor": "user:a"})
	p.must("DeleteJobRun", pargs{"job": "batch", "seq": 1})
	p.must("CreateJobRun", pargs{"job": "batch", "trigger": TriggerManual, "actor": "user:a"})
	p.must("Deploy", pargs{"spec": paritySpec(t, "", "kind: job\nname: batch\nimage: busybox:2\n"), "actor": "user:a"})
	p.must("CreateReplica", pargs{"replica": Replica{ID: "batch-j2-a", App: "batch", Revision: "batch--r1", NodeID: "n1", Run: 2}})
	p.must("DeleteJob", pargs{"job": "batch", "actor": "user:a"})
	p.fails("DeleteJob", pargs{"job": "batch", "actor": "user:a"})
	p.fails("DeleteJob", pargs{"job": "web", "actor": "user:a"})
	p.must("ListReplicas", pargs{"filter": ReplicaFilter{}})
	p.reencode()
}

func TestArmadaStoreAccess(t *testing.T) {
	t.Parallel()
	p := newPair(t, startRust(t), parityStart)
	now := parityStart
	p.must("CreateSpace", pargs{"name": "shop", "actor": "user:a"})
	p.must("CreateSpace", pargs{"name": "blog", "actor": "user:a"})
	p.must("UserAccess", pargs{"name": "root", "notBefore": now.Add(-time.Hour)})
	p.fails("RenewedUser", pargs{"name": "root", "notBefore": now, "callerSerial": "1", "serial": "2"})
	p.must("KnowUser", pargs{"name": "root"})
	p.must("KnowUser", pargs{"name": "root"})
	p.fails("CreateUser", pargs{"principal": Principal{Name: "root"}, "actor": "user:root"})
	p.fails("CreateUser", pargs{"principal": Principal{Name: "x", Roles: []Grant{{Role: "god"}}}, "actor": "user:root"})
	p.fails("CreateUser", pargs{"principal": Principal{Name: "x", Roles: []Grant{{Role: RoleAdmin}}}, "actor": "user:root"})
	p.fails("CreateUser", pargs{"principal": Principal{Name: "x", Roles: []Grant{{Role: RoleAdmin, Space: "default"}}}, "actor": "user:root"})
	p.fails("CreateUser", pargs{"principal": Principal{Name: "x", Roles: []Grant{{Role: RoleAdmin, Space: "nope"}}}, "actor": "user:root"})
	p.fails("CreateUser", pargs{"principal": Principal{Name: "x", Roles: []Grant{{Role: RoleClusterAdmin, Space: "shop"}}}, "actor": "user:root"})
	p.fails("CreateUser", pargs{"principal": Principal{Name: "x", Roles: []Grant{{Role: RoleViewer, Space: "Bad"}}}, "actor": "user:root"})
	p.fails("CreateUser", pargs{"principal": Principal{Name: "x", Labels: map[string][]string{"zone": {}}}, "actor": "user:root"})
	p.fails("CreateUser", pargs{"principal": Principal{Name: "x", Labels: map[string][]string{"Bad Key": {"a"}}}, "actor": "user:root"})
	ana := Principal{Name: "ana", Roles: []Grant{{Role: RoleViewer}, {Role: RoleAdmin, Space: "shop"}, {Role: RoleSpaceCreator}, {Role: RoleViewer}},
		Labels: map[string][]string{"zone": {"a", "b"}}, Since: now.Add(-time.Minute), SinceSerial: "100"}
	p.must("CreateUser", pargs{"principal": ana, "actor": "user:root"})
	p.must("CreateUser", pargs{"principal": Principal{Name: "bob", Roles: []Grant{{Role: RoleDeployer, Space: "blog"}}}, "actor": "user:root"})
	for _, c := range []struct {
		nb     time.Time
		serial string
	}{{now.Add(-2 * time.Minute), "100"}, {now.Add(-2 * time.Minute), "99"}, {now.Add(10 * time.Second), "101"}, {now.Add(-10 * time.Minute), "102"}} {
		p.must("UserAccess", pargs{"name": "ana", "notBefore": c.nb, "serial": c.serial})
		p.must("UserAccess", pargs{"name": "bob", "notBefore": c.nb, "serial": c.serial})
	}
	p.setNow(now.Add(time.Hour))
	p.must("SetUserSince", pargs{"name": "ana", "since": now.Add(time.Hour), "serial": "200", "actor": "user:root"})
	p.fails("SetUserSince", pargs{"name": "nope", "since": now, "serial": "1", "actor": "user:root"})
	p.must("RenewedUser", pargs{"name": "ana", "notBefore": now.Add(time.Hour), "callerSerial": "200", "serial": "201"})
	p.fails("RenewedUser", pargs{"name": "ana", "notBefore": now, "callerSerial": "100", "serial": "202"})
	p.must("Assign", pargs{"kind": KindUser, "name": "bob", "grant": Grant{Role: RoleViewer, Space: "shop"}, "actor": "user:root"})
	p.must("Assign", pargs{"kind": KindUser, "name": "bob", "grant": Grant{Role: RoleViewer, Space: "shop"}, "actor": "user:root"})
	p.fails("Assign", pargs{"kind": KindUser, "name": "bob", "grant": Grant{Role: RoleAdmin, Space: "nope"}, "actor": "user:root"})
	p.fails("Assign", pargs{"kind": "robot", "name": "bob", "grant": Grant{Role: RoleViewer}, "actor": "user:root"})
	p.must("Unassign", pargs{"kind": KindUser, "name": "bob", "grant": Grant{Role: RoleDeployer, Space: "blog"}, "actor": "user:root"})
	p.fails("Unassign", pargs{"kind": KindUser, "name": "bob", "grant": Grant{Role: RoleDeployer, Space: "blog"}, "actor": "user:root"})
	p.must("SetPrincipalLabels", pargs{"kind": KindUser, "name": "bob", "labels": map[string][]string{"pool": {"gpu"}}, "actor": "user:root"})
	p.must("SetPrincipalLabels", pargs{"kind": KindUser, "name": "bob", "actor": "user:root"})
	p.fails("SetPrincipalLabels", pargs{"kind": KindUser, "name": "nope", "actor": "user:root"})

	// Services.
	p.must("CreateService", pargs{"principal": Principal{Name: "ci", Roles: []Grant{{Role: RoleDeployer, Space: "shop"}, {Role: RoleSpaceCreator}}}, "actor": "user:root"})
	p.fails("CreateService", pargs{"principal": Principal{Name: "ci"}, "actor": "user:root"})
	for i := range 10 {
		p.must("RecordServiceCert", pargs{"name": "ci", "cert": NodeCert{Serial: fmt.Sprint(i), NotAfter: now.Add(time.Duration(i+2) * time.Hour)}, "actor": "user:root"})
	}
	p.must("RecordServiceCert", pargs{"name": "ci", "cert": NodeCert{Serial: "new", NotAfter: now.Add(90 * 24 * time.Hour)}, "keep": "9", "actor": "user:ci"})
	p.fails("RecordServiceCert", pargs{"name": "nope", "cert": NodeCert{Serial: "x"}, "actor": "user:root"})
	p.must("ServiceAccess", pargs{"name": "ci", "serial": "9"})
	p.must("ServiceAccess", pargs{"name": "ci", "serial": "1"})
	p.must("ServiceAccess", pargs{"name": "nope", "serial": "1"})
	p.must("GetPrincipal", pargs{"kind": KindService, "name": "ci"})
	p.fails("GetPrincipal", pargs{"kind": KindService, "name": "nope"})
	p.fails("GetPrincipal", pargs{"kind": "robot", "name": "ci"})
	p.must("ListPrincipals", pargs{"kind": ""})
	p.must("ListPrincipals", pargs{"kind": KindService})
	by, err := p.g.GetPrincipal(context.Background(), KindService, "ci")
	if err != nil {
		t.Fatal(err)
	}
	p.must("CreateSpace", pargs{"name": "ci-space", "actor": "service:ci", "by": &by})
	bob, _ := p.g.GetPrincipal(context.Background(), KindUser, "bob")
	p.fails("CreateSpace", pargs{"name": "bob-space", "actor": "user:bob", "by": &bob})
	p.must("DeleteSpace", pargs{"name": "ci-space", "actor": "user:root"})
	p.must("DeleteSpace", pargs{"name": "shop", "actor": "user:root"})
	p.must("ListPrincipals", pargs{"kind": ""})
	p.must("DeletePrincipal", pargs{"kind": KindService, "name": "ci", "actor": "user:root"})
	p.fails("DeletePrincipal", pargs{"kind": KindService, "name": "ci", "actor": "user:root"})
	p.must("DeletePrincipal", pargs{"kind": KindUser, "name": "bob", "actor": "user:root"})
	p.must("DeletePrincipal", pargs{"kind": KindUser, "name": "ghost", "actor": "user:root"})
	p.must("UserAccess", pargs{"name": "bob", "notBefore": now.Add(2 * time.Hour), "serial": "1"})
	p.must("CreateUser", pargs{"principal": Principal{Name: "bob"}, "actor": "user:root"})

	// Metrics scrapers.
	p.must("MetricsAccess", pargs{"name": "prom", "notBefore": now, "serial": "1"})
	for i := range 10 {
		p.must("RecordMetricsCert", pargs{"name": "prom", "cert": NodeCert{Serial: fmt.Sprint(i), NotAfter: now.Add(time.Duration(i) * time.Hour)}, "actor": "user:root"})
	}
	p.must("MetricsAccess", pargs{"name": "prom", "notBefore": now, "serial": "9"})
	p.must("MetricsAccess", pargs{"name": "prom", "notBefore": now, "serial": "0"})
	p.must("ListMetricsCerts", nil)
	p.must("RevokeMetricsCerts", pargs{"name": "prom", "actor": "user:root"})
	p.must("RevokeMetricsCerts", pargs{"name": "other", "actor": "user:root"})
	p.must("MetricsAccess", pargs{"name": "prom", "notBefore": now, "serial": "9"})
	p.must("ListMetricsCerts", nil)
	p.reencode()
}

func TestArmadaStoreEvents(t *testing.T) {
	t.Parallel()
	p := newPair(t, startRust(t), parityStart)
	now := parityStart
	e := Event{Kind: "replica", Object: "web-r1-a", App: "web", Node: "n1", Reason: "Crashed", Message: "exit <1> & more", Count: 1, First: now, Last: now}
	k1 := p.must("PutEvent", pargs{"event": e}).(string)
	e.Count, e.Last = 2, now.Add(time.Minute)
	k2 := p.must("PutEvent", pargs{"event": e, "replace": k1}).(string)
	p.must("PutEvent", pargs{"event": Event{Kind: "node", Object: "n1", Reason: "NodeLost", Count: 1, First: now.Add(time.Hour), Last: now.Add(2 * time.Hour)}})
	p.must("PutEvent", pargs{"event": Event{Kind: "cluster", Object: "x", Reason: "Y", Count: 1, First: now, Last: now.Add(time.Second)}, "replace": k2})
	p.must("ListEvents", pargs{"since": time.Time{}})
	p.must("ListEvents", pargs{"since": now.Add(30 * time.Second)})
	p.must("TrimEvents", pargs{"keep": 5})
	p.must("TrimEvents", pargs{"keep": 1})
	p.must("ListEvents", pargs{"since": time.Time{}})
	// Events carry the hour's lease.
	for _, pfx := range []string{p.g.prefix, p.rPfx} {
		resp, err := testMember.Client().Get(context.Background(), pfx+pfxEvents, clientv3.WithPrefix())
		if err != nil || len(resp.Kvs) != 1 || resp.Kvs[0].Lease == 0 {
			t.Fatalf("events of %s: %v %v", pfx, resp, err)
		}
		ttl, err := testMember.Client().TimeToLive(context.Background(), clientv3.LeaseID(resp.Kvs[0].Lease))
		if err != nil || ttl.GrantedTTL != int64((EventTTL+eventLeaseSpan).Seconds()) {
			t.Errorf("lease of %s: %+v %v", pfx, ttl, err)
		}
	}
	p.reencode()
}

// Every record type with every field set: Go writes, Rust reads and
// encodes again to the same bytes (reencode), and Rust's answers about
// them equal Go's.
func TestArmadaStoreRecords(t *testing.T) {
	t.Parallel()
	r := startRust(t)
	s, ctx := open(t), context.Background()
	full := map[string]any{
		"meta/settings":                        `{"a":1}`,
		"meta/user-cutoff":                     int64(1_700_000_000_123),
		"meta/metrics-cutoff":                  int64(1_700_000_000_456),
		"auditseq":                             int64(7),
		"network":                              networkRec{Mode: NetworkWireGuard, ClusterCIDR: "10.120.0.0/16", IsolateDefault: true, MeshCIDR: "10.122.0.0/16", Switch: &networkSwitchRec{To: NetworkPlain, Step: SwitchMove, Since: time.Date(2026, 1, 2, 3, 4, 5, 6000, time.FixedZone("x", 7*3600))}},
		"nodes/n1":                             nodeRec{ID: "n1", PrivateIP: "10.0.0.1", CPUMillis: 1, MemoryBytes: 2, State: "ready", LastSeen: 3, CreatedAt: 4, Cordoned: true, Version: "v", LegacyCerts: true, Labels: map[string]string{"b": "2", "a": "<1>"}, Restricted: true, OS: "linux", Arch: "arm64", Jobs: true, Volumes: true, Containers: true, NFS: true, Subnet: "10.120.0.0/24", NetworkKey: "k", Endpoint: "1.2.3.4", Site: "s", MeshAddress: true, BehindNAT: true, Relay: true},
		"nodes/n2":                             nodeRec{ID: "n2"},
		"nodecerts/n1/s":                       certRec{Serial: "s", Node: "n1", NotAfter: -5, CreatedAt: 6},
		"tokens/t":                             tokenRec{ID: "t", SecretHash: "h", ExpiresAt: 1, CreatedAt: 2, CreatedBy: "c", UsedAt: 3, UsedBy: "u", Server: true, Labels: map[string]string{"x": "y"}, From: "f", Site: "s"},
		"tokens/t0":                            tokenRec{},
		"servers/a":                            serverRec{Name: "a", PrivateIP: "p", APIAddr: "a", JoinAddr: "j", MemberID: 1<<64 - 1, Schema: 15, Version: "v", CreatedAt: 9},
		"servers/b":                            serverRec{},
		"apps/web":                             appRec{Name: "web", ActiveRevision: "web--r1", TargetRevision: "web--r2", Replicas: 3, RolloutState: "progressing", RolloutMessage: "m", RolloutProgressAt: 1, CreatedAt: 2, UpdatedAt: 3, LastScheduled: 4, LastRun: 5, Traffic: []spec.TrafficTarget{{Revision: "web--r1", Weight: 60, Label: "a"}, {Revision: "web--r2", Weight: 40}}, Removing: true, ScaledAt: 6},
		"apps/x":                               appRec{},
		"revs/web/0000000001":                  revRec{Name: "web--r1", App: "web", Seq: 1, Spec: json.RawMessage(`{"name":"web","image":"nginx:\u003c1\u003e","env":[{"name":"A","value":"\u0026"}],"drain":"30s","space":"shop"}`), ImageDigest: "d", Platforms: []string{"linux/amd64"}, Secrets: map[string]int{"b": 2, "a/k": 1}, CreatedAt: 7},
		"revs/web/0000000002":                  revRec{Name: "web--r2", App: "web", Seq: 2, Spec: json.RawMessage(`{"name":"web","image":"nginx"}`)},
		"replicas/web-r1-a":                    replicaRec{ID: "web-r1-a", App: "web", Revision: "web--r1", NodeID: "n1", State: "running", ContainerID: "c", Address: "a", IP: "i", Message: "m", Ready: true, ReadySince: 1, DrainingSince: 2, MovingSince: 3, UpdatedAt: 4, CreatedAt: 5, Restarts: 6, LastRestartAt: 7, LastRestart: "oom", Run: 8, Done: true, Task: 9, Finished: true, ExitCode: -1, Held: true},
		"replicas/web-r1-b":                    replicaRec{},
		"secrets/a/k/0000000001":               secretRec{KeyID: "k", WrappedKey: []byte{0, 1, 2, 255}, Ciphertext: []byte("hello"), CreatedAt: 1, CreatedBy: "u"},
		"secrets/a/k/0000000002":               secretRec{},
		"secrets/a/k/0000000003":               secretRec{WrappedKey: []byte{}, Ciphertext: []byte{1}},
		"secretseq/a/k":                        int64(4),
		"secretusers/a/web":                    true,
		"domains/d":                            domainRec{Name: "d", Token: "t", Verified: true, VerifiedAt: 1, Message: "m", CreatedAt: 2, Space: "s"},
		"domains/e":                            domainRec{},
		"audit/00000000000000000001":           auditRec{ID: 1, At: 2, Actor: "a", Action: "b", Target: "c", Detail: "d <x>"},
		"runs/j/0000000001":                    jobRunRec{Job: "j", Seq: 1, Revision: "r", Trigger: "t", State: "s", Attempts: 1, Replica: "r", Node: "n", ExitCode: 2, Message: "m", CreatedAt: 3, StartedAt: 4, AttemptAt: 5, FinishedAt: 6, Tasks: []runTaskRec{{Index: 0, State: "s", Attempts: 1, Replica: "r", Node: "n", ExitCode: 1, Message: "m", AttemptAt: 1, WaitingSince: 2, FinishedAt: 3}, {}}},
		"runs/j/0000000002":                    jobRunRec{},
		"volumes/a/v":                          volumeRec{App: "a", Name: "v", Node: "n", CreatedAt: 1, BackupAt: 2, BackupID: "i", BackupFailedAt: 3, BackupError: "e", BackupStored: 4, BackupSnapshots: 5},
		"volumes/a/w":                          volumeRec{},
		"spaces/s":                             spaceRec{Name: "s", CreatedAt: 1, CreatedBy: "u"},
		"spaces/t":                             spaceRec{},
		"users/u":                              principalRec{Name: "u", Roles: []grantRec{{Role: "admin", Space: "s"}, {Role: "viewer"}}, Labels: map[string][]string{"z": {"b", "a"}}, CreatedAt: 1, CreatedBy: "c", Since: -62135596800, SinceSerial: "s", Cutoff: 3, Removed: true, Certs: []certRec{{Serial: "1", NotAfter: 2, Node: "n", CreatedAt: 4}}},
		"services/v":                           principalRec{Name: "v"},
		"metrics/m":                            metricsRec{Name: "m", Certs: []certRec{{Serial: "1", NotAfter: 2, CreatedAt: 3}}},
		"metrics/n":                            metricsRec{Name: "n"},
		"placements/web-r1-a":                  placementRec{App: "web", Node: "n1", At: 1},
		"events/00000000000000000001-00000000": eventRec{Kind: "k", Object: "o", App: "a", Node: "n", Reason: "r", Message: "m", Count: 1, First: 2, Last: 3},
		"events/00000000000000000002-00000000": eventRec{},
	}
	err := s.tx(ctx, func(t *etx) error {
		for k, v := range full {
			if err := t.put(k, v); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	h := fmt.Sprintf("s%d", parityHandles.Add(1))
	r.ok(r.conn(map[string]any{"op": "open", "handle": h, "prefix": s.prefix, "ms": parityStart.UnixMilli()}))
	reencodeOK(t, r, h)
	before := dump(t, s.prefix)
	// Reads of the records, through both stores.
	s.SetNow(func() time.Time { return parityStart })
	for _, c := range []struct {
		method string
		args   pargs
	}{
		{"ListNodes", nil}, {"GetNode", pargs{"id": "n1"}}, {"GetNetwork", nil}, {"OpenJoinTokens", nil}, {"ListServers", nil},
		{"ListReplicas", pargs{"filter": ReplicaFilter{}}}, {"GetRevision", pargs{"name": "web--r1"}}, {"ListRevisions", pargs{"app": "web"}},
		{"GetApp", pargs{"name": "web"}}, {"ListDomains", nil}, {"ListJobRuns", pargs{"job": ""}}, {"ListVolumes", pargs{"app": ""}},
		{"ListSpaces", nil}, {"ListPrincipals", pargs{"kind": ""}}, {"ListAudit", pargs{"limit": 10}}, {"ReplicaPlacements", pargs{"app": "web"}},
		{"GetSecret", pargs{"secret": "a", "key": "k", "version": 1}}, {"GetSecret", pargs{"secret": "a", "key": "k", "version": 2}},
		{"ListSecrets", pargs{"secret": "a"}}, {"GetMeta", pargs{"key": "settings"}}, {"ListMetricsCerts", nil},
	} {
		gv, gerr := goCall(ctx, s, c.method, c.args)
		args := c.args
		if args == nil {
			args = pargs{}
		}
		rr := r.do(map[string]any{"op": "call", "handle": h, "method": c.method, "args": args})
		if errKind(gerr) != rr.Kind || errText(gerr) != rr.Error {
			t.Errorf("%s: go %v, rust %s (%s)", c.method, gerr, rr.Error, rr.Kind)
			continue
		}
		if gerr == nil {
			gb, _ := json.Marshal(gv)
			if g, rv := decodeAny(t, gb), decodeAny(t, rr.Value); !reflect.DeepEqual(g, rv) {
				gj, _ := json.Marshal(g)
				rj, _ := json.Marshal(rv)
				t.Errorf("%s answers differ:\n  go   %s\n  rust %s", c.method, gj, rj)
			}
		}
	}
	if d := diffKeyspaces(before, dump(t, s.prefix)); len(d) > 0 {
		t.Errorf("reads changed the keyspace:\n%s", strings.Join(d, "\n"))
	}
}

// Migrations from a keyspace of schema 8, on both sides.
func TestArmadaStoreMigrations(t *testing.T) {
	t.Parallel()
	r := startRust(t)
	ctx := context.Background()
	old := map[string]any{
		"schema":                   8,
		"admins/root":              map[string]any{"name": "root", "since": 1_800_000_000, "addedAt": 5, "addedBy": "admin:init"},
		"admins/old":               map[string]any{"name": "old", "removed": true},
		"automation/ci":            map[string]any{"name": "ci", "projects": []string{"shop"}, "createProjects": true, "labels": map[string][]string{"pool": {"a"}}, "createdAt": 7, "certs": []map[string]any{{"serial": "9", "notAfter": 99}}},
		"automation/ro":            map[string]any{"name": "ro", "projects": []string{"shop"}},
		"projects/shop":            map[string]any{"name": "shop", "createdAt": 5, "createdBy": "user:ana"},
		"domains/shop.example.com": map[string]any{"name": "shop.example.com", "project": "shop", "token": "<t>"},
		"domains/example.com":      map[string]any{"name": "example.com"},
		"revs/web.shop/0000000001": map[string]any{"name": "web.shop--r1", "app": "web.shop", "seq": 1, "spec": map[string]any{"name": "web", "image": "nginx", "project": "shop"}},
		"revs/web/0000000001":      map[string]any{"name": "web--r1", "app": "web", "seq": 1, "spec": map[string]any{"name": "web", "image": "nginx"}},
	}
	write := func(prefix string) {
		for k, v := range old {
			b, err := json.Marshal(v)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := testMember.Client().Put(ctx, prefix+k, string(b)); err != nil {
				t.Fatal(err)
			}
		}
		// A record written by hand, not by json.Marshal: spaces and a
		// key order Go's encoder would not choose.
		if _, err := testMember.Client().Put(ctx, prefix+"projects/blog", `{ "createdBy": "user:bo", "name": "blog" }`); err != nil {
			t.Fatal(err)
		}
		if _, err := testMember.Client().Put(ctx, prefix+"users/ana", `{"name":"ana","roles":[{"role":"admin","project":"shop"},{"project":"blog","role":"admin"},{"role":"project-creator"},{"role":"viewer"}]}`); err != nil {
			t.Fatal(err)
		}
	}
	gPfx := fmt.Sprintf("/test/%d/", testPrefix.Add(1))
	rPfx := fmt.Sprintf("/test/%d/", testPrefix.Add(1))
	write(gPfx)
	write(rPfx)
	g, err := NewEtcd(ctx, testMember.Client(), gPfx)
	if err != nil {
		t.Fatal(err)
	}
	g.SetNow(func() time.Time { return parityStart })
	h := fmt.Sprintf("s%d", parityHandles.Add(1))
	r.ok(r.conn(map[string]any{"op": "open", "handle": h, "prefix": rPfx, "ms": parityStart.UnixMilli()}))
	p := &pair{t: t, g: g, r: r, h: h, rPfx: rPfx}
	p.must("StoredSchema", nil)
	p.must("MigrateTo", pargs{"target": 10})
	p.must("MigrateTo", pargs{"target": 10})
	p.fails("MigrateTo", pargs{"target": 9})
	p.must("Migrate", nil)
	p.must("StoredSchema", nil)
	// The records the migration wrote read back as written.
	p.must("ListPrincipals", pargs{"kind": ""})
	p.must("ListSpaces", nil)
	p.must("ListDomains", nil)

	// A newer schema is refused by both when they open the keyspace.
	if _, err := testMember.Client().Put(ctx, gPfx+keySchema, "16"); err != nil {
		t.Fatal(err)
	}
	_, gerr := NewEtcd(ctx, testMember.Client(), gPfx)
	rr := r.do(r.conn(map[string]any{"op": "open", "handle": h + "x", "prefix": gPfx}))
	if gerr == nil || gerr.Error() != rr.Error {
		t.Errorf("newer schema: go %v, rust %q", gerr, rr.Error)
	}
	rr = r.do(r.conn(map[string]any{"op": "open", "handle": h + "y", "prefix": "/no-slash"}))
	if rr.Error != "store: etcd prefix must end with /" {
		t.Errorf("prefix without a slash: %q", rr.Error)
	}
}

// Go and Rust write one keyspace at the same time: every transaction
// either sees the other's writes or runs again.
func TestArmadaStoreConcurrentWriters(t *testing.T) {
	t.Parallel()
	r := startRust(t)
	s, ctx := open(t), context.Background()
	h := fmt.Sprintf("s%d", parityHandles.Add(1))
	r.ok(r.conn(map[string]any{"op": "open", "handle": h, "prefix": s.prefix, "ms": time.Now().UnixMilli()}))
	const each = 60
	done := r.send(map[string]any{"op": "call", "handle": h, "method": "RecordAudit", "repeat": each, "parallel": 6,
		"args": pargs{"actor": "rust", "action": "x", "target": "t"}})
	var wg sync.WaitGroup
	for range 6 {
		wg.Go(func() {
			for range each / 6 {
				if err := s.RecordAudit(ctx, "go", "x", "t", ""); err != nil {
					t.Error(err)
				}
			}
		})
	}
	wg.Wait()
	if rep := <-done; rep.Error != "" {
		t.Fatal(rep.Error)
	}
	events, err := s.ListAudit(ctx, 1000)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[int64]bool{}
	by := map[string]int{}
	for _, e := range events {
		seen[e.ID] = true
		by[e.Actor]++
	}
	if len(events) != 2*each || len(seen) != 2*each || by["go"] != each || by["rust"] != each {
		t.Errorf("%d events, %d IDs, by %v; want %d each", len(events), len(seen), by, each)
	}
	// Both read the same log.
	var rust []AuditEvent
	if err := json.Unmarshal(r.ok(map[string]any{"op": "call", "handle": h, "method": "ListAudit", "args": pargs{"limit": 1000}}), &rust); err != nil {
		t.Fatal(err)
	}
	if len(rust) != len(events) || rust[0].ID != events[0].ID || rust[len(rust)-1].ID != events[len(events)-1].ID {
		t.Errorf("rust lists %d events, go %d", len(rust), len(events))
	}
	// A join token redeemed by both at once is consumed once.
	exp := time.Now().Add(time.Hour)
	if err := s.CreateJoinToken(ctx, JoinToken{ID: "tok", SecretHash: "h", ExpiresAt: exp}); err != nil {
		t.Fatal(err)
	}
	var wins atomic.Int32
	var chans []<-chan rustReply
	for i := range 5 {
		chans = append(chans, r.send(map[string]any{"op": "call", "handle": h, "method": "RedeemJoinToken", "args": pargs{
			"id": "tok", "hash": "h", "node": Node{ID: fmt.Sprintf("r%d", i), PrivateIP: fmt.Sprintf("10.0.1.%d", i)},
			"cert": NodeCert{Serial: "x", NotAfter: exp}}}))
	}
	for i := range 5 {
		wg.Go(func() {
			err := s.RedeemJoinToken(ctx, "tok", accept, Node{ID: fmt.Sprintf("g%d", i), PrivateIP: fmt.Sprintf("10.0.2.%d", i)}, issued("x", exp))
			if err == nil {
				wins.Add(1)
			} else if !errors.Is(err, ErrNotFound) {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	for _, ch := range chans {
		rep := <-ch
		switch {
		case rep.Error == "":
			wins.Add(1)
		case rep.Kind != "notFound":
			t.Error(rep.Error)
		}
	}
	if nodes, _ := s.ListNodes(ctx); wins.Load() != 1 || len(nodes) != 1 {
		t.Errorf("%d redemptions won, %d nodes", wins.Load(), len(nodes))
	}
}

// A store fenced to a term that ended writes nothing, whichever side
// fenced it and whichever side led.
func TestArmadaStoreFencing(t *testing.T) {
	r := startRust(t)
	s, ctx := open(t), context.Background()
	h := fmt.Sprintf("s%d", parityHandles.Add(1))
	r.ok(r.conn(map[string]any{"op": "open", "handle": h, "prefix": s.prefix, "ms": time.Now().UnixMilli()}))

	// Go leads; a Rust store fenced to Go's term writes until Go resigns.
	l, err := etcd.Campaign(ctx, testMember.Client(), 5*time.Second, "go-1")
	if err != nil {
		t.Fatal(err)
	}
	key, rev := l.Fence()
	r.ok(map[string]any{"op": "fenced", "handle": h + "f", "from": h, "key": key, "rev": rev})
	r.ok(map[string]any{"op": "call", "handle": h + "f", "method": "SetMeta", "args": pargs{"key": "a", "value": "1"}})
	r.ok(map[string]any{"op": "call", "handle": h + "f", "method": "PutEvent", "args": pargs{"event": Event{Kind: "k", Object: "o", Reason: "r", Count: 1, First: time.Now(), Last: time.Now()}}})
	if err := l.Resign(ctx); err != nil {
		t.Fatal(err)
	}
	for _, m := range []struct {
		method string
		args   pargs
	}{
		{"SetMeta", pargs{"key": "a", "value": "2"}},
		{"PutEvent", pargs{"event": Event{Kind: "k", Object: "o", Reason: "r", Count: 1, First: time.Now(), Last: time.Now()}}},
	} {
		rep := r.do(map[string]any{"op": "call", "handle": h + "f", "method": m.method, "args": m.args})
		if rep.Kind != "notLeader" || rep.Error != ErrNotLeader.Error() {
			t.Errorf("%s after the term: %q (%s)", m.method, rep.Error, rep.Kind)
		}
	}
	// Rust leads; a Go store fenced to Rust's term writes until Rust
	// resigns.
	var fence struct {
		Key string `json:"key"`
		Rev int64  `json:"rev"`
	}
	if err := json.Unmarshal(r.ok(r.conn(map[string]any{"op": "campaign", "handle": "lead", "ttl": 5, "name": "rust-1"})), &fence); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(fence.Key, "/armada-leader//") {
		t.Errorf("rust's election key %q", fence.Key)
	}
	f := s.Fenced(fence.Key, fence.Rev)
	if err := f.SetMeta(ctx, "b", "1"); err != nil {
		t.Fatal(err)
	}
	r.ok(map[string]any{"op": "resign", "handle": "lead"})
	if err := f.SetMeta(ctx, "b", "2"); !errors.Is(err, ErrNotLeader) {
		t.Errorf("go fenced to rust's ended term: %v", err)
	}
	if v, _ := s.GetMeta(ctx, "b"); v != "1" {
		t.Errorf("meta b = %q", v)
	}
}

// Go and Rust servers campaign in one election, and take one lock.
func TestArmadaStoreElection(t *testing.T) {
	r := startRust(t)
	ctx := context.Background()
	leader := func() (string, string) {
		g, err := etcd.Leader(ctx, testMember.Client())
		if err != nil {
			t.Fatal(err)
		}
		var rs string
		if err := json.Unmarshal(r.ok(r.conn(map[string]any{"op": "leader"})), &rs); err != nil {
			t.Fatal(err)
		}
		return g, rs
	}
	gl, err := etcd.Campaign(ctx, testMember.Client(), 5*time.Second, "go-a")
	if err != nil {
		t.Fatal(err)
	}
	rustWon := r.send(r.conn(map[string]any{"op": "campaign", "handle": "ra", "ttl": 5, "name": "rust-a"}))
	select {
	case rep := <-rustWon:
		t.Fatalf("rust won while go led: %+v", rep)
	case <-time.After(time.Second):
	}
	if g, rs := leader(); g != "go-a" || rs != "go-a" {
		t.Fatalf("leader: go says %q, rust says %q", g, rs)
	}
	if err := gl.Resign(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case rep := <-rustWon:
		if rep.Error != "" {
			t.Fatal(rep.Error)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("rust did not take over")
	}
	if g, rs := leader(); g != "rust-a" || rs != "rust-a" {
		t.Fatalf("leader: go says %q, rust says %q", g, rs)
	}
	goWon := make(chan *etcd.Leadership, 1)
	go func() {
		l, err := etcd.Campaign(ctx, testMember.Client(), 5*time.Second, "go-b")
		if err != nil {
			t.Error(err)
		}
		goWon <- l
	}()
	select {
	case <-goWon:
		t.Fatal("go won while rust led")
	case <-time.After(time.Second):
	}
	r.ok(map[string]any{"op": "resign", "handle": "ra"})
	select {
	case l := <-goWon:
		if g, rs := leader(); g != "go-b" || rs != "go-b" {
			t.Fatalf("leader: go says %q, rust says %q", g, rs)
		}
		_ = l.Resign(ctx)
	case <-time.After(30 * time.Second):
		t.Fatal("go did not take over")
	}

	// Locks: Rust holds one, Go waits; Go holds, Rust's TryLock fails.
	r.ok(r.conn(map[string]any{"op": "lock", "handle": "m", "ttl": 5, "prefix": "/armada-acme/locks/x"}))
	sess, err := concurrency.NewSession(testMember.Client(), concurrency.WithTTL(5))
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	m := concurrency.NewMutex(sess, "/armada-acme/locks/x")
	if err := m.TryLock(ctx); !errors.Is(err, concurrency.ErrLocked) {
		t.Fatalf("go took a lock rust holds: %v", err)
	}
	locked := make(chan error, 1)
	go func() { locked <- m.Lock(ctx) }()
	select {
	case err := <-locked:
		t.Fatalf("go locked while rust held: %v", err)
	case <-time.After(time.Second):
	}
	r.ok(map[string]any{"op": "unlock", "handle": "m"})
	if err := <-locked; err != nil {
		t.Fatal(err)
	}
	rep := r.do(r.conn(map[string]any{"op": "tryLock", "handle": "m2", "ttl": 5, "prefix": "/armada-acme/locks/x"}))
	if rep.Error != concurrency.ErrLocked.Error() {
		t.Errorf("rust TryLock while go holds: %q", rep.Error)
	}
	rustLocked := r.send(r.conn(map[string]any{"op": "lock", "handle": "m3", "ttl": 5, "prefix": "/armada-acme/locks/x"}))
	select {
	case rep := <-rustLocked:
		t.Fatalf("rust locked while go held: %+v", rep)
	case <-time.After(time.Second):
	}
	if err := m.Unlock(ctx); err != nil {
		t.Fatal(err)
	}
	if rep := <-rustLocked; rep.Error != "" {
		t.Fatal(rep.Error)
	}
	r.ok(map[string]any{"op": "unlock", "handle": "m3"})
}

// A Rust leader keeps its lease alive past its TTL: etcd answers the
// keep-alive stream's headers only after its first request, so a client
// that waits for them first lets the lease run out and loses leadership
// once a TTL after its campaign.
func TestArmadaStoreLeaseKeptAlive(t *testing.T) {
	r := startRust(t)
	ctx := context.Background()
	r.ok(r.conn(map[string]any{"op": "campaign", "handle": "kept", "ttl": 2, "name": "rust-kept"}))
	defer r.ok(map[string]any{"op": "resign", "handle": "kept"})
	time.Sleep(7 * time.Second)
	g, err := etcd.Leader(ctx, testMember.Client())
	if err != nil {
		t.Fatal(err)
	}
	if g != "rust-kept" {
		t.Fatalf("leader after three TTLs: %q, want rust-kept", g)
	}
}
