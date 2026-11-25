package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"io/fs"
	"maps"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/runtime"
)

// The agent parity harness of the Rust agent (ADR 0055, item 16). A
// scenario drives an agent the way its loop would, one step at a time:
// assignments, reconcile passes, the clock, the session's contact, usage
// samples, and image prunes, against pfake, a fake runtime the scenario
// changes between steps (crashes, failed pulls, probe answers). runAgentParity
// runs it against Go's agent in process and, with ARMADA_AGENT_BIN (cargo
// build -p armada-agent --features parity), against the Rust agent as a
// program whose every runtime call comes back to the test and is answered
// by its own pfake. Each run records a transcript: the reports, the
// runtime calls of each step (sorted, since starts run at once), and the
// files the agent wrote (secret files, volume directories); the two must
// be equal step by step. Probes run on their own timers in both agents,
// so steps that wait for a probe's verdict (until) poll until the report
// says what the scenario waits for, and record the last report and the
// calls of the wait without repeats.

// agentBin is the Rust agent's parity program, if given.
func agentBin() string { return os.Getenv("ARMADA_AGENT_BIN") }

// parityT0 is when every scenario starts on the test clock.
var parityT0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// testClock is the agents' clock in the parity tests.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

// The wire shapes of runtime values between the test and the Rust
// program, also the shape of the recorded calls.
type wireFile struct {
	Source string `json:"source"`
	Target string `json:"target"`
}

type wireVolume struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	Shared   bool   `json:"shared,omitempty"`
	ReadOnly bool   `json:"readOnly,omitempty"`
}

type wireMember struct {
	Name             string       `json:"name"`
	Image            string       `json:"image"`
	Entrypoint       []string     `json:"entrypoint,omitempty"`
	Cmd              []string     `json:"cmd,omitempty"`
	Env              []string     `json:"env,omitempty"`
	MemoryBytes      int64        `json:"memoryBytes,omitempty"`
	NanoCPUs         int64        `json:"nanoCpus,omitempty"`
	CPUReserveMillis int64        `json:"cpuReserveMillis,omitempty"`
	PidsLimit        int64        `json:"pidsLimit,omitempty"`
	Files            []wireFile   `json:"files,omitempty"`
	Volumes          []wireVolume `json:"volumes,omitempty"`
}

type wireSpec struct {
	Name             string            `json:"name"`
	Image            string            `json:"image"`
	Entrypoint       []string          `json:"entrypoint,omitempty"`
	Cmd              []string          `json:"cmd,omitempty"`
	Env              []string          `json:"env,omitempty"`
	Labels           map[string]string `json:"labels,omitempty"`
	Port             int               `json:"port,omitempty"`
	HostIP           string            `json:"hostIp,omitempty"`
	MemoryBytes      int64             `json:"memoryBytes,omitempty"`
	NanoCPUs         int64             `json:"nanoCpus,omitempty"`
	CPUReserveMillis int64             `json:"cpuReserveMillis,omitempty"`
	PidsLimit        int64             `json:"pidsLimit,omitempty"`
	Files            []wireFile        `json:"files,omitempty"`
	DNS              []string          `json:"dns,omitempty"`
	DNSSearch        []string          `json:"dnsSearch,omitempty"`
	Volumes          []wireVolume      `json:"volumes,omitempty"`
	Init             []wireMember      `json:"init,omitempty"`
	Sidecars         []wireMember      `json:"sidecars,omitempty"`
}

type wireMemberState struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Role      string `json:"role"`
	State     string `json:"state"`
	ExitCode  int    `json:"exitCode"`
	StartedNs int64  `json:"startedNs"`
}

type wireContainer struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Image      string            `json:"image"`
	Labels     map[string]string `json:"labels"`
	State      string            `json:"state"`
	ExitCode   int               `json:"exitCode"`
	HostIP     string            `json:"hostIp"`
	HostPort   int               `json:"hostPort"`
	IP         string            `json:"ip"`
	StartedNs  int64             `json:"startedNs"`
	Members    []wireMemberState `json:"members"`
	StartError string            `json:"startError"`
}

func unixNs(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}

func wireFiles(fs []runtime.FileMount) []wireFile {
	var out []wireFile
	for _, f := range fs {
		out = append(out, wireFile{f.Source, f.Target})
	}
	return out
}

func wireVolumes(vs []runtime.VolumeMount) []wireVolume {
	var out []wireVolume
	for _, v := range vs {
		out = append(out, wireVolume{v.Source, v.Target, v.Shared, v.ReadOnly})
	}
	return out
}

func wireMembers(ms []runtime.MemberSpec) []wireMember {
	var out []wireMember
	for _, m := range ms {
		out = append(out, wireMember{
			Name: m.Name, Image: m.Image, Entrypoint: m.Entrypoint, Cmd: m.Cmd, Env: m.Env,
			MemoryBytes: m.MemoryBytes, NanoCPUs: m.NanoCPUs, CPUReserveMillis: m.CPUReserveMillis, PidsLimit: m.PidsLimit,
			Files: wireFiles(m.Files), Volumes: wireVolumes(m.Volumes),
		})
	}
	return out
}

func toWireSpec(s runtime.ContainerSpec) wireSpec {
	return wireSpec{
		Name: s.Name, Image: s.Image, Entrypoint: s.Entrypoint, Cmd: s.Cmd, Env: s.Env, Labels: s.Labels,
		Port: s.Port, HostIP: s.HostIP, MemoryBytes: s.MemoryBytes, NanoCPUs: s.NanoCPUs,
		CPUReserveMillis: s.CPUReserveMillis, PidsLimit: s.PidsLimit, Files: wireFiles(s.Files),
		DNS: s.DNS, DNSSearch: s.DNSSearch, Volumes: wireVolumes(s.Volumes),
		Init: wireMembers(s.Init), Sidecars: wireMembers(s.Sidecars),
	}
}

func fromWireMembers(ms []wireMember) []runtime.MemberSpec {
	var out []runtime.MemberSpec
	for _, m := range ms {
		mm := runtime.MemberSpec{
			Name: m.Name, Image: m.Image, Entrypoint: m.Entrypoint, Cmd: m.Cmd, Env: m.Env,
			MemoryBytes: m.MemoryBytes, NanoCPUs: m.NanoCPUs, CPUReserveMillis: m.CPUReserveMillis, PidsLimit: m.PidsLimit,
		}
		for _, f := range m.Files {
			mm.Files = append(mm.Files, runtime.FileMount{Source: f.Source, Target: f.Target})
		}
		for _, v := range m.Volumes {
			mm.Volumes = append(mm.Volumes, runtime.VolumeMount{Source: v.Source, Target: v.Target, Shared: v.Shared, ReadOnly: v.ReadOnly})
		}
		out = append(out, mm)
	}
	return out
}

func fromWireSpec(s wireSpec) runtime.ContainerSpec {
	cs := runtime.ContainerSpec{
		Name: s.Name, Image: s.Image, Entrypoint: s.Entrypoint, Cmd: s.Cmd, Env: s.Env, Labels: s.Labels,
		Port: s.Port, HostIP: s.HostIP, MemoryBytes: s.MemoryBytes, NanoCPUs: s.NanoCPUs,
		CPUReserveMillis: s.CPUReserveMillis, PidsLimit: s.PidsLimit, DNS: s.DNS, DNSSearch: s.DNSSearch,
		Init: fromWireMembers(s.Init), Sidecars: fromWireMembers(s.Sidecars),
	}
	for _, f := range s.Files {
		cs.Files = append(cs.Files, runtime.FileMount{Source: f.Source, Target: f.Target})
	}
	for _, v := range s.Volumes {
		cs.Volumes = append(cs.Volumes, runtime.VolumeMount{Source: v.Source, Target: v.Target, Shared: v.Shared, ReadOnly: v.ReadOnly})
	}
	return cs
}

func toWireContainer(c runtime.Container) wireContainer {
	w := wireContainer{
		ID: c.ID, Name: c.Name, Image: c.Image, Labels: c.Labels, State: c.State, ExitCode: c.ExitCode,
		HostIP: c.HostIP, HostPort: c.HostPort, IP: c.IP, StartedNs: unixNs(c.StartedAt), StartError: c.StartError,
		Members: []wireMemberState{},
	}
	for _, m := range c.Members {
		w.Members = append(w.Members, wireMemberState{m.ID, m.Name, m.Role, m.State, m.ExitCode, unixNs(m.StartedAt)})
	}
	return w
}

// pfake is the fake runtime of the parity tests: pfake's IDs, ports, and
// addresses follow from container names, so both agents' runs give the
// same ones whatever order their concurrent starts take; every call that
// changes or reads the containers is recorded.
type pfake struct {
	mu         sync.Mutex
	clock      *testClock
	containers map[string]*runtime.Container
	specs      map[string]runtime.ContainerSpec
	pod        map[string]string // member ID -> its replica's container
	gen        map[string]int
	calls      []string
	norm       func(string) string

	pullErr     map[string]error
	runErr      map[string]string
	digests     map[string]string
	platforms   map[string][]string
	initExits   map[string]int
	holdStarts  bool
	usage       map[string]runtime.Stats
	agentStatus runtime.AgentStatus
	bridge      string
	noMembers   bool
	noVolumes   bool
	noExec      bool
	noStats     bool
	// checks answers health checks by "addr path": an error text, "" for
	// success, "timeout" to wait for the deadline, "fail N TEXT" to fail N
	// times first, "slow D TEXT" to answer TEXT after D.
	checks map[string]string
	failed map[string]int
	// execCodes answers probe commands by their first word ("sleep" waits
	// for the deadline, "missing" fails to start).
	execCodes map[string]int
	// pullHold, while set, holds every pull until it is closed.
	pullHold chan struct{}
}

func newPfake(clock *testClock) *pfake {
	return &pfake{
		clock: clock, containers: map[string]*runtime.Container{}, specs: map[string]runtime.ContainerSpec{},
		pod: map[string]string{}, gen: map[string]int{}, norm: func(s string) string { return s },
		pullErr: map[string]error{}, runErr: map[string]string{}, digests: map[string]string{}, platforms: map[string][]string{},
		initExits: map[string]int{}, usage: map[string]runtime.Stats{}, checks: map[string]string{}, failed: map[string]int{},
		execCodes: map[string]int{},
	}
}

// record notes a call; the lock is held.
func (f *pfake) record(method string, args any) {
	b, _ := json.Marshal(args)
	f.calls = append(f.calls, method+" "+f.norm(string(b)))
}

// takeCalls returns the calls since the last time, sorted. Equal pulls
// count once: replicas starting together share a pull only while it is in
// flight (pullOnce), so how many there are depends on timing.
func (f *pfake) takeCalls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.calls
	f.calls = nil
	sort.Strings(c)
	return slices.CompactFunc(c, func(a, b string) bool { return a == b && strings.HasPrefix(a, "pull ") })
}

func nameHash(s string) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(s))
	return int(h.Sum32())
}

func (f *pfake) Ping(context.Context) error { return nil }

func (f *pfake) Pull(ctx context.Context, image string, auth *runtime.RegistryAuth) (runtime.Image, error) {
	f.mu.Lock()
	hold := f.pullHold
	f.mu.Unlock()
	if hold != nil {
		select {
		case <-hold:
		case <-ctx.Done():
			return runtime.Image{}, ctx.Err()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	type wireAuth struct {
		Username      string `json:"username"`
		Password      string `json:"password"`
		ServerAddress string `json:"serverAddress"`
	}
	var a *wireAuth
	if auth != nil {
		a = &wireAuth{auth.Username, auth.Password, auth.ServerAddress}
	}
	f.record("pull", map[string]any{"image": image, "auth": a})
	if err := f.pullErr[image]; err != nil {
		return runtime.Image{}, err
	}
	return runtime.Image{Ref: f.digests[image], Platforms: f.platforms[image]}, nil
}

func (f *pfake) Run(_ context.Context, s runtime.ContainerSpec) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("run", map[string]any{"spec": toWireSpec(s)})
	if e := f.runErr[s.Image]; e != "" {
		return "", errors.New(e)
	}
	for _, c := range f.containers {
		if c.Name == s.Name {
			return "", fmt.Errorf("container name %q already in use", s.Name)
		}
	}
	if (len(s.Init) > 0 || len(s.Sidecars) > 0) && f.noMembers {
		return "", errors.New("this runtime runs no init containers or sidecars")
	}
	f.gen[s.Name]++
	id := s.Name + "-" + strconv.Itoa(f.gen[s.Name])
	c := &runtime.Container{ID: id, Name: s.Name, Image: s.Image, Labels: maps.Clone(s.Labels), State: runtime.StateRunning, StartedAt: f.clock.Now()}
	if s.Port != 0 {
		c.HostIP, c.HostPort = s.HostIP, 30000+nameHash(s.Name)%2000
	}
	if f.bridge != "" {
		c.IP = f.bridge + strconv.Itoa(2+nameHash(s.Name)%200)
	}
	f.containers[id] = c
	f.specs[id] = s
	if len(s.Init) > 0 || len(s.Sidecars) > 0 {
		c.State = runtime.StateStarting
		if !f.holdStarts {
			f.bringUp(id)
		}
	}
	return id, nil
}

// bringUp runs a replica's init containers and starts its sidecars, then
// it, as the runtime does after Run. The lock is held.
func (f *pfake) bringUp(id string) {
	c, s := f.containers[id], f.specs[id]
	if c == nil || c.State != runtime.StateStarting {
		return
	}
	add := func(m runtime.MemberSpec, role, state string, code int) {
		mid := id + "-" + m.Name
		labels := maps.Clone(s.Labels)
		labels[runtime.LabelRole] = role
		labels[runtime.LabelContainer] = m.Name
		f.containers[mid] = &runtime.Container{ID: mid, Name: s.Name + "-" + m.Name, Image: m.Image, Labels: labels, State: state, ExitCode: code, StartedAt: f.clock.Now()}
		f.pod[mid] = id
	}
	for _, m := range s.Init {
		code := f.initExits[m.Name]
		add(m, runtime.RoleInit, runtime.StateExited, code)
		if code != 0 {
			c.State, c.ExitCode = runtime.StateExited, 255
			return
		}
	}
	for _, m := range s.Sidecars {
		add(m, runtime.RoleSidecar, runtime.StateRunning, 0)
	}
	c.State = runtime.StateRunning
}

// members of the container id, by ID. The lock is held.
func (f *pfake) members(id string) []runtime.Member {
	var out []runtime.Member
	for mid, main := range f.pod {
		if main != id {
			continue
		}
		c := f.containers[mid]
		out = append(out, runtime.Member{ID: mid, Name: c.Labels[runtime.LabelContainer], Role: c.Labels[runtime.LabelRole], State: c.State, ExitCode: c.ExitCode, StartedAt: c.StartedAt})
	}
	slices.SortFunc(out, func(a, b runtime.Member) int { return strings.Compare(a.ID, b.ID) })
	return out
}

func (f *pfake) with(c *runtime.Container) runtime.Container {
	out := *c
	out.Labels = maps.Clone(c.Labels)
	out.Members = f.members(c.ID)
	return out
}

func (f *pfake) Stop(_ context.Context, id string, grace time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("stop", map[string]any{"id": id, "graceMs": grace.Milliseconds()})
	c, ok := f.containers[id]
	if !ok {
		return runtime.ErrNotFound
	}
	c.State = runtime.StateExited
	for _, m := range f.members(id) {
		if mc := f.containers[m.ID]; m.Role == runtime.RoleSidecar && mc.State == runtime.StateRunning {
			mc.State = runtime.StateExited
		}
	}
	return nil
}

func (f *pfake) Remove(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("remove", map[string]any{"id": id})
	if _, ok := f.containers[id]; !ok {
		return runtime.ErrNotFound
	}
	for _, m := range f.members(id) {
		delete(f.containers, m.ID)
		delete(f.pod, m.ID)
	}
	delete(f.containers, id)
	delete(f.specs, id)
	delete(f.pod, id)
	return nil
}

func (f *pfake) List(_ context.Context, labels map[string]string) ([]runtime.Container, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("list", map[string]any{"labels": labels})
	var out []runtime.Container
outer:
	for id, c := range f.containers {
		if main, ok := f.pod[id]; ok && f.containers[main] != nil {
			continue
		}
		for k, v := range labels {
			if c.Labels[k] != v {
				continue outer
			}
		}
		out = append(out, f.with(c))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (f *pfake) Inspect(_ context.Context, id string) (runtime.Container, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("inspect", map[string]any{"id": id})
	c, ok := f.containers[id]
	if !ok {
		return runtime.Container{}, runtime.ErrNotFound
	}
	return f.with(c), nil
}

func (f *pfake) Logs(context.Context, string, runtime.LogOptions) (runtime.LogStream, error) {
	return nil, errors.New("no logs in the parity tests")
}

func (f *pfake) CanRunMembers() bool   { return !f.noMembers }
func (f *pfake) CanMountVolumes() bool { return !f.noVolumes }
func (f *pfake) CanExec() bool         { return !f.noExec }
func (f *pfake) CanStats() bool        { return !f.noStats }

// ExecApp answers probe commands from execCodes; they are not recorded,
// since probes run on their own timers.
func (f *pfake) ExecApp(ctx context.Context, _ string, opts runtime.ExecOptions) (int, error) {
	f.mu.Lock()
	code := f.execCodes[opts.Cmd[0]]
	f.mu.Unlock()
	switch opts.Cmd[0] {
	case "sleep":
		<-ctx.Done()
		return 0, ctx.Err()
	case "missing":
		return 0, errors.New("exec: no such file")
	}
	return code, nil
}

// Check answers health checks from checks; not recorded either.
func (f *pfake) Check(ctx context.Context, addr, path string) error {
	key := addr + " " + path
	f.mu.Lock()
	ans := f.checks[key]
	if n, text, ok := strings.Cut(strings.TrimPrefix(ans, "fail "), " "); strings.HasPrefix(ans, "fail ") && ok {
		limit, _ := strconv.Atoi(n)
		f.failed[key]++
		ans = ""
		if f.failed[key] <= limit {
			ans = text
		}
	}
	f.mu.Unlock()
	if d, text, ok := strings.Cut(strings.TrimPrefix(ans, "slow "), " "); strings.HasPrefix(ans, "slow ") && ok {
		dur, _ := time.ParseDuration(d)
		select {
		case <-time.After(dur):
		case <-ctx.Done():
			return ctx.Err()
		}
		ans = text
	}
	switch ans {
	case "":
		return nil
	case "timeout":
		<-ctx.Done()
		return ctx.Err()
	}
	return errors.New(ans)
}

func (f *pfake) Stats(_ context.Context, id string) (runtime.Stats, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("stats", map[string]any{"id": id})
	c, ok := f.containers[id]
	if !ok {
		return runtime.Stats{}, runtime.ErrNotFound
	}
	u := f.usage[c.Labels[runtime.LabelReplica]]
	if c.State != runtime.StateRunning && u.OOMKills == 0 {
		return runtime.Stats{}, fmt.Errorf("container %s is not running", id)
	}
	return u, nil
}

func (f *pfake) ReleaseNetwork(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("release", map[string]any{"id": id})
	return nil
}

func (f *pfake) PruneImages(_ context.Context, keep []string, grace time.Duration) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("prune", map[string]any{"keep": slices.Sorted(slices.Values(keep)), "graceMs": grace.Milliseconds()})
	return nil, nil
}

func (f *pfake) RuntimeAgent() runtime.AgentStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.agentStatus
}

// add puts in a container left from before, with its spec hash.
func (f *pfake) add(c runtime.Container) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := c
	f.containers[c.ID] = &cp
}

func (f *pfake) setState(id, state string, code int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c, ok := f.containers[id]; ok {
		c.State, c.ExitCode = state, code
	}
}

func (f *pfake) setMemberState(id, name, state string, code int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c, ok := f.containers[id+"-"+name]; ok {
		c.State, c.ExitCode = state, code
	}
}

// set changes the fake's script under its lock.
func (f *pfake) set(fn func(f *pfake)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

// wireError is a runtime error as the Rust program reads it.
func wireError(err error) map[string]any {
	if errors.Is(err, runtime.ErrNotFound) {
		return map[string]any{"kind": "notFound"}
	}
	if pe := (*runtime.PlatformError)(nil); errors.As(err, &pe) {
		return map[string]any{"kind": "platform", "image": pe.Image, "want": pe.Want, "have": pe.Have}
	}
	return map[string]any{"kind": "other", "text": err.Error()}
}

// rustCall is a runtime call of the Rust program.
type rustCall struct {
	Call    int64             `json:"call"`
	Method  string            `json:"method"`
	Image   string            `json:"image"`
	Auth    *rustAuth         `json:"auth"`
	Spec    *wireSpec         `json:"spec"`
	ID      string            `json:"id"`
	GraceMs int64             `json:"graceMs"`
	Labels  map[string]string `json:"labels"`
	Keep    []string          `json:"keep"`
	Cmd     []string          `json:"cmd"`
	Addr    string            `json:"addr"`
	Path    string            `json:"path"`
	Timeout int64             `json:"timeoutMs"`
}

type rustAuth struct {
	Username      string `json:"username"`
	Password      string `json:"password"`
	ServerAddress string `json:"serverAddress"`
}

// answer runs a call of the Rust program on f.
func (f *pfake) answer(c rustCall) (any, error) {
	ctx := context.Background()
	switch c.Method {
	case "ping":
		return nil, f.Ping(ctx)
	case "pull":
		var auth *runtime.RegistryAuth
		if c.Auth != nil {
			auth = &runtime.RegistryAuth{Username: c.Auth.Username, Password: c.Auth.Password, ServerAddress: c.Auth.ServerAddress}
		}
		img, err := f.Pull(ctx, c.Image, auth)
		return map[string]any{"ref": img.Ref, "platforms": img.Platforms}, err
	case "run":
		return f.Run(ctx, fromWireSpec(*c.Spec))
	case "stop":
		return nil, f.Stop(ctx, c.ID, time.Duration(c.GraceMs)*time.Millisecond)
	case "remove":
		return nil, f.Remove(ctx, c.ID)
	case "list":
		cs, err := f.List(ctx, c.Labels)
		out := []wireContainer{}
		for _, x := range cs {
			out = append(out, toWireContainer(x))
		}
		return out, err
	case "inspect":
		x, err := f.Inspect(ctx, c.ID)
		return toWireContainer(x), err
	case "exec":
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		return f.ExecApp(ctx, c.ID, runtime.ExecOptions{Cmd: c.Cmd})
	case "check":
		ctx, cancel := context.WithTimeout(ctx, time.Duration(c.Timeout)*time.Millisecond)
		defer cancel()
		if err := f.Check(ctx, c.Addr, c.Path); err != nil {
			return err.Error(), nil
		}
		return "", nil
	case "stats":
		st, err := f.Stats(ctx, c.ID)
		return map[string]any{"cpuNs": int64(st.CPU), "memoryBytes": st.MemoryBytes, "egressBytes": st.EgressBytes, "networkLost": st.NetworkLost, "oomKills": st.OOMKills}, err
	case "release":
		return nil, f.ReleaseNetwork(ctx, c.ID)
	case "prune":
		return f.PruneImages(ctx, c.Keep, time.Duration(c.GraceMs)*time.Millisecond)
	case "runtimeAgent":
		s := f.RuntimeAgent()
		return map[string]any{"agent": s.Agent, "goImages": s.GoImages, "converted": s.Converted, "imagesToPull": s.ImagesToPull, "error": s.Error}, nil
	}
	return nil, fmt.Errorf("unknown call %q", c.Method)
}

// parityOpts is how a scenario's node is set up.
type parityOpts struct {
	members, volumes, exec, stats bool // what the runtime offers (default all)
	noSecretsDir                  bool
	volumesDir                    bool
	unpublished                   bool
	dns                           string
	bridge                        string
	crashBase                     time.Duration
	boot                          time.Time
}

func defaultOpts() parityOpts {
	return parityOpts{members: true, volumes: true, exec: true, stats: true, volumesDir: true, crashBase: time.Second, boot: parityT0.Add(-time.Hour)}
}

// agentUnderTest is the Go or the Rust agent.
type agentUnderTest interface {
	assign(*armadav1.Assignment)
	reconcile() (*armadav1.ReplicaReport, string)
	contact(up bool)
	fence()
	prune()
	sample() *armadav1.UsageReport
	hello() *armadav1.Hello
	setNow(time.Time)
	stop()
}

// goAgent is Go's agent in process.
type goAgent struct {
	a      *Agent
	f      *pfake
	ctx    context.Context
	cancel context.CancelFunc
	prev   map[string]usageSample
}

func (g *goAgent) assign(a *armadav1.Assignment) {
	g.a.setDesired(a.GetReplicas(), a.GetProxy())
	g.a.setServers(a.GetServers())
}

func (g *goAgent) reconcile() (*armadav1.ReplicaReport, string) {
	r, err := g.a.Reconcile(g.ctx)
	if err != nil {
		return nil, err.Error()
	}
	return r, ""
}

func (g *goAgent) contact(up bool)  { g.a.setContact(up) }
func (g *goAgent) fence()           { g.a.fenceUnassigned(g.ctx) }
func (g *goAgent) prune()           { g.a.PruneImages(g.ctx) }
func (g *goAgent) setNow(time.Time) {}
func (g *goAgent) stop()            { g.cancel() }
func (g *goAgent) hello() *armadav1.Hello {
	return g.a.hello()
}

// sample is one round of the usage loop, the parts the Rust agent has.
func (g *goAgent) sample() *armadav1.UsageReport {
	report, sampled := &armadav1.UsageReport{}, false
	if runtime.CanStats(g.f) {
		var r *armadav1.UsageReport
		if r, g.prev = g.a.sampleUsage(g.ctx, g.f, g.prev); r != nil {
			report.Replicas, sampled = r.Replicas, true
		}
	}
	report.Runtime = g.a.withMoveError(runtimeStatus(g.f.RuntimeAgent()))
	if !sampled && report.Runtime == nil {
		return nil
	}
	return report
}

// stubDNS is the node's resolver: only its address is used here.
type stubDNS string

func (d stubDNS) Address() string                { return string(d) }
func (stubDNS) SetNames([]string)                {}
func (stubDNS) SetClients(map[netip.Addr]string) {}

// rustAgent is the Rust agent's parity program.
type rustAgent struct {
	t       *testing.T
	f       *pfake
	cmd     *exec.Cmd
	in      io.WriteCloser
	inMu    sync.Mutex
	mu      sync.Mutex
	pending map[int64]chan map[string]json.RawMessage
	next    int64
	done    chan struct{}
}

func startRust(t *testing.T, f *pfake) *rustAgent {
	t.Helper()
	r := &rustAgent{t: t, f: f, pending: map[int64]chan map[string]json.RawMessage{}, done: make(chan struct{})}
	r.cmd = exec.Command(agentBin())
	r.cmd.Stderr = os.Stderr
	var err error
	if r.in, err = r.cmd.StdinPipe(); err != nil {
		t.Fatal(err)
	}
	out, err := r.cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := r.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		defer close(r.done)
		sc := bufio.NewScanner(out)
		sc.Buffer(make([]byte, 1<<20), 64<<20)
		for sc.Scan() {
			line := slices.Clone(sc.Bytes())
			var m map[string]json.RawMessage
			if err := json.Unmarshal(line, &m); err != nil {
				continue
			}
			if _, ok := m["call"]; ok {
				var c rustCall
				_ = json.Unmarshal(line, &c)
				go r.reply(c)
				continue
			}
			var id int64
			_ = json.Unmarshal(m["id"], &id)
			r.mu.Lock()
			ch := r.pending[id]
			delete(r.pending, id)
			r.mu.Unlock()
			if ch != nil {
				ch <- m
			}
		}
	}()
	return r
}

func (r *rustAgent) write(v any) {
	b, _ := json.Marshal(v)
	r.inMu.Lock()
	defer r.inMu.Unlock()
	_, _ = r.in.Write(append(b, '\n'))
}

func (r *rustAgent) reply(c rustCall) {
	res, err := r.f.answer(c)
	m := map[string]any{"reply": c.Call, "result": res}
	if err != nil {
		m["error"] = wireError(err)
	}
	r.write(m)
}

// request sends one request and waits for its answer.
func (r *rustAgent) request(op string, fields map[string]any) map[string]json.RawMessage {
	r.t.Helper()
	r.mu.Lock()
	r.next++
	id := r.next
	ch := make(chan map[string]json.RawMessage, 1)
	r.pending[id] = ch
	r.mu.Unlock()
	m := map[string]any{"id": id, "op": op}
	maps.Copy(m, fields)
	r.write(m)
	select {
	case ans := <-ch:
		if f, ok := ans["fail"]; ok {
			r.t.Fatalf("rust %s: %s", op, f)
		}
		return ans
	case <-r.done:
		r.t.Fatalf("rust program ended during %s", op)
	case <-time.After(30 * time.Second):
		r.t.Fatalf("rust %s: no answer", op)
	}
	return nil
}

func protoJSON(m proto.Message) json.RawMessage {
	b, err := protojson.Marshal(m)
	if err != nil {
		panic(err)
	}
	return b
}

func (r *rustAgent) assign(a *armadav1.Assignment) {
	r.request("assign", map[string]any{"assignment": protoJSON(a)})
}

func (r *rustAgent) reconcile() (*armadav1.ReplicaReport, string) {
	ans := r.request("reconcile", nil)
	if e, ok := ans["error"]; ok {
		var s string
		_ = json.Unmarshal(e, &s)
		return nil, s
	}
	raw := ans["report"]
	if len(raw) == 0 || string(raw) == "null" {
		return nil, ""
	}
	rep := &armadav1.ReplicaReport{}
	if err := protojson.Unmarshal(raw, rep); err != nil {
		r.t.Fatalf("rust report %s: %v", raw, err)
	}
	return rep, ""
}

func (r *rustAgent) contact(up bool) { r.request("contact", map[string]any{"up": up}) }
func (r *rustAgent) fence()          { r.request("fence", nil) }
func (r *rustAgent) prune()          { r.request("prune", nil) }
func (r *rustAgent) setNow(t time.Time) {
	r.request("now", map[string]any{"ns": t.UnixNano()})
}

func (r *rustAgent) sample() *armadav1.UsageReport {
	raw := r.request("sample", nil)["usage"]
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	u := &armadav1.UsageReport{}
	if err := protojson.Unmarshal(raw, u); err != nil {
		r.t.Fatalf("rust usage %s: %v", raw, err)
	}
	return u
}

func (r *rustAgent) hello() *armadav1.Hello {
	h := &armadav1.Hello{}
	if err := protojson.Unmarshal(r.request("hello", nil)["hello"], h); err != nil {
		r.t.Fatal(err)
	}
	return h
}

func (r *rustAgent) stop() {
	_ = r.in.Close()
	_ = r.cmd.Wait()
}

// parityRun is one run of a scenario against one agent.
type parityRun struct {
	t       *testing.T
	f       *pfake
	clk     *testClock
	a       agentUnderTest
	secrets string
	volumes string
	out     []string
}

// note adds an entry to the transcript.
func (p *parityRun) note(kind, v string) {
	p.out = append(p.out, kind+" "+v)
}

// compact is a message's protojson, stable.
func compact(m proto.Message) string {
	if m == nil || !m.ProtoReflect().IsValid() {
		return "null"
	}
	b, err := protojson.Marshal(m)
	if err != nil {
		return "error " + err.Error()
	}
	var buf bytes.Buffer
	_ = json.Compact(&buf, b)
	return buf.String()
}

func (p *parityRun) normalize(s string) string {
	if p.secrets != "" {
		s = strings.ReplaceAll(s, p.secrets, "$SECRETS")
	}
	if p.volumes != "" {
		s = strings.ReplaceAll(s, p.volumes, "$VOLUMES")
	}
	return s
}

// files lists the agent's secret files and volume directories.
func (p *parityRun) files() string {
	var lines []string
	for _, root := range []string{p.secrets, p.volumes} {
		if root == "" {
			continue
		}
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || path == root {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			line := p.normalize(path) + " " + info.Mode().String()
			if d.Type().IsRegular() {
				b, _ := os.ReadFile(path)
				line += " " + strconv.Quote(string(b))
			}
			lines = append(lines, line)
			return nil
		})
	}
	return strings.Join(lines, "\n")
}

// step records what a step did.
func (p *parityRun) step(name string, report *armadav1.ReplicaReport, err string, calls []string) {
	p.note("step", name)
	if err != "" {
		p.note("error", p.normalize(err))
	} else {
		p.note("report", p.normalize(compact(report)))
	}
	p.note("calls", strings.Join(calls, "\n"))
	p.note("files", p.files())
}

// assign sends the node its replicas.
func (p *parityRun) assign(replicas ...*armadav1.ReplicaSpec) {
	p.a.assign(&armadav1.Assignment{Replicas: replicas})
}

// reconcile runs a pass and records it.
func (p *parityRun) reconcile(name string) *armadav1.ReplicaReport {
	r, err := p.a.reconcile()
	p.step(name, r, err, p.f.takeCalls())
	return r
}

// until runs passes until done says the report is what the scenario waits
// for, then records the last report and the calls without repeats.
func (p *parityRun) until(name string, done func(*armadav1.ReplicaReport) bool) *armadav1.ReplicaReport {
	p.t.Helper()
	var calls []string
	deadline := time.Now().Add(15 * time.Second)
	for {
		r, err := p.a.reconcile()
		calls = append(calls, p.f.takeCalls()...)
		if err == "" && done(r) {
			slices.Sort(calls)
			p.step(name, r, err, slices.Compact(calls))
			return r
		}
		if time.Now().After(deadline) {
			p.t.Fatalf("%s: never reached; last report %s %s", name, compact(r), err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// advance moves both clocks on.
func (p *parityRun) advance(d time.Duration) {
	p.clk.Set(p.clk.Now().Add(d))
	p.a.setNow(p.clk.Now())
}

// sample records a usage sample.
func (p *parityRun) sample(name string) *armadav1.UsageReport {
	u := p.a.sample()
	p.note("usage "+name, compact(u))
	p.note("calls", strings.Join(p.f.takeCalls(), "\n"))
	return u
}

// other runs fn (contact, fence, prune) and records its calls.
func (p *parityRun) other(name string, fn func(agentUnderTest)) {
	fn(p.a)
	p.note("step", name)
	p.note("calls", strings.Join(p.f.takeCalls(), "\n"))
	p.note("files", p.files())
}

// newParityRun sets up a node with opts and an agent: Go's, or the Rust
// program.
func newParityRun(t *testing.T, opts parityOpts, rust bool) *parityRun {
	clk := &testClock{t: parityT0}
	f := newPfake(clk)
	f.noMembers, f.noVolumes, f.noExec, f.noStats, f.bridge = !opts.members, !opts.volumes, !opts.exec, !opts.stats, opts.bridge
	p := &parityRun{t: t, f: f, clk: clk}
	if !opts.noSecretsDir {
		p.secrets = t.TempDir()
	}
	if opts.volumesDir {
		p.volumes = t.TempDir()
	}
	f.norm = p.normalize
	if rust {
		r := startRust(t, f)
		r.request("config", map[string]any{"config": map[string]any{
			"nodeId": "n1", "privateIp": "10.0.0.2", "cpuMillis": 2000, "memoryBytes": 1 << 30,
			"bootNs": opts.boot.UnixNano(), "nowNs": parityT0.UnixNano(), "crashBaseNs": int64(opts.crashBase),
			"unpublished": opts.unpublished, "volumesDir": p.volumes, "secretsDir": p.secrets, "dns": opts.dns,
			"os": "linux", "arch": "amd64",
			"caps": map[string]any{"members": opts.members, "volumes": opts.volumes, "exec": opts.exec, "stats": opts.stats},
		}})
		p.a = r
		return p
	}
	cfg := Config{
		NodeID: "n1", PrivateIP: "10.0.0.2", Driver: f, Check: f.Check, CPUMillis: 2000, MemoryBytes: 1 << 30,
		BootTime: opts.boot, Unpublished: opts.unpublished, VolumesDir: p.volumes, SecretsDir: p.secrets,
		OS: "linux", Arch: "amd64", ImagePrune: -1, UsageInterval: time.Hour,
	}
	if opts.dns != "" {
		cfg.DNS = stubDNS(opts.dns)
	}
	a := New(cfg)
	a.now, a.began, a.crashBase = clk.Now, clk.Now(), opts.crashBase
	ctx, cancel := context.WithCancel(context.Background())
	p.a = &goAgent{a: a, f: f, ctx: ctx, cancel: cancel}
	return p
}

// runAgentParity runs body against Go's agent and, with ARMADA_AGENT_BIN,
// against the Rust agent, and compares their transcripts.
func runAgentParity(t *testing.T, opts parityOpts, body func(p *parityRun)) {
	t.Helper()
	run := func(rust bool) []string {
		p := newParityRun(t, opts, rust)
		defer p.a.stop()
		body(p)
		return p.out
	}
	g := run(false)
	if os.Getenv("ARMADA_AGENT_PARITY_DUMP") != "" {
		t.Log("go's transcript:\n" + strings.Join(g, "\n"))
	}
	if agentBin() == "" {
		return
	}
	r := run(true)
	compareAgentTranscripts(t, g, r)
}

func compareAgentTranscripts(t *testing.T, g, r []string) {
	t.Helper()
	shown := 0
	for i := range max(len(g), len(r)) {
		var a, b string
		if i < len(g) {
			a = g[i]
		}
		if i < len(r) {
			b = r[i]
		}
		if a == b {
			continue
		}
		context := ""
		for j := i - 1; j >= 0; j-- {
			if strings.HasPrefix(g[j], "step ") {
				context = g[j]
				break
			}
		}
		t.Errorf("transcripts differ at %d (%s):\n go:   %s\n rust: %s", i, context, a, b)
		if shown++; shown == 3 {
			return
		}
	}
}
