package haproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/proxy"
)

// The Rust agent's HAProxy driver (agent/src/haproxy, ADR 0055) is checked
// against this one through scenarios kept in testdata/rust: each step's
// input (a ProxyConfig as protojson, clients, the proxy's answers, whether
// it runs) and what this driver did (the Runtime API commands, starts,
// reloads, configuration checks, every file it wrote, the error, the
// load). The Rust test (haproxy::tests::go_scenarios) replays the inputs
// and compares. go test -update rewrites the files.

// rsStep is one step of a scenario.
type rsStep struct {
	// Op is apply, clients, load, health, or restart (a new driver on the
	// same directory, as after an agent restart).
	Op          string            `json:"op"`
	Config      json.RawMessage   `json:"config,omitempty"`
	Clients     map[string]string `json:"clients,omitempty"`
	Running     *bool             `json:"running,omitempty"`
	APIErr      string            `json:"apiErr,omitempty"`
	ValidateErr string            `json:"validateErr,omitempty"`
	// Replies answer the Runtime API's commands from this step on;
	// Listeners are the node's listening sockets.
	Replies   map[string]string `json:"replies,omitempty"`
	Listeners []string          `json:"listeners,omitempty"`

	Err         string                      `json:"err"`
	Cmds        []string                    `json:"cmds"`
	Starts      int                         `json:"starts"`
	Reloads     int                         `json:"reloads"`
	Validations []string                    `json:"validations"`
	Files       map[string]string           `json:"files"`
	Load        map[string]proxy.ServerLoad `json:"load,omitempty"`
}

type rsScenario struct {
	PrivateIP  string   `json:"privateIP"`
	InternalIP string   `json:"internalIP"`
	Subnet     string   `json:"subnet"`
	Steps      []rsStep `json:"steps"`
}

// Fixed bundles: Validate only counts their blocks.
var (
	rsPEM1 = []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")
	rsPEM2 = []byte("-----BEGIN CERTIFICATE-----\nAAEC\n-----END CERTIFICATE-----\n\n\n-----BEGIN PRIVATE KEY-----\nAAEC\n-----END PRIVATE KEY-----\n\n")
	rsPEM3 = []byte("-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n-----BEGIN EC PRIVATE KEY-----\nAQID\n-----END EC PRIVATE KEY-----\n")
)

func rsConfig(t *testing.T, c proxy.Config) json.RawMessage {
	t.Helper()
	b, err := protojson.Marshal(c.ToProto())
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := json.Compact(&out, b); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func rsBool(b bool) *bool { return &b }

// rsFiles is every file under etc but the random default certificate.
func rsFiles(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	root := etcDir(dir)
	err := filepath.WalkDir(root, func(p string, e os.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		if rel == defaultCertFile {
			return nil
		}
		b, err := os.ReadFile(p)
		out[filepath.ToSlash(rel)] = string(b)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// runRustScenario runs sc's inputs on this driver and fills in what it did.
func runRustScenario(t *testing.T, sc *rsScenario) {
	t.Helper()
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "haproxy")
	e := &fakeEngine{}
	replies := map[string]string{}
	a := &fakeAPI{reply: func(cmd string) string {
		if r, ok := replies[cmd]; ok {
			return r
		}
		if strings.HasPrefix(cmd, "prepare map") {
			return "New version created: 7"
		}
		return ""
	}}
	var listeners []netip.AddrPort
	newD := func() *Driver {
		d, err := New(Config{Dir: dir, PrivateIP: sc.PrivateIP, InternalIP: sc.InternalIP, Subnet: sc.Subnet, Engine: e, API: a,
			Listeners: func() ([]netip.AddrPort, error) { return listeners, nil }})
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	d := newD()
	for i := range sc.Steps {
		s := &sc.Steps[i]
		if s.Running != nil {
			e.running = *s.Running
		}
		if s.Replies != nil {
			replies = s.Replies
		}
		if s.Listeners != nil {
			listeners = nil
			for _, l := range s.Listeners {
				listeners = append(listeners, netip.MustParseAddrPort(l))
			}
		}
		a.cmds, a.err, e.validateErr = nil, nil, nil
		if s.APIErr != "" {
			a.err = errors.New(s.APIErr)
		}
		if s.ValidateErr != "" {
			e.validateErr = errors.New(s.ValidateErr)
		}
		var err error
		switch s.Op {
		case "apply":
			var pc armadav1.ProxyConfig
			if err := protojson.Unmarshal(s.Config, &pc); err != nil {
				t.Fatal(err)
			}
			err = d.Apply(ctx, proxy.FromProto(&pc))
		case "clients":
			clients := map[netip.Addr]string{}
			for k, v := range s.Clients {
				clients[netip.MustParseAddr(k)] = v
			}
			err = d.SetClients(ctx, clients)
		case "load":
			s.Load, err = d.Load(ctx)
		case "health":
			err = d.Health(ctx)
		case "restart":
			d = newD()
		default:
			t.Fatalf("unknown op %q", s.Op)
		}
		s.Err = ""
		if err != nil {
			s.Err = err.Error()
		}
		s.Cmds = append([]string{}, a.cmds...)
		s.Starts, s.Reloads = e.starts, e.reloads
		s.Validations = append([]string{}, e.validations...)
		s.Files = rsFiles(t, dir)
	}
}

func rsScenarios(t *testing.T) map[string]*rsScenario {
	t.Helper()
	life := sampleConfig(t)
	life.Certificates[0].PEM = rsPEM1
	for i := range life.Backends[1].Servers {
		life.Backends[1].Servers[i].Weight = 0
	}
	steps := []rsStep{{Op: "apply", Config: rsConfig(t, life)}, {Op: "apply", Config: rsConfig(t, life)}}
	moved := life
	moved.Backends = append([]proxy.Backend{}, life.Backends...)
	moved.Backends[1].Servers = []proxy.Server{{Name: "api-bengkel-r3-a", Address: "10.0.0.2:32769"}, {Name: "api-bengkel-r3-c", Address: "10.0.0.4:32771"}}
	steps = append(steps, rsStep{Op: "apply", Config: rsConfig(t, moved)})
	moved.Backends[1].Servers = moved.Backends[1].Servers[1:]
	steps = append(steps, rsStep{Op: "apply", Config: rsConfig(t, moved)})
	moved.Backends[1].Servers = []proxy.Server{{Name: "api-bengkel-r4-a", Address: "10.0.0.5:32772", Weight: 30}}
	steps = append(steps, rsStep{Op: "apply", Config: rsConfig(t, moved)})
	renewed := moved
	renewed.Certificates = []proxy.Certificate{{Name: "example.org", PEM: rsPEM2}}
	steps = append(steps, rsStep{Op: "apply", Config: rsConfig(t, renewed)})
	renewed.Certificates = []proxy.Certificate{{Name: "example.org", PEM: rsPEM3}}
	steps = append(steps, rsStep{Op: "apply", Config: rsConfig(t, renewed), APIErr: "injected"})
	more := renewed
	more.Rules = append(append([]proxy.Rule{}, renewed.Rules...), proxy.Rule{Host: "www.example.org", PathPrefix: "/", Backend: "frontend"})
	more.Certificates = append(append([]proxy.Certificate{}, renewed.Certificates...), proxy.Certificate{Name: "*.example.org", PEM: rsPEM1})
	steps = append(steps, rsStep{Op: "apply", Config: rsConfig(t, more), ValidateErr: "bad line"})
	steps = append(steps, rsStep{Op: "apply", Config: rsConfig(t, more)})
	steps = append(steps, rsStep{Op: "apply", Config: rsConfig(t, renewed)})
	bad := renewed
	bad.Backends = append([]proxy.Backend{}, renewed.Backends...)
	bad.Backends[0] = proxy.Backend{Name: "frontend", Servers: []proxy.Server{{Name: "x", Address: "8.8.8.8:1", Weight: -1}, {Name: "x", Address: "10.0.0.2:01"}}}
	bad.Rules = append(append([]proxy.Rule{}, renewed.Rules...), proxy.Rule{Host: "x.example.org", PathPrefix: "/", Backend: "nope", Allow: []string{"web"}})
	steps = append(steps, rsStep{Op: "apply", Config: rsConfig(t, bad)}, rsStep{Op: "health"})

	// Weights, local-first, the clients map, and internal TCP.
	net := proxy.Config{
		Backends: []proxy.Backend{
			{Name: "web", LocalFirst: true, Servers: []proxy.Server{{Name: "web-r1-a", Address: "10.120.0.5:8080"}, {Name: "web-r1-b", Address: "10.120.1.5:8080"}}},
			{Name: "db", LocalFirst: true, Servers: []proxy.Server{{Name: "db-r1-a", Address: "10.120.0.7:5432"}}},
			{Name: "sticky", Sticky: true, Servers: []proxy.Server{{Name: "sticky-r1-a", Address: "10.120.0.8:80"}}},
		},
		Rules: []proxy.Rule{
			{Host: "web.internal", PathPrefix: "/", Backend: "web", Internal: true},
			{Host: "web.example.org", PathPrefix: "/", Backend: "web"},
			{Host: "sticky.example.org", PathPrefix: "/", Backend: "sticky"},
		},
		TCP: []proxy.TCPRoute{{Port: 5432, Backend: "db"}},
	}
	netSteps := []rsStep{
		{Op: "clients", Clients: map[string]string{"10.120.0.5": "web", "10.120.0.9": "db.staging"}},
		{Op: "apply", Config: rsConfig(t, net), Listeners: []string{"0.0.0.0:22", "10.120.0.1:6379"}},
		{Op: "clients", Clients: map[string]string{"10.120.0.5": "web", "10.120.0.4": "web"}},
		{Op: "clients", Clients: map[string]string{"10.120.0.5": "web", "10.120.0.4": "web"}},
		{Op: "clients", Clients: map[string]string{"10.120.1.3": "web"}},
	}
	moved2 := net
	moved2.Backends = append([]proxy.Backend{}, net.Backends...)
	moved2.Backends[0].Servers = []proxy.Server{{Name: "web-r1-b", Address: "10.120.1.5:8080"}, {Name: "web-r2-a", Address: "10.120.0.6:8080"}}
	netSteps = append(netSteps, rsStep{Op: "apply", Config: rsConfig(t, moved2)})
	moved2.Backends[2].Servers = []proxy.Server{{Name: "sticky-r2-a", Address: "10.120.0.9:80"}}
	netSteps = append(netSteps, rsStep{Op: "apply", Config: rsConfig(t, moved2)})
	netSteps = append(netSteps, rsStep{Op: "apply", Config: rsConfig(t, moved2), Listeners: []string{"0.0.0.0:5432"}})
	netSteps = append(netSteps,
		rsStep{Op: "load", Replies: map[string]string{"show info": "Pid: 10\n", "show stat -1 4 -1 no-maint": "# pxname,svname,qcur,scur,stot\nbe_web,s1,1,2,40\nbe_web,s2,0,1,5\nbe_db,s1,0,0,3\n"}},
		rsStep{Op: "load", Replies: map[string]string{"show info": "Pid: 11\n", "show stat -1 4 -1 no-maint": "# pxname,svname,qcur,scur,stot\nbe_web,s1,0,0,2\n"}},
	)

	// Taking over a running proxy after a restart.
	take := proxy.Config{Backends: []proxy.Backend{{Name: "web", Servers: []proxy.Server{{Name: "a", Address: "10.0.0.2:81"}, {Name: "b", Address: "10.0.0.3:82"}}}}}
	state := "1\n# be_id be_name srv_id srv_name srv_addr srv_op_state srv_admin_state srv_uweight srv_port\n" +
		"3 be_web 1 s1 10.0.0.3 2 0 1 82\n3 be_web 2 s2 10.0.0.2 2 0 1 81\n3 be_web 3 s3 10.0.0.9 2 0 1 89\n3 be_web 4 s4 10.0.0.8 0 5 1 88\n"
	moreTake := take
	moreTake.Backends = append(append([]proxy.Backend{}, take.Backends...), proxy.Backend{Name: "api", Servers: []proxy.Server{{Name: "c", Address: "10.0.0.3:83"}}})
	takeSteps := []rsStep{
		{Op: "apply", Config: rsConfig(t, take)},
		{Op: "restart", Replies: map[string]string{"show servers state": state}},
		{Op: "apply", Config: rsConfig(t, take)},
		{Op: "restart"},
		{Op: "apply", Config: rsConfig(t, moreTake)},
		{Op: "restart", Running: rsBool(false)},
		{Op: "apply", Config: rsConfig(t, moreTake)},
	}
	return map[string]*rsScenario{
		"lifecycle": {PrivateIP: "10.0.0.2", Steps: steps},
		"network":   {PrivateIP: "10.0.0.2", InternalIP: "10.120.0.1", Subnet: "10.120.0.0/24", Steps: netSteps},
		"takeover":  {PrivateIP: "10.0.0.2", Steps: takeSteps},
	}
}

func TestRustDriverScenarios(t *testing.T) {
	t.Parallel()
	scs := rsScenarios(t)
	names := make([]string, 0, len(scs))
	for n := range scs {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		sc := scs[name]
		runRustScenario(t, sc)
		got, err := json.MarshalIndent(sc, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, '\n')
		path := filepath.Join("testdata", "rust", name+".json")
		if *update {
			if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, got, 0o600); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%v (run go test -update)", err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s is stale: run go test ./internal/proxy/haproxy -run TestRustDriverScenarios -update", path)
		}
	}
}
