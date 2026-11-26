package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/proxy"
)

// The parity harness's proxy, cluster network, resolver, certificate
// source, and runtime move (ADR 0055, item 16b): fakes on pfake whose
// calls go into the same transcript as the runtime's, answered for the
// Rust program from the same fakes. The proxy notes how many containers
// ran when it applied a configuration, which shows the order of a pass
// although the calls of a step are sorted.

// ingress is what the fakes answer, under pfake's lock.
type ingress struct {
	proxyErr   string
	healthErr  string
	load       map[string]proxy.ServerLoad
	loadErr    string
	clientsErr string
	netErr     string
	switching  *armadav1.NetworkSwitchStatus
	peers      []string
	userspace  bool
	keys       int
	keyErr     string
	certs      map[string][]byte
	certErr    string
	moveErr    string
}

// pproxy is the node's proxy.
type pproxy struct{ f *pfake }

func (p pproxy) Apply(_ context.Context, cfg proxy.Config) error {
	p.f.mu.Lock()
	defer p.f.mu.Unlock()
	running := 0
	for _, c := range p.f.containers {
		if c.State == "running" {
			running++
		}
	}
	if p.f.recording {
		// The replay sees the configuration as the Rust agent sends it.
		p.f.record("proxy.apply", map[string]any{"running": running, "config": json.RawMessage(compact(cfg.ToProto()))})
	} else {
		p.f.record("proxy.apply", map[string]any{"running": running, "config": cfg})
	}
	if p.f.in.proxyErr != "" {
		return errors.New(p.f.in.proxyErr)
	}
	return nil
}

func (p pproxy) Health(context.Context) error {
	p.f.mu.Lock()
	defer p.f.mu.Unlock()
	p.f.record("proxy.health", nil)
	if p.f.in.healthErr != "" {
		return errors.New(p.f.in.healthErr)
	}
	return nil
}

func (p pproxy) SetClients(_ context.Context, clients map[netip.Addr]string) error {
	p.f.mu.Lock()
	defer p.f.mu.Unlock()
	p.f.record("proxy.clients", clients)
	if p.f.in.clientsErr != "" {
		return errors.New(p.f.in.clientsErr)
	}
	return nil
}

func (p pproxy) Load(context.Context) (map[string]proxy.ServerLoad, error) {
	p.f.mu.Lock()
	defer p.f.mu.Unlock()
	p.f.record("proxy.load", nil)
	if p.f.in.loadErr != "" {
		return nil, errors.New(p.f.in.loadErr)
	}
	out := map[string]proxy.ServerLoad{}
	for k, v := range p.f.in.load {
		out[k] = v
	}
	return out, nil
}

// pnet is the cluster network, with every optional part.
type pnet struct{ f *pfake }

func (n pnet) Apply(_ context.Context, cfg *armadav1.NetworkConfig, local map[netip.Addr]string) error {
	n.f.mu.Lock()
	defer n.f.mu.Unlock()
	n.f.record("net.apply", map[string]any{"config": json.RawMessage(compact(cfg)), "local": local})
	if n.f.in.netErr != "" {
		return errors.New(n.f.in.netErr)
	}
	return nil
}

func (n pnet) SwitchStatus() *armadav1.NetworkSwitchStatus {
	n.f.mu.Lock()
	defer n.f.mu.Unlock()
	return n.f.in.switching
}

func (n pnet) UnreachablePeers() []string {
	n.f.mu.Lock()
	defer n.f.mu.Unlock()
	return slices.Clone(n.f.in.peers)
}

func (n pnet) WireGuardUserspace() bool {
	n.f.mu.Lock()
	defer n.f.mu.Unlock()
	return n.f.in.userspace
}

func (n pnet) RotateKey() (string, error) {
	n.f.mu.Lock()
	defer n.f.mu.Unlock()
	n.f.record("net.rotate", nil)
	if n.f.in.keyErr != "" {
		return "", errors.New(n.f.in.keyErr)
	}
	n.f.in.keys++
	return "key-" + strconv.Itoa(n.f.in.keys), nil
}

// pdns is the node's resolver.
type pdns struct {
	f    *pfake
	addr string
}

func (d pdns) Address() string { return d.addr }

func (d pdns) SetNames(apps []string) {
	d.f.mu.Lock()
	defer d.f.mu.Unlock()
	if len(apps) == 0 {
		apps = nil
	}
	d.f.record("dns.names", apps)
}

func (d pdns) SetClients(clients map[netip.Addr]string) {
	d.f.mu.Lock()
	defer d.f.mu.Unlock()
	d.f.record("dns.clients", clients)
}

// pcerts answers GetCertificates; the rest of the client is never called.
type pcerts struct {
	armadav1.AgentServiceClient
	f *pfake
}

func (c pcerts) GetCertificates(_ context.Context, in *armadav1.GetCertificatesRequest, _ ...grpc.CallOption) (*armadav1.GetCertificatesResponse, error) {
	c.f.mu.Lock()
	defer c.f.mu.Unlock()
	c.f.record("certs", in.GetNames())
	if c.f.in.certErr != "" {
		return nil, errors.New(c.f.in.certErr)
	}
	out := &armadav1.GetCertificatesResponse{}
	for _, n := range in.GetNames() {
		if pem, ok := c.f.in.certs[n]; ok {
			out.Certificates = append(out.Certificates, &armadav1.ProxyCertificate{Name: n, Pem: pem})
		}
	}
	return out, nil
}

// moveRuntime, prepareMove, and onPlan are the node's runtime move hooks.
func (f *pfake) moveRuntime(_ context.Context, to string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("move", to)
	if f.in.moveErr != "" {
		return errors.New(f.in.moveErr)
	}
	return nil
}

func (f *pfake) prepareMove(_ context.Context, to string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("prepare", to)
}

func (f *pfake) onPlan(p *armadav1.RuntimeMovePlan) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("plan", json.RawMessage(compact(p)))
}

// ingressCall is the part of a Rust program's call the fakes read.
type ingressCall struct {
	Config json.RawMessage `json:"config"`
	Local  json.RawMessage `json:"local"`
	Names  []string        `json:"names"`
	Apps   []string        `json:"apps"`
	To     string          `json:"to"`
	Plan   json.RawMessage `json:"plan"`
}

// answerIngress runs a call of the Rust program on the fakes; ok is false
// for a method that is not theirs.
func (f *pfake) answerIngress(method string, raw []byte) (res any, ok bool, err error) {
	var c ingressCall
	_ = json.Unmarshal(raw, &c)
	ctx := context.Background()
	local := func() map[netip.Addr]string {
		if len(c.Local) == 0 || string(c.Local) == "null" {
			return nil
		}
		m := map[netip.Addr]string{}
		if err := json.Unmarshal(c.Local, &m); err != nil {
			panic(err)
		}
		return m
	}
	switch method {
	case "proxyApply":
		pc := &armadav1.ProxyConfig{}
		if err := protojson.Unmarshal(c.Config, pc); err != nil {
			return nil, true, err
		}
		return nil, true, pproxy{f}.Apply(ctx, proxy.FromProto(pc))
	case "proxyHealth":
		return nil, true, pproxy{f}.Health(ctx)
	case "proxyClients":
		return nil, true, pproxy{f}.SetClients(ctx, local())
	case "proxyLoad":
		l, err := pproxy{f}.Load(ctx)
		out := map[string]map[string]int64{}
		for k, v := range l {
			out[k] = map[string]int64{"inFlight": v.InFlight, "total": v.Total}
		}
		return out, true, err
	case "netApply":
		nc := &armadav1.NetworkConfig{}
		if err := protojson.Unmarshal(c.Config, nc); err != nil {
			return nil, true, err
		}
		return nil, true, pnet{f}.Apply(ctx, nc, local())
	case "netSwitch":
		return json.RawMessage(compact(pnet{f}.SwitchStatus())), true, nil
	case "netPeers":
		return pnet{f}.UnreachablePeers(), true, nil
	case "netUserspace":
		return pnet{f}.WireGuardUserspace(), true, nil
	case "netRotate":
		k, err := pnet{f}.RotateKey()
		return k, true, err
	case "dnsNames":
		pdns{f: f}.SetNames(c.Apps)
		return nil, true, nil
	case "dnsClients":
		pdns{f: f}.SetClients(local())
		return nil, true, nil
	case "certs":
		r, err := pcerts{f: f}.GetCertificates(ctx, &armadav1.GetCertificatesRequest{Names: c.Names})
		if err != nil {
			return nil, true, err
		}
		var out []json.RawMessage
		for _, x := range r.GetCertificates() {
			out = append(out, json.RawMessage(compact(x)))
		}
		return out, true, nil
	case "move":
		return nil, true, f.moveRuntime(ctx, c.To)
	case "prepare":
		f.prepareMove(ctx, c.To)
		return nil, true, nil
	case "plan":
		p := &armadav1.RuntimeMovePlan{}
		if len(c.Plan) == 0 || string(c.Plan) == "null" {
			p = nil
		} else if err := protojson.Unmarshal(c.Plan, p); err != nil {
			return nil, true, err
		}
		f.onPlan(p)
		return nil, true, nil
	}
	return nil, false, fmt.Errorf("unknown call %q", method)
}

// withIngress gives Go's agent the fakes opts asks for.
func withIngress(cfg *Config, f *pfake, opts parityOpts) {
	if opts.proxy {
		cfg.Proxy = pproxy{f}
		cfg.Client = pcerts{f: f}
	}
	if opts.network {
		cfg.Network = pnet{f}
		cfg.NetworkKey = opts.networkKey
	}
	if opts.dns != "" {
		cfg.DNS = pdns{f: f, addr: opts.dns}
	}
	if opts.move {
		cfg.MoveRuntime = f.moveRuntime
		cfg.PrepareRuntimeMove = f.prepareMove
		cfg.OnRuntimeMove = f.onPlan
	}
}
