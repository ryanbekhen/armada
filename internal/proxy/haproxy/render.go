// Package haproxy implements proxy.Driver with HAProxy running as an
// Armada-managed system container. Structural changes are rendered to a
// config file, validated with `haproxy -c`, and applied with a graceful
// reload; server changes go through the Runtime API without a reload.
package haproxy

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/ryanbekhen/armada/internal/proxy"
)

// Paths inside the HAProxy container.
const (
	containerConfDir = "/usr/local/etc/haproxy"
	containerRunDir  = "/var/run/haproxy"
	configFile       = "haproxy.cfg"
	defaultCertFile  = "default.pem"
	certDir          = "certs"
	socketFile       = "admin.sock"
	clientsFile      = "clients.map"
	// routeFilePrefix starts the name of every route map.
	routeFilePrefix = "routes-"
	metricsPort     = MetricsPort
)

// MetricsPort is the HAProxy stats/metrics port on the node's private IP.
const MetricsPort = 8404

// Layout assigns replicas to fixed server slots per HAProxy backend (be_web,
// lo_web). Slots let the Runtime API change servers without a reload; an
// empty string marks a free slot.
type Layout map[string][]string

// slotCount rounds up to a multiple of 10 so scaling within a band needs no
// reload.
func slotCount(n int) int {
	if n <= 10 {
		return 10
	}
	return (n + 9) / 10 * 10
}

// renderOptions are the node-specific parts of the configuration.
type renderOptions struct {
	// PrivateIP is where the metrics endpoint listens; never public.
	PrivateIP string
	// InternalIP is the container bridge gateway where the internal
	// frontend listens on port 80. It is reachable only from this node's
	// containers. Empty disables internal ingress.
	InternalIP string
	// Subnet is the node's container subnet in the cluster network
	// (ADR 0025), where its replicas have their own addresses; empty when
	// replicas are reached through ports on the private IP. With a subnet
	// the node knows its containers' apps (the clients map), and the
	// internal frontend admits a request only from the target's project,
	// or its allowed apps (ADR 0026).
	Subnet string
}

// checksCallers reports whether the internal frontend checks who calls.
func (o renderOptions) checksCallers() bool { return o.Subnet != "" }

// node returns where this node's replicas are.
func (o renderOptions) node() node {
	n := node{}
	n.ip, _ = netip.ParseAddr(o.PrivateIP)
	n.subnet, _ = netip.ParsePrefix(o.Subnet)
	return n
}

// node is where a node's own replicas are: ports on its private IP, or
// addresses in its container subnet.
type node struct {
	ip     netip.Addr
	subnet netip.Prefix
}

// known reports whether the node's address is known, which local-first
// routing needs.
func (n node) known() bool { return n.ip.IsValid() }

// has reports whether a server's ip:port is on the node.
func (n node) has(addr string) bool {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil || !n.known() {
		return false
	}
	ip := ap.Addr().Unmap()
	return ip == n.ip.Unmap() || (n.subnet.IsValid() && n.subnet.Contains(ip))
}

// internalPort is the port of the internal frontend: apps call
// http://<app>.internal without a port.
const internalPort = 80

func backendName(app string) string { return "be_" + app }

// localBackendName is the backend of an app's replicas on this node, which
// local-first routing prefers (ADR 0024).
func localBackendName(app string) string { return "lo_" + app }

// pool is one HAProxy backend with server slots.
type pool struct {
	name    string
	servers []proxy.Server
}

// pools returns every slotted backend of cfg: be_<app> with all of an
// app's servers and, for local-first apps when the node's private IP is
// known, lo_<app> with the servers on this node. Local servers always have
// weight 1: weights only split traffic, which is never local-first.
func pools(cfg proxy.Config, n node) []pool {
	var out []pool
	for _, be := range cfg.Backends {
		out = append(out, pool{backendName(be.Name), be.Servers})
		if !localFirst(be, n) {
			continue
		}
		out = append(out, pool{localBackendName(be.Name), localServers(be, n)})
	}
	return out
}

// localServers returns be's servers on the node, at weight 1.
func localServers(be proxy.Backend, n node) []proxy.Server {
	var local []proxy.Server
	for _, s := range be.Servers {
		if n.has(s.Address) {
			local = append(local, proxy.Server{Name: s.Name, Address: s.Address})
		}
	}
	return local
}

// localFirst reports whether be gets a local backend on a node: only with a
// replica there, because its rules run for every request of the frontend. The
// first replica to arrive on a node therefore reloads the proxy; others join
// through the Runtime API.
func localFirst(be proxy.Backend, n node) bool {
	return be.LocalFirst && n.known() && len(localServers(be, n)) > 0
}

// wakeBackendName is the backend of an app's wake socket (ADR 0021).
func wakeBackendName(app string) string { return "wk_" + app }

// WakeSocketFile is the agent's wake socket in the proxy's run directory,
// the only place HAProxy and the agent share.
const WakeSocketFile = "wake.sock"

// WakeSocket returns the host path of the wake socket for a proxy
// directory.
func WakeSocket(dir string) string { return filepath.Join(runDir(dir), WakeSocketFile) }
func slotName(i int) string        { return "s" + strconv.Itoa(i+1) }

// stripField returns the field() index of the first path segment after
// prefix: "/api" splits as "", "api", ... so the rest starts at field 3.
// Counting segments keeps user input out of any regular expression.
func stripField(prefix string) int { return strings.Count(prefix, "/") + 2 }

// render produces haproxy.cfg. cfg must already be validated: every value
// interpolated here is constrained to a safe character set by
// proxy.Config.Validate. As a second line of defence, an interpolated string
// holding whitespace or a control character (a smuggled directive) makes
// render return nil instead of a configuration.
func render(cfg proxy.Config, layout Layout, opts renderOptions) []byte {
	if !safeConfig(cfg, opts) {
		return nil
	}
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }

	w("# Generated by Armada. Do not edit: changes are overwritten.")
	w("global")
	w("    stats socket %s/%s mode 600 level admin", containerRunDir, socketFile)
	w("    log stdout format raw local0")
	w("    maxconn 20000")
	w("    ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets")
	w("    ssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256")
	w("    ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305")
	w("")
	w("defaults")
	w("    mode http")
	w("    log global")
	w("    option httplog")
	w("    option forwardfor")
	// A connection that fails (e.g. to a replica that is just stopping) is
	// retried on another server instead of answering 503.
	// Servers are on the private network, where a connection takes
	// milliseconds: a server that does not answer within 2s is down, and
	// the request moves on to another one.
	w("    retries 3")
	w("    option redispatch 1")
	w("    timeout connect 2s")
	w("    timeout client 60s")
	w("    timeout server 60s")
	w("    timeout http-request 10s")
	w("    timeout http-keep-alive 10s")
	w("    timeout queue 30s")
	w("")

	if opts.PrivateIP != "" {
		w("frontend metrics")
		w("    bind %s:%d", hostForBind(opts.PrivateIP), metricsPort)
		w("    http-request use-service prometheus-exporter if { path /metrics }")
		w("    http-request return status 404")
		w("")
	}

	w("frontend http")
	w("    bind :80")
	if cfg.ACMEAddress != "" {
		w("    acl acme path_beg /.well-known/acme-challenge/")
		w("    http-request redirect scheme https code 301 unless acme")
		w("    use_backend be_armada_acme if acme")
	} else {
		w("    http-request redirect scheme https code 301")
	}
	w("")

	w("frontend https")
	w("    bind :443 ssl crt %s/%s crt %s/%s/ alpn h2,http/1.1", containerConfDir, defaultCertFile, containerConfDir, certDir)
	w("    http-request set-header X-Forwarded-Proto https")
	w("    http-request set-var(txn.host) req.hdr(host),field(1,:),lower")
	w("    http-request set-var(txn.path) path")

	public, internal := splitRules(cfg)
	backendsByName := map[string]proxy.Backend{}
	for _, be := range cfg.Backends {
		backendsByName[be.Name] = be
	}
	rr := ruleRenderer{w: w, backends: backendsByName, node: opts.node()}
	rr.write(routesPublic, public)
	w("    default_backend be_armada_notfound")
	w("")

	if opts.InternalIP != "" {
		w("frontend internal")
		w("    bind %s:%d", hostForBind(opts.InternalIP), internalPort)
		w("    http-request set-header X-Forwarded-Proto http")
		w("    http-request set-var(txn.host) req.hdr(host),field(1,:),lower")
		w("    http-request set-var(txn.path) path")
		if opts.checksCallers() {
			// The caller's project and app, from its address; nothing for an
			// address this node does not know, which then matches no route.
			w("    http-request set-var(txn.cproj) src,map_ip(%s/%s),field(1,:)", containerConfDir, clientsFile)
			w("    http-request set-var(txn.capp) src,map_ip(%s/%s),field(2,:)", containerConfDir, clientsFile)
			rr.callers = true
		}
		rr.write(routesInternal, internal)
		w("    default_backend be_armada_notfound")
		w("")
	}

	backends := slices.Clone(cfg.Backends)
	slices.SortFunc(backends, func(a, b proxy.Backend) int { return cmp.Compare(a.Name, b.Name) })
	for _, be := range backends {
		writeBackend(w, backendName(be.Name), be.HealthPath, be.Servers, layout)
		if localFirst(be, opts.node()) {
			// Always rendered, empty or not, so a replica arriving on or
			// leaving this node needs no reload.
			writeBackend(w, localBackendName(be.Name), be.HealthPath, localServers(be, opts.node()), layout)
		}
		if be.Wake {
			w("backend %s", wakeBackendName(be.Name))
			w("    http-request set-header %s %s", proxy.WakeHeader, be.Name)
			// Long enough for a replica to start, then answer.
			w("    timeout server %ds", int((proxy.WakeTimeout + 60*time.Second).Seconds()))
			w("    server wake unix@%s/%s", containerRunDir, WakeSocketFile)
			w("")
		}
	}

	if cfg.ACMEAddress != "" {
		w("backend be_armada_acme")
		w("    server acme %s", cfg.ACMEAddress)
		w("")
	}
	w("backend be_armada_notfound")
	w("    http-request return status 404 content-type text/plain string \"no app is configured for this host\"")
	return []byte(b.String())
}

// writeBackend emits one slotted backend.
func writeBackend(w func(string, ...any), name, healthPath string, list []proxy.Server, layout Layout) {
	servers := map[string]proxy.Server{}
	for _, s := range list {
		servers[s.Name] = s
	}
	w("backend %s", name)
	w("    balance roundrobin")
	if healthPath != "" {
		w("    option httpchk GET %s", healthPath)
		w("    http-check expect status 200-399")
	}
	// A dead node is out of rotation within about 4s.
	w("    default-server check inter 2s fall 2 rise 2")
	for i, sname := range layout[name] {
		if s, ok := servers[sname]; ok && sname != "" && s.EffectiveWeight() != 1 {
			w("    server %s %s weight %d", slotName(i), s.Address, s.EffectiveWeight())
		} else if ok && sname != "" {
			w("    server %s %s", slotName(i), s.Address)
		} else {
			w("    server %s 127.0.0.1:1 disabled", slotName(i))
		}
	}
	w("")
}

// ruleRenderer emits the routing of the frontends.
type ruleRenderer struct {
	w        func(string, ...any)
	backends map[string]proxy.Backend
	node     node
	// callers restricts each route to its backend's project, or its
	// allowed apps.
	callers bool
}

// Route IDs start with these, one per frontend.
const (
	routesPublic   = "r"
	routesInternal = "i"
)

// splitRules separates the public rules from the internal ones.
func splitRules(cfg proxy.Config) (public, internal []proxy.Rule) {
	for _, r := range cfg.Rules {
		if r.Internal {
			internal = append(internal, r)
		} else {
			public = append(public, r)
		}
	}
	return public, internal
}

// sortRules orders rules longest path first, so the most specific route wins;
// ties by host for deterministic output.
func sortRules(rules []proxy.Rule) []proxy.Rule {
	rules = slices.Clone(rules)
	slices.SortFunc(rules, func(a, b proxy.Rule) int {
		if c := cmp.Compare(len(b.PathPrefix), len(a.PathPrefix)); c != 0 {
			return c
		}
		if c := cmp.Compare(a.Host, b.Host); c != 0 {
			return c
		}
		return cmp.Compare(a.PathPrefix, b.PathPrefix)
	})
	return rules
}

// mapped reports whether a rule can be looked up in the frontend's route map
// instead of having rules of its own: it matches a whole host, and only needs
// the backend's project checked. HAProxy runs every http-request rule of a
// frontend for every request, so this keeps a request's cost from growing with
// the number of apps in the cluster.
func mapped(r proxy.Rule, be proxy.Backend) bool {
	return r.PathPrefix == "/" && !r.StripPrefix && len(r.Allow) == 0 && !be.Wake
}

// routeMap returns the route map of a frontend: one "<key> <backend>" line per
// mapped rule, where the key is the host, or "<project>/<host>" when callers
// are checked. It is named after its content, so a configuration and its map
// are validated and replaced together. Its name is empty without mapped rules.
// Every value is checked by safeConfig before this is used.
func routeMap(prefix string, rules []proxy.Rule, backends map[string]proxy.Backend, callers bool) (string, []byte) {
	var b bytes.Buffer
	for _, r := range sortRules(rules) {
		if !mapped(r, backends[r.Backend]) {
			continue
		}
		key := r.Host
		if callers {
			key = proxy.BackendProject(r.Backend) + "/" + r.Host
		}
		fmt.Fprintf(&b, "%s %s\n", key, backendName(r.Backend))
	}
	if b.Len() == 0 {
		return "", nil
	}
	sum := sha256.Sum256(b.Bytes())
	return routeFilePrefix + prefix + "-" + hex.EncodeToString(sum[:8]) + ".map", b.Bytes()
}

// routeFiles returns the route maps a configuration needs, by file name.
func routeFiles(cfg proxy.Config, opts renderOptions) map[string][]byte {
	public, internal := splitRules(cfg)
	backends := map[string]proxy.Backend{}
	for _, be := range cfg.Backends {
		backends[be.Name] = be
	}
	out := map[string][]byte{}
	if name, content := routeMap(routesPublic, public, backends, false); name != "" {
		out[name] = content
	}
	if opts.InternalIP != "" {
		if name, content := routeMap(routesInternal, internal, backends, opts.checksCallers()); name != "" {
			out[name] = content
		}
	}
	return out
}

// write emits the routing of one frontend. Rules that need rules of their own
// get a route ID, prefix plus an index, and win over mapped ones; a mapped
// route's value is its backend.
func (rr ruleRenderer) write(prefix string, rules []proxy.Rule) {
	w := rr.w
	rules = sortRules(rules)
	var own, viaMap []proxy.Rule
	for _, r := range rules {
		if mapped(r, rr.backends[r.Backend]) {
			viaMap = append(viaMap, r)
		} else {
			own = append(own, r)
		}
	}
	for i, r := range own {
		// HAProxy evaluates AND before OR, so each alternative gets its own
		// line, all guarded by "no route chosen yet".
		set := fmt.Sprintf("    http-request set-var(txn.route) str(%s%d) if !{ var(txn.route) -m found } { var(txn.host) -m str %s }", prefix, i, r.Host)
		if rr.callers {
			set += fmt.Sprintf(" { var(txn.cproj) -m str %s }", proxy.BackendProject(r.Backend))
			if len(r.Allow) > 0 {
				set += fmt.Sprintf(" { var(txn.capp) -m str %s }", strings.Join(r.Allow, " "))
			}
		}
		if r.PathPrefix == "/" {
			w("%s", set)
			continue
		}
		w("%s { var(txn.path) -m str %s }", set, r.PathPrefix)
		w("%s { var(txn.path) -m beg %s/ }", set, r.PathPrefix)
	}
	if name, _ := routeMap(prefix, rules, rr.backends, rr.callers); name != "" {
		path := containerConfDir + "/" + name
		if rr.callers {
			// A caller this node does not know has no project, so no key and
			// no route.
			w("    http-request set-var(txn.rkey) var(txn.cproj),concat(/,txn.host) if !{ var(txn.route) -m found }")
			w("    http-request set-var(txn.route) var(txn.rkey),map(%s) if !{ var(txn.route) -m found }", path)
		} else {
			w("    http-request set-var(txn.route) var(txn.host),map(%s) if !{ var(txn.route) -m found }", path)
		}
	}
	// HAProxy runs every http-request rule before any use_backend rule,
	// whatever their order; writing them in that order keeps the file
	// honest.
	match := func(i int) string { return fmt.Sprintf("{ var(txn.route) -m str %s%d }", prefix, i) }
	matchMapped := func(r proxy.Rule) string { return fmt.Sprintf("{ var(txn.route) -m str %s }", backendName(r.Backend)) }
	for i, r := range own {
		if r.StripPrefix {
			w("    http-request set-path /%%[path,field(%d,/,0)] if %s", stripField(r.PathPrefix), match(i))
		}
		if localFirst(rr.backends[r.Backend], rr.node) {
			writeLocalLoad(w, match(i), r.Backend)
		}
	}
	for _, r := range viaMap {
		if localFirst(rr.backends[r.Backend], rr.node) {
			writeLocalLoad(w, matchMapped(r), r.Backend)
		}
	}
	for i, r := range own {
		be := rr.backends[r.Backend]
		if be.Wake {
			// No server up (scaled to zero, or starting): the request waits
			// at the agent, which starts a replica (ADR 0021).
			w("    use_backend %s if %s { nbsrv(%s) eq 0 }", wakeBackendName(r.Backend), match(i), backendName(r.Backend))
		}
		if localFirst(be, rr.node) {
			lo := localBackendName(r.Backend)
			w("    use_backend %s if %s { nbsrv(%s) gt 0 } { var(txn.lf_d) -m int le 0 }", lo, match(i), lo)
		}
		w("    use_backend %s if %s", backendName(r.Backend), match(i))
	}
	for _, r := range viaMap {
		if localFirst(rr.backends[r.Backend], rr.node) {
			lo := localBackendName(r.Backend)
			w("    use_backend %s if %s { nbsrv(%s) gt 0 } { var(txn.lf_d) -m int le 0 }", lo, matchMapped(r), lo)
		}
	}
	if len(viaMap) > 0 {
		w("    use_backend %%[var(txn.route)] if { var(txn.route) -m beg be_ }")
	}
}

// writeLocalLoad compares the load of an app's replicas on this node with
// that of all its replicas, for local-first routing (ADR 0024): a request
// goes to the replicas on this node while they are up and no busier, per
// replica, than the app's replicas overall. With L requests in progress on the N local replicas
// and R more on all M replicas through be_<app>, local wins while
// L/N <= (L+R)/M, compared as L*M - (L+R)*N <= 0 in integers. Only this
// proxy's own requests count. At low load every request stays on the node;
// under load the excess spreads over every replica. txn.lf_d holds the
// result.
func writeLocalLoad(w func(string, ...any), match, app string) {
	lo, be := localBackendName(app), backendName(app)
	w("    http-request set-var(txn.lf_l) be_conn(%s) if %s", lo, match)
	w("    http-request set-var(txn.lf_n) nbsrv(%s) if %s", lo, match)
	w("    http-request set-var(txn.lf_m) nbsrv(%s) if %s", be, match)
	w("    http-request set-var(txn.lf_all) be_conn(%s),add(txn.lf_l),mul(txn.lf_n) if %s", be, match)
	w("    http-request set-var(txn.lf_d) var(txn.lf_l),mul(txn.lf_m),sub(txn.lf_all) if %s", match)
}

func hostForBind(ip string) string {
	if strings.Contains(ip, ":") {
		return "[" + ip + "]"
	}
	return ip
}

// safeConfig checks every value render interpolates.
func safeConfig(cfg proxy.Config, opts renderOptions) bool {
	vals := []string{cfg.ACMEAddress, opts.PrivateIP, opts.InternalIP, opts.Subnet}
	for _, be := range cfg.Backends {
		vals = append(vals, be.Name, be.HealthPath)
		for _, s := range be.Servers {
			vals = append(vals, s.Name, s.Address)
		}
	}
	for _, r := range cfg.Rules {
		vals = append(vals, r.Host, r.PathPrefix, r.Backend)
		vals = append(vals, r.Allow...)
	}
	for _, c := range cfg.Certificates {
		vals = append(vals, c.Name)
	}
	for _, v := range vals {
		if !safeToken(v) {
			return false
		}
	}
	return true
}

// safeToken reports whether s can be interpolated as a single HAProxy token.
func safeToken(s string) bool {
	return !strings.ContainsFunc(s, func(r rune) bool {
		return r <= ' ' || r == 0x7f || unicode.IsSpace(r) || unicode.IsControl(r)
	})
}
