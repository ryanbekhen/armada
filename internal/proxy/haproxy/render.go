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
	localFile        = "local.map"
	// routeFilePrefix starts the name of every route map.
	routeFilePrefix = "routes-"
	metricsPort     = MetricsPort
)

// MetricsPort is the HAProxy stats/metrics port on the node's private IP.
const MetricsPort = 8404

// Layout assigns replicas to fixed server slots per HAProxy backend. Slots let the Runtime API change servers without a reload; an
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

// pool is one HAProxy backend with server slots.
type pool struct {
	name    string
	servers []proxy.Server
	// leastconn balances by requests in progress instead of in turn.
	leastconn bool
	// timeout is how long a request waits for an answer, in seconds; 0 keeps
	// the default.
	timeout int
	// ipAllow and ipDeny are the backend's client address rules (ADR 0035).
	ipAllow, ipDeny []string
	// sticky keeps clients on one server with a cookie (ADR 0036).
	sticky bool
}

// Weights of a local-first backend (ADR 0024). HAProxy's leastconn picks the
// server with the fewest requests in progress for its weight, so a replica here
// takes at most a tenth more than a replica elsewhere under load. Idle servers
// tie whatever their weight; the local map decides those.
const (
	localWeight  = 11
	remoteWeight = 10
)

// localChoices is how many entries the local map holds per backend; requests
// to an idle app pick one at random, which spreads them over that many local
// replicas.
const localChoices = 4

// pools returns every slotted backend of cfg with the weights it has on this
// node.
func pools(cfg proxy.Config, n node) []pool {
	out := make([]pool, 0, len(cfg.Backends))
	for _, be := range cfg.Backends {
		out = append(out, backendPool(be, n))
	}
	return out
}

// backendPool returns be's backend on the node. Local-first needs the node's
// address; an app that splits traffic keeps its weights and takes turns.
func backendPool(be proxy.Backend, n node) pool {
	p := pool{name: backendName(be.Name), servers: be.Servers, timeout: be.TimeoutSeconds, ipAllow: be.IPAllow, ipDeny: be.IPDeny, sticky: be.Sticky}
	if !localFirst(be, n) {
		return p
	}
	p.leastconn = true
	p.servers = slices.Clone(be.Servers)
	for i, s := range p.servers {
		p.servers[i].Weight = remoteWeight
		if n.has(s.Address) {
			p.servers[i].Weight = localWeight
		}
	}
	return p
}

// localMap renders the local map: for each local-first backend with a replica
// on this node, localChoices "<backend>/<n> <slot>" lines that take the local
// slots in turn. The Runtime API replaces it, so an app's first replica on a
// node, and its last, need no reload. Every value is a backend name or a slot.
func localMap(cfg proxy.Config, layout Layout, n node) []byte {
	var b bytes.Buffer
	backends := slices.Clone(cfg.Backends)
	slices.SortFunc(backends, func(a, b proxy.Backend) int { return cmp.Compare(a.Name, b.Name) })
	for _, be := range backends {
		if !localFirst(be, n) {
			continue
		}
		addr := make(map[string]string, len(be.Servers))
		for _, s := range be.Servers {
			addr[s.Name] = s.Address
		}
		name := backendName(be.Name)
		var slots []string
		for i, sname := range layout[name] {
			if sname != "" && n.has(addr[sname]) {
				slots = append(slots, slotName(i))
			}
		}
		if len(slots) == 0 {
			continue
		}
		for i := range localChoices {
			fmt.Fprintf(&b, "%s/%d %s\n", name, i, slots[i%len(slots)])
		}
	}
	return b.Bytes()
}

// localFirst reports whether be prefers the replicas of the node.
func localFirst(be proxy.Backend, n node) bool { return be.LocalFirst && n.known() }

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
	// A reload leaves the old process serving its open connections. Long-lived
	// ones would keep it, and its memory, for as long as they last.
	w("    hard-stop-after 1h")
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
	// A WebSocket may stay silent far longer than a request may.
	w("    timeout tunnel 1h")
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
	// Only a trusted proxy may say who the client is. The proxy adds the
	// connection's own address to X-Forwarded-For after these rules.
	unless := ""
	if len(cfg.TrustedProxies) > 0 {
		w("    acl trusted_proxy src %s", strings.Join(cfg.TrustedProxies, " "))
		unless = " unless trusted_proxy"
	}
	for _, h := range proxy.ClientAddressHeaders {
		w("    http-request del-header %s%s", h, unless)
	}
	if hasIPRules(cfg) {
		writeClientAddress(w, cfg.TrustedProxies)
	}
	w("    http-request set-var(txn.host) req.hdr(host),field(1,:),lower")
	w("    http-request set-var(txn.path) path")

	public, internal := splitRules(cfg)
	backendsByName := map[string]proxy.Backend{}
	for _, be := range cfg.Backends {
		backendsByName[be.Name] = be
	}
	rr := ruleRenderer{w: w, backends: backendsByName}
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
		writeBackend(w, backendPool(be, opts.node()), be.HealthPath, layout)
		if be.Wake {
			w("backend %s", wakeBackendName(be.Name))
			// A refused client wakes nothing.
			writeIPRules(w, be.IPAllow, be.IPDeny)
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

// stickyCookie names a sticky backend's cookie: one per backend, so two
// sticky apps on one host keep their own, and from a hash, so the name
// says nothing about the app.
func stickyCookie(backend string) string {
	sum := sha256.Sum256([]byte(backend))
	return "armada_" + hex.EncodeToString(sum[:4])
}

// maxProxyHops is how many trusted proxies in a row the client's address is
// looked for behind (ADR 0035).
const maxProxyHops = 4

func hasIPRules(cfg proxy.Config) bool {
	for _, b := range cfg.Backends {
		if len(b.IPAllow) > 0 || len(b.IPDeny) > 0 {
			return true
		}
	}
	return false
}

// writeClientAddress sets txn.client, in the public frontend, to the address
// the backends' client address rules judge (ADR 0035), and txn.ext to say
// the request came from outside.
//
// The connection's own address is the client, unless the connection comes
// from a trusted proxy. Then it is the last address in X-Forwarded-For,
// which that proxy appended; addresses before it are whatever the client
// sent. If that one is a trusted proxy too, the one before it, and so on,
// for at most maxProxyHops. A trusted proxy that names no valid address, or
// only trusted proxies, leaves txn.client unset, and the rules refuse the
// request. No other header is read.
func writeClientAddress(w func(string, ...any), trusted []string) {
	w("    http-request set-var(txn.ext) bool(true)")
	w("    http-request set-var(txn.client) src")
	if len(trusted) == 0 {
		return
	}
	t := strings.Join(trusted, " ")
	w("    http-request unset-var(txn.client) if trusted_proxy")
	w("    http-request set-var(txn.client) req.hdr_ip(X-Forwarded-For,-1) if trusted_proxy")
	for hop := 2; hop <= maxProxyHops; hop++ {
		w("    http-request set-var(txn.client) req.hdr_ip(X-Forwarded-For,-%d) if trusted_proxy { var(txn.client) -m ip %s }", hop, t)
	}
	w("    http-request unset-var(txn.client) if trusted_proxy { var(txn.client) -m ip %s }", t)
}

// writeIPRules refuses requests from the public frontend whose client
// address the rules do not let through. Requests through the internal
// frontend have no txn.ext and pass: ingress.allow chooses internal callers.
func writeIPRules(w func(string, ...any), allow, deny []string) {
	switch {
	case len(allow) > 0:
		w("    http-request deny deny_status 403 if { var(txn.ext) -m bool } !{ var(txn.client) -m ip %s }", strings.Join(allow, " "))
	case len(deny) > 0:
		w("    http-request deny deny_status 403 if { var(txn.ext) -m bool } !{ var(txn.client) -m found }")
		w("    http-request deny deny_status 403 if { var(txn.ext) -m bool } { var(txn.client) -m ip %s }", strings.Join(deny, " "))
	}
}

// writeBackend emits one slotted backend.
func writeBackend(w func(string, ...any), p pool, healthPath string, layout Layout) {
	servers := map[string]proxy.Server{}
	for _, s := range p.servers {
		servers[s.Name] = s
	}
	w("backend %s", p.name)
	writeIPRules(w, p.ipAllow, p.ipDeny)
	if p.timeout > 0 {
		w("    timeout server %ds", p.timeout)
	}
	if p.leastconn {
		w("    balance leastconn")
		// With no other request in progress, a replica on this node. A name
		// the map does not have, or a server that is down, falls through to
		// balancing.
		w("    http-request set-var(txn.lk) rand(%d)", localChoices)
		w("    use-server %%[str(%s),concat(/,txn.lk),map(%s/%s)] if { be_conn le 1 }", p.name, containerConfDir, localFile)
	} else {
		w("    balance roundrobin")
	}
	cookie := ""
	if p.sticky {
		// The cookie names the slot, which says nothing about the replica;
		// a slot that is down or empty sends the client elsewhere
		// (option redispatch), and the next answer sets a new cookie.
		w("    cookie %s insert indirect nocache httponly secure attr \"SameSite=Lax\"", stickyCookie(p.name))
		cookie = " cookie "
	}
	if healthPath != "" {
		w("    option httpchk GET %s", healthPath)
		w("    http-check expect status 200-399")
	}
	// A dead node is out of rotation within about 4s.
	w("    default-server check inter 2s fall 2 rise 2")
	for i, sname := range layout[p.name] {
		c := ""
		if cookie != "" {
			c = cookie + slotName(i)
		}
		if s, ok := servers[sname]; ok && sname != "" && s.EffectiveWeight() != 1 {
			w("    server %s %s weight %d%s", slotName(i), s.Address, s.EffectiveWeight(), c)
		} else if ok && sname != "" {
			w("    server %s %s%s", slotName(i), s.Address, c)
		} else {
			w("    server %s 127.0.0.1:1 disabled%s", slotName(i), c)
		}
	}
	w("")
}

// ruleRenderer emits the routing of the frontends.
type ruleRenderer struct {
	w        func(string, ...any)
	backends map[string]proxy.Backend
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
	for i, r := range own {
		if r.StripPrefix {
			w("    http-request set-path /%%[path,field(%d,/,0)] if %s", stripField(r.PathPrefix), match(i))
		}
	}
	for i, r := range own {
		be := rr.backends[r.Backend]
		if be.Wake {
			// No server up (scaled to zero, or starting): the request waits
			// at the agent, which starts a replica (ADR 0021).
			w("    use_backend %s if %s { nbsrv(%s) eq 0 }", wakeBackendName(r.Backend), match(i), backendName(r.Backend))
		}
		w("    use_backend %s if %s", backendName(r.Backend), match(i))
	}
	if len(viaMap) > 0 {
		w("    use_backend %%[var(txn.route)] if { var(txn.route) -m beg be_ }")
	}
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
	vals = append(vals, cfg.TrustedProxies...)
	for _, be := range cfg.Backends {
		vals = append(vals, be.Name, be.HealthPath)
		vals = append(vals, be.IPAllow...)
		vals = append(vals, be.IPDeny...)
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
