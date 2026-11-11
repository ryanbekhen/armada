package server

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/proxy"
	"github.com/ryanbekhen/armada/internal/spec"
	"github.com/ryanbekhen/armada/internal/store"
)

// Meta keys for cluster settings.
const (
	metaRootDomain     = "root_domain"
	metaTrustedProxies = "trusted_proxies"
)

// TXTPrefix is the label under which domain owners publish the verification
// token: TXT _armada-verify.<domain> = <token>.
const TXTPrefix = "_armada-verify."

// TXTResolver looks up DNS TXT records.
type TXTResolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

const defaultVerifyInterval = time.Minute

func (s *Server) rootDomain(ctx context.Context) string {
	v, err := s.store.GetMeta(ctx, metaRootDomain)
	if err != nil {
		return ""
	}
	return v
}

// appHosts returns the hostnames that route to an app: <app>.<root> and its
// verified custom domains.
func appHosts(app store.App, root string, verified map[string]bool) []string {
	var hosts []string
	if root != "" {
		h := app.Name + "." + root
		if spec.ValidateDomain(h) == nil {
			hosts = append(hosts, h)
		}
	}
	for _, d := range app.Spec.Ingress.Domains {
		if verified[d] {
			hosts = append(hosts, d)
		}
	}
	return hosts
}

func appRoutes(sp *spec.App) []spec.Route {
	if len(sp.Ingress.Routes) == 0 {
		return []spec.Route{{Path: "/"}}
	}
	return sp.Ingress.Routes
}

// allowedCallers turns an app's ingress.allow into the app IDs that may
// call it through its internal name, itself first; nil when it allows its
// whole project.
func allowedCallers(id string, names []string) []string {
	if len(names) == 0 {
		return nil
	}
	project, _, _ := spec.SplitAppID(id)
	out := []string{id}
	for _, n := range names {
		out = append(out, spec.AppID(project, n))
	}
	return out
}

// trustedProxies returns the prefixes set with SetClusterConfig. A record that
// no longer parses is an error rather than no proxies: taking them away would
// change every app's client addresses.
func (s *Server) trustedProxies(ctx context.Context) ([]string, error) {
	v, err := s.store.GetMeta(ctx, metaTrustedProxies)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if v == "" {
		return nil, nil
	}
	return proxy.ParseTrustedProxies(strings.Split(v, ","))
}

// buildProxy computes the ingress configuration shared by every node.
func (s *Server) buildProxy(ctx context.Context, apps []store.App, replicas []store.Replica) (*proxy.Config, error) {
	root := s.rootDomain(ctx)
	domains, err := s.store.ListDomains(ctx)
	if err != nil {
		return nil, err
	}
	verified := map[string]bool{}
	for _, d := range domains {
		if d.Verified {
			verified[d.Name] = true
		}
	}

	trusted, err := s.trustedProxies(ctx)
	if err != nil {
		return nil, err
	}
	cfg := &proxy.Config{TrustedProxies: trusted}
	var certNames []string
	wildcard := s.certs != nil && s.certs.SupportsWildcard() && root != ""
	if wildcard {
		certNames = append(certNames, "*."+root)
	}

	perApp := byApp(replicas)
	for _, app := range apps {
		sp := app.Spec
		if sp.Ingress == nil || sp.Ingress.Type == spec.IngressNone {
			continue
		}
		replicas := perApp[app.Name]
		splits := len(app.Traffic) > 0 && !app.Rolling()
		// Traffic splitting keeps every replica in one pool so revision
		// weights hold; other apps prefer each node's own replicas.
		// A sticky app keeps each client on one replica: local-first would
		// pick another one for it on each node.
		be := proxy.Backend{Name: app.Name, Wake: sp.ScalesToZero() && !app.Removing, LocalFirst: !splits && !sp.Ingress.Sticky,
			TimeoutSeconds: int(sp.Ingress.Timeout.D().Seconds()), Sticky: sp.Ingress.Sticky}
		if sp.Probes != nil && sp.Probes.Readiness != nil {
			be.HealthPath = sp.Probes.Readiness.Path
		}
		// Who may reach the app from outside (ADR 0035); internal callers
		// are chosen by ingress.allow.
		if sp.Ingress.Type == spec.IngressExternal {
			be.IPAllow, be.IPDeny = nilIfEmpty(spec.IPRanges(sp.Ingress.IPAllow)), nilIfEmpty(spec.IPRanges(sp.Ingress.IPDeny))
		}
		be.Servers = s.proxyServers(app, replicas, func(r store.Replica) bool { return inProxy(app, r) })
		if splits {
			weighServers(app, replicas, be.Servers)
		}
		cfg.Backends = append(cfg.Backends, be)

		// Every app with an ingress port is reachable inside the cluster,
		// by the apps of its project or the ones it allows (ADR 0026).
		allow := allowedCallers(app.Name, sp.Ingress.Allow)
		for _, rt := range appRoutes(sp) {
			cfg.Rules = append(cfg.Rules, proxy.Rule{Host: spec.InternalHost(app.Name), PathPrefix: rt.Path, StripPrefix: rt.StripPrefix, Backend: app.Name, Internal: true, Allow: allow})
		}

		// Each labelled revision has a backend of its own, served under
		// <label>--<app> (ADR 0022).
		external := sp.Ingress.Type == spec.IngressExternal
		if splits {
			for _, t := range app.Traffic {
				if t.Label == "" {
					continue
				}
				name := spec.LabelHost(t.Label, app.Name)
				lb := proxy.Backend{Name: name, HealthPath: be.HealthPath, TimeoutSeconds: be.TimeoutSeconds, IPAllow: be.IPAllow, IPDeny: be.IPDeny, Sticky: be.Sticky}
				lb.Servers = s.proxyServers(app, replicas, func(r store.Replica) bool {
					return r.App == app.Name && r.Revision == t.Revision && r.State == store.ReplicaRunning && r.Ready && !r.Draining() && r.Address != ""
				})
				cfg.Backends = append(cfg.Backends, lb)
				for _, rt := range appRoutes(sp) {
					cfg.Rules = append(cfg.Rules, proxy.Rule{Host: spec.InternalHost(name), PathPrefix: rt.Path, StripPrefix: rt.StripPrefix, Backend: name, Internal: true, Allow: allow})
				}
				// Labels serve under the root domain only, not custom domains.
				h := name + "." + root
				if !external || root == "" || spec.ValidateDomain(h) != nil {
					continue
				}
				for _, rt := range appRoutes(sp) {
					cfg.Rules = append(cfg.Rules, proxy.Rule{Host: h, PathPrefix: rt.Path, StripPrefix: rt.StripPrefix, Backend: name})
				}
				if !wildcard {
					certNames = append(certNames, h)
				}
			}
		}
		if !external {
			continue
		}
		for _, h := range appHosts(app, root, verified) {
			for _, rt := range appRoutes(sp) {
				cfg.Rules = append(cfg.Rules, proxy.Rule{Host: h, PathPrefix: rt.Path, StripPrefix: rt.StripPrefix, Backend: app.Name})
			}
			if !wildcard || !underWildcard(h, root) {
				certNames = append(certNames, h)
			}
		}
	}

	if s.certs != nil {
		s.certMu.Lock()
		defer s.certMu.Unlock()
		slices.Sort(certNames)
		certNames = slices.Compact(certNames)
		if !slices.Equal(certNames, s.lastCertNames) {
			if err := s.certs.Manage(ctx, certNames, root); err != nil {
				s.log.Error("certificate management failed", "err", err)
			} else {
				s.lastCertNames = certNames
			}
		}
		for _, n := range certNames {
			if pem, ok := s.certificate(ctx, n); ok {
				cfg.Certificates = append(cfg.Certificates, proxy.Certificate{Name: n, PEM: pem})
			}
		}
		cfg.ACMEAddress = s.acmeAddr
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("generated proxy config is invalid: %w", err)
	}
	return cfg, nil
}

// labelURLs returns the URLs a revision label serves under (ADR 0022).
func (s *Server) labelURLs(ctx context.Context, app store.App, label string) []string {
	if label == "" || app.Rolling() || app.Spec.Ingress == nil {
		return nil
	}
	// Like appURLs: public apps show their public URLs.
	name := spec.LabelHost(label, app.Name)
	prefix := "http://" + spec.InternalHost(name)
	if app.Spec.Ingress.Type == spec.IngressExternal {
		root := s.rootDomain(ctx)
		if root == "" || spec.ValidateDomain(name+"."+root) != nil {
			return nil
		}
		prefix = "https://" + name + "." + root
	}
	var urls []string
	for _, r := range appRoutes(app.Spec) {
		urls = append(urls, prefix+r.Path)
	}
	return urls
}

// proxyServers returns the servers of app's replicas that pass keep.
func (s *Server) proxyServers(app store.App, replicas []store.Replica, keep func(store.Replica) bool) []proxy.Server {
	var out []proxy.Server
	for _, r := range replicas {
		if !keep(r) {
			continue
		}
		// One bad address must not invalidate the configuration of the
		// whole cluster; reports are validated, this is a backstop.
		if err := (proxy.Config{Backends: []proxy.Backend{{Name: app.Name, Servers: []proxy.Server{{Name: r.ID, Address: r.Address}}}}}).Validate(); err != nil {
			s.log.Warn("leaving replica out of the proxy", "replica", r.ID, "err", err)
			continue
		}
		out = append(out, proxy.Server{Name: r.ID, Address: r.Address})
	}
	return out
}

// weighServers gives each server its revision's weight divided among the
// revision's servers, scaled to the proxy's weight range, so each revision
// gets its share of requests whatever its replica count (ADR 0022). A
// revision with no server up has no share: its requests go to the others.
func weighServers(app store.App, replicas []store.Replica, servers []proxy.Server) {
	revOf := map[string]string{}
	for _, r := range replicas {
		revOf[r.ID] = r.Revision
	}
	count := map[string]int{}
	for _, sv := range servers {
		count[revOf[sv.Name]]++
	}
	for i, sv := range servers {
		rev := revOf[sv.Name]
		w := trafficWeight(app, rev)
		servers[i].Weight = max(1, (w*proxy.MaxWeight+50*count[rev])/(100*count[rev]))
	}
}

// verifyDomain checks the TXT record for d and records the result.
func (s *Server) verifyDomain(ctx context.Context, d store.Domain) (store.Domain, error) {
	if d.Verified {
		return d, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	records, err := s.resolver.LookupTXT(ctx, TXTPrefix+d.Name)
	ok := false
	for _, r := range records {
		if strings.TrimSpace(r) == d.Token {
			ok = true
		}
	}
	msg := ""
	switch {
	case ok:
	case err != nil || len(records) == 0:
		msg = "TXT record " + TXTPrefix + d.Name + " not found"
	default:
		msg = "TXT record " + TXTPrefix + d.Name + " does not contain the expected token"
	}
	if err := s.store.SetDomainVerification(context.WithoutCancel(ctx), d.Name, ok, msg); err != nil {
		return d, err
	}
	if ok {
		s.log.Info("domain verified", "domain", d.Name)
		s.record(ctx, store.Event{Kind: eventDomain, Object: d.Name, Reason: "Verified"})
		s.Trigger()
	}
	s.condition(ctx, "domain-unverified:"+d.Name, !ok, store.Event{Kind: eventDomain, Object: d.Name, Reason: "NotVerified", Message: msg})
	return s.store.GetDomain(context.WithoutCancel(ctx), d.Name)
}

func (s *Server) verifyLoop(ctx context.Context) {
	t := time.NewTicker(s.verifyInterval)
	defer t.Stop()
	for {
		domains, err := s.store.ListDomains(ctx)
		if err == nil {
			for _, d := range domains {
				if !d.Verified {
					if _, err := s.verifyDomain(ctx, d); err != nil && ctx.Err() == nil {
						s.log.Warn("domain verification failed", "domain", d.Name, "err", err)
					}
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// GetClusterConfig returns cluster-wide settings.
func (s *Server) GetClusterConfig(ctx context.Context, _ *armadav1.GetClusterConfigRequest) (*armadav1.ClusterConfig, error) {
	trusted, err := s.trustedProxies(ctx)
	if err != nil {
		return nil, storeErr(err)
	}
	set, err := LoadSettings(ctx, s.store)
	if err != nil {
		return nil, storeErr(err)
	}
	cc := &armadav1.ClusterConfig{
		RootDomain: s.rootDomain(ctx), AcmeEmail: s.acmeEmail, TrustedProxies: trusted,
		Tls: s.certs != nil, AcmeCa: s.acmeCA, DnsProvider: s.dnsProvider, DnsTokenSet: set.DNSToken != nil,
		NodeLostTimeoutSeconds: int64(s.nodeLostTimeout / time.Second),
	}
	if ap, err := netip.ParseAddrPort(s.metricsAddr); err == nil {
		cc.MetricsPort = int32(ap.Port())
	}
	return cc, nil
}

// SetClusterConfig updates the cluster-wide settings the request names: the
// root domain and the trusted proxies apply at once; the server settings
// (ADR 0031) are stored and the leader restarts its term to apply them.
func (s *Server) SetClusterConfig(ctx context.Context, req *armadav1.SetClusterConfigRequest) (*armadav1.ClusterConfig, error) {
	if req.GetSetRootDomain() {
		root := strings.ToLower(strings.TrimSpace(req.GetConfig().GetRootDomain()))
		if root != "" {
			if err := spec.ValidateDomain(root); err != nil {
				return nil, status.Errorf(codes.InvalidArgument, "root domain: %v", err)
			}
		}
		if err := s.store.SetMeta(ctx, metaRootDomain, root); err != nil {
			return nil, storeErr(err)
		}
		if err := s.store.RecordAudit(ctx, actor(ctx), "cluster.root_domain", "cluster", root); err != nil {
			return nil, storeErr(err)
		}
		s.log.Info("root domain changed", "root_domain", root, "by", actor(ctx))
	}
	if req.GetSetTrustedProxies() {
		trusted, err := proxy.ParseTrustedProxies(req.GetConfig().GetTrustedProxies())
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
		list := strings.Join(trusted, ",")
		if err := s.store.SetMeta(ctx, metaTrustedProxies, list); err != nil {
			return nil, storeErr(err)
		}
		if err := s.store.RecordAudit(ctx, actor(ctx), "cluster.trusted_proxies", "cluster", list); err != nil {
			return nil, storeErr(err)
		}
		s.log.Info("trusted proxies changed", "trusted_proxies", list, "by", actor(ctx))
	}
	changed, err := s.setSettings(ctx, req)
	if err != nil {
		return nil, err
	}
	s.Trigger()
	cc, err := s.GetClusterConfig(ctx, nil)
	if err == nil && changed && s.onSettings != nil {
		// After this answer: the term ends with the API it serves.
		time.AfterFunc(300*time.Millisecond, s.onSettings)
	}
	return cc, err
}

// setSettings validates and stores the server settings the request names.
// It reports whether anything changed; the token is never logged.
func (s *Server) setSettings(ctx context.Context, req *armadav1.SetClusterConfigRequest) (bool, error) {
	c := req.GetConfig()
	settings := req.GetSetTls() || req.GetSetAcmeEmail() || req.GetSetAcmeCa() || req.GetSetDnsProvider() ||
		req.GetSetMetricsPort() || req.GetSetNodeLostTimeout() || req.GetSetDnsToken()
	if !settings {
		return false, nil
	}
	set, err := LoadSettings(ctx, s.store)
	if err != nil {
		return false, storeErr(err)
	}
	var what []string
	if req.GetSetTls() {
		on := c.GetTls()
		set.TLS = &on
		what = append(what, fmt.Sprintf("tls=%t", on))
	}
	if req.GetSetAcmeEmail() {
		email := strings.TrimSpace(c.GetAcmeEmail())
		if err := CheckEmail(email); err != nil {
			return false, status.Error(codes.InvalidArgument, err.Error())
		}
		set.ACMEEmail = email
		what = append(what, "acme_email="+email)
	}
	if req.GetSetAcmeCa() {
		if err := CheckACMECA(c.GetAcmeCa()); err != nil {
			return false, status.Error(codes.InvalidArgument, err.Error())
		}
		set.ACMECA = c.GetAcmeCa()
		what = append(what, "acme_ca="+c.GetAcmeCa())
	}
	if req.GetSetDnsProvider() {
		p := c.GetDnsProvider()
		if p == "none" {
			p = ""
		}
		if err := CheckDNSProvider(p); err != nil {
			return false, status.Error(codes.InvalidArgument, err.Error())
		}
		set.DNSProvider, set.DNSProviderSet = p, true
		what = append(what, "dns_provider="+cmp.Or(p, "none"))
	}
	if req.GetSetDnsToken() {
		if s.keys == nil {
			return false, status.Error(codes.FailedPrecondition, "this server has no master key to encrypt the token with")
		}
		token := []byte(strings.TrimSpace(string(req.GetDnsToken())))
		if err := CheckDNSToken(token); err != nil {
			return false, status.Error(codes.InvalidArgument, err.Error())
		}
		if err := set.SealToken(s.keys, token); err != nil {
			return false, status.Error(codes.Internal, "seal the DNS token")
		}
		what = append(what, "dns_token")
	}
	if req.GetSetMetricsPort() {
		port := int(c.GetMetricsPort())
		if port < 0 || port > 65535 {
			return false, status.Error(codes.InvalidArgument, "metrics port must be between 0 (off) and 65535")
		}
		set.MetricsPort = &port
		what = append(what, fmt.Sprintf("metrics_port=%d", port))
	}
	if req.GetSetNodeLostTimeout() {
		d := time.Duration(c.GetNodeLostTimeoutSeconds()) * time.Second
		if err := CheckNodeLostTimeout(d); err != nil {
			return false, status.Error(codes.InvalidArgument, err.Error())
		}
		set.NodeLostSeconds = c.GetNodeLostTimeoutSeconds()
		what = append(what, "node_lost_timeout="+d.String())
	}
	if set.DNSProvider != "" && set.DNSToken == nil {
		return false, status.Errorf(codes.FailedPrecondition, "DNS provider %s needs a token: armada cluster set --dns-token - < FILE", set.DNSProvider)
	}
	if err := SaveSettings(ctx, s.store, set); err != nil {
		return false, storeErr(err)
	}
	detail := strings.Join(what, " ")
	if err := s.store.RecordAudit(ctx, actor(ctx), "cluster.settings", "cluster", detail); err != nil {
		return false, storeErr(err)
	}
	s.log.Info("cluster settings changed", "changed", detail, "by", actor(ctx))
	return true, nil
}

// ListDomains returns custom domains with what their owners must configure.
func (s *Server) ListDomains(ctx context.Context, req *armadav1.ListDomainsRequest) (*armadav1.ListDomainsResponse, error) {
	apps, err := s.store.ListApps(ctx)
	if err != nil {
		return nil, storeErr(err)
	}
	// A rolling app uses the domains of both its active and target spec;
	// owners need the TXT record of a new domain before the rollout ends.
	users := map[string][]string{}
	for _, a := range apps {
		specs := []*spec.App{a.Spec}
		if a.TargetRevision != a.ActiveRevision {
			if rev, err := s.store.GetRevision(ctx, a.TargetRevision); err == nil {
				specs = append(specs, rev.Spec)
			}
		}
		for _, sp := range specs {
			if sp.Ingress == nil {
				continue
			}
			for _, d := range sp.Ingress.Domains {
				if !slices.Contains(users[d], a.Name) {
					users[d] = append(users[d], a.Name)
				}
			}
		}
	}
	domains, err := s.store.ListDomains(ctx)
	if err != nil {
		return nil, storeErr(err)
	}
	acc := accessFrom(ctx)
	if req.GetApp() != "" {
		if err := acc.app(req.GetApp()); err != nil {
			return nil, err
		}
	}
	resp := &armadav1.ListDomainsResponse{}
	for _, d := range domains {
		if req.GetApp() != "" && !slices.Contains(users[d.Name], req.GetApp()) {
			continue
		}
		// Others see a domain only through the apps of theirs that use it.
		apps := slices.DeleteFunc(slices.Clone(users[d.Name]), func(a string) bool { return !acc.sees(a) })
		if len(apps) == 0 && !acc.admin() {
			continue
		}
		if acc.admin() {
			apps = users[d.Name]
		}
		resp.Domains = append(resp.Domains, s.domainProto(ctx, d, apps))
	}
	return resp, nil
}

func (s *Server) domainProto(ctx context.Context, d store.Domain, apps []string) *armadav1.Domain {
	out := &armadav1.Domain{
		Name: d.Name, Apps: apps, Verified: d.Verified,
		TxtName: TXTPrefix + d.Name, TxtValue: d.Token, Message: d.Message,
	}
	if s.certs != nil && d.Verified {
		name := d.Name
		// A domain one label under the root domain is served with the
		// wildcard certificate, like <app>.<root> (buildProxy).
		if root := s.rootDomain(ctx); s.certs.SupportsWildcard() && root != "" && underWildcard(name, root) {
			name = "*." + root
		}
		_, out.TlsReady = s.certs.Certificate(ctx, name)
	}
	return out
}

// underWildcard reports whether host is exactly one label under root, so the
// certificate for *.root covers it.
func underWildcard(host, root string) bool {
	label, ok := strings.CutSuffix(host, "."+root)
	return ok && label != "" && !strings.Contains(label, ".")
}

// VerifyDomain checks a domain's TXT record now.
func (s *Server) VerifyDomain(ctx context.Context, req *armadav1.VerifyDomainRequest) (*armadav1.Domain, error) {
	if !accessFrom(ctx).admin() {
		// Only a domain one of the caller's apps uses.
		resp, err := s.ListDomains(ctx, &armadav1.ListDomainsRequest{})
		if err != nil {
			return nil, err
		}
		if !slices.ContainsFunc(resp.Domains, func(d *armadav1.Domain) bool { return d.Name == req.GetName() }) {
			return nil, status.Errorf(codes.PermissionDenied, "%s may not verify %s", accessFrom(ctx).id, req.GetName())
		}
	}
	d, err := s.store.GetDomain(ctx, req.GetName())
	if err != nil {
		return nil, storeErr(err)
	}
	d, err = s.verifyDomain(ctx, d)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, storeErr(err)
		}
		return nil, status.Error(codes.Internal, "verification failed")
	}
	resp, err := s.ListDomains(ctx, &armadav1.ListDomainsRequest{})
	if err != nil {
		return nil, err
	}
	for _, x := range resp.Domains {
		if x.Name == d.Name {
			return x, nil
		}
	}
	return s.domainProto(ctx, d, nil), nil
}

// urlSources are what an app's URLs depend on beyond the app: read once for
// many apps.
type urlSources struct {
	root     string
	verified map[string]bool
}

// urlSource reads the root domain and the verified domains.
func (s *Server) urlSource(ctx context.Context) urlSources {
	src := urlSources{root: s.rootDomain(ctx), verified: map[string]bool{}}
	if domains, err := s.store.ListDomains(ctx); err == nil {
		for _, d := range domains {
			src.verified[d.Name] = d.Verified
		}
	}
	return src
}

// appURLsFrom lists app's URLs.
func appURLsFrom(app store.App, src urlSources) []string {
	if app.Spec.Ingress == nil || app.Spec.Ingress.Type == spec.IngressNone {
		return nil
	}
	if app.Spec.Ingress.Type == spec.IngressInternal {
		var urls []string
		for _, r := range appRoutes(app.Spec) {
			urls = append(urls, "http://"+spec.InternalHost(app.Name)+r.Path)
		}
		return urls
	}
	var urls []string
	for _, h := range appHosts(app, src.root, src.verified) {
		for _, r := range appRoutes(app.Spec) {
			urls = append(urls, "https://"+h+r.Path)
		}
	}
	return urls
}

// maxCertificateNames bounds one GetCertificates call.
const maxCertificateNames = 256

// GetCertificates hands an agent the proxy certificates its assignment
// names by reference. Only node certificates reach it (AgentService), and
// only names the last proxy configuration holds are answered: every node
// serves every one of them.
func (s *Server) GetCertificates(ctx context.Context, req *armadav1.GetCertificatesRequest) (*armadav1.GetCertificatesResponse, error) {
	names := req.GetNames()
	if len(names) > maxCertificateNames {
		return nil, status.Errorf(codes.InvalidArgument, "at most %d names per call", maxCertificateNames)
	}
	resp := &armadav1.GetCertificatesResponse{}
	if s.certs == nil {
		return resp, nil
	}
	s.certMu.Lock()
	served := s.servedCerts
	s.certMu.Unlock()
	seen := map[string]bool{}
	for _, n := range names {
		if seen[n] || !served[n] {
			continue
		}
		seen[n] = true
		if pem, ok := s.certificate(ctx, n); ok {
			resp.Certificates = append(resp.Certificates, &armadav1.ProxyCertificate{Name: n, Pem: pem})
		}
	}
	return resp, nil
}

// certificate returns the certificate for name, read from the certificate
// manager's storage once and then kept until the manager obtains it again
// (CertificateEvent): a reconcile pass needs every certificate of the
// cluster, and each read costs round trips to etcd.
func (s *Server) certificate(ctx context.Context, name string) ([]byte, bool) {
	s.pemMu.Lock()
	pem, ok := s.pems[name]
	s.pemMu.Unlock()
	if ok {
		return pem, true
	}
	pem, ok = s.certs.Certificate(ctx, name)
	if ok {
		s.pemMu.Lock()
		if s.pems == nil {
			s.pems = map[string][]byte{}
		}
		s.pems[name] = pem
		s.pemMu.Unlock()
	}
	return pem, ok
}

// forgetCertificate drops the kept certificate for name.
func (s *Server) forgetCertificate(name string) {
	s.pemMu.Lock()
	delete(s.pems, name)
	s.pemMu.Unlock()
}

func nilIfEmpty(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return s
}
