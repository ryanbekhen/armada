package server

import (
	"context"
	"errors"
	"fmt"
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
const metaRootDomain = "root_domain"

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

	cfg := &proxy.Config{}
	var certNames []string
	wildcard := s.certs != nil && s.certs.SupportsWildcard() && root != ""
	if wildcard {
		certNames = append(certNames, "*."+root)
	}

	for _, app := range apps {
		sp := app.Spec
		if sp.Ingress == nil || sp.Ingress.Type == spec.IngressNone {
			continue
		}
		splits := len(app.Traffic) > 0 && !app.Rolling()
		// Traffic splitting keeps every replica in one pool so revision
		// weights hold; other apps prefer each node's own replicas.
		be := proxy.Backend{Name: app.Name, Wake: sp.ScalesToZero() && !app.Removing, LocalFirst: !splits}
		if sp.Probes != nil && sp.Probes.Readiness != nil {
			be.HealthPath = sp.Probes.Readiness.Path
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
				lb := proxy.Backend{Name: name, HealthPath: be.HealthPath}
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
			// <app>.<root> is covered by the wildcard certificate.
			coveredByWildcard := wildcard && strings.HasSuffix(h, "."+root) && strings.Count(h, ".") == strings.Count(root, ".")+1
			if !coveredByWildcard {
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
			if err := s.certs.Manage(ctx, certNames); err != nil {
				s.log.Error("certificate management failed", "err", err)
			} else {
				s.lastCertNames = certNames
			}
		}
		for _, n := range certNames {
			if pem, ok := s.certs.Certificate(ctx, n); ok {
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
	return &armadav1.ClusterConfig{RootDomain: s.rootDomain(ctx), AcmeEmail: s.acmeEmail}, nil
}

// SetClusterConfig updates cluster-wide settings. Only the root domain is
// settable at runtime; the ACME email is a server flag.
func (s *Server) SetClusterConfig(ctx context.Context, req *armadav1.SetClusterConfigRequest) (*armadav1.ClusterConfig, error) {
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
	s.Trigger()
	return s.GetClusterConfig(ctx, nil)
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
		_, out.TlsReady = s.certs.Certificate(ctx, d.Name)
	}
	return out
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

// appURLs lists the URLs of an app for status output: public ones, or the
// cluster-internal one for internal apps.
func (s *Server) appURLs(ctx context.Context, app store.App) []string {
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
	domains, err := s.store.ListDomains(ctx)
	if err != nil {
		return nil
	}
	verified := map[string]bool{}
	for _, d := range domains {
		verified[d.Name] = d.Verified
	}
	var urls []string
	for _, h := range appHosts(app, s.rootDomain(ctx), verified) {
		for _, r := range appRoutes(app.Spec) {
			urls = append(urls, "https://"+h+r.Path)
		}
	}
	return urls
}
