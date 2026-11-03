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
		be := proxy.Backend{Name: app.Name}
		if sp.Probes != nil && sp.Probes.Readiness != nil {
			be.HealthPath = sp.Probes.Readiness.Path
		}
		for _, r := range replicas {
			if !inProxy(app, r) {
				continue
			}
			// One bad address must not invalidate the configuration of the
			// whole cluster; reports are validated, this is a backstop.
			if err := (proxy.Config{Backends: []proxy.Backend{{Name: app.Name, Servers: []proxy.Server{{Name: r.ID, Address: r.Address}}}}}).Validate(); err != nil {
				s.log.Warn("leaving replica out of the proxy", "replica", r.ID, "err", err)
				continue
			}
			be.Servers = append(be.Servers, proxy.Server{Name: r.ID, Address: r.Address})
		}
		cfg.Backends = append(cfg.Backends, be)

		// Every app with an ingress port is reachable inside the cluster.
		for _, rt := range appRoutes(sp) {
			cfg.Rules = append(cfg.Rules, proxy.Rule{Host: spec.InternalHost(app.Name), PathPrefix: rt.Path, StripPrefix: rt.StripPrefix, Backend: app.Name, Internal: true})
		}
		if sp.Ingress.Type != spec.IngressExternal {
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
	resp := &armadav1.ListDomainsResponse{}
	for _, d := range domains {
		if req.GetApp() != "" && !slices.Contains(users[d.Name], req.GetApp()) {
			continue
		}
		resp.Domains = append(resp.Domains, s.domainProto(ctx, d, users[d.Name]))
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
