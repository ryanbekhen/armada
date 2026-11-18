package server

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/spec"
)

// MaxDNSZones bounds the zones with credentials of their own (ADR 0047).
const MaxDNSZones = 64

// CheckDNSZone canonicalizes a zone name: a valid domain name in lower case,
// no wildcard, no trailing dot, at least two labels.
func CheckDNSZone(zone string) (string, error) {
	z := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(zone), "."))
	if strings.HasPrefix(z, "*.") {
		return "", fmt.Errorf("zone %q: name the zone, not a wildcard", zone)
	}
	if err := spec.ValidateDomain(z); err != nil {
		return "", fmt.Errorf("zone %q: %w", zone, err)
	}
	return z, nil
}

// SetDNSZone creates or replaces a zone's DNS credentials. The token is
// sealed with the master key, audited without its value, and the leader
// restarts its control plane with it, like the cluster's DNS provider.
func (s *Server) SetDNSZone(ctx context.Context, req *armadav1.SetDNSZoneRequest) (*armadav1.ClusterConfig, error) {
	zone, err := CheckDNSZone(req.GetZone())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	provider := req.GetProvider()
	if provider == "" || provider == "none" {
		return nil, status.Error(codes.InvalidArgument, "a DNS zone needs a provider: cloudflare")
	}
	if err := CheckDNSProvider(provider); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	token := []byte(strings.TrimSpace(string(req.GetToken())))
	if len(token) == 0 {
		return nil, status.Error(codes.InvalidArgument, "a DNS zone needs its provider's API token")
	}
	if err := CheckDNSToken(token); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if s.keys == nil {
		return nil, status.Error(codes.FailedPrecondition, "this server has no master key to encrypt the token with")
	}

	s.settingsMu.Lock()
	set, err := LoadSettings(ctx, s.store)
	if err != nil {
		s.settingsMu.Unlock()
		return nil, storeErr(err)
	}
	i := slices.IndexFunc(set.DNSZones, func(z DNSZone) bool { return z.Zone == zone })
	switch {
	case i >= 0 && req.GetMustCreate():
		s.settingsMu.Unlock()
		return nil, status.Errorf(codes.AlreadyExists, "DNS zone %s exists; change it with armada cluster dns update", zone)
	case i < 0 && req.GetMustExist():
		s.settingsMu.Unlock()
		return nil, status.Errorf(codes.NotFound, "DNS zone %s does not exist", zone)
	case i < 0 && len(set.DNSZones) >= MaxDNSZones:
		s.settingsMu.Unlock()
		return nil, status.Errorf(codes.ResourceExhausted, "at most %d DNS zones", MaxDNSZones)
	}
	z := DNSZone{Zone: zone, Provider: provider}
	if err := set.SealZoneToken(s.keys, &z, token); err != nil {
		s.settingsMu.Unlock()
		return nil, status.Error(codes.Internal, "seal the DNS zone's token")
	}
	if i >= 0 {
		set.DNSZones[i] = z
	} else {
		set.DNSZones = append(set.DNSZones, z)
		slices.SortFunc(set.DNSZones, func(a, b DNSZone) int { return strings.Compare(a.Zone, b.Zone) })
	}
	err = SaveSettings(ctx, s.store, set)
	s.settingsMu.Unlock()
	if err != nil {
		return nil, storeErr(err)
	}
	return s.dnsZonesChanged(ctx, "cluster.dns_zone", zone+" provider="+provider)
}

// DeleteDNSZone removes a zone's credentials; its names go back to the root
// domain's provider or HTTP-01.
func (s *Server) DeleteDNSZone(ctx context.Context, req *armadav1.DeleteDNSZoneRequest) (*armadav1.ClusterConfig, error) {
	zone, err := CheckDNSZone(req.GetZone())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	s.settingsMu.Lock()
	set, err := LoadSettings(ctx, s.store)
	if err != nil {
		s.settingsMu.Unlock()
		return nil, storeErr(err)
	}
	i := slices.IndexFunc(set.DNSZones, func(z DNSZone) bool { return z.Zone == zone })
	if i < 0 {
		s.settingsMu.Unlock()
		return nil, status.Errorf(codes.NotFound, "DNS zone %s does not exist", zone)
	}
	set.DNSZones = slices.Delete(set.DNSZones, i, i+1)
	err = SaveSettings(ctx, s.store, set)
	s.settingsMu.Unlock()
	if err != nil {
		return nil, storeErr(err)
	}
	return s.dnsZonesChanged(ctx, "cluster.dns_zone_delete", zone)
}

// dnsZonesChanged audits a change of the zones (never a token) and has the
// leader restart its control plane with them after answering.
func (s *Server) dnsZonesChanged(ctx context.Context, action, detail string) (*armadav1.ClusterConfig, error) {
	if err := s.store.RecordAudit(ctx, actor(ctx), action, "cluster", detail); err != nil {
		return nil, storeErr(err)
	}
	s.log.Info("DNS zones changed", "action", action, "detail", detail, "by", actor(ctx))
	cc, err := s.GetClusterConfig(ctx, nil)
	if err == nil && s.onSettings != nil {
		time.AfterFunc(300*time.Millisecond, s.onSettings)
	}
	return cc, err
}

// dnsZonesProto lists the stored zones without their tokens.
func dnsZonesProto(set Settings) []*armadav1.DNSZone {
	out := make([]*armadav1.DNSZone, 0, len(set.DNSZones))
	for _, z := range set.DNSZones {
		out = append(out, &armadav1.DNSZone{Zone: z.Zone, Provider: z.Provider})
	}
	return out
}
