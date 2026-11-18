package server

import (
	"bytes"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/secrets"
)

// DNS zones (ADR 0047) keep each zone's token sealed under its own name and a
// version never used before, audit without it, list without it, and restart
// the leader's term like the DNS provider.
func TestDNSZones(t *testing.T) {
	t.Parallel()
	c := newClockServer(t)
	keys, err := secrets.NewKeyring(bytes.Repeat([]byte{5}, 32))
	if err != nil {
		t.Fatal(err)
	}
	c.srv.keys = keys
	var restarts atomic.Int32
	c.srv.onSettings = func() { restarts.Add(1) }
	set := func(zone, token string, create bool) (*armadav1.ClusterConfig, error) {
		return c.srv.SetDNSZone(c.ctx, &armadav1.SetDNSZoneRequest{Zone: zone, Provider: "cloudflare", Token: []byte(token), MustCreate: create, MustExist: !create})
	}

	refuse := map[string]*armadav1.SetDNSZoneRequest{
		"wildcard":          {Zone: "*.shop.net", Provider: "cloudflare", Token: []byte("t")},
		"one label":         {Zone: "shop", Provider: "cloudflare", Token: []byte("t")},
		"bad name":          {Zone: "shop..net", Provider: "cloudflare", Token: []byte("t")},
		"no provider":       {Zone: "shop.net", Token: []byte("t")},
		"none":              {Zone: "shop.net", Provider: "none", Token: []byte("t")},
		"unknown provider":  {Zone: "shop.net", Provider: "route66", Token: []byte("t")},
		"no token":          {Zone: "shop.net", Provider: "cloudflare"},
		"token with a line": {Zone: "shop.net", Provider: "cloudflare", Token: []byte("a\nb")},
	}
	for name, req := range refuse {
		if _, err := c.srv.SetDNSZone(c.ctx, req); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := set("shop.net", "tok-1", false); status.Code(err) != codes.NotFound {
		t.Errorf("update of a missing zone: %v", err)
	}

	cc, err := set("Shop.NET.", " zone-token-a1\n", true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := set("eu.shop.net", "zone-token-b2", true); err != nil {
		t.Fatal(err)
	}
	if _, err := set("shop.net", "zone-token-a1", true); status.Code(err) != codes.AlreadyExists {
		t.Errorf("second create: %v", err)
	}
	if len(cc.DnsZones) != 1 || cc.DnsZones[0].Zone != "shop.net" || cc.DnsZones[0].Provider != "cloudflare" {
		t.Errorf("zones = %v", cc.DnsZones)
	}

	st, err := LoadSettings(c.ctx, c.st)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.DNSZones) != 2 || st.DNSZones[0].Zone != "eu.shop.net" || st.DNSZones[1].Zone != "shop.net" {
		t.Fatalf("stored zones = %+v", st.DNSZones)
	}
	if v, err := st.DNSZones[1].ZoneToken(keys); err != nil || string(v.Bytes()) != "zone-token-a1" {
		t.Errorf("shop.net token: %v", err)
	}
	// A token sealed for one zone does not open as another's.
	swapped := st.DNSZones[0]
	swapped.Token = st.DNSZones[1].Token
	if _, err := swapped.ZoneToken(keys); err == nil {
		t.Error("one zone's token opened as another zone's")
	}

	// Replacing, deleting, and creating again never reuse a version.
	if _, err := set("shop.net", "zone-token-a2", false); err != nil {
		t.Fatal(err)
	}
	if _, err := c.srv.DeleteDNSZone(c.ctx, &armadav1.DeleteDNSZoneRequest{Zone: "shop.net"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.srv.DeleteDNSZone(c.ctx, &armadav1.DeleteDNSZoneRequest{Zone: "shop.net"}); status.Code(err) != codes.NotFound {
		t.Errorf("second delete: %v", err)
	}
	if _, err := set("shop.net", "zone-token-a3", true); err != nil {
		t.Fatal(err)
	}
	st, _ = LoadSettings(c.ctx, c.st)
	if st.DNSZoneSeq != 4 || st.DNSZones[1].Version != 4 || st.DNSZones[0].Version != 2 {
		t.Errorf("versions: seq %d, zones %+v", st.DNSZoneSeq, st.DNSZones)
	}

	cfg, err := c.srv.GetClusterConfig(c.ctx, nil)
	if err != nil || len(cfg.DnsZones) != 2 {
		t.Errorf("cluster config zones = %v, %v", cfg.GetDnsZones(), err)
	}
	audit, err := c.st.ListAudit(c.ctx, 20)
	if err != nil {
		t.Fatal(err)
	}
	actions := 0
	for _, a := range audit {
		if strings.Contains(a.Detail, "zone-token") {
			t.Errorf("token in the audit log: %+v", a)
		}
		if strings.HasPrefix(a.Action, "cluster.dns_zone") {
			actions++
		}
	}
	if actions != 5 {
		t.Errorf("audited %d zone changes, want 5", actions)
	}
	deadline := time.Now().Add(2 * time.Second)
	for restarts.Load() < 5 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if restarts.Load() != 5 {
		t.Errorf("term restarts = %d, want 5", restarts.Load())
	}

	// A zone change keeps the other settings, and a settings change keeps
	// the zones.
	if _, err := c.srv.SetClusterConfig(c.ctx, &armadav1.SetClusterConfigRequest{Config: &armadav1.ClusterConfig{AcmeEmail: "ops@shop.net"}, SetAcmeEmail: true}); err != nil {
		t.Fatal(err)
	}
	st, _ = LoadSettings(c.ctx, c.st)
	if len(st.DNSZones) != 2 || st.ACMEEmail != "ops@shop.net" {
		t.Errorf("settings after both changes: %+v", st)
	}
}

// At most MaxDNSZones zones.
func TestDNSZoneLimit(t *testing.T) {
	t.Parallel()
	c := newClockServer(t)
	keys, err := secrets.NewKeyring(bytes.Repeat([]byte{6}, 32))
	if err != nil {
		t.Fatal(err)
	}
	c.srv.keys = keys
	st, _ := LoadSettings(c.ctx, c.st)
	for i := range MaxDNSZones {
		z := DNSZone{Zone: "z" + strings.Repeat("a", i%5) + string(rune('a'+i%26)) + ".net", Provider: "cloudflare"}
		st.DNSZones = append(st.DNSZones, z)
	}
	if err := SaveSettings(c.ctx, c.st, st); err != nil {
		t.Fatal(err)
	}
	_, err = c.srv.SetDNSZone(c.ctx, &armadav1.SetDNSZoneRequest{Zone: "one-more.net", Provider: "cloudflare", Token: []byte("t")})
	if status.Code(err) != codes.ResourceExhausted {
		t.Errorf("zone past the limit: %v", err)
	}
}
