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

const settingsToken = "cf-token-7d1e4a"

func TestSetServerSettings(t *testing.T) {
	t.Parallel()
	c := newClockServer(t)
	keys, err := secrets.NewKeyring(bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	c.srv.keys = keys
	var restarts atomic.Int32
	c.srv.onSettings = func() { restarts.Add(1) }

	refuse := map[string]*armadav1.SetClusterConfigRequest{
		"http CA":            {Config: &armadav1.ClusterConfig{AcmeCa: "http://acme.local"}, SetAcmeCa: true},
		"unknown provider":   {Config: &armadav1.ClusterConfig{DnsProvider: "route66"}, SetDnsProvider: true},
		"provider, no token": {Config: &armadav1.ClusterConfig{DnsProvider: "cloudflare"}, SetDnsProvider: true},
		"short timeout":      {Config: &armadav1.ClusterConfig{NodeLostTimeoutSeconds: 3}, SetNodeLostTimeout: true},
		"bad port":           {Config: &armadav1.ClusterConfig{MetricsPort: 70000}, SetMetricsPort: true},
		"bad email":          {Config: &armadav1.ClusterConfig{AcmeEmail: "a b"}, SetAcmeEmail: true},
		"token with newline": {SetDnsToken: true, DnsToken: []byte("abc\ndef")},
	}
	for name, req := range refuse {
		if _, err := c.srv.SetClusterConfig(c.ctx, req); status.Code(err) != codes.InvalidArgument && status.Code(err) != codes.FailedPrecondition {
			t.Errorf("%s: %v", name, err)
		}
	}

	cc, err := c.srv.SetClusterConfig(c.ctx, &armadav1.SetClusterConfigRequest{
		Config:         &armadav1.ClusterConfig{DnsProvider: "cloudflare", AcmeEmail: "ops@example.org", NodeLostTimeoutSeconds: 120, MetricsPort: 9443},
		SetDnsProvider: true, SetDnsToken: true, DnsToken: []byte(" " + settingsToken + "\n"),
		SetAcmeEmail: true, SetNodeLostTimeout: true, SetMetricsPort: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !cc.DnsTokenSet {
		t.Error("the token is not reported as set")
	}
	set, err := LoadSettings(c.ctx, c.st)
	if err != nil {
		t.Fatal(err)
	}
	if set.DNSProvider != "cloudflare" || set.ACMEEmail != "ops@example.org" || set.NodeLostSeconds != 120 || *set.MetricsPort != 9443 {
		t.Errorf("stored %+v", set)
	}
	if v, ok, err := set.Token(keys); err != nil || !ok || string(v.Bytes()) != settingsToken {
		t.Errorf("token round trip: %v %v", ok, err)
	}
	if strings.Contains(string(set.DNSToken.Ciphertext), settingsToken) {
		t.Error("token stored in the clear")
	}
	audit, err := c.st.ListAudit(c.ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range audit {
		if strings.Contains(a.Detail, settingsToken) {
			t.Errorf("token in the audit log: %+v", a)
		}
	}
	// The leader restarts its term once the answer is out.
	deadline := time.Now().Add(2 * time.Second)
	for restarts.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if restarts.Load() != 1 {
		t.Errorf("term restarts = %d, want 1", restarts.Load())
	}

	// The root domain alone does not restart anything.
	if _, err := c.srv.SetClusterConfig(c.ctx, &armadav1.SetClusterConfigRequest{Config: &armadav1.ClusterConfig{RootDomain: "apps.example.org"}, SetRootDomain: true}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	if restarts.Load() != 1 {
		t.Errorf("root domain restarted the term")
	}
}
