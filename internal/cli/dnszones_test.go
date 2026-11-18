package cli

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
)

// dnsFake records the zone requests the commands send.
type dnsFake struct {
	*fakeAdmin
	sets    []*armadav1.SetDNSZoneRequest
	deletes []string
}

func (f *dnsFake) SetDNSZone(_ context.Context, in *armadav1.SetDNSZoneRequest, _ ...grpc.CallOption) (*armadav1.ClusterConfig, error) {
	f.sets = append(f.sets, in)
	return &armadav1.ClusterConfig{}, nil
}

func (f *dnsFake) DeleteDNSZone(_ context.Context, in *armadav1.DeleteDNSZoneRequest, _ ...grpc.CallOption) (*armadav1.ClusterConfig, error) {
	f.deletes = append(f.deletes, in.Zone)
	return &armadav1.ClusterConfig{}, nil
}

func (f *dnsFake) GetClusterConfig(context.Context, *armadav1.GetClusterConfigRequest, ...grpc.CallOption) (*armadav1.ClusterConfig, error) {
	return &armadav1.ClusterConfig{DnsZones: []*armadav1.DNSZone{{Zone: "shop.net", Provider: "cloudflare"}}}, nil
}

// Zone tokens come from a file (or stdin), never an argument; create and
// update say which they mean; the list never shows a token.
func TestDNSZoneCommands(t *testing.T) {
	f := &dnsFake{fakeAdmin: newFakeAdmin()}
	orig := settingsSettle
	settingsSettle = 0
	t.Cleanup(func() { settingsSettle = orig })
	cfg := withFake(t, f.fakeAdmin)
	dialAdmin = func(*globals) (armadav1.AdminServiceClient, io.Closer, error) { return f, nopCloser{}, nil }
	cli := func(args ...string) (int, string, string) { return run(t, append(args, "--config", cfg)...) }

	if code, _, stderr := cli("cluster", "dns", "create", "shop.net"); code == 0 || !strings.Contains(stderr, "--token is required") {
		t.Errorf("create without a token: %d %q", code, stderr)
	}
	token := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(token, []byte("zone-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := cli("cluster", "dns", "create", "shop.net", "--token", token); code != 0 || !strings.Contains(stdout, "Created DNS zone shop.net") {
		t.Fatalf("create: %d %q %q", code, stdout, stderr)
	}
	if code, _, stderr := cli("cluster", "dns", "update", "shop.net", "--token", token, "--provider", "cloudflare"); code != 0 {
		t.Fatalf("update: %d %q", code, stderr)
	}
	if len(f.sets) != 2 || !f.sets[0].MustCreate || f.sets[0].MustExist || f.sets[1].MustCreate || !f.sets[1].MustExist ||
		string(f.sets[0].Token) != "zone-secret" || f.sets[0].Provider != "cloudflare" {
		t.Errorf("requests = %v", f.sets)
	}
	code, stdout, _ := cli("cluster", "dns", "list")
	if code != 0 || !strings.Contains(stdout, "shop.net") || strings.Contains(stdout, "zone-secret") {
		t.Errorf("list: %d %q", code, stdout)
	}
	if code, _, stderr := cli("cluster", "dns", "delete", "shop.net"); code != 0 || len(f.deletes) != 1 {
		t.Errorf("delete: %d %q %v", code, stderr, f.deletes)
	}
}
