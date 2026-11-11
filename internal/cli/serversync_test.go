package cli

import (
	"path/filepath"
	"slices"
	"testing"

	"google.golang.org/grpc/metadata"

	"github.com/ryanbekhen/armada/internal/clientconfig"
)

func TestServerSync(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".armada", "config")
	cc := &clientconfig.Config{Servers: []string{"10.0.0.1:7443"}, CA: "ca", Cert: "cert", Key: "key"}
	if err := cc.Save(path); err != nil {
		t.Fatal(err)
	}
	load := func() []string {
		c, err := clientconfig.Load(path)
		if err != nil {
			t.Fatal(err)
		}
		return c.Servers
	}
	s := &serverSync{path: path, servers: cc.Servers}

	// No header, an invalid list, or the same set: nothing is written.
	s.observe(nil)
	s.observe(metadata.Pairs(clientconfig.ServersHeader, "8.8.8.8:7443"))
	s.observe(metadata.Pairs(clientconfig.ServersHeader, "10.0.0.1:7443"))
	if got := load(); !slices.Equal(got, []string{"10.0.0.1:7443"}) {
		t.Fatalf("servers = %v", got)
	}

	s.observe(metadata.Pairs(clientconfig.ServersHeader, "10.0.0.2:7443,10.0.0.1:7443,10.0.0.3:7443"))
	if got := load(); !slices.Equal(got, []string{"10.0.0.2:7443", "10.0.0.1:7443", "10.0.0.3:7443"}) {
		t.Fatalf("servers = %v", got)
	}
	// Once per process.
	s.observe(metadata.Pairs(clientconfig.ServersHeader, "10.0.0.4:7443"))
	if got := load(); len(got) != 3 {
		t.Errorf("written twice: %v", got)
	}
	if c, _ := clientconfig.Load(path); c.Key != "key" || c.CA != "ca" {
		t.Error("credentials changed")
	}

	// A config that goes through a tunnel keeps its list.
	cc.Servers = []string{"127.0.0.1:7443"}
	if err := cc.Save(path); err != nil {
		t.Fatal(err)
	}
	s = &serverSync{path: path, servers: cc.Servers}
	s.observe(metadata.Pairs(clientconfig.ServersHeader, "10.0.0.2:7443"))
	if got := load(); !slices.Equal(got, []string{"127.0.0.1:7443"}) {
		t.Errorf("tunnelled config changed: %v", got)
	}
}
