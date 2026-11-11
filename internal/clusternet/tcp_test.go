package clusternet

import (
	"slices"
	"testing"
)

// The ports of internal TCP apps reach the policy checked, sorted, and once
// each; a port of Armada's own, or none at all, refuses the whole list
// (ADR 0039).
func TestParseTCPPorts(t *testing.T) {
	t.Parallel()
	cfg := config(np("a", "10.0.0.1", "10.120.0.0/24"))
	cfg.TcpPorts = []uint32{6379, 5432, 6379}
	p, err := parse(cfg, "a", self)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(p.tcpPorts, []uint16{5432, 6379}) {
		t.Errorf("ports = %v", p.tcpPorts)
	}
	if pol := buildPolicy(p, nil); !slices.Equal(pol.tcpPorts, []uint16{5432, 6379}) {
		t.Errorf("policy ports = %v", pol.tcpPorts)
	}
	for _, bad := range [][]uint32{{0}, {53}, {80}, {443}, {22}, {65536}, {1 << 31}, make([]uint32, maxTCPPorts+1)} {
		cfg.TcpPorts = bad
		if _, err := parse(cfg, "a", self); err == nil {
			t.Errorf("ports %v accepted", bad[:min(len(bad), 3)])
		}
	}
	cfg.TcpPorts = nil
	if p, err := parse(cfg, "a", self); err != nil || len(p.tcpPorts) != 0 {
		t.Errorf("no ports: %v %v", p.tcpPorts, err)
	}
}
