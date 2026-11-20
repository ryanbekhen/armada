package clusternet

import (
	"testing"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
)

func TestParseSwitch(t *testing.T) {
	t.Parallel()
	peers := []*armadav1.NetworkPeer{np("a", "10.0.0.1", "10.120.0.0/24"), np("b", "10.0.0.2", "10.120.1.0/24")}
	with := func(mode, to, step string) *armadav1.NetworkConfig {
		return &armadav1.NetworkConfig{Mode: mode, ClusterCidr: "10.120.0.0/16", Peers: peers, SwitchTo: to, SwitchStep: step}
	}
	for _, c := range []struct{ mode, to, step string }{
		{ModePlain, ModeWireGuard, SwitchPrepare},
		{ModePlain, ModeWireGuard, SwitchMove},
		{ModeWireGuard, ModePlain, SwitchPrepare},
		{ModeWireGuard, ModePlain, SwitchMove},
	} {
		p, err := parse(with(c.mode, c.to, c.step), "a", self)
		if err != nil || !p.switching() || p.switchTo != c.to || p.step != c.step {
			t.Errorf("%s → %s %s: %+v, %v", c.mode, c.to, c.step, p, err)
		}
		// Peers without a key stay for the VXLAN side; the WireGuard
		// side skips them itself.
		if c.mode == ModePlain && len(p.peers) != 1 {
			t.Errorf("%s → %s: peers %+v", c.mode, c.to, p.peers)
		}
	}
	for name, c := range map[string]struct{ mode, to, step string }{
		"same mode":       {ModePlain, ModePlain, SwitchPrepare},
		"to mesh":         {ModePlain, ModeMesh, SwitchPrepare},
		"unknown target":  {ModePlain, "ipsec", SwitchPrepare},
		"unknown step":    {ModePlain, ModeWireGuard, "cleanup"},
		"no step":         {ModePlain, ModeWireGuard, ""},
		"step, no target": {ModePlain, "", SwitchMove},
	} {
		if _, err := parse(with(c.mode, c.to, c.step), "a", self); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A mesh cluster never switches.
	mesh := &armadav1.NetworkConfig{Mode: ModeMesh, ClusterCidr: "10.120.0.0/16", MeshCidr: "10.122.0.0/16", SwitchTo: ModeWireGuard, SwitchStep: SwitchPrepare}
	if _, _, err := parseSwitch(mesh); err == nil {
		t.Error("mesh: switch accepted")
	}
}
