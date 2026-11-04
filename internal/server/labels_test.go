package server

import (
	"context"
	goruntime "runtime"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/pki"
	"github.com/ryanbekhen/armada/internal/spec"
	"github.com/ryanbekhen/armada/internal/store"
)

func TestLabelNodeRPC(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	if err := c.store.UpsertNode(c.ctx, store.Node{ID: "n1", PrivateIP: "10.0.0.11"}); err != nil {
		t.Fatal(err)
	}
	resp, err := c.admin.LabelNode(c.ctx, &armadav1.LabelNodeRequest{Node: "n1", Set: map[string]string{"region": "sulawesi"}})
	if err != nil || resp.Labels["region"] != "sulawesi" {
		t.Fatalf("label: %v, %v", resp, err)
	}
	for name, req := range map[string]*armadav1.LabelNodeRequest{
		"empty":            {Node: "n1"},
		"reserved key":     {Node: "n1", Set: map[string]string{"armada.arch": "amd64"}},
		"remove reserved":  {Node: "n1", Remove: []string{"armada.os"}},
		"upper case":       {Node: "n1", Set: map[string]string{"Region": "x"}},
		"newline":          {Node: "n1", Set: map[string]string{"region": "a\nb"}},
		"set and remove":   {Node: "n1", Set: map[string]string{"region": "x"}, Remove: []string{"region"}},
		"template-ish":     {Node: "n1", Set: map[string]string{"k": "{{.Secret}}"}},
		"empty value":      {Node: "n1", Set: map[string]string{"k": ""}},
		"slash in value":   {Node: "n1", Set: map[string]string{"k": "../x"}},
		"key with spaces":  {Node: "n1", Set: map[string]string{"a b": "x"}},
		"overlong value":   {Node: "n1", Set: map[string]string{"k": string(make([]byte, 64))}},
		"bad remove chars": {Node: "n1", Remove: []string{"a=b"}},
	} {
		if _, err := c.admin.LabelNode(c.ctx, req); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: %v, want InvalidArgument", name, err)
		}
	}
	if _, err := c.admin.LabelNode(c.ctx, &armadav1.LabelNodeRequest{Node: "ghost", Set: map[string]string{"a": "b"}}); status.Code(err) != codes.NotFound {
		t.Errorf("unknown node: %v", err)
	}
	if _, err := c.admin.RestrictNode(c.ctx, &armadav1.RestrictNodeRequest{Node: "n1", Restricted: true}); err != nil {
		t.Fatal(err)
	}
	st, err := c.admin.Status(c.ctx, &armadav1.StatusRequest{})
	if err != nil || len(st.Nodes) != 1 || !st.Nodes[0].Restricted || st.Nodes[0].Labels["region"] != "sulawesi" {
		t.Errorf("status nodes = %v, %v", st.GetNodes(), err)
	}
	if _, err := c.admin.RestrictNode(c.ctx, &armadav1.RestrictNodeRequest{Node: "ghost", Restricted: true}); status.Code(err) != codes.NotFound {
		t.Errorf("restrict unknown node: %v", err)
	}
}

func TestJoinTokenLabels(t *testing.T) {
	t.Parallel()
	c := newCluster(t, withJoin(t))
	tok, err := c.admin.CreateJoinToken(c.ctx, &armadav1.CreateJoinTokenRequest{Labels: map[string]string{"region": "papua"}})
	if err != nil {
		t.Fatal(err)
	}
	req, keyPEM := joinReq(t, tok.Token, "n7", "10.0.0.17")
	resp, err := c.joinClient(tok).Join(c.ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	c.runJoinedAgent("n7", "10.0.0.17", resp, keyPEM)
	// The token's labels, plus what the agent reports about itself.
	c.eventually("labels", func() bool {
		n, err := c.store.GetNode(c.ctx, "n7")
		all := n.AllLabels()
		return err == nil && all["region"] == "papua" && all["armada.os"] == goruntime.GOOS && all["armada.arch"] == goruntime.GOARCH &&
			all["armada.runtime"] == "embedded"
	})

	for name, labels := range map[string]map[string]string{
		"reserved": {"armada.arch": "arm64"},
		"bad key":  {"Region": "x"},
		"bad val":  {"region": "a b"},
	} {
		if _, err := c.admin.CreateJoinToken(c.ctx, &armadav1.CreateJoinTokenRequest{Labels: labels}); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: %v, want InvalidArgument", name, err)
		}
	}
}

// The OS and architecture an agent reports become labels; values that are
// not valid label values are dropped, not stored.
func TestHelloOSAndArch(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	for id, ip := range map[string]string{"good": "10.0.0.21", "evil": "10.0.0.22"} {
		if err := c.store.UpsertNode(c.ctx, store.Node{ID: id, PrivateIP: ip}); err != nil {
			t.Fatal(err)
		}
	}
	connect := func(id string, hello *armadav1.Hello) {
		client := armadav1.NewAgentServiceClient(c.dial(c.ca, pki.Identity{Kind: pki.KindNode, Name: id}))
		ctx, cancel := context.WithCancel(c.ctx)
		t.Cleanup(cancel)
		stream, err := client.Connect(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := stream.Send(&armadav1.AgentMessage{Msg: &armadav1.AgentMessage_Hello{Hello: hello}}); err != nil {
			t.Fatal(err)
		}
		c.eventually(id+" connected", func() bool { return c.srv.session(id) != nil })
	}
	connect("good", &armadav1.Hello{PrivateIp: "10.0.0.21", Os: "linux", Arch: "arm64", Runtime: "embedded", MinMemoryBytes: 200 << 20, Sandbox: true})
	connect("evil", &armadav1.Hello{PrivateIp: "10.0.0.22", Os: "linux\nregion=x", Arch: "../../amd64", Runtime: "Docker Engine", MinMemoryBytes: -1})
	time.Sleep(100 * time.Millisecond)
	if n, _ := c.store.GetNode(c.ctx, "good"); n.OS != "linux" || n.Arch != "arm64" || n.AllLabels()[spec.LabelRuntime] != "embedded" {
		t.Errorf("good node: os %q arch %q runtime %q", n.OS, n.Arch, n.Runtime)
	} else if n.MinMemoryBytes != 200<<20 || !n.Sandbox {
		t.Errorf("good node: minimum memory %d, sandbox %v", n.MinMemoryBytes, n.Sandbox)
	}
	if n, _ := c.store.GetNode(c.ctx, "evil"); n.OS != "" || n.Arch != "" || n.Runtime != "" || n.MinMemoryBytes != 0 || n.Sandbox {
		t.Errorf("invalid values stored: os %q arch %q runtime %q minimum memory %d", n.OS, n.Arch, n.Runtime, n.MinMemoryBytes)
	}
}
