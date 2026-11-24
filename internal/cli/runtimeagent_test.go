package cli

import (
	"strings"
	"testing"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
)

// cluster status says where the nodes' move to armada-node stands, naming
// the nodes not there yet and what holds each (ADR 0054).
func TestPrintClusterStatusRuntime(t *testing.T) {
	t.Parallel()
	var b strings.Builder
	err := printClusterStatus(&b, &armadav1.ClusterStatusResponse{Nodes: 6, NodesReady: 6, Runtime: &armadav1.RuntimeProgress{
		Nodes: 7, Moved: 2, OthersTotal: 6,
		Others: []*armadav1.NodeRuntime{
			{Node: "lab2", Status: &armadav1.RuntimeStatus{Agent: "supervisor-rust", Converting: true}},
			{Node: "lab3", Status: &armadav1.RuntimeStatus{Agent: "supervisor-rust", ImagesToPull: 2}},
			{Node: "lab4", Status: &armadav1.RuntimeStatus{Agent: "containerd"}},
			{Node: "lab5", Status: &armadav1.RuntimeStatus{Agent: "supervisor-go"}},
			{Node: "lab6"},
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	want := "runtime: 2 of 7 nodes on armada-node; lab2 converting, lab3 with 2 images to pull again, lab4 on containerd, lab5 on Go's runtime code, lab6 not reporting, and 1 more"
	if !strings.Contains(b.String(), want) {
		t.Errorf("want %q in:\n%s", want, b.String())
	}
	b.Reset()
	if err := printClusterStatus(&b, &armadav1.ClusterStatusResponse{Runtime: &armadav1.RuntimeProgress{Nodes: 3, Moved: 3}}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "runtime: 3 of 3 nodes on armada-node\n") {
		t.Errorf("all moved:\n%s", b.String())
	}
	b.Reset()
	if err := printClusterStatus(&b, &armadav1.ClusterStatusResponse{}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "runtime:") {
		t.Errorf("a runtime line without nodes:\n%s", b.String())
	}
}

// node show says how the node runs containers.
func TestNodeRuntime(t *testing.T) {
	t.Parallel()
	cases := []struct {
		st   *armadav1.RuntimeStatus
		want string
	}{
		{nil, "-"},
		{&armadav1.RuntimeStatus{Agent: "containerd"}, "containerd (armadad runtime migrate --to supervisor moves it)"},
		{&armadav1.RuntimeStatus{Agent: "supervisor-go"}, `supervisor, Go's code (agent.json runtimeAgent "go")`},
		{&armadav1.RuntimeStatus{Agent: "supervisor-rust"}, "supervisor, armada-node"},
		{&armadav1.RuntimeStatus{Agent: "supervisor-rust", Converting: true, ImagesToPull: 4}, "supervisor, armada-node; Go's image store still holds containers made before the move; 4 images to pull again"},
		{&armadav1.RuntimeStatus{Agent: "supervisor-rust", Converting: true, Error: "no space\x1b[2J"}, "supervisor, armada-node; converting Go's image store failed: no space"},
	}
	for _, c := range cases {
		got := nodeRuntime(c.st)
		if !strings.HasPrefix(got, c.want) || strings.ContainsRune(got, 0x1b) {
			t.Errorf("%v: %q, want %q", c.st, got, c.want)
		}
	}
}
