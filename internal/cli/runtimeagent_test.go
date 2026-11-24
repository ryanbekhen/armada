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

// cluster status shows the leader's move of containerd nodes: the node and
// its step, what it said, and the nodes that wait and for whom (ADR 0054).
func TestPrintClusterStatusRuntimeMove(t *testing.T) {
	t.Parallel()
	var b strings.Builder
	err := printClusterStatus(&b, &armadav1.ClusterStatusResponse{RuntimeMove: &armadav1.RuntimeMoveStatus{
		Node: "lab2", Step: "draining", SinceUnix: 1, StepSinceUnix: 1, Error: "replicas are still assigned\x1b[2J",
		Waiting: []*armadav1.RuntimeMoveWait{
			{Node: "lab3", Reason: "holds volumes of db", Operator: true},
			{Node: "lab4", Reason: "the other nodes have no room for a replica of web"},
		},
		WaitingTotal: 3,
	}})
	if err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"runtime move: moving lab2 to the supervisor runtime, its replicas start on other nodes",
		"the node said: replicas are still assigned",
		"lab3", "its operator: holds volumes of db",
		"lab4", "the other nodes have no room for a replica of web",
		"and 1 more",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("want %q in:\n%s", want, out)
		}
	}
	if strings.ContainsRune(out, 0x1b) {
		t.Errorf("control characters:\n%q", out)
	}
	b.Reset()
	if err := printClusterStatus(&b, &armadav1.ClusterStatusResponse{RuntimeMove: &armadav1.RuntimeMoveStatus{Off: true, Held: "turned off"}}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "runtime move: off") {
		t.Errorf("off:\n%s", b.String())
	}
	b.Reset()
	if err := printClusterConfig(&b, &armadav1.ClusterConfig{RuntimeMoveOff: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "runtime move:      off\n") {
		t.Errorf("cluster show:\n%s", b.String())
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
		{&armadav1.RuntimeStatus{Agent: "containerd"}, "containerd (the leader moves it to the supervisor runtime; armada cluster status)"},
		{&armadav1.RuntimeStatus{Agent: "containerd", MoveError: "replicas are still assigned\x1b[2J"}, "containerd (the leader moves it to the supervisor runtime; armada cluster status); it did not move: replicas are still assigned"},
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
