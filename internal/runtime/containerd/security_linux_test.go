//go:build linux

package containerd

import (
	"strings"
	"testing"
)

// The profile lets a container's processes signal and trace each other
// also under the stacked label kernels give them with no_new_privileges.
func TestAppArmorProfileStackedPeer(t *testing.T) {
	text, err := appArmorProfile("armada-default")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"signal (send,receive) peer=armada-default,\n",
		"signal (send,receive) peer=\"armada-default//&unconfined\",\n",
		"ptrace (trace,tracedby,read,readby) peer=armada-default,\n",
		"ptrace (trace,tracedby,read,readby) peer=\"armada-default//&unconfined\",\n",
		"profile armada-default ",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("profile lacks %q:\n%s", want, text)
		}
	}
	if n := strings.Count(text, "//&unconfined"); n != 2 {
		t.Errorf("%d stacked rules, want 2", n)
	}
}
