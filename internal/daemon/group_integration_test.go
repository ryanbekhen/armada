//go:build integration

package daemon

import (
	"context"
	"os"
	"os/user"
	"slices"
	"testing"

	"github.com/ryanbekhen/armada/internal/clientconfig"
)

// On a real machine, as root, with the armada group and an account named
// by ARMADA_TEST_USER: joinAdminGroup adds the account once with the
// distribution's own tool. Run it in a throwaway container or VM of each
// distribution:
//
//	go test -c -tags integration ./internal/daemon -o groupt
//	ARMADA_TEST_USER=devops ./groupt -test.run IntegrationJoinAdminGroup
func TestIntegrationJoinAdminGroup(t *testing.T) {
	name := os.Getenv("ARMADA_TEST_USER")
	if name == "" || os.Geteuid() != 0 {
		t.Skip("needs root and ARMADA_TEST_USER")
	}
	u, err := user.Lookup(name)
	if err != nil {
		t.Fatal(err)
	}
	joined, err := joinAdminGroup(context.Background(), u)
	if err != nil || !joined {
		t.Fatalf("first join: %v, %v", joined, err)
	}
	g, err := user.LookupGroup(clientconfig.Group)
	if err != nil {
		t.Fatal(err)
	}
	if ids, _ := u.GroupIds(); !slices.Contains(ids, g.Gid) {
		t.Fatalf("%s is not in %s after joining: %v", name, clientconfig.Group, ids)
	}
	if joined, err := joinAdminGroup(context.Background(), u); err != nil || joined {
		t.Errorf("second join: %v, %v", joined, err)
	}
}
