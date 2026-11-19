package daemon

import (
	"context"
	"fmt"
	"os/exec"
	"os/user"
	"slices"
	"strings"

	"github.com/ryanbekhen/armada/internal/clientconfig"
)

// joinAdminGroup adds the account that ran init or server join through
// sudo to the group that may read /etc/armada/admin.config (ADR 0027).
// That file is the machine's one cluster-admin config, and the server
// renews it, so the person needs no copy of their own. It reports whether
// the account joined now: membership counts in sessions that start
// afterwards.
func joinAdminGroup(ctx context.Context, u *user.User) (bool, error) {
	g, err := lookupGroup(clientconfig.Group)
	if err != nil {
		return false, fmt.Errorf("group %s: %w", clientconfig.Group, err)
	}
	ids, err := groupIDs(u)
	if err != nil {
		return false, err
	}
	if slices.Contains(ids, g.Gid) {
		return false, nil
	}
	if err := addToGroup(ctx, u.Username, clientconfig.Group); err != nil {
		return false, err
	}
	return true, nil
}

// adminGroupNote tells a person who just joined the group how to use it.
func adminGroupNote(name string) string {
	return fmt.Sprintf("%s joined the %s group: log in again (or run `newgrp %s`) to use armada without sudo", name, clientconfig.Group, clientconfig.Group)
}

// Hooks for tests.
var (
	lookupGroup = user.LookupGroup
	groupIDs    = func(u *user.User) ([]string, error) { return u.GroupIds() }
	addToGroup  = func(ctx context.Context, name, group string) error {
		out, err := exec.CommandContext(ctx, "usermod", "--append", "--groups", group, name).CombinedOutput() //nolint:gosec // an account sudo named and user.Lookup found, no shell
		if err != nil {
			return fmt.Errorf("usermod: %w: %s", err, strings.TrimSpace(string(out)))
		}
		return nil
	}
)
