package daemon

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"os/user"
	"path/filepath"
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

// groupCommand is the command that adds account name to group, by the
// first tool the machine has: usermod (shadow-utils: Debian, Ubuntu, RHEL,
// Rocky, Oracle Linux, Fedora, SUSE), gpasswd (also shadow-utils), or
// BusyBox's addgroup (Alpine), the same families install.sh creates the
// group with. look finds a tool; sudo's PATH may lack the sbin
// directories, so they are tried too.
func groupCommand(look func(string) (string, error), name, group string) ([]string, error) {
	for _, c := range [][]string{
		{"usermod", "-a", "-G", group, name},
		{"gpasswd", "-a", name, group},
		{"addgroup", name, group},
	} {
		if path, err := findTool(look, c[0]); err == nil {
			return append([]string{path}, c[1:]...), nil
		}
	}
	return nil, errors.New("found none of usermod, gpasswd, or addgroup")
}

func findTool(look func(string) (string, error), tool string) (string, error) {
	if p, err := look(tool); err == nil {
		return p, nil
	}
	for _, dir := range []string{"/usr/sbin", "/sbin", "/usr/bin", "/bin"} {
		if p, err := look(filepath.Join(dir, tool)); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s not found", tool)
}

// Hooks for tests.
var (
	lookupGroup = user.LookupGroup
	groupIDs    = func(u *user.User) ([]string, error) { return u.GroupIds() }
	addToGroup  = func(ctx context.Context, name, group string) error {
		argv, err := groupCommand(exec.LookPath, name, group)
		if err != nil {
			return err
		}
		out, err := exec.CommandContext(ctx, argv[0], argv[1:]...).CombinedOutput() //nolint:gosec // a system tool; an account sudo named and user.Lookup found, no shell
		if err != nil {
			return fmt.Errorf("%s: %w: %s", filepath.Base(argv[0]), err, strings.TrimSpace(string(out)))
		}
		return nil
	}
)
