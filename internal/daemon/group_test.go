package daemon

import (
	"context"
	"errors"
	"os/user"
	"strings"
	"testing"
)

// init and server join add the person who ran them through sudo to the
// armada group, once, instead of copying the admin config to their home.
func TestJoinAdminGroup(t *testing.T) {
	oldLookup, oldIDs, oldAdd := lookupGroup, groupIDs, addToGroup
	t.Cleanup(func() { lookupGroup, groupIDs, addToGroup = oldLookup, oldIDs, oldAdd })
	var added []string
	addToGroup = func(_ context.Context, name, group string) error {
		added = append(added, name+":"+group)
		return nil
	}
	lookupGroup = func(string) (*user.Group, error) { return &user.Group{Gid: "990", Name: "armada"}, nil }
	devops := &user.User{Username: "devops", Uid: "1000", Gid: "1000"}

	groupIDs = func(*user.User) ([]string, error) { return []string{"1000", "27"}, nil }
	if joined, err := joinAdminGroup(context.Background(), devops); err != nil || !joined || len(added) != 1 || added[0] != "devops:armada" {
		t.Errorf("not a member: joined %v, %v, added %v", joined, err, added)
	}
	if note := adminGroupNote("devops"); !strings.Contains(note, "log in again") || !strings.Contains(note, "newgrp armada") {
		t.Errorf("note %q", note)
	}

	added = nil
	groupIDs = func(*user.User) ([]string, error) { return []string{"1000", "990"}, nil }
	if joined, err := joinAdminGroup(context.Background(), devops); err != nil || joined || len(added) != 0 {
		t.Errorf("already a member: joined %v, %v, added %v", joined, err, added)
	}

	lookupGroup = func(string) (*user.Group, error) { return nil, user.UnknownGroupError("armada") }
	if _, err := joinAdminGroup(context.Background(), devops); err == nil || len(added) != 0 {
		t.Errorf("no group: %v, added %v", err, added)
	}

	lookupGroup = func(string) (*user.Group, error) { return &user.Group{Gid: "990"}, nil }
	groupIDs = func(*user.User) ([]string, error) { return []string{"1000"}, nil }
	addToGroup = func(context.Context, string, string) error { return errors.New("usermod failed") }
	if _, err := joinAdminGroup(context.Background(), devops); err == nil {
		t.Error("a failed usermod passed")
	}
}

// The group is joined with whichever tool the distribution has, found in
// the sbin directories too when sudo's PATH lacks them.
func TestGroupCommand(t *testing.T) {
	t.Parallel()
	has := func(paths ...string) func(string) (string, error) {
		return func(p string) (string, error) {
			for _, h := range paths {
				if p == h || (!strings.Contains(p, "/") && strings.HasSuffix(h, "/"+p) && strings.HasPrefix(h, "/path/")) {
					return h, nil
				}
			}
			return "", errors.New("not found")
		}
	}
	for name, tt := range map[string]struct {
		look func(string) (string, error)
		want string
	}{
		"shadow-utils in PATH":      {has("/path/usermod", "/path/gpasswd"), "/path/usermod -a -G armada devops"},
		"shadow-utils outside PATH": {has("/usr/sbin/usermod"), "/usr/sbin/usermod -a -G armada devops"},
		"gpasswd only":              {has("/usr/bin/gpasswd"), "/usr/bin/gpasswd -a devops armada"},
		"busybox":                   {has("/usr/sbin/addgroup"), "/usr/sbin/addgroup devops armada"},
		"nothing":                   {has(), ""},
	} {
		argv, err := groupCommand(tt.look, "devops", "armada")
		if got := strings.Join(argv, " "); got != tt.want || (err == nil) != (tt.want != "") {
			t.Errorf("%s: %q, %v; want %q", name, got, err, tt.want)
		}
	}
}
