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
