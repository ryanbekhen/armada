package store

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

func TestDeleteRanges(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	err := s.tx(ctx, func(tx *etx) error {
		for i := range 300 {
			if err := tx.put(fmt.Sprintf("rangetest/a/%03d", i), i); err != nil {
				return err
			}
		}
		return tx.put("rangetest/b", 1)
	})
	if err != nil {
		t.Fatal(err)
	}
	var ops int
	s.onCommit = func(n int) { ops = n }
	defer func() { s.onCommit = nil }()
	err = s.tx(ctx, func(tx *etx) error {
		tx.delete("rangetest/a/001")
		tx.deletePrefix("rangetest/a/")
		var v int
		if ok, err := tx.get("rangetest/a/005", &v); err != nil || ok {
			return fmt.Errorf("deleted key still read: %v %w", ok, err)
		}
		if kvs, err := tx.list("rangetest/"); err != nil || len(kvs) != 1 || kvs[0].key != "rangetest/b" {
			return fmt.Errorf("list after delete: %v %w", kvs, err)
		}
		if err := tx.put("rangetest/a/new", 1); err == nil || !strings.Contains(err.Error(), "after deleting its range") {
			return fmt.Errorf("write into a deleted range: %w", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if ops != 2 {
		t.Errorf("deleting 300 keys took %d operations, want the range and the commit", ops)
	}
	err = s.view(ctx, func(tx *etx) error {
		kvs, err := tx.list("rangetest/")
		if err != nil || len(kvs) != 1 {
			return fmt.Errorf("after commit: %v %w", kvs, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// Removing an app costs a few operations however many revisions and
// secret versions it has: etcd bounds a transaction's operations.
func TestDeleteAppIsSmall(t *testing.T) {
	t.Parallel()
	s, ctx, k := open(t), context.Background(), testKeyring(t)
	for i := range 150 {
		setSecret(t, s, k, "web", fmt.Sprintf("s%d", i%5), "v", false)
	}
	for i := range 12 {
		if _, _, err := s.Deploy(ctx, secretSpec(t, "s0", "s1", "s2", "s3", "s4"), "a"); err != nil {
			t.Fatal(err)
		}
		setSecret(t, s, k, "web", "s0", fmt.Sprint(i), false)
	}
	if err := s.MarkAppRemoving(ctx, "web", "a"); err != nil {
		t.Fatal(err)
	}
	var ops int
	s.onCommit = func(n int) { ops = n }
	defer func() { s.onCommit = nil }()
	if err := s.DeleteApp(ctx, "web"); err != nil {
		t.Fatal(err)
	}
	if ops > 4 {
		t.Errorf("DeleteApp took %d operations", ops)
	}
	if _, err := s.GetApp(ctx, "web"); err == nil {
		t.Error("app still there")
	}
}
