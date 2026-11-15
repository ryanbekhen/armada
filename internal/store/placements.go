package store

import (
	"context"
	"encoding/json"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
)

// pfxPlacements records the node each replica was created on
// (placements/<replica ID>), written by CreateReplica in its transaction
// and kept after the replica is gone, so a node's log history answer can
// be checked against the replicas that ran there (ADR 0043). The leader
// prunes records older than the log retention (PrunePlacements). Older
// binaries ignore the prefix, so it needs no schema step.
const pfxPlacements = "placements/"

// placementBatch bounds the deletes of one PrunePlacements transaction,
// well below etcd's maxTxnOps.
const placementBatch = 1000

type placementRec struct {
	App  string `json:"app"`
	Node string `json:"node"`
	At   int64  `json:"at"` // unix milliseconds
}

func (t *etx) putPlacement(r Replica, now time.Time) error {
	return t.put(pfxPlacements+r.ID, placementRec{App: r.App, Node: r.NodeID, At: now.UnixMilli()})
}

// ReplicaPlacements returns the node of every recorded replica of app,
// gone ones included, by replica ID: the placement records, and the
// replicas the store still holds (created before records were kept).
func (s *Etcd) ReplicaPlacements(ctx context.Context, app string) (map[string]string, error) {
	out := map[string]string{}
	err := s.view(ctx, func(t *etx) error {
		clear(out)
		// The prefix of "web" also holds "web-api"'s: the record's app
		// decides.
		if err := listInto(t, pfxPlacements+replicaPrefix(app), func(key string, r placementRec) error {
			if r.App == app {
				out[key[len(pfxPlacements):]] = r.Node
			}
			return nil
		}); err != nil {
			return err
		}
		return appReplicas(t, app, func(_ string, r replicaRec) error {
			out[r.ID] = r.NodeID
			return nil
		})
	})
	return out, err
}

// PrunePlacements deletes the placement records written before before
// and returns how many it deleted.
func (s *Etcd) PrunePlacements(ctx context.Context, before time.Time) (int, error) {
	resp, err := s.c.Get(ctx, s.prefix+pfxPlacements, clientv3.WithPrefix())
	if err != nil {
		return 0, err
	}
	cut := before.UnixMilli()
	var ops []clientv3.Op
	n := 0
	flush := func() error {
		if len(ops) == 0 {
			return nil
		}
		if _, err := s.c.Txn(ctx).Then(ops...).Commit(); err != nil {
			return err
		}
		n += len(ops)
		ops = ops[:0]
		return nil
	}
	for _, kv := range resp.Kvs {
		var r placementRec
		if json.Unmarshal(kv.Value, &r) == nil && r.At >= cut {
			continue
		}
		ops = append(ops, clientv3.OpDelete(string(kv.Key)))
		if len(ops) == placementBatch {
			if err := flush(); err != nil {
				return n, err
			}
		}
	}
	return n, flush()
}
