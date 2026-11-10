package server

import (
	"bytes"
	"context"
	"sync/atomic"
	"testing"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/secrets"
	"github.com/ryanbekhen/armada/internal/store"
)

type secretReads struct {
	store.Store
	n atomic.Int64
}

func (s *secretReads) GetSecret(ctx context.Context, app, name string, version int) (secrets.Sealed, error) {
	s.n.Add(1)
	return s.Store.GetSecret(ctx, app, name, version)
}

// A secret version is read and opened once, not on every pass.
func TestSecretsOpenedOnce(t *testing.T) {
	t.Parallel()
	c := newClockServer(t)
	keys, err := secrets.NewKeyring(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	c.srv.keys = keys
	if _, _, err := c.st.SetSecret(c.ctx, "web", "db", func(v int) (secrets.Sealed, error) {
		return keys.Seal("web", "db", v, secrets.NewValue([]byte("pw")))
	}, false, "t"); err != nil {
		t.Fatal(err)
	}
	reads := &secretReads{Store: c.st}
	c.srv.store = reads
	c.srv.sessions["n1"] = &session{nodeID: "n1", send: make(chan *armadav1.ServerMessage, 64), done: make(chan struct{})}
	c.deploy("name: web\nimage: nginx:1\nenv:\n  - { name: DB, secretRef: db }\n")
	first := reads.n.Load()
	if first == 0 {
		t.Fatal("the secret was never read; is an assignment built?")
	}
	for range 5 {
		c.reconcile()
	}
	if got := reads.n.Load(); got != first {
		t.Errorf("secret reads went from %d to %d over five more passes", first, got)
	}
}
