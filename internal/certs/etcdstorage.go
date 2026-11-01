package certs

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/client/v3/concurrency"
)

// EtcdStorage keeps certmagic's data (ACME account, certificates and their
// keys, challenge tokens) in etcd, so every control plane node sees the
// same certificates and a new leader neither re-issues them nor loses its
// ACME account. Each value is stored as an 8-byte big-endian modification
// time (Unix nanoseconds) followed by the data.
type EtcdStorage struct {
	c      *clientv3.Client
	prefix string

	mu      sync.Mutex
	session *concurrency.Session
	locks   map[string]*concurrency.Mutex
}

var _ certmagic.Storage = (*EtcdStorage)(nil)

// lockTTL bounds how long a lock outlives a crashed holder.
const lockTTL = 60

// NewEtcdStorage returns a storage under prefix (e.g. "/armada-acme/").
func NewEtcdStorage(c *clientv3.Client, prefix string) (*EtcdStorage, error) {
	if !strings.HasSuffix(prefix, "/") {
		return nil, errors.New("certs: etcd prefix must end with /")
	}
	return &EtcdStorage{c: c, prefix: prefix, locks: map[string]*concurrency.Mutex{}}, nil
}

func (s *EtcdStorage) key(k string) string { return s.prefix + "data/" + strings.Trim(k, "/") }

// Store implements certmagic.Storage.
func (s *EtcdStorage) Store(ctx context.Context, key string, value []byte) error {
	b := make([]byte, 8, 8+len(value))
	binary.BigEndian.PutUint64(b, uint64(time.Now().UnixNano()))
	_, err := s.c.Put(ctx, s.key(key), string(append(b, value...)))
	return err
}

func (s *EtcdStorage) get(ctx context.Context, key string) (data []byte, mod time.Time, err error) {
	resp, err := s.c.Get(ctx, s.key(key))
	if err != nil {
		return nil, time.Time{}, err
	}
	if len(resp.Kvs) == 0 {
		return nil, time.Time{}, fs.ErrNotExist
	}
	v := resp.Kvs[0].Value
	if len(v) < 8 {
		return nil, time.Time{}, fmt.Errorf("certs: corrupt value at %s", key)
	}
	return v[8:], time.Unix(0, int64(binary.BigEndian.Uint64(v[:8]))), nil //nolint:gosec // written by Store
}

// Load implements certmagic.Storage.
func (s *EtcdStorage) Load(ctx context.Context, key string) ([]byte, error) {
	b, _, err := s.get(ctx, key)
	return b, err
}

// Delete implements certmagic.Storage: it removes the key and, like a
// directory, everything below it.
func (s *EtcdStorage) Delete(ctx context.Context, key string) error {
	k := s.key(key)
	_, err := s.c.Txn(ctx).Then(clientv3.OpDelete(k), clientv3.OpDelete(k+"/", clientv3.WithPrefix())).Commit()
	return err
}

// Exists implements certmagic.Storage.
func (s *EtcdStorage) Exists(ctx context.Context, key string) bool {
	_, err := s.Stat(ctx, key)
	return err == nil
}

// List implements certmagic.Storage.
func (s *EtcdStorage) List(ctx context.Context, dir string, recursive bool) ([]string, error) {
	base := s.key(dir) + "/"
	if strings.Trim(dir, "/") == "" {
		base = s.prefix + "data/"
	}
	resp, err := s.c.Get(ctx, base, clientv3.WithPrefix(), clientv3.WithKeysOnly())
	if err != nil {
		return nil, err
	}
	if len(resp.Kvs) == 0 {
		return nil, fs.ErrNotExist
	}
	seen := map[string]bool{}
	for _, kv := range resp.Kvs {
		rel := strings.TrimPrefix(string(kv.Key), base)
		if !recursive {
			rel, _, _ = strings.Cut(rel, "/")
		}
		seen[path.Join(strings.Trim(dir, "/"), rel)] = true
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, nil
}

// Stat implements certmagic.Storage.
func (s *EtcdStorage) Stat(ctx context.Context, key string) (certmagic.KeyInfo, error) {
	b, mod, err := s.get(ctx, key)
	if err == nil {
		return certmagic.KeyInfo{Key: key, Modified: mod, Size: int64(len(b)), IsTerminal: true}, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return certmagic.KeyInfo{}, err
	}
	resp, err := s.c.Get(ctx, s.key(key)+"/", clientv3.WithPrefix(), clientv3.WithCountOnly())
	if err != nil {
		return certmagic.KeyInfo{}, err
	}
	if resp.Count == 0 {
		return certmagic.KeyInfo{}, fs.ErrNotExist
	}
	return certmagic.KeyInfo{Key: key, IsTerminal: false}, nil
}

// Lock implements certmagic.Locker with an etcd mutex tied to a lease, so
// the lock is released if its holder dies.
func (s *EtcdStorage) Lock(ctx context.Context, name string) error {
	s.mu.Lock()
	if s.session != nil {
		select {
		case <-s.session.Done():
			s.session = nil
		default:
		}
	}
	if s.session == nil {
		sess, err := concurrency.NewSession(s.c, concurrency.WithTTL(lockTTL))
		if err != nil {
			s.mu.Unlock()
			return fmt.Errorf("certs: lock session: %w", err)
		}
		s.session = sess
	}
	m := concurrency.NewMutex(s.session, s.prefix+"locks/"+strings.Trim(name, "/"))
	s.mu.Unlock()
	if err := m.Lock(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	s.locks[name] = m
	s.mu.Unlock()
	return nil
}

// Unlock implements certmagic.Locker.
func (s *EtcdStorage) Unlock(ctx context.Context, name string) error {
	s.mu.Lock()
	m := s.locks[name]
	delete(s.locks, name)
	s.mu.Unlock()
	if m == nil {
		return fmt.Errorf("certs: %s is not locked", name)
	}
	return m.Unlock(ctx)
}

// Close releases the locks' lease.
func (s *EtcdStorage) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.session == nil {
		return nil
	}
	err := s.session.Close()
	s.session = nil
	return err
}
