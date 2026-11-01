package etcd

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/client/v3/concurrency"
)

// MemberInfo describes a member of the cluster.
type MemberInfo struct {
	ID uint64
	// Name is empty until the member starts for the first time.
	Name      string
	PeerURL   string
	ClientURL string
	Learner   bool
}

// Members lists the cluster's members.
func Members(ctx context.Context, c *clientv3.Client) ([]MemberInfo, error) {
	resp, err := c.MemberList(ctx)
	if err != nil {
		return nil, fmt.Errorf("etcd member list: %w", err)
	}
	out := make([]MemberInfo, 0, len(resp.Members))
	for _, m := range resp.Members {
		mi := MemberInfo{ID: m.ID, Name: m.Name, Learner: m.IsLearner}
		if len(m.PeerURLs) > 0 {
			mi.PeerURL = m.PeerURLs[0]
		}
		if len(m.ClientURLs) > 0 {
			mi.ClientURL = m.ClientURLs[0]
		}
		out = append(out, mi)
	}
	return out, nil
}

// AddLearner adds a non-voting member named name that will listen on
// addr:peerPort, and returns its ID and the InitialCluster for its first
// start. A learner cannot affect quorum: if it never starts, the cluster
// keeps working. The leader promotes it once it has caught up (Promote).
func AddLearner(ctx context.Context, c *clientv3.Client, name string, addr netip.Addr, peerPort int) (uint64, string, error) {
	members, err := Members(ctx, c)
	if err != nil {
		return 0, "", err
	}
	u := memberURL(addr, peerPort)
	peer := u.String()
	parts := make([]string, 0, len(members)+1)
	for _, m := range members {
		switch {
		case m.Name == name:
			return 0, "", fmt.Errorf("etcd member %s already exists", name)
		case m.PeerURL == peer:
			return 0, "", fmt.Errorf("etcd member at %s already exists", peer)
		case m.Name == "":
			return 0, "", fmt.Errorf("a control plane node added at %s has not started yet; start it or remove it first", m.PeerURL)
		}
		parts = append(parts, m.Name+"="+m.PeerURL)
	}
	// etcd refuses changes until every voting member has been connected for
	// a few seconds, e.g. right after a promotion.
	var resp *clientv3.MemberAddResponse
	for {
		resp, err = c.MemberAddAsLearner(ctx, []string{peer})
		if err == nil || !strings.Contains(err.Error(), "unhealthy cluster") {
			break
		}
		select {
		case <-ctx.Done():
			return 0, "", fmt.Errorf("etcd add member: %w", err)
		case <-time.After(time.Second):
		}
	}
	if err != nil {
		return 0, "", fmt.Errorf("etcd add member: %w", err)
	}
	parts = append(parts, name+"="+peer)
	return resp.Member.ID, strings.Join(parts, ","), nil
}

// Promote turns caught-up learners into voting members. A learner that has
// not caught up yet is left for the next call.
func Promote(ctx context.Context, c *clientv3.Client) (promoted []string, err error) {
	members, err := Members(ctx, c)
	if err != nil {
		return nil, err
	}
	for _, m := range members {
		if !m.Learner || m.Name == "" {
			continue
		}
		if _, err := c.MemberPromote(ctx, m.ID); err != nil {
			if strings.Contains(err.Error(), "not in sync") {
				continue
			}
			return promoted, fmt.Errorf("etcd promote %s: %w", m.Name, err)
		}
		promoted = append(promoted, m.Name)
	}
	return promoted, nil
}

// RemoveMember removes the member with the given ID.
func RemoveMember(ctx context.Context, c *clientv3.Client, id uint64) error {
	if _, err := c.MemberRemove(ctx, id); err != nil {
		return fmt.Errorf("etcd remove member: %w", err)
	}
	return nil
}

// WaitVoter returns once the member is a voting member: a server that joined
// starts as a learner, and a learner cannot serve the store.
func (m *Member) WaitVoter(ctx context.Context) error {
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	for m.IsLearner() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
	return nil
}

// electionPrefix holds the leader election, outside the store's prefix.
const electionPrefix = "/armada-leader/"

// Leadership is held by the one control plane node that runs the
// reconcilers and serves the API.
type Leadership struct {
	session  *concurrency.Session
	election *concurrency.Election
}

// Campaign blocks until this node is the leader or ctx ends. Leadership is
// tied to a lease of the given TTL: if the node stops renewing it (it
// crashed or lost its quorum), another node takes over once it expires.
func Campaign(ctx context.Context, c *clientv3.Client, ttl time.Duration, name string) (*Leadership, error) {
	s, err := concurrency.NewSession(c, concurrency.WithTTL(int(ttl/time.Second)), concurrency.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("etcd session: %w", err)
	}
	e := concurrency.NewElection(s, electionPrefix)
	if err := e.Campaign(ctx, name); err != nil {
		_ = s.Close()
		return nil, err
	}
	return &Leadership{session: s, election: e}, nil
}

// Done is closed when leadership is lost.
func (l *Leadership) Done() <-chan struct{} { return l.session.Done() }

// Fence returns the key and creation revision identifying this term: a
// write guarded by them succeeds only while this node is still the leader.
func (l *Leadership) Fence() (key string, rev int64) { return l.election.Key(), l.election.Rev() }

// Resign gives up leadership so another node can take over at once.
func (l *Leadership) Resign(ctx context.Context) error {
	err := l.election.Resign(ctx)
	return errors.Join(err, l.session.Close())
}

// Leader returns the name of the current leader, or "" if there is none.
func Leader(ctx context.Context, c *clientv3.Client) (string, error) {
	resp, err := c.Get(ctx, electionPrefix, clientv3.WithPrefix(), clientv3.WithSort(clientv3.SortByCreateRevision, clientv3.SortAscend), clientv3.WithLimit(1))
	if err != nil {
		return "", err
	}
	if len(resp.Kvs) == 0 {
		return "", nil
	}
	return string(resp.Kvs[0].Value), nil
}

// Cluster manages the membership of the cluster c belongs to.
type Cluster struct{ C *clientv3.Client }

// Members lists the members.
func (c Cluster) Members(ctx context.Context) ([]MemberInfo, error) { return Members(ctx, c.C) }

// AddLearner adds a learner; see AddLearner.
func (c Cluster) AddLearner(ctx context.Context, name string, addr netip.Addr, peerPort int) (uint64, string, error) {
	return AddLearner(ctx, c.C, name, addr, peerPort)
}

// Promote promotes caught-up learners; see Promote.
func (c Cluster) Promote(ctx context.Context) ([]string, error) { return Promote(ctx, c.C) }

// Reachable reports whether the member answers on its client URL.
func (c Cluster) Reachable(ctx context.Context, m MemberInfo) bool {
	u, err := url.Parse(m.ClientURL)
	if err != nil || u.Host == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	_, err = c.C.Status(ctx, u.Host)
	return err == nil
}

// RemoveMember removes a member.
func (c Cluster) RemoveMember(ctx context.Context, id uint64) error {
	return RemoveMember(ctx, c.C, id)
}
