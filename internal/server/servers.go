package server

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/etcd"
	"github.com/ryanbekhen/armada/internal/netutil"
	"github.com/ryanbekhen/armada/internal/pki"
	"github.com/ryanbekhen/armada/internal/spec"
	"github.com/ryanbekhen/armada/internal/store"
)

// Cluster manages the etcd membership of the control plane nodes.
type Cluster interface {
	Members(ctx context.Context) ([]etcd.MemberInfo, error)
	// AddLearner adds a non-voting member and returns its ID and the
	// initial cluster for its first start.
	AddLearner(ctx context.Context, name string, addr netip.Addr, peerPort int) (uint64, string, error)
	// Promote turns caught-up learners into voting members.
	Promote(ctx context.Context) ([]string, error)
	// Reachable reports whether a member answers.
	Reachable(ctx context.Context, m etcd.MemberInfo) bool
	RemoveMember(ctx context.Context, id uint64) error
}

var _ Cluster = etcd.Cluster{}

// serverView is a control plane node as the leader sees it.
type serverView struct {
	store.Server
	member, voting bool
	info           etcd.MemberInfo
}

// servers joins the recorded control plane nodes with the etcd membership.
// Without a Cluster (tests, or a server started without one) every record
// counts as a voting member.
func (s *Server) servers(ctx context.Context) ([]serverView, error) {
	recs, err := s.store.ListServers(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]serverView, 0, len(recs))
	if s.cluster == nil {
		for _, r := range recs {
			out = append(out, serverView{Server: r, member: true, voting: true})
		}
		return out, nil
	}
	members, err := s.cluster.Members(ctx)
	if err != nil {
		return nil, err
	}
	byID := map[uint64]etcd.MemberInfo{}
	for _, m := range members {
		byID[m.ID] = m
	}
	for _, r := range recs {
		m, ok := byID[r.MemberID]
		out = append(out, serverView{Server: r, member: ok, voting: ok && !m.Learner, info: m})
	}
	return out, nil
}

// endpoints returns the API addresses agents may connect to: every control
// plane node that is an etcd member, in name order (a stable list keeps
// assignments from changing needlessly).
func (s *Server) endpoints(ctx context.Context) ([]string, error) {
	views, err := s.servers(ctx)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, v := range views {
		if v.member && v.APIAddr != "" {
			out = append(out, v.APIAddr)
		}
	}
	if len(out) == 0 && s.apiAddr != "" {
		out = []string{s.apiAddr}
	}
	return out, nil
}

// promoteLearners promotes servers that joined and caught up.
func (s *Server) promoteLearners(ctx context.Context) {
	if s.cluster == nil {
		return
	}
	promoted, err := s.cluster.Promote(ctx)
	if err != nil {
		s.log.Warn("promote joining servers", "err", err)
	}
	for _, name := range promoted {
		s.log.Info("server promoted to a voting member", "server", name)
		s.Trigger()
	}
}

// startTerm prepares the state for a new leadership term. Nodes recorded as
// ready may have been connected to the previous leader, which can no longer
// report them gone: they start over as unknown, last seen now, so a node
// that died together with that leader is still found lost after the
// timeout, and one that reconnects is ready again at once.
func (s *Server) startTerm(ctx context.Context) error {
	nodes, err := s.store.ListNodes(ctx)
	if err != nil {
		return err
	}
	now := s.now()
	for _, n := range nodes {
		if n.State != store.NodeReady || s.session(n.ID) != nil {
			continue
		}
		if err := s.store.SetNodeStatus(ctx, n.ID, store.NodeStatus{State: store.NodeUnknown, LastSeen: now, CPUMillis: n.CPUMillis, MemoryBytes: n.MemoryBytes, MinMemoryBytes: n.MinMemoryBytes, Jobs: n.Jobs}); err != nil {
			return err
		}
	}
	return nil
}

// ListServers lists the control plane nodes.
func (s *Server) ListServers(ctx context.Context, _ *armadav1.ListServersRequest) (*armadav1.ListServersResponse, error) {
	views, err := s.servers(ctx)
	if err != nil {
		return nil, status.Error(codes.Unavailable, "list servers")
	}
	schema, err := s.store.StoredSchema(ctx)
	if err != nil {
		return nil, status.Error(codes.Unavailable, "read state schema")
	}
	resp := &armadav1.ListServersResponse{Servers: make([]*armadav1.ServerInfo, len(views)), StateSchema: int32(schema)} //nolint:gosec // schemas are small
	var wg sync.WaitGroup
	for i, v := range views {
		info := &armadav1.ServerInfo{
			Name: v.Name, PrivateIp: v.PrivateIP, ApiAddr: v.APIAddr,
			Leader: v.Name == s.name, Voting: v.voting, Member: v.member,
			Reachable: v.member && s.cluster == nil,
			Schema:    int32(v.Schema), //nolint:gosec // schemas are small
			Version:   v.Version,
		}
		resp.Servers[i] = info
		if v.member && s.cluster != nil {
			wg.Go(func() { info.Reachable = s.cluster.Reachable(ctx, v.info) })
		}
	}
	wg.Wait()
	return resp, nil
}

// RemoveServer removes a control plane node from the etcd cluster and
// forgets it. Its agent stays a node until `node remove`.
func (s *Server) RemoveServer(ctx context.Context, req *armadav1.RemoveServerRequest) (*armadav1.RemoveServerResponse, error) {
	if s.cluster == nil {
		return nil, status.Error(codes.FailedPrecondition, "server membership is not managed by this server")
	}
	name := req.GetName()
	if name == s.name {
		return nil, status.Errorf(codes.FailedPrecondition, "%s is the leader serving this request; stop it first, and remove it once another server leads", name)
	}
	views, err := s.servers(ctx)
	if err != nil {
		return nil, status.Error(codes.Unavailable, "list servers")
	}
	i := slices.IndexFunc(views, func(v serverView) bool { return v.Name == name })
	if i < 0 {
		return nil, status.Errorf(codes.NotFound, "server %s not found", name)
	}
	if v := views[i]; v.member {
		if err := s.cluster.RemoveMember(ctx, v.MemberID); err != nil {
			return nil, status.Errorf(codes.FailedPrecondition, "%v", err)
		}
	}
	if err := s.store.RemoveServer(ctx, name, actor(ctx)); err != nil {
		return nil, storeErr(err)
	}
	s.log.Info("server removed", "server", name, "by", actor(ctx))
	s.Trigger()
	return &armadav1.RemoveServerResponse{}, nil
}

// JoinServer adds a control plane node presenting a valid server token: it
// registers the server and its node, adds its etcd member as a learner, and
// returns the cluster's keys. The token secret and the keys are never
// logged.
func (j *joinService) JoinServer(ctx context.Context, req *armadav1.JoinServerRequest) (*armadav1.JoinServerResponse, error) {
	s := j.s
	if s.cluster == nil || s.keys == nil {
		return nil, status.Error(codes.FailedPrecondition, "this server cannot add control plane nodes")
	}
	from := "unknown"
	if p, ok := peer.FromContext(ctx); ok {
		from = p.Addr.String()
	}
	tok, err := pki.ParseJoinToken(req.GetTokenId() + "." + req.GetTokenSecret())
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid join token")
	}
	name := req.GetName()
	if err := spec.ValidateName(name); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "server name: %v", err)
	}
	ip, err := netutil.CheckNodeIP(req.GetPrivateIp())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "private IP: %v", err)
	}
	if len(req.GetNodeCsr()) == 0 || len(req.GetNodeCsr()) > maxCSRSize {
		return nil, status.Error(codes.InvalidArgument, "missing or oversized CSR")
	}
	ports := []int32{req.GetApiPort(), req.GetEtcdPeerPort()}
	if req.GetJoinPort() != 0 {
		ports = append(ports, req.GetJoinPort())
	}
	for _, p := range ports {
		if p < 1 || p > 65535 {
			return nil, status.Errorf(codes.InvalidArgument, "invalid port %d", p)
		}
	}
	apiAddr := net.JoinHostPort(ip.String(), strconv.Itoa(int(req.GetApiPort())))
	joinAddr := ""
	if req.GetJoinPort() != 0 {
		joinAddr = net.JoinHostPort(ip.String(), strconv.Itoa(int(req.GetJoinPort())))
	}

	var nodeCert pki.NodeCert
	srv := store.Server{Name: name, PrivateIP: ip.String(), APIAddr: apiAddr, JoinAddr: joinAddr}
	err = s.store.RedeemServerToken(ctx, tok.ID,
		func(hash string) bool { return pki.TokenSecretMatches(tok.Secret, hash) },
		srv, store.Node{ID: name, PrivateIP: ip.String()},
		func() (store.NodeCert, error) {
			var err error
			nodeCert, err = s.ca.SignNodeCSR(req.GetNodeCsr(), name, s.nodeCertValidity)
			return store.NodeCert{Serial: nodeCert.Serial, NotAfter: nodeCert.NotAfter}, err
		})
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.log.Warn("server join rejected: bad token", "token", tok.ID, "server", name, "from", from)
		return nil, status.Error(codes.Unauthenticated, "invalid join token")
	case errors.Is(err, store.ErrConflict):
		return nil, status.Error(codes.AlreadyExists, err.Error())
	case err != nil:
		s.log.Warn("server join failed", "token", tok.ID, "server", name, "from", from, "err", err)
		return nil, status.Errorf(codes.InvalidArgument, "join failed: %v", err)
	}

	// The token is spent; if the rest fails, undo the registration so the
	// name and IP can be used with a new token.
	undo := func(cause error) error {
		uctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		err := errors.Join(s.store.RemoveServer(uctx, name, "token:"+tok.ID), s.store.RemoveNode(uctx, name, true, "token:"+tok.ID))
		s.log.Warn("server join failed", "server", name, "from", from, "err", cause, "cleanup_err", err)
		return status.Errorf(codes.FailedPrecondition, "join failed: %v", cause)
	}
	actx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	memberID, initial, err := s.cluster.AddLearner(actx, name, ip, int(req.GetEtcdPeerPort()))
	if err != nil {
		return nil, undo(err)
	}
	srv.MemberID = memberID
	if err := s.store.UpsertServer(ctx, srv); err != nil {
		_ = s.cluster.RemoveMember(context.WithoutCancel(ctx), memberID)
		return nil, undo(err)
	}
	srvCert, srvKey, err := s.ca.Issue(pki.IssueRequest{
		Identity: pki.Identity{Kind: pki.KindServer, Name: name},
		DNSNames: []string{pki.ServerName},
		IPs:      []net.IP{ip.AsSlice()},
		Server:   true,
	})
	if err != nil {
		return nil, status.Error(codes.Internal, "issue server certificate")
	}
	caKey, err := s.ca.KeyPEM()
	if err != nil {
		return nil, status.Error(codes.Internal, "encode CA key")
	}
	eps, err := s.endpoints(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, "list servers")
	}
	s.log.Info("server joined", "server", name, "private_ip", ip.String(), "token", tok.ID, "version", req.GetVersion())
	s.Trigger()
	return &armadav1.JoinServerResponse{
		CaCert: s.ca.CertPEM, CaKey: caKey, MasterKey: s.keys.Export().Bytes(),
		ServerCert: srvCert, ServerKey: srvKey, NodeCert: nodeCert.PEM,
		InitialCluster: initial, Servers: eps,
	}, nil
}
