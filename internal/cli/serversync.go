package cli

import (
	"context"
	"net/netip"
	"slices"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/ryanbekhen/armada/internal/clientconfig"
)

// serverSync keeps the client config's control plane addresses current: the
// leader sends them with every answer (clientconfig.ServersHeader), and a
// list that differs from the config's is written back once per process.
// Without it a config made when the cluster had one server would know only
// that one, and stop working once another server leads.
type serverSync struct {
	path    string
	servers []string

	mu   sync.Mutex
	done bool
}

func (s *serverSync) unary(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
	var md metadata.MD
	err := invoker(ctx, method, req, reply, cc, append(opts, grpc.Header(&md))...)
	s.observe(md)
	return err
}

func (s *serverSync) stream(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	var md metadata.MD
	cs, err := streamer(ctx, desc, cc, method, append(opts, grpc.Header(&md))...)
	if err != nil {
		return cs, err
	}
	return &syncedStream{ClientStream: cs, sync: s, md: &md}, nil
}

// syncedStream looks at the header once the first message arrives, when
// grpc.Header has filled it.
type syncedStream struct {
	grpc.ClientStream
	sync *serverSync
	md   *metadata.MD
	once sync.Once
}

func (s *syncedStream) RecvMsg(m any) error {
	err := s.ClientStream.RecvMsg(m)
	s.once.Do(func() { s.sync.observe(*s.md) })
	return err
}

// tunnelled reports whether the config reaches the control plane through a
// loopback address that is no server's own, such as an SSH tunnel: its
// list is the person's to keep, since the servers' addresses may not be
// reachable from here.
func tunnelled(servers, actual []string) bool {
	for _, a := range servers {
		if ap, err := netip.ParseAddrPort(a); err == nil && ap.Addr().IsLoopback() && !slices.Contains(actual, a) {
			return true
		}
	}
	return false
}

// observe saves the leader's list when it differs from the config's. A
// config the caller may not write (a shared one, without sudo) is left as
// it is: commands still work through the addresses the machine knows.
func (s *serverSync) observe(md metadata.MD) {
	vals := md.Get(clientconfig.ServersHeader)
	if len(vals) == 0 || s.path == "" {
		return
	}
	addrs := clientconfig.ParseServers(vals[0])
	if _, err := clientconfig.CheckServers(addrs); err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done || clientconfig.SameServers(addrs, s.servers) || tunnelled(s.servers, addrs) {
		return
	}
	s.done = true
	cc, err := clientconfig.Load(s.path)
	if err != nil {
		return
	}
	cc.Servers = addrs
	if cc.SaveFile(s.path) == nil {
		s.servers = addrs
	}
}
