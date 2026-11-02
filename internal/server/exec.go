package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/runtime"
	"github.com/ryanbekhen/armada/internal/store"
)

// execIdleTimeout ends an exec session without input or output (ADR 0017).
const execIdleTimeout = 30 * time.Minute

// Exec runs a command in one replica of an app (ADR 0017): it picks the
// replica, asks its node's agent to open a session, and relays between the
// admin's stream and the agent's. The command's arguments are never logged
// or audited, only its name.
func (s *Server) Exec(stream armadav1.AdminService_ExecServer) error {
	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	start := first.GetStart()
	if start == nil {
		return status.Error(codes.InvalidArgument, "the first message must be start")
	}
	if err := runtime.CheckExecCommand(start.GetCmd()); err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	app, err := s.store.GetApp(ctx, start.GetApp())
	if err != nil {
		return storeErr(err)
	}
	r, err := s.execReplica(ctx, app, start.GetReplica())
	if err != nil {
		return err
	}
	sess := s.session(r.NodeID)
	if sess == nil {
		return status.Errorf(codes.Unavailable, "node %s is not connected", r.NodeID)
	}

	name := filepath.Base(start.GetCmd()[0])
	if err := s.store.RecordAudit(ctx, actor(ctx), "app.exec", app.Name, fmt.Sprintf("replica=%s command=%s tty=%t", r.ID, name, start.GetTty())); err != nil {
		return storeErr(err)
	}
	s.log.Info("exec", "app", app.Name, "replica", r.ID, "node", r.NodeID, "command", name, "tty", start.GetTty(), "by", actor(ctx))

	id, p := s.execs.register(r.NodeID)
	defer s.execs.cancel(id, p)
	// Nothing may send on the agent's stream once its handler has returned,
	// which closing p.done allows; this defer runs before that one.
	var agentMu sync.Mutex
	agentOpen := true
	defer func() {
		agentMu.Lock()
		agentOpen = false
		agentMu.Unlock()
	}()
	if !sess.offer(&armadav1.ServerMessage{Msg: &armadav1.ServerMessage_ExecRequest{ExecRequest: &armadav1.ExecRequest{
		RequestId: id, ReplicaId: r.ID, Cmd: start.GetCmd(), Tty: start.GetTty(), Stdin: start.GetStdin(), Size: start.GetSize(),
	}}}) {
		return status.Errorf(codes.Unavailable, "node %s did not accept the exec request", r.NodeID)
	}
	var agent armadav1.AgentService_ExecSessionServer
	select {
	case agent = <-p.attached:
	case <-time.After(attachTimeout):
		return status.Errorf(codes.Unavailable, "node %s did not start the exec session", r.NodeID)
	case <-ctx.Done():
		return ctx.Err()
	}

	// The agent's first message carried the request ID; an error there
	// means the command did not start.
	if e := p.first.GetError(); e != "" {
		return status.Error(codes.FailedPrecondition, e)
	}
	if err := stream.Send(&armadav1.ExecServerMessage{Msg: &armadav1.ExecServerMessage_Replica{Replica: r.ID}}); err != nil {
		return err
	}

	// end records why the session ended early, then cancels it.
	reason := make(chan error, 1)
	end := func(err error) {
		select {
		case reason <- err:
		default:
		}
		cancel()
	}
	var last atomic.Int64
	touch := func() { last.Store(time.Now().UnixNano()) }
	touch()
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				if time.Since(time.Unix(0, last.Load())) > execIdleTimeout {
					end(status.Error(codes.DeadlineExceeded, "exec session idle for too long"))
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	// Admin input to the agent.
	go func() {
		defer cancel()
		for {
			m, err := stream.Recv()
			if err != nil {
				if errors.Is(err, io.EOF) {
					// The CLI has nothing more to send; output may follow.
					<-ctx.Done()
				}
				return
			}
			in := m.GetInput()
			if in == nil || len(in.GetStdin()) > runtime.MaxExecChunk {
				end(status.Error(codes.InvalidArgument, "expected input of at most 32 KiB"))
				return
			}
			touch()
			agentMu.Lock()
			err = io.ErrClosedPipe
			if agentOpen {
				err = agent.Send(in)
			}
			agentMu.Unlock()
			if err != nil {
				end(status.Error(codes.Unavailable, "the node ended the exec session"))
				return
			}
		}
	}()
	// Agent output to the admin.
	out := make(chan *armadav1.ExecSessionOutput)
	go func() {
		defer close(out)
		for {
			m, err := agent.Recv()
			if err != nil {
				return
			}
			select {
			case out <- m:
			case <-ctx.Done():
				return
			}
		}
	}()
	for {
		select {
		case m, ok := <-out:
			if !ok {
				return status.Error(codes.Unavailable, "the node ended the exec session")
			}
			touch()
			var msg *armadav1.ExecServerMessage
			switch o := m.GetOutput().(type) {
			case *armadav1.ExecSessionOutput_Stdout:
				msg = &armadav1.ExecServerMessage{Msg: &armadav1.ExecServerMessage_Stdout{Stdout: o.Stdout}}
			case *armadav1.ExecSessionOutput_Stderr:
				msg = &armadav1.ExecServerMessage{Msg: &armadav1.ExecServerMessage_Stderr{Stderr: o.Stderr}}
			case *armadav1.ExecSessionOutput_ExitCode:
				return stream.Send(&armadav1.ExecServerMessage{Msg: &armadav1.ExecServerMessage_ExitCode{ExitCode: o.ExitCode}})
			case *armadav1.ExecSessionOutput_Error:
				return status.Error(codes.FailedPrecondition, o.Error)
			default:
				continue
			}
			if err := stream.Send(msg); err != nil {
				return err
			}
		case <-ctx.Done():
			select {
			case err := <-reason:
				return err
			default:
				return stream.Context().Err()
			}
		}
	}
}

// execReplica returns the replica to run a command in: the one named, or a
// running, ready replica of the serving revision.
func (s *Server) execReplica(ctx context.Context, app store.App, replica string) (store.Replica, error) {
	reps, err := s.store.ListReplicas(ctx, store.ReplicaFilter{App: app.Name})
	if err != nil {
		return store.Replica{}, storeErr(err)
	}
	for _, r := range reps {
		if replica != "" && r.ID == replica {
			if r.State != store.ReplicaRunning {
				return store.Replica{}, status.Errorf(codes.FailedPrecondition, "replica %s is %s, not running", r.ID, r.State)
			}
			return r, nil
		}
	}
	if replica != "" {
		return store.Replica{}, status.Errorf(codes.NotFound, "replica %s not found in app %s", replica, app.Name)
	}
	for _, r := range reps {
		if r.Revision == app.ActiveRevision && r.State == store.ReplicaRunning && r.Ready && r.DrainingSince.IsZero() {
			return r, nil
		}
	}
	return store.Replica{}, status.Errorf(codes.FailedPrecondition, "app %s has no running, ready replica of its serving revision; name one with --replica", app.Name)
}

// ExecSession receives the session stream for a pending exec request from
// the agent it was sent to, and holds it until the admin side is done.
func (s *Server) ExecSession(stream armadav1.AgentService_ExecSessionServer) error {
	id, _ := IdentityFrom(stream.Context())
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	p := s.execs.attach(first.GetRequestId(), id.Name, first, stream)
	if p == nil {
		return status.Error(codes.PermissionDenied, "unknown exec request")
	}
	select {
	case <-p.done:
		return nil
	case <-stream.Context().Done():
		return stream.Context().Err()
	}
}

// execRouter pairs admin exec requests with the agent streams that serve
// them, like logRouter.
type execRouter struct {
	mu      sync.Mutex
	pending map[string]*pendingExec
}

type pendingExec struct {
	nodeID string
	// first is the agent's first message, set before attached delivers.
	first    *armadav1.ExecSessionOutput
	attached chan armadav1.AgentService_ExecSessionServer
	done     chan struct{} // closed by the admin side
}

func newExecRouter() *execRouter { return &execRouter{pending: map[string]*pendingExec{}} }

func (r *execRouter) register(nodeID string) (string, *pendingExec) {
	id := randomID(20)
	p := &pendingExec{nodeID: nodeID, attached: make(chan armadav1.AgentService_ExecSessionServer, 1), done: make(chan struct{})}
	r.mu.Lock()
	r.pending[id] = p
	r.mu.Unlock()
	return id, p
}

// attach claims a pending request for nodeID with the agent's stream. Each
// request can be attached once, and only by the node it was sent to.
func (r *execRouter) attach(id, nodeID string, first *armadav1.ExecSessionOutput, stream armadav1.AgentService_ExecSessionServer) *pendingExec {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.pending[id]
	if !ok || p.nodeID != nodeID {
		return nil
	}
	delete(r.pending, id)
	p.first = first
	p.attached <- stream
	return p
}

func (r *execRouter) cancel(id string, p *pendingExec) {
	r.mu.Lock()
	delete(r.pending, id)
	r.mu.Unlock()
	close(p.done)
}
