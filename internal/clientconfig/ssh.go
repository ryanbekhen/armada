package clientconfig

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

// sshDest is what Config.SSH may hold: an ssh(1) destination, [user@]host
// or an alias from ~/.ssh/config, or ssh://[user@]host[:port]. It never
// starts with "-", so ssh cannot read it as an option.
var sshDest = regexp.MustCompile(`^(ssh://)?([A-Za-z0-9._][A-Za-z0-9._-]*@)?[A-Za-z0-9._\[][A-Za-z0-9._:\[\]-]*$`)

// CheckSSH validates the SSH destination a config reaches the control plane
// through.
func CheckSSH(dest string) error {
	if len(dest) > 255 || !sshDest.MatchString(dest) {
		return fmt.Errorf("ssh destination %q: want [user@]host, a host alias from ~/.ssh/config, or ssh://[user@]host[:port]", dest)
	}
	return nil
}

// SSHProgram is the ssh program the dialer runs; tests point it at a stand-in
// (package sshtest).
var SSHProgram = "ssh"

// sshDialer reaches each control plane address through `ssh -W ADDR DEST`,
// the way git reaches a remote: the user's own ssh, with their keys, agent,
// known_hosts, and ~/.ssh/config (ProxyJump included). The API stays on
// the servers' private addresses; mTLS runs end to end inside the SSH
// channel, so the SSH host only relays bytes it can neither read nor change.
func sshDialer(dest string) func(context.Context, string) (net.Conn, error) {
	return func(ctx context.Context, addr string) (net.Conn, error) {
		if strings.HasPrefix(addr, "-") {
			return nil, fmt.Errorf("control plane address %q", addr)
		}
		return dialSSH(ctx, dest, addr)
	}
}

func dialSSH(ctx context.Context, dest, addr string) (net.Conn, error) {
	// Our ends: we read what ssh writes to stdout and write to its stdin.
	outR, outW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	inR, inW, err := os.Pipe()
	if err != nil {
		_ = outR.Close()
		_ = outW.Close()
		return nil, err
	}
	c := &sshConn{r: outR, w: inW, addr: addr, dest: dest}
	// Not CommandContext: gRPC ends ctx once the connection is made, and
	// ssh must live as long as the connection.
	cmd := exec.Command(SSHProgram, "-o", "ExitOnForwardFailure=yes", "-W", addr, "--", dest) //nolint:gosec // dest checked by CheckSSH, addr is an option value; no shell
	cmd.Stdin, cmd.Stdout, cmd.Stderr = inR, outW, &c.stderr
	if err := cmd.Start(); err != nil {
		for _, f := range []*os.File{outR, outW, inR, inW} {
			_ = f.Close()
		}
		return nil, fmt.Errorf("ssh %s: %w", dest, err)
	}
	// The child holds its ends now.
	_ = inR.Close()
	_ = outW.Close()
	c.cmd = cmd
	c.exited = make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(c.exited)
	}()
	select {
	case <-ctx.Done():
		_ = c.Close()
		return nil, ctx.Err()
	default:
	}
	return c, nil
}

// sshConn is a net.Conn over an ssh -W process.
type sshConn struct {
	r, w       *os.File
	cmd        *exec.Cmd
	exited     chan struct{}
	addr, dest string
	stderr     syncBuffer
	closeOnce  sync.Once
}

func (c *sshConn) Read(b []byte) (int, error) {
	n, err := c.r.Read(b)
	if err == io.EOF {
		// ssh exited: say why, from what it printed (no secrets: ssh
		// never prints keys), so "Permission denied" or "Host key
		// verification failed" reaches the person.
		if msg := c.why(); msg != "" {
			return n, fmt.Errorf("ssh %s to %s: %s", c.dest, c.addr, msg)
		}
	}
	return n, err
}

func (c *sshConn) why() string {
	select {
	case <-c.exited:
	case <-time.After(100 * time.Millisecond):
	}
	lines := strings.Split(strings.TrimSpace(c.stderr.String()), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

func (c *sshConn) Write(b []byte) (int, error) { return c.w.Write(b) }

func (c *sshConn) Close() error {
	c.closeOnce.Do(func() {
		_ = c.w.Close()
		_ = c.r.Close()
		if c.cmd != nil && c.cmd.Process != nil {
			select {
			case <-c.exited:
			case <-time.After(time.Second):
				_ = c.cmd.Process.Kill()
			}
		}
	})
	return nil
}

func (c *sshConn) LocalAddr() net.Addr  { return sshAddr("ssh") }
func (c *sshConn) RemoteAddr() net.Addr { return sshAddr(c.addr) }

func (c *sshConn) SetDeadline(t time.Time) error {
	return errors.Join(c.r.SetReadDeadline(t), c.w.SetWriteDeadline(t))
}
func (c *sshConn) SetReadDeadline(t time.Time) error  { return c.r.SetReadDeadline(t) }
func (c *sshConn) SetWriteDeadline(t time.Time) error { return c.w.SetWriteDeadline(t) }

type sshAddr string

func (a sshAddr) Network() string { return "ssh" }
func (a sshAddr) String() string  { return string(a) }

// syncBuffer collects ssh's stderr while it runs, at most 4 KiB.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if room := 4096 - s.b.Len(); room > 0 {
		s.b.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}
