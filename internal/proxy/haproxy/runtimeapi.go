package haproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// API is the subset of the HAProxy Runtime API the driver uses.
type API interface {
	Command(ctx context.Context, cmd string) (string, error)
	// Payload sends a command followed by a multi-line payload.
	Payload(ctx context.Context, cmd, payload string) (string, error)
}

// Socket talks to the Runtime API over its Unix socket, one command per
// connection (non-interactive mode).
type Socket struct {
	Path    string
	Timeout time.Duration
}

const maxResponse = 1 << 20

// errorPrefixes are how the Runtime API reports failures; it has no status
// codes.
var errorPrefixes = []string{
	"no such", "unknown", "require", "can't", "cannot", "missing", "invalid",
	"error", "failed", "unable", "not found", "permission denied",
}

// Command runs one Runtime API command.
func (s Socket) Command(ctx context.Context, cmd string) (string, error) {
	if strings.ContainsAny(cmd, "\r\n;") {
		return "", fmt.Errorf("runtime API command must be a single statement")
	}
	return s.send(ctx, cmd+"\n")
}

// Payload runs a command that takes a payload (e.g. "set ssl cert").
func (s Socket) Payload(ctx context.Context, cmd, payload string) (string, error) {
	if strings.ContainsAny(cmd, "\r\n;") {
		return "", fmt.Errorf("runtime API command must be a single statement")
	}
	payload = strings.TrimRight(payload, "\n")
	if strings.Contains(payload, "\n\n") {
		return "", errors.New("payload must not contain empty lines")
	}
	return s.send(ctx, cmd+" <<\n"+payload+"\n\n")
}

func (s Socket) send(ctx context.Context, msg string) (string, error) {
	timeout := s.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	var d net.Dialer
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := d.DialContext(ctx, "unix", s.Path)
	if err != nil {
		return "", fmt.Errorf("haproxy runtime API: %w", err)
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if _, err := io.WriteString(conn, msg); err != nil {
		return "", fmt.Errorf("haproxy runtime API: %w", err)
	}
	b, err := io.ReadAll(io.LimitReader(conn, maxResponse))
	if err != nil {
		return "", fmt.Errorf("haproxy runtime API: %w", err)
	}
	out := strings.TrimSpace(string(b))
	lower := strings.ToLower(out)
	for _, p := range errorPrefixes {
		if strings.HasPrefix(lower, p) {
			return out, fmt.Errorf("haproxy runtime API: %s", out)
		}
	}
	return out, nil
}
