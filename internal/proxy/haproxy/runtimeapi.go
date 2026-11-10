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

// maxResponse bounds a reply. Replies grow with the cluster (a row per
// server in "show stat"), so the bound is generous, and a reply past it is
// an error rather than a silently shorter answer.
var maxResponse = 128 << 20

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
	if err := checkPayload(payload); err != nil {
		return "", err
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
	b, err := io.ReadAll(io.LimitReader(conn, int64(maxResponse)+1))
	if err != nil {
		return "", fmt.Errorf("haproxy runtime API: %w", err)
	}
	if len(b) > maxResponse {
		return "", fmt.Errorf("haproxy runtime API: reply larger than %d bytes", maxResponse)
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

// checkPayload refuses a payload with an empty line: the Runtime API reads
// one as its end, and the rest as further commands.
func checkPayload(payload string) error {
	if strings.Contains(strings.TrimRight(payload, "\n"), "\n\n") {
		return errors.New("payload must not contain empty lines")
	}
	return nil
}

// pemPayload is a PEM bundle without empty or whitespace-only lines, which
// PEM readers skip anyway; issued bundles have them between blocks.
func pemPayload(b []byte) string {
	var out strings.Builder
	for line := range strings.Lines(string(b)) {
		if strings.TrimSpace(line) == "" {
			continue
		}
		out.WriteString(strings.TrimRight(line, "\r\n"))
		out.WriteByte('\n')
	}
	return out.String()
}
