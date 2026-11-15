package cli

import (
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// A server error can carry a file name an app chose; it must not reach the
// terminal as control sequences.
func TestRPCErrorReplacesControlCharacters(t *testing.T) {
	t.Parallel()
	msg := "archive volume: statat \"g\x1b]0;TITLE\x07\x1b[2K\": no such file or directory\r"
	got := RPCError(status.Error(codes.FailedPrecondition, msg)).Error()
	if strings.ContainsFunc(got, func(r rune) bool { return r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) }) {
		t.Errorf("control characters left: %q", got)
	}
	if !strings.Contains(got, "TITLE") || !strings.HasPrefix(got, "archive volume: ") {
		t.Errorf("message lost: %q", got)
	}
	// The server lists a spec's problems one per line.
	if got := RPCError(status.Error(codes.InvalidArgument, "a: bad\nb: \u009bbad")).Error(); got != "a: bad\nb:  bad" {
		t.Errorf("lines: %q", got)
	}
	plain := errors.New("dial: refused")
	if !errors.Is(RPCError(plain), plain) {
		t.Error("a local error was changed")
	}
}
