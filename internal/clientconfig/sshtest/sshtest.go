// Package sshtest stands in for ssh(1) in tests. A test binary whose
// TestMain calls Main, and whose path is clientconfig.SSHProgram, acts as
// `ssh -W ADDR DEST` when the SSH dialer starts it: it connects to ADDR
// directly and relays stdin and stdout.
package sshtest

import (
	"fmt"
	"io"
	"net"
	"os"
)

// Host is the only destination the stand-in reaches; any other fails like
// an unknown host, so a test that succeeds went through the configured host.
const Host = "bastion.test"

// Main acts as ssh and exits when the arguments are the dialer's
// (`-o ExitOnForwardFailure=yes -W ADDR -- DEST`); otherwise it returns.
func Main() {
	a := os.Args
	if len(a) != 7 || a[1] != "-o" || a[3] != "-W" || a[5] != "--" {
		return
	}
	addr, dest := a[4], a[6]
	if dest != Host && dest != "ops@"+Host {
		fmt.Fprintf(os.Stderr, "ssh: Could not resolve hostname %s: Name or service not known\n", dest)
		os.Exit(255)
	}
	c, err := net.Dial("tcp", addr) //nolint:gosec // a test stand-in for ssh -W: it dials what the test asked for
	if err != nil {
		fmt.Fprintf(os.Stderr, "channel 0: open failed: connect failed: %v\n", err)
		os.Exit(255)
	}
	go func() {
		_, _ = io.Copy(c, os.Stdin)
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	_, _ = io.Copy(os.Stdout, c)
	os.Exit(0)
}
