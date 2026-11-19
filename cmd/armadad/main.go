// Command armadad runs on every machine of an Armada cluster: the control
// plane, the node agent, and the embedded container runtime. The client is
// the separate armada binary.
package main

import (
	"context"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/ryanbekhen/armada/internal/cli"
	"github.com/ryanbekhen/armada/internal/daemon"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := command(os.Args[0])(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

// command is the daemon, or the client when the binary was run by the name
// armada: v0.1.0-alpha.35 installed armada as a link to armadad, and its
// armadad upgrade still does so once more; the next upgrade puts the client
// binary back. Remove this once no release that makes the link is supported.
func command(argv0 string) func(context.Context, []string, io.Writer, io.Writer) int {
	if filepath.Base(argv0) == "armada" {
		return cli.Execute
	}
	return daemon.Execute
}
