// Command armadad runs on every machine of an Armada cluster: the control
// plane, the node agent, and the embedded container runtime. Run as armada
// (the link install.sh and armadad upgrade make next to it), it is the
// client, whose code it carries anyway, so a machine holds that code once.
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

// command is the client when the binary was run by the name armada, and the
// daemon otherwise.
func command(argv0 string) func(context.Context, []string, io.Writer, io.Writer) int {
	if filepath.Base(argv0) == "armada" {
		return cli.Execute
	}
	return daemon.Execute
}
