// Command armadad runs on every machine of an Armada cluster: the control
// plane, the node agent, and the embedded container runtime.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/ryanbekhen/armada/internal/daemon"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := daemon.Execute(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
