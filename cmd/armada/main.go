// Command armada is the client: it manages apps on an Armada cluster through
// the control plane's API.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/ryanbekhen/armada/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli.Execute(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
