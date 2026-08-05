package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/pgsty/sow/internal/v2cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := v2cli.MainContext(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
