package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	runtimepkg "github.com/arcelo/rtbh-panel/internal/runtime"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		slog.Error("rtbh server stopped", "error", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	flags := flag.NewFlagSet("rtbh-server", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	config, err := runtimepkg.LoadServerConfig(flags, args)
	if err != nil {
		return err
	}
	server, err := runtimepkg.NewServer(config)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	slog.Info("starting rtbh server", "http", config.HTTPListenAddress, "bgp", config.BGPListenAddress, "sync", config.SyncListenAddress, "dry_run", config.DryRun)
	if err := server.Run(ctx); err != nil {
		return fmt.Errorf("run server: %w", err)
	}
	return nil
}
