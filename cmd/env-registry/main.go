// Command env-registry runs the env-registry service.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/pandops/flowai-env-registry/internal/app"
	"github.com/pandops/flowai-env-registry/internal/config"
)

func main() {
	path := flag.String("config", "/etc/flowai/config.yaml", "configuration file")
	flag.Parse()
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("service", "env-registry")
	cfg, err := config.Load(*path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "env-registry:", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := app.Run(ctx, cfg, log); err != nil {
		log.Error("env-registry stopped", "error", err.Error())
		os.Exit(1)
	}
}
