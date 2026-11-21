package app

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // PostgreSQL driver

	"github.com/pandops/flowai-env-registry/internal/broker"
	"github.com/pandops/flowai-env-registry/internal/claimtoken"
	"github.com/pandops/flowai-env-registry/internal/config"
	"github.com/pandops/flowai-env-registry/internal/cursor"
	"github.com/pandops/flowai-env-registry/internal/httpapi"
	"github.com/pandops/flowai-env-registry/internal/migrations"
	"github.com/pandops/flowai-env-registry/internal/outbox"
	"github.com/pandops/flowai-env-registry/internal/secretbox"
	"github.com/pandops/flowai-env-registry/internal/service"
	"github.com/pandops/flowai-env-registry/internal/store"
)

// Durable consumer env-registry binds; the deployment creates it from
// schemas/consumers.json.
const (
	archivedStream  = "ALL_EVENT"
	archivedDurable = "env-registry-task-archived"
	retryWait       = 2 * time.Second
	relayInterval   = 200 * time.Millisecond
)

// Run starts env-registry and blocks until ctx ends.
func Run(ctx context.Context, cfg config.Config, log *slog.Logger) error {
	crypto, err := secretbox.NewLocal(cfg.EncryptionKeys, cfg.ActiveKeyID)
	if err != nil {
		return fmt.Errorf("encryption keys: %w", err)
	}
	claims, err := claimtoken.NewVerifier(cfg.VerificationKey)
	if err != nil {
		return fmt.Errorf("claim token verification key: %w", err)
	}
	cursors, err := cursor.NewCodec(cfg.CursorKeys, cfg.ActiveCursorKey)
	if err != nil {
		return fmt.Errorf("cursor keys: %w", err)
	}
	db, err := sql.Open("pgx", cfg.DB.DSN())
	if err != nil {
		return fmt.Errorf("database: %w", err)
	}
	defer db.Close()
	st := store.NewPostgres(db, cfg.DB.Schema)
	health := NewHealth(st.Ping)

	// Probes answer from the start; readiness stays 503 until everything is
	// up. The open edge is added once the service exists.
	var handler atomic.Pointer[http.Handler]
	setHandler := func(h http.Handler) { handler.Store(&h) }
	setHandler(httpapi.NewRouter(nil, health))
	server := &http.Server{Addr: cfg.HTTPBind, ReadHeaderTimeout: 10 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { (*handler.Load()).ServeHTTP(w, r) })}
	serverErr := make(chan error, 1)
	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()
	defer func() {
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()

	if err := retry(ctx, log, "database migration", func(ctx context.Context) error { return migrations.Apply(ctx, db, cfg.DB.Schema) }); err != nil {
		return err
	}
	var conn *broker.NATS
	dial := func(context.Context) error {
		c, err := broker.DialNATS(broker.NATSOptions{URL: cfg.NATS.URL, CredentialsFile: cfg.NATS.CredsFile, CAFile: cfg.NATS.CAFile, InboxPrefix: cfg.NATS.InboxPrefix})
		if err != nil {
			log.Warn("broker connection failed; retrying", "error_class", fmt.Sprintf("%T", err))
			return err
		}
		conn = c
		return nil
	}
	if err := ConnectWithRetry(ctx, health, dial, retryWait); err != nil {
		return err
	}
	defer conn.Close()

	svc := service.New(service.Deps{Store: st, Crypto: crypto, Claims: claims, Broker: conn, Cursor: cursors, Logger: log, RequestTimeout: cfg.NATS.RequestTimeout})
	if err := conn.ServeQueue(ctx, service.UISubject, service.UIQueue, svc.HandleUI); err != nil {
		return fmt.Errorf("ui subscription: %w", err)
	}
	setHandler(httpapi.NewRouter(svc, health))
	bind := func(ctx context.Context) error {
		err := conn.BindConsumer(ctx, archivedStream, archivedDurable, svc.HandleArchived)
		if err != nil {
			log.Warn("durable consumer not bound; retrying", "durable", archivedDurable)
		}
		return err
	}
	go Supervise(ctx, health, conn.Status(), bind, retryWait)

	relay := &outbox.Relay{Store: st, Publisher: conn, Logger: log}
	ticker := time.NewTicker(relayInterval)
	defer ticker.Stop()
	log.Info("env-registry started", "listen", cfg.HTTPBind)
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-serverErr:
			return fmt.Errorf("http server: %w", err)
		case <-ticker.C:
			_, _ = relay.Flush(ctx)
		}
	}
}

func retry(ctx context.Context, log *slog.Logger, what string, fn func(context.Context) error) error {
	for {
		err := fn(ctx)
		if err == nil {
			return nil
		}
		log.Warn(what+" failed; retrying", "error", err.Error())
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(retryWait):
		}
	}
}
