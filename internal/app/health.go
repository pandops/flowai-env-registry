// Package app wires env-registry's process: configuration, database,
// broker connection with retry, subscriptions, relay and HTTP server.
package app

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Health tracks readiness: broker connected, consumers bound and database reachable.
type Health struct {
	ping      func(context.Context) error
	mu        sync.Mutex
	broker    bool
	consumers bool
	gen       uint64 // connection generation, to ignore stale consumer binds
}

// NewHealth returns a Health whose database check is ping.
func NewHealth(ping func(context.Context) error) *Health { return &Health{ping: ping} }

// SetBroker records the broker connection state.
func (h *Health) SetBroker(connected bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.broker = connected
}

// SetConsumers records whether every declared durable consumer is bound.
func (h *Health) SetConsumers(bound bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.consumers = bound
}

// Ready implements httpapi.Readiness.
func (h *Health) Ready(ctx context.Context) error {
	h.mu.Lock()
	broker, consumers := h.broker, h.consumers
	h.mu.Unlock()
	switch {
	case !broker:
		return errors.New("broker not connected")
	case !consumers:
		return errors.New("durable consumers not bound")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := h.ping(ctx); err != nil {
		return errors.New("database unavailable")
	}
	return nil
}

// ConnectWithRetry calls dial until it succeeds or ctx ends, waiting backoff
// between attempts, and reports each outcome to h.
func ConnectWithRetry(ctx context.Context, h *Health, dial func(context.Context) error, backoff time.Duration) error {
	for {
		if err := ctx.Err(); err != nil {
			h.SetBroker(false)
			return err
		}
		if err := dial(ctx); err == nil {
			h.SetBroker(true)
			return nil
		}
		h.SetBroker(false)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
	}
}

// Supervise turns broker connection events into readiness until ctx ends:
// on connect it marks the broker up and calls bind (binding every declared
// durable consumer) until it succeeds, waiting retry between attempts; on
// disconnect it marks the broker and consumers down.
func Supervise(ctx context.Context, h *Health, status <-chan bool, bind func(context.Context) error, retry time.Duration) {
	stop := func() {}
	defer func() { stop() }()
	for {
		select {
		case <-ctx.Done():
			return
		case up, ok := <-status:
			if !ok {
				return
			}
			stop()
			h.mu.Lock()
			h.gen++
			gen := h.gen
			h.broker, h.consumers = up, false
			h.mu.Unlock()
			if !up {
				stop = func() {}
				continue
			}
			bctx, cancel := context.WithCancel(ctx)
			stop = cancel
			go func() {
				for {
					if err := bind(bctx); err == nil {
						h.mu.Lock()
						if h.gen == gen && bctx.Err() == nil {
							h.consumers = true
						}
						h.mu.Unlock()
						return
					}
					select {
					case <-bctx.Done():
						return
					case <-time.After(retry):
					}
				}
			}()
		}
	}
}
