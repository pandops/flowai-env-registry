// Package outbox relays committed outbox rows to JetStream in commit order.
package outbox

import (
	"context"
	"log/slog"

	"github.com/pandops/flowai-env-registry/internal/broker"
	"github.com/pandops/flowai-env-registry/internal/store"
)

const batch = 100

// Relay publishes pending rows and marks each sent after its acknowledgement.
type Relay struct {
	Store     store.Store
	Publisher broker.StreamPublisher
	Logger    *slog.Logger
}

// Flush publishes every pending row once, in order, stopping at the first failure.
func (r *Relay) Flush(ctx context.Context) (int, error) {
	sent := 0
	for {
		rows, err := r.Store.PendingOutbox(ctx, batch)
		if err != nil {
			return sent, err
		}
		for _, row := range rows {
			if err := r.Publisher.PublishStream(ctx, row.Subject, broker.Header(row.Header), row.Payload); err != nil {
				r.log().Warn("outbox publish failed; will retry", "subject", row.Subject, "publisher_seq", row.PublisherSeq)
				return sent, err
			}
			if err := r.Store.MarkOutboxSent(ctx, row.ID); err != nil {
				// Published but not marked: the retry republishes under the same Nats-Msg-Id.
				return sent, err
			}
			sent++
		}
		if len(rows) < batch {
			return sent, nil
		}
	}
}

func (r *Relay) log() *slog.Logger {
	if r.Logger == nil {
		return slog.New(slog.DiscardHandler)
	}
	return r.Logger
}
