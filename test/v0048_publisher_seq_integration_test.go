//go:build integration

package test

import (
	"context"
	"errors"
	"testing"

	"github.com/pandops/flowai-env-registry/internal/store"
)

// Coverage: "Outbox publisher_seq comes from the service's own sequence in the
// committing transaction: a rolled-back transaction publishes nothing, and a
// restart continues the sequence, so a new message never reuses a
// Nats-Msg-Id" (1.7).

func enqueue(ctx context.Context, s store.Store, fail error) (int64, error) {
	var seq int64
	err := s.InTx(ctx, func(tx store.Tx) error {
		var err error
		seq, err = tx.Enqueue(ctx, "env-registry.audit.secret_created.pub", map[string]string{"team": "3", "request_id": "1"}, func(n int64) ([]byte, error) {
			return []byte(`{"publisher_seq":` + itoa(n) + `}`), nil
		})
		if err != nil {
			return err
		}
		return fail
	})
	return seq, err
}

func TestPublisherSeq(t *testing.T) {
	ctx := context.Background()
	d := newTestDB(t, true)
	s, _ := d.openStore(t)
	first, err := enqueue(ctx, s, nil)
	if err != nil || first < 1 {
		t.Fatalf("first seq %d %v", first, err)
	}
	lost, err := enqueue(ctx, s, errors.New("rollback"))
	if err == nil || lost <= first {
		t.Fatalf("rolled-back seq %d %v", lost, err)
	}
	pending, err := s.PendingOutbox(ctx, 100)
	if err != nil || len(pending) != 1 || pending[0].PublisherSeq != first || pending[0].Header["Nats-Msg-Id"] != "env-registry-"+itoa(first) {
		t.Fatalf("pending %+v %v", pending, err)
	}
	if err := s.MarkOutboxSent(ctx, pending[0].ID); err != nil {
		t.Fatal(err)
	}
	// Restart: a new connection pool on the same database continues the sequence.
	s2, _ := d.openStore(t)
	next, err := enqueue(ctx, s2, nil)
	if err != nil || next <= lost {
		t.Fatalf("seq after restart %d (rolled back %d) %v", next, lost, err)
	}
	pending, _ = s2.PendingOutbox(ctx, 100)
	for _, p := range pending {
		if p.PublisherSeq == lost {
			t.Fatal("the rolled-back seq reached the outbox")
		}
	}
	if len(pending) != 1 || pending[0].PublisherSeq != next || string(pending[0].Payload) != `{"publisher_seq":`+itoa(next)+`}` {
		t.Fatalf("pending after restart %+v", pending)
	}
}
