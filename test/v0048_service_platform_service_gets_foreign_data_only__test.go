package test

import (
	"context"
	"testing"

	"github.com/pandops/flowai-env-registry/internal/broker"
)

// Requirement: service-platform service gets foreign data only from the broker.
func TestServicePlatformServiceGetsForeignDataOnlyFromTheBroker(t *testing.T) {
	t.Run("Team archive reaches a projection", func(t *testing.T) {
		// env-registry's foreign projection is task-manager's archived event:
		// it deletes the task's snapshots without asking task-manager.
		e := newEnv(t)
		e.createTeam(3, "team", map[string]string{"A": "1"})
		c := claim(5, 1, 1)
		e.setClaim(c, 1, true)
		openValues(t, e.open("5", e.token(c)))
		requestsBefore := len(e.broker.Requests())
		if got := e.svc.HandleArchived(context.Background(), archivedMsg(10, 3, 5)); got != broker.Ack {
			t.Fatalf("archived decision %v", got)
		}
		if len(e.store.Snapshots()) != 0 {
			t.Fatalf("snapshots kept: %+v", e.store.Snapshots())
		}
		if len(e.broker.Requests()) != requestsBefore {
			t.Fatal("projection update asked another service")
		}
		// A payload naming another team than its header is acknowledged and not applied.
		retry := claim(5, 2, 1)
		e.setClaim(retry, 1, true)
		openValues(t, e.open("5", e.token(retry)))
		bad := archivedMsg(11, 3, 5)
		bad.Header["team"] = "4"
		if got := e.svc.HandleArchived(context.Background(), bad); got != broker.Ack && got != broker.Term {
			t.Fatalf("mismatched archived decision %v", got)
		}
		if len(e.store.Snapshots()) != 1 {
			t.Fatal("a mismatched archived event deleted a snapshot")
		}
	})

	t.Run("Projection ignores a replayed event", func(t *testing.T) {
		e := newEnv(t)
		e.createTeam(3, "team", map[string]string{"A": "1"})
		c1 := claim(5, 1, 1)
		e.setClaim(c1, 1, true)
		openValues(t, e.open("5", e.token(c1)))
		if got := e.svc.HandleArchived(context.Background(), archivedMsg(10, 3, 5)); got != broker.Ack {
			t.Fatalf("first delivery %v", got)
		}
		// A snapshot frozen after the first application survives the replay.
		c2 := claim(5, 2, 1)
		e.setClaim(c2, 1, true)
		openValues(t, e.open("5", e.token(c2)))
		if got := e.svc.HandleArchived(context.Background(), archivedMsg(10, 3, 5)); got != broker.Ack {
			t.Fatalf("replayed delivery %v", got)
		}
		if s := e.store.Snapshots(); len(s) != 1 || s[0].Attempt != 2 {
			t.Fatalf("replay applied again: %+v", s)
		}
	})
}
