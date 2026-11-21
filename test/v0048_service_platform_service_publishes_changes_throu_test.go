package test

import (
	"testing"
)

// Requirement: service-platform service publishes changes through an outbox.
func TestServicePlatformServicePublishesChangesThroughAnOutbox(t *testing.T) {
	t.Run("Rolled-back change publishes nothing", func(t *testing.T) {
		e := newEnv(t)
		id := e.createTeam(3, "team", map[string]string{"A": "1"})
		flushAll(t, e)
		e.store.FailNextCommit(errInjected)
		r := e.ui("replace", 3, map[string]any{"team_id": 3, "environment_id": id}, map[string]any{"scope": "team", "name": "team", "env": map[string]string{"A": "2"}})
		if r.Status < 500 {
			t.Fatalf("replace with failed commit: %d %s", r.Status, r.Raw)
		}
		e.store.FailNextCommit(errInjected)
		if r := e.ui("create-secret", 3, map[string]any{"team_id": 3, "environment_id": id}, map[string]any{"key": "S", "value": secretCanary}); r.Status < 500 {
			t.Fatalf("create-secret with failed commit: %d %s", r.Status, r.Raw)
		}
		flushAll(t, e)
		if len(e.store.Outbox()) != 1 || len(e.broker.Published()) != 1 {
			t.Fatalf("rolled-back changes reached the outbox or broker: %d rows, %d published", len(e.store.Outbox()), len(e.broker.Published()))
		}
		if d := e.store.Definitions(); d[0].Revision != 1 || d[0].Env["A"] != "1" || len(e.store.Secrets()) != 0 {
			t.Fatalf("rolled-back change persisted: %+v", d)
		}
	})
}
