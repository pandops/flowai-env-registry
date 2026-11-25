package test

import (
	"strings"
	"testing"
)

// Requirement: service-platform service sends human actions to audit and others to journal.
// "Forwarded administrator action is audited by its owner" is not applicable
// to env-registry: it serves no administrator operation.
func TestServicePlatformServiceSendsHumanActionsToAudit(t *testing.T) {
	t.Run("Operator cancels a task", func(t *testing.T) {
		// env-registry's counterpart: one operator mutation, one audit message.
		e := newEnv(t)
		id := e.createTeam(3, "team", map[string]string{"A": "1"})
		before := len(e.store.Outbox())
		e.ui("replace", 3, map[string]any{"team_id": 3, "environment_id": id}, map[string]any{"scope": "team", "name": "team", "env": map[string]string{"A": "2"}})
		rows := e.store.Outbox()[before:]
		if len(rows) != 1 || rows[0].Subject != "env-registry.audit.launch_parameters_replaced.pub" {
			t.Fatalf("replace published %+v", rows)
		}
		a := e.outboxPayloads("env-registry.audit.launch_parameters_replaced.pub")[0]
		if a["outcome"] != "succeeded" || a["actor_type"] != "operator" || num(t, a, "resource_id") != id || a["source_service"] != "env-registry" {
			t.Fatalf("audit %v", a)
		}
	})

	t.Run("Rejected human action is audited", func(t *testing.T) {
		e := newEnv(t)
		id := e.createTeam(3, "team", map[string]string{"A": "1"})
		before := len(e.store.Outbox())
		conflict := e.ui("create", 3, map[string]any{"team_id": 3}, map[string]any{"scope": "team", "name": "second", "env": map[string]string{}})
		foreign := e.ui("replace", 4, map[string]any{"team_id": 4, "environment_id": id}, map[string]any{"scope": "team", "name": "x", "env": map[string]string{}})
		if conflict.Status != 409 || conflict.code() != "scope_conflict" || foreign.Status != 404 {
			t.Fatalf("rejections %d %s / %d %s", conflict.Status, conflict.Raw, foreign.Status, foreign.Raw)
		}
		rows := e.store.Outbox()[before:]
		if len(rows) != 2 {
			t.Fatalf("rejections published %d messages, want one each", len(rows))
		}
		for _, row := range rows {
			if !strings.HasPrefix(row.Subject, "env-registry.audit.") {
				t.Fatalf("rejection published %s", row.Subject)
			}
		}
		for _, a := range e.outboxPayloads("env-registry.audit.") {
			if a["action"] == "launch_parameters_created" && num(t, a, "team_id") == 3 && a["outcome"] == "rejected" && a["reason"] == "scope_conflict" {
				continue
			}
			if a["action"] == "launch_parameters_replaced" && num(t, a, "team_id") == 4 && a["outcome"] == "rejected" && a["reason"] == "environment_unknown_or_unavailable" {
				continue
			}
			if a["outcome"] == "succeeded" {
				continue
			}
			t.Fatalf("unexpected rejection audit %v", a)
		}
		if d := e.store.Definitions(); len(d) != 1 || d[0].Revision != 1 {
			t.Fatalf("rejected actions changed data: %+v", d)
		}
	})

	t.Run("Executor event goes to journal", func(t *testing.T) {
		e := newEnv(t)
		e.createTeam(3, "team", map[string]string{"A": "1"})
		before := len(e.store.Outbox())
		c := claim(1, 1, 1)
		e.setClaim(c, 1, true)
		openValues(t, e.open("1", e.token(c)))
		rows := e.store.Outbox()[before:]
		if len(rows) != 1 || rows[0].Subject != "env-registry.event.launch_parameters_open.pub" {
			t.Fatalf("Executor open published %+v, want only the journal event", rows)
		}
	})
}
