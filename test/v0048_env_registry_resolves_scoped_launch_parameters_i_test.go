package test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/pandops/flowai-env-registry/internal/broker"
	"github.com/pandops/flowai-env-registry/internal/store"
)

// archivedMsg is task-manager's archived event as env-registry consumes it.
func archivedMsg(seq, team, task int64) broker.Msg {
	payload := map[string]any{
		"publisher": "task-manager", "publisher_seq": seq, "team_id": team, "task_id": task,
		"kind": "archived", "occurred_at": "2026-11-07T10:00:00.000Z", "task_name": taskName(team, task),
		"flow_id": 1, "source_id": 1, "final_state": "finished", "final_reason": nil, "attempts": 2,
	}
	data, _ := json.Marshal(payload)
	return broker.Msg{
		Subject: "task-manager.event.archived.sub",
		Header:  broker.Header{"team": itoa(team), "Nats-Msg-Id": "task-manager-" + itoa(seq)},
		Data:    data,
	}
}

// taskName is the fixture task name, unique per team and task: team<team_id>-<task_id>.
func taskName(team, task int64) string {
	return "team" + itoa(team) + "-" + itoa(task)
}

// Requirement: env-registry resolves scoped launch parameters into a per-attempt snapshot.
func TestEnvRegistryResolvesScopedLaunchParametersIntoSnapshots(t *testing.T) {
	t.Run("Flow parameters apply inside one team", func(t *testing.T) {
		e := newEnv(t)
		e.seedGlobal(map[string]string{"A": "global", "B": "global", "C": "global", "OPENAI_MODEL": "never"})
		team := e.createTeam(3, "team", map[string]string{"B": "team", "C": "team"})
		e.createSecret(3, team, "S", secretCanary)
		flow := e.createFlow(3, 2, "flow", map[string]string{"C": "flow", "S": "flow-plain"})
		_ = flow
		e.createFlow(4, 2, "other team flow 2", map[string]string{"C": "team4"})
		c := claim(1, 1, 1)
		e.setClaim(c, 2, true)
		v := openValues(t, e.open("1", e.token(c)))
		want := map[string]string{"A": "global", "B": "team", "C": "flow", "S": "flow-plain"}
		if len(v) != len(want) {
			t.Fatalf("values %v, want %v", v, want)
		}
		for k, w := range want {
			if v[k] != w {
				t.Fatalf("values %v, want %v", v, want)
			}
		}
		// A narrower secret replaces a broader ordinary value of the same name.
		e.createSecret(3, flow, "B", secretCanary2)
		c2 := claim(2, 1, 1)
		e.setClaim(c2, 2, true)
		if v := openValues(t, e.open("2", e.token(c2))); v["B"] != secretCanary2 {
			t.Fatalf("flow secret did not replace team value: %v", v)
		}
		// Team 3's tasks of another Flow do not get Flow 2's values.
		c3 := claim(3, 1, 1)
		e.setClaim(c3, 1, true)
		if v := openValues(t, e.open("3", e.token(c3))); v["C"] != "team" {
			t.Fatalf("Flow 1 task %v", v)
		}
	})

	t.Run("Definition changes after the first open of an attempt", func(t *testing.T) {
		e := newEnv(t)
		id := e.createTeam(3, "team", map[string]string{"A": "before"})
		sid := e.createSecret(3, id, "S", secretCanary)
		c := claim(1, 1, 1)
		e.setClaim(c, 1, true)
		first := openValues(t, e.open("1", e.token(c)))
		e.ui("replace", 3, map[string]any{"team_id": 3, "environment_id": id}, map[string]any{"scope": "team", "name": "team", "env": map[string]string{"A": "after", "NEW": "x"}})
		e.ui("replace-secret", 3, map[string]any{"team_id": 3, "environment_id": id, "secret_id": sid}, map[string]any{"value": secretCanary2})
		again := openValues(t, e.open("1", e.token(c)))
		if again["A"] != "before" || again["S"] != secretCanary || again["NEW"] != "" || len(again) != len(first) {
			t.Fatalf("second open of attempt 1 %v, first %v", again, first)
		}
		snaps := e.store.Snapshots()
		if len(snaps) != 1 || len(snaps[0].Secrets) != 1 || snaps[0].Secrets[0].Version != 1 {
			t.Fatalf("snapshots %+v", snaps)
		}
	})

	t.Run("Released claim reuses the attempt snapshot", func(t *testing.T) {
		e := newEnv(t)
		id := e.createTeam(3, "team", map[string]string{"A": "frozen"})
		c1 := claim(1, 1, 1)
		e.setClaim(c1, 1, true)
		openValues(t, e.open("1", e.token(c1)))
		e.setClaim(c1, 1, false) // released
		e.ui("replace", 3, map[string]any{"team_id": 3, "environment_id": id}, map[string]any{"scope": "team", "name": "team", "env": map[string]string{"A": "changed"}})
		c2 := claim(1, 1, 2)
		e.setClaim(c2, 1, true)
		if v := openValues(t, e.open("1", e.token(c2))); v["A"] != "frozen" {
			t.Fatalf("claim 2 of attempt 1 got %v", v)
		}
		if len(e.store.Snapshots()) != 1 {
			t.Fatal("a second snapshot was frozen for attempt 1")
		}
	})

	t.Run("Retry attempt freezes a new snapshot", func(t *testing.T) {
		e := newEnv(t)
		id := e.createTeam(3, "team", map[string]string{"A": "attempt1"})
		c1 := claim(1, 1, 1)
		e.setClaim(c1, 1, true)
		openValues(t, e.open("1", e.token(c1)))
		e.setClaim(c1, 1, false)
		e.ui("replace", 3, map[string]any{"team_id": 3, "environment_id": id}, map[string]any{"scope": "team", "name": "team", "env": map[string]string{"A": "attempt2"}})
		c2 := claim(1, 2, 1)
		e.setClaim(c2, 1, true)
		if v := openValues(t, e.open("1", e.token(c2))); v["A"] != "attempt2" {
			t.Fatalf("attempt 2 got %v", v)
		}
		if len(e.store.Snapshots()) != 2 {
			t.Fatalf("snapshots %+v", e.store.Snapshots())
		}
	})

	t.Run("Task without launch values", func(t *testing.T) {
		e := newEnv(t)
		e.createTeam(4, "other team", map[string]string{"A": "1"})
		c := claim(1, 1, 1)
		e.setClaim(c, 1, true)
		r := e.open("1", e.token(c))
		if r.Status != 200 || strings.TrimSpace(string(r.Body)) != `{"values":{}}` {
			t.Fatalf("empty open: %d %s", r.Status, r.Body)
		}
		if err := validateJSON(t, "executor.launch-parameters-open.reply.schema.json", r.Body); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("Declared secret has no stored version", func(t *testing.T) {
		e := newEnv(t)
		id := e.createTeam(3, "team", map[string]string{"A": "1"})
		// A logical secret declared without a stored encrypted version.
		err := e.store.InTx(context.Background(), func(tx store.Tx) error {
			sid, err := tx.NextTeamNumber(context.Background(), 3, store.KindSecret)
			if err != nil {
				return err
			}
			return tx.InsertSecret(context.Background(), store.Secret{TeamID: 3, SecretID: sid, EnvironmentID: id, Key: "DB_PASSWORD", LatestVersion: 0})
		})
		if err != nil {
			t.Fatal(err)
		}
		c := claim(1, 1, 1)
		e.setClaim(c, 1, true)
		r := e.open("1", e.token(c))
		b := openBody(t, r)
		if r.Status != 422 || b["code"] != "configuration_error" || b["failure_reason"] != "missing_required_parameter" || b["missing_parameter"] != "DB_PASSWORD" {
			t.Fatalf("open with a declared secret without version: %d %s", r.Status, r.Body)
		}
		if _, ok := b["values"]; ok || strings.Contains(string(r.Body), `"1"`) {
			t.Fatalf("422 carries values: %s", r.Body)
		}
		if len(e.store.Snapshots()) != 0 || e.decrypts() != 0 {
			t.Fatal("a snapshot was frozen or a secret decrypted")
		}
		if err := validateJSON(t, "error.reply.schema.json", r.Body); err != nil {
			t.Fatal(err)
		}
		// An ordinary value that is absent (empty) is a missing parameter too.
		e2 := newEnv(t)
		e2.createTeam(3, "team", map[string]string{"REQUIRED": ""})
		e2.setClaim(c, 1, true)
		if r := e2.open("1", e2.token(c)); r.Status != 422 || openBody(t, r)["missing_parameter"] != "REQUIRED" {
			t.Fatalf("absent ordinary value: %d %s", r.Status, r.Body)
		}
	})

	t.Run("Archived task snapshots are deleted", func(t *testing.T) {
		e := newEnv(t)
		e.createTeam(3, "team", map[string]string{"A": "1"})
		e.createTeam(4, "team", map[string]string{"A": "4"})
		for _, c := range []struct{ task, attempt int64 }{{1, 1}, {1, 2}, {2, 1}} {
			cl := claim(c.task, c.attempt, 1)
			e.setClaim(cl, 1, true)
			openValues(t, e.open(itoa(c.task), e.token(cl)))
		}
		other := claim(1, 1, 1)
		other.TeamID = 4
		e.setClaim(other, 1, true)
		openValues(t, e.open("1", e.token(other)))
		if got := e.svc.HandleArchived(context.Background(), archivedMsg(50, 3, 1)); got != broker.Ack {
			t.Fatalf("archived decision %v, want Ack", got)
		}
		left := e.store.Snapshots()
		if len(left) != 2 {
			t.Fatalf("snapshots after archive %+v", left)
		}
		for _, s := range left {
			if s.TeamID == 3 && s.TaskID == 1 {
				t.Fatalf("snapshot of archived task kept: %+v", s)
			}
		}
	})
}
