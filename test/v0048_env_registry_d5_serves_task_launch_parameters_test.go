package test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// D5 (coordinator deviation): env-registry.ui.task-parameters serves
// GET /ui/v1/teams/{team_id}/tasks/{task_id}/launch-parameters from the
// latest frozen attempt snapshot of the team's task.
func TestEnvRegistryD5ServesTaskLaunchParameters(t *testing.T) {
	setup := func(t *testing.T) *env {
		e := newEnv(t)
		id := e.createTeam(3, "team", map[string]string{"PLAIN": "plain-value", "MODE": "a"})
		e.createSecret(3, id, "ZETA_TOKEN", secretCanary)
		e.createSecret(3, id, "ALPHA_KEY", secretCanary2)
		c := claim(5, 1, 1)
		e.setClaim(c, 1, true)
		openValues(t, e.open("5", e.token(c)))
		return e
	}
	empty := func(task int64) string {
		return `{"attempt":null,"environment":{},"secret_keys":[],"task_id":` + itoa(task) + `}`
	}
	// compact normalizes a reply so equal JSON values compare equal.
	compact := func(raw []byte) string {
		var v any
		if err := json.Unmarshal(raw, &v); err != nil {
			return string(raw)
		}
		b, _ := json.Marshal(v)
		return string(b)
	}

	t.Run("Team predicate applies before the read", func(t *testing.T) {
		e := setup(t)
		r := e.ui("task-parameters", 3, map[string]any{"team_id": 3, "task_id": 5}, nil)
		env, _ := r.Body["environment"].(map[string]any)
		if r.Status != 200 || num(t, r.Body, "task_id") != 5 || num(t, r.Body, "attempt") != 1 || env["PLAIN"] != "plain-value" || env["MODE"] != "a" || len(env) != 2 {
			t.Fatalf("team 3 read: %d %s", r.Status, r.Raw)
		}
		h := ctxHeaders(4)
		if r := e.uiWith("task-parameters", h, map[string]any{"team_id": 4, "task_id": 5}, nil); r.Status != 200 || compact(r.Raw) != empty(5) {
			t.Fatalf("team 4 read of team 3's task: %d %s", r.Status, r.Raw)
		}
		if r := e.ui("task-parameters", 4, map[string]any{"team_id": 3, "task_id": 5}, nil); r.Status != 404 || r.code() != "environment_unknown_or_unavailable" {
			t.Fatalf("params team 3 under header team 4: %d %s", r.Status, r.Raw)
		}
	})

	t.Run("Foreign or unknown task gets the same empty reply", func(t *testing.T) {
		e := setup(t)
		other := claim(6, 1, 1)
		other.TeamID = 4
		e.createTeam(4, "four", map[string]string{"X": "4"})
		e.setClaim(other, 1, true)
		openValues(t, e.open("6", e.token(other)))
		foreign := e.ui("task-parameters", 3, map[string]any{"team_id": 3, "task_id": 6}, nil)
		unknown := e.ui("task-parameters", 3, map[string]any{"team_id": 3, "task_id": 7}, nil)
		if foreign.Status != 200 || compact(foreign.Raw) != empty(6) || unknown.Status != 200 || compact(unknown.Raw) != empty(7) {
			t.Fatalf("foreign %d %s, unknown %d %s", foreign.Status, foreign.Raw, unknown.Status, unknown.Raw)
		}
	})

	t.Run("Latest attempt after a retry", func(t *testing.T) {
		e := setup(t)
		e.setClaim(claim(5, 1, 1), 1, false)
		e.ui("replace", 3, map[string]any{"team_id": 3, "environment_id": 1}, map[string]any{"scope": "team", "name": "team", "env": map[string]string{"PLAIN": "plain-value", "MODE": "b"}})
		c2 := claim(5, 2, 1)
		e.setClaim(c2, 1, true)
		openValues(t, e.open("5", e.token(c2)))
		r := e.ui("task-parameters", 3, map[string]any{"team_id": 3, "task_id": 5}, nil)
		env, _ := r.Body["environment"].(map[string]any)
		if r.Status != 200 || num(t, r.Body, "attempt") != 2 || env["MODE"] != "b" {
			t.Fatalf("after retry: %d %s", r.Status, r.Raw)
		}
	})

	t.Run("Secret plaintext never in the reply or logs", func(t *testing.T) {
		e := setup(t)
		decrypts := e.decrypts()
		before := len(e.store.Outbox())
		r := e.ui("task-parameters", 3, map[string]any{"team_id": 3, "task_id": 5}, nil)
		keys, _ := r.Body["secret_keys"].([]any)
		if r.Status != 200 || len(keys) != 2 || keys[0] != "ALPHA_KEY" || keys[1] != "ZETA_TOKEN" {
			t.Fatalf("secret keys: %d %s", r.Status, r.Raw)
		}
		for _, leak := range []string{secretCanary, secretCanary2, "secret_id", "version", "ciphertext", "key_id"} {
			if strings.Contains(string(r.Raw), leak) {
				t.Fatalf("reply carries %q: %s", leak, r.Raw)
			}
		}
		if env, _ := r.Body["environment"].(map[string]any); env["ZETA_TOKEN"] != nil || env["ALPHA_KEY"] != nil {
			t.Fatalf("secret keys inside environment: %s", r.Raw)
		}
		if e.decrypts() != decrypts {
			t.Fatal("the read decrypted a secret")
		}
		if len(e.store.Outbox()) != before {
			t.Fatal("the read published an audit or event")
		}
		e.assertNoCanary(t, secretCanary, secretCanary2)
	})

	t.Run("Invalid identifier returns 400 before any read", func(t *testing.T) {
		e := setup(t)
		for _, raw := range []string{`"abc"`, `0`, `-1`, `1.5`, `9223372036854775808`, `"5"`, `null`} {
			e.store.FailNext("LatestSnapshot", errInjected)
			e.store.FailNext("GetSnapshot", errInjected)
			r := e.uiRaw("task-parameters", ctxHeaders(3), []byte(`{"params":{"team_id":3,"task_id":`+raw+`}}`))
			if r.Status != 400 || r.code() != "invalid_request" {
				t.Errorf("task_id %s: %d %s", raw, r.Status, r.Raw)
			}
		}
		if r := e.uiRaw("task-parameters", ctxHeaders(3), []byte(`{"params":{"team_id":3}}`)); r.Status != 400 {
			t.Errorf("missing task_id: %d %s", r.Status, r.Raw)
		}
	})

	t.Run("Archived task reads empty", func(t *testing.T) {
		e := setup(t)
		e.svc.HandleArchived(context.Background(), archivedMsg(30, 3, 5))
		if r := e.ui("task-parameters", 3, map[string]any{"team_id": 3, "task_id": 5}, nil); r.Status != 200 || compact(r.Raw) != empty(5) {
			t.Fatalf("after archived: %d %s", r.Status, r.Raw)
		}
	})
}
