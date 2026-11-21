package test

import (
	"strings"
	"testing"
)

// Requirement: env-registry stores immutable launch-parameter revisions.
func TestEnvRegistryStoresImmutableLaunchParameterRevisions(t *testing.T) {
	t.Run("Operator changes an ordinary value", func(t *testing.T) {
		e := newEnv(t)
		id := e.createTeam(3, "base", map[string]string{"LEVEL": "info", "KEEP": "same"})
		sid := e.createSecret(3, id, "TOKEN", secretCanary)
		_ = sid
		e.store.FailNext("AppendRevision", errInjected)
		failed := e.ui("replace", 3, map[string]any{"team_id": 3, "environment_id": id}, map[string]any{"scope": "team", "name": "base", "env": map[string]string{"LEVEL": "debug", "KEEP": "same"}})
		if failed.Status < 500 {
			t.Fatalf("replace with failing revision append: %d %s", failed.Status, failed.Raw)
		}
		if d := e.store.Definitions()[0]; d.Env["LEVEL"] != "info" || d.Revision != 1 {
			t.Fatalf("projection changed without its revision: %+v", d)
		}
		r := e.ui("replace", 3, map[string]any{"team_id": 3, "environment_id": id}, map[string]any{"scope": "team", "name": "base", "env": map[string]string{"LEVEL": "debug", "KEEP": "same"}})
		if r.Status != 200 || num(t, r.Body, "revision") != 2 || r.Body["env"].(map[string]any)["LEVEL"] != "debug" {
			t.Fatalf("replace: %d %s", r.Status, r.Raw)
		}
		h := e.ui("list-revisions", 3, map[string]any{"team_id": 3, "environment_id": id}, nil)
		if h.Status != 200 {
			t.Fatalf("history: %d %s", h.Status, h.Raw)
		}
		items := h.Body["items"].([]any)
		if len(items) != 2 {
			t.Fatalf("history %s", h.Raw)
		}
		newest, oldest := items[0].(map[string]any), items[1].(map[string]any)
		if num(t, newest, "revision") != 2 || num(t, oldest, "revision") != 1 {
			t.Fatalf("history order %s", h.Raw)
		}
		if newest["env"].(map[string]any)["LEVEL"] != "debug" || oldest["env"].(map[string]any)["LEVEL"] != "info" {
			t.Fatalf("history does not show the key's change: %s", h.Raw)
		}
		if num(t, newest, "actor_id") != 41 || num(t, newest, "request_id") != 9001 || newest["deleted"] != false {
			t.Fatalf("revision metadata %v", newest)
		}
		keys := newest["secret_keys"].([]any)
		if len(keys) != 1 || keys[0] != "TOKEN" {
			t.Fatalf("revision secret keys %v", keys)
		}
		e.assertNoCanary(t, secretCanary)
	})

	t.Run("Operator deletes launch parameters", func(t *testing.T) {
		e := newEnv(t)
		id := e.createTeam(3, "base", map[string]string{"A": "1"})
		e.ui("replace", 3, map[string]any{"team_id": 3, "environment_id": id}, map[string]any{"scope": "team", "name": "base", "env": map[string]string{"A": "2"}})
		r := e.ui("delete", 3, map[string]any{"team_id": 3, "environment_id": id}, nil)
		if r.Status != 204 || len(r.Raw) != 0 {
			t.Fatalf("delete: %d %q", r.Status, r.Raw)
		}
		revs := e.store.Revisions()
		if len(revs) != 3 || !revs[2].Deleted || revs[2].Revision != 3 || revs[0].Env["A"] != "1" || revs[1].Env["A"] != "2" {
			t.Fatalf("revisions after delete: %+v", revs)
		}
		if d := e.store.Definitions()[0]; !d.Deleted || d.Revision != 3 {
			t.Fatalf("projection after delete: %+v", d)
		}
		if g := e.ui("get", 3, map[string]any{"team_id": 3, "environment_id": id}, nil); g.Status != 404 {
			t.Fatalf("deleted definition still readable: %d", g.Status)
		}
		h := e.ui("list-revisions", 3, map[string]any{"team_id": 3, "environment_id": id}, nil)
		if h.Status != 200 || len(h.Body["items"].([]any)) != 3 || h.Body["items"].([]any)[0].(map[string]any)["deleted"] != true {
			t.Fatalf("history after delete: %d %s", h.Status, h.Raw)
		}
		if again := e.ui("delete", 3, map[string]any{"team_id": 3, "environment_id": id}, nil); again.Status != 404 {
			t.Fatalf("second delete: %d", again.Status)
		}
	})

	t.Run("Deleted ordinary value is absent from later snapshots", func(t *testing.T) {
		e := newEnv(t)
		id := e.createTeam(3, "base", map[string]string{"KEEP": "k", "DROP": "d"})
		before := claim(1, 1, 1)
		e.setClaim(before, 1, true)
		if v := openValues(t, e.open("1", e.token(before))); v["DROP"] != "d" {
			t.Fatalf("before removal %v", v)
		}
		e.ui("replace", 3, map[string]any{"team_id": 3, "environment_id": id}, map[string]any{"scope": "team", "name": "base", "env": map[string]string{"KEEP": "k"}})
		after := claim(2, 1, 1)
		e.setClaim(after, 1, true)
		if v := openValues(t, e.open("2", e.token(after))); v["DROP"] != "" || v["KEEP"] != "k" || len(v) != 1 {
			t.Fatalf("after key removal %v", v)
		}
		e.ui("delete", 3, map[string]any{"team_id": 3, "environment_id": id}, nil)
		later := claim(3, 1, 1)
		e.setClaim(later, 1, true)
		if v := openValues(t, e.open("3", e.token(later))); len(v) != 0 {
			t.Fatalf("after definition delete %v", v)
		}
		// The snapshot frozen before the change is unchanged.
		if v := openValues(t, e.open("1", e.token(before))); v["DROP"] != "d" {
			t.Fatalf("earlier snapshot changed %v", v)
		}
	})

	t.Run("Operator reads foreign history", func(t *testing.T) {
		e := newEnv(t)
		// Team 4 owns environments 1 and 2; a global definition exists; team 3 owns none.
		foreign := e.createTeam(4, "team 4", map[string]string{"HINT": "x"})
		e.createSecret(4, foreign, "TOKEN", secretCanary)
		e.addFlow(4, 1)
		e.ui("create", 4, map[string]any{"team_id": 4}, map[string]any{"scope": "flow", "flow_id": 1, "name": "f", "env": map[string]string{}})
		gid := e.seedGlobal(map[string]string{"G": "1"})
		unknown := e.ui("list-revisions", 3, map[string]any{"team_id": 3, "environment_id": 77}, nil)
		if unknown.Status != 404 || unknown.code() != "environment_unknown_or_unavailable" {
			t.Fatalf("unknown history %d %s", unknown.Status, unknown.Raw)
		}
		for _, id := range []int64{1, 2, gid} {
			got := e.ui("list-revisions", 3, map[string]any{"team_id": 3, "environment_id": id}, nil)
			if got.Status != unknown.Status || got.code() != unknown.code() || got.Body["message"] != unknown.Body["message"] {
				t.Fatalf("foreign history %d: %d %s differs from unknown %s", id, got.Status, got.Raw, unknown.Raw)
			}
			if strings.Contains(string(got.Raw), "items") || strings.Contains(string(got.Raw), "cursor") {
				t.Fatalf("foreign history revealed rows: %s", got.Raw)
			}
		}
		if e.decrypts() != 0 {
			t.Fatal("history read decrypted a secret")
		}
	})
}
