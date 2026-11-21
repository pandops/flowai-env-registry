package test

import (
	"testing"
)

// Requirement: service-platform service stores team ownership in normalized form.
func TestServicePlatformServiceStoresTeamOwnershipInNormalizedForm(t *testing.T) {
	t.Run("Team-owned parent keeps its team", func(t *testing.T) {
		e := newEnv(t)
		id := e.createTeam(3, "team", map[string]string{"A": "1"})
		sid := e.createSecret(3, id, "S", secretCanary)
		attempts := []struct {
			op     string
			team   int64
			params map[string]any
			body   any
		}{
			{"replace", 3, map[string]any{"team_id": 3, "environment_id": id}, map[string]any{"scope": "team", "team_id": 4, "name": "team", "env": map[string]string{}}},
			{"replace", 4, map[string]any{"team_id": 4, "environment_id": id}, map[string]any{"scope": "team", "name": "team", "env": map[string]string{}}},
			{"replace-secret", 3, map[string]any{"team_id": 3, "environment_id": id, "secret_id": sid}, map[string]any{"value": secretCanary2, "team_id": 4}},
			{"replace-secret", 4, map[string]any{"team_id": 4, "environment_id": id, "secret_id": sid}, map[string]any{"value": secretCanary2}},
		}
		for _, a := range attempts {
			if r := e.ui(a.op, a.team, a.params, a.body); r.Status < 400 {
				t.Errorf("%s as team %d: %d %s", a.op, a.team, r.Status, r.Raw)
			}
		}
		for _, d := range e.store.Definitions() {
			if d.TeamID != 3 {
				t.Fatalf("definition moved to team %d", d.TeamID)
			}
		}
		for _, s := range e.store.Secrets() {
			if s.TeamID != 3 || s.LatestVersion != 1 {
				t.Fatalf("secret changed: %+v", s)
			}
		}
		for _, v := range e.store.Versions() {
			if v.TeamID != 3 {
				t.Fatalf("version of team %d", v.TeamID)
			}
		}
	})

	t.Run("Child references a foreign-team parent", func(t *testing.T) {
		e := newEnv(t)
		e.createTeam(3, "three", map[string]string{})
		four := e.createTeam(4, "four", map[string]string{})
		e.createFlow(4, 1, "four-b", map[string]string{}) // team 4 has environment 2, team 3 has not
		r := e.ui("create-secret", 3, map[string]any{"team_id": 3, "environment_id": 2}, map[string]any{"key": "S", "value": secretCanary})
		if r.Status != 404 || r.code() != "environment_unknown_or_unavailable" {
			t.Fatalf("secret on a foreign parent: %d %s", r.Status, r.Raw)
		}
		sid := e.createSecret(4, four, "S", secretCanary)
		if r := e.ui("replace-secret", 3, map[string]any{"team_id": 3, "environment_id": 1, "secret_id": sid}, map[string]any{"value": secretCanary2}); r.Status != 404 {
			t.Fatalf("version on a foreign secret: %d %s", r.Status, r.Raw)
		}
		if s := e.store.Secrets(); len(s) != 1 || s[0].TeamID != 4 || s[0].EnvironmentID != four || len(e.store.Versions()) != 1 {
			t.Fatalf("child created or reparented: %+v", s)
		}
	})

	t.Run("Display metadata never authorizes", func(t *testing.T) {
		e := newEnv(t)
		id := e.createTeam(3, "team", map[string]string{"A": "1"})
		for _, name := range []string{"Operations", "Renamed team", "Team 4"} {
			h := ctxHeaders(3)
			h["team_name"] = name
			r := e.uiWith("get", h, map[string]any{"team_id": 3, "environment_id": id}, nil)
			if r.Status != 200 || num(t, r.Body, "team_id") != 3 {
				t.Fatalf("team_name %q: %d %s", name, r.Status, r.Raw)
			}
		}
		if d := e.store.Definitions(); d[0].TeamID != 3 {
			t.Fatalf("ownership changed: %+v", d)
		}
	})
}
