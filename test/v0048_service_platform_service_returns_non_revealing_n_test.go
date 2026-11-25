package test

import (
	"testing"
)

// Requirement: service-platform service returns non-revealing not-found for foreign resources.
func TestServicePlatformServiceReturnsNonRevealingNotFound(t *testing.T) {
	t.Run("Operator reads a foreign task", func(t *testing.T) {
		// env-registry's read counterpart: a foreign definition, its history
		// and a foreign secret's versions answer exactly like unknown ones.
		e := newEnv(t)
		for i := 0; i < 5; i++ {
			e.createTeam(4, "four", map[string]string{"A": "4"})
			e.ui("delete", 4, map[string]any{"team_id": 4, "environment_id": i + 1}, nil)
		}
		four := e.createTeam(4, "four", map[string]string{"A": "4"})
		sid := e.createSecret(4, four, "S", secretCanary)
		cases := []struct {
			op             string
			foreign, unkno map[string]any
		}{
			{"get", map[string]any{"team_id": 3, "environment_id": four}, map[string]any{"team_id": 3, "environment_id": 99}},
			{"list-revisions", map[string]any{"team_id": 3, "environment_id": four}, map[string]any{"team_id": 3, "environment_id": 99}},
			{"list-secret-versions", map[string]any{"team_id": 3, "environment_id": four, "secret_id": sid}, map[string]any{"team_id": 3, "environment_id": 99, "secret_id": 99}},
		}
		for _, c := range cases {
			f := e.ui(c.op, 3, c.foreign, nil)
			u := e.ui(c.op, 3, c.unkno, nil)
			if f.Status != 404 || u.Status != 404 || f.code() != u.code() || f.Body["message"] != u.Body["message"] {
				t.Errorf("%s foreign %d %s, unknown %d %s", c.op, f.Status, f.Raw, u.Status, u.Raw)
			}
		}
	})

	t.Run("Operator writes a foreign environment", func(t *testing.T) {
		e := newEnv(t)
		for i := 0; i < 4; i++ {
			e.createTeam(4, "pad", map[string]string{})
			e.ui("delete", 4, map[string]any{"team_id": 4, "environment_id": i + 1}, nil)
		}
		five := e.createTeam(4, "four", map[string]string{"A": "4"})
		if five != 5 {
			t.Fatalf("team 4 environment %d, want 5", five)
		}
		sid := e.createSecret(4, five, "S", secretCanary)
		decrypts := e.decrypts()
		writes := []struct {
			op     string
			params map[string]any
			body   any
		}{
			{"replace", map[string]any{"team_id": 3, "environment_id": 5}, map[string]any{"scope": "team", "name": "x", "env": map[string]string{"A": "x"}}},
			{"delete", map[string]any{"team_id": 3, "environment_id": 5}, nil},
			{"create-secret", map[string]any{"team_id": 3, "environment_id": 5}, map[string]any{"key": "T", "value": secretCanary2}},
			{"replace-secret", map[string]any{"team_id": 3, "environment_id": 5, "secret_id": sid}, map[string]any{"value": secretCanary2}},
			{"revoke-secret", map[string]any{"team_id": 3, "environment_id": 5, "secret_id": sid}, nil},
		}
		for _, w := range writes {
			f := e.ui(w.op, 3, w.params, w.body)
			unknown := map[string]any{}
			for k, v := range w.params {
				unknown[k] = v
			}
			unknown["environment_id"] = 77
			u := e.ui(w.op, 3, unknown, w.body)
			if f.Status != 404 || f.code() != u.code() || f.Body["message"] != u.Body["message"] {
				t.Errorf("%s foreign %d %s, unknown %d %s", w.op, f.Status, f.Raw, u.Status, u.Raw)
			}
		}
		var d5 bool
		for _, d := range e.store.Definitions() {
			if d.TeamID == 4 && d.EnvironmentID == 5 {
				d5 = !d.Deleted && d.Revision == 1 && d.Env["A"] == "4"
			}
		}
		s := e.store.Secrets()
		if !d5 || len(s) != 1 || s[0].LatestVersion != 1 || s[0].Revoked || len(e.store.Versions()) != 1 {
			t.Fatalf("team 4's environment 5 changed: %+v %+v", e.store.Definitions(), s)
		}
		if e.decrypts() != decrypts {
			t.Fatal("a foreign write decrypted a secret")
		}
	})
}
