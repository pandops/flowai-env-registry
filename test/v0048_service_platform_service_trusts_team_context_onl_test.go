package test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/pandops/flowai-env-registry/internal/broker"
)

// Requirement: service-platform service trusts team context only from ui requests.
func TestServicePlatformServiceTrustsTeamContextOnlyFromUIRequests(t *testing.T) {
	t.Run("Gateway forwards verified operator context", func(t *testing.T) {
		e := newEnv(t)
		id := e.createTeam(3, "team", map[string]string{"A": "1"})
		for _, name := range []string{"", "Operations", "Team Four", "admin"} {
			h := ctxHeaders(3)
			if name == "" {
				delete(h, "team_name")
			} else {
				h["team_name"] = name
			}
			r := e.uiWith("get", h, map[string]any{"team_id": 3, "environment_id": id}, nil)
			if r.Status != 200 || num(t, r.Body, "team_id") != 3 {
				t.Fatalf("team_name %q: %d %s", name, r.Status, r.Raw)
			}
			// team_name never authorizes another team.
			h["team"] = "4"
			if r := e.uiWith("get", h, map[string]any{"team_id": 4, "environment_id": id}, nil); r.Status != 404 {
				t.Fatalf("team 4 with team_name %q: %d %s", name, r.Status, r.Raw)
			}
		}
		for _, a := range e.outboxPayloads("env-registry.audit.") {
			// Each audit carries its own request's verified context: team 3, or
			// team 4 for the refused foreign reads.
			team := num(t, a, "team_id")
			if (team != 3 && (team != 4 || a["outcome"] != "rejected")) || num(t, a, "actor_id") != 41 || num(t, a, "request_id") != 9001 {
				t.Fatalf("audit context %v", a)
			}
		}
	})

	t.Run("Payload names another team", func(t *testing.T) {
		e := newEnv(t)
		e.createTeam(3, "three", map[string]string{"A": "3"})
		four := e.createTeam(4, "four", map[string]string{"A": "4"})
		before := len(e.store.Outbox())
		cases := []struct {
			op     string
			params map[string]any
			body   any
		}{
			{"list", map[string]any{"team_id": 4}, nil},
			{"get", map[string]any{"team_id": 4, "environment_id": four}, nil},
			{"replace", map[string]any{"team_id": 4, "environment_id": four}, map[string]any{"scope": "team", "name": "x", "env": map[string]string{"A": "x"}}},
			{"delete", map[string]any{"team_id": 4, "environment_id": four}, nil},
			{"create-secret", map[string]any{"team_id": 4, "environment_id": four}, map[string]any{"key": "S", "value": secretCanary}},
			{"create", map[string]any{"team_id": 4}, map[string]any{"scope": "team", "name": "x", "env": map[string]string{}}},
		}
		for _, c := range cases {
			r := e.ui(c.op, 3, c.params, c.body)
			if r.Status != 404 || r.code() != "environment_unknown_or_unavailable" {
				t.Errorf("%s with header team 3, params team 4: %d %s, want 404 environment_unknown_or_unavailable", c.op, r.Status, r.Raw)
			}
			if strings.Contains(string(r.Raw), `"4"`) || strings.Contains(string(r.Raw), "four") {
				t.Errorf("%s revealed team 4 data: %s", c.op, r.Raw)
			}
		}
		// A team_id inside the body is not a context field either.
		r := e.ui("create", 3, map[string]any{"team_id": 3}, map[string]any{"scope": "team", "team_id": 4, "name": "x", "env": map[string]string{}})
		if r.Status != 400 || r.code() != "invalid_request" {
			t.Errorf("body team_id: %d %s", r.Status, r.Raw)
		}
		for _, d := range e.store.Definitions() {
			if d.TeamID == 4 && (d.Revision != 1 || d.Deleted || d.Env["A"] != "4") {
				t.Fatalf("team 4 changed: %+v", d)
			}
		}
		if len(e.store.Secrets()) != 0 || len(e.store.Definitions()) != 2 {
			t.Fatal("a request for team 3 wrote team 4 data")
		}
		for _, row := range e.store.Outbox()[before:] {
			if row.Header["team"] != "3" {
				t.Fatalf("published for team %s", row.Header["team"])
			}
		}
	})

	t.Run("Context is missing", func(t *testing.T) {
		e := newEnv(t)
		id := e.createTeam(3, "team", map[string]string{"A": "1"})
		// A protected read would surface this injected failure as a 5xx.
		for _, m := range []string{"GetDefinition", "ListDefinitions", "ListRevisions", "GetSecret", "ListSecrets"} {
			e.store.FailNext(m, errInjected)
		}
		for _, h := range []broker.Header{{}, {"operator_id": "41", "request_id": "9001"}, {"team": "", "operator_id": "41", "request_id": "9001"},
			{"team": "3", "operator_id": "41"}, {"team": "3", "operator_id": "41", "request_id": "0"}, {"team": "3", "operator_id": "41", "request_id": "r-1"}} {
			for _, op := range []string{"list", "get", "list-revisions", "create", "delete"} {
				var body any
				if op == "create" {
					body = map[string]any{"scope": "team", "name": "x", "env": map[string]string{}}
				}
				r := e.uiWith(op, h, map[string]any{"team_id": 3, "environment_id": id}, body)
				if r.Status != 400 || r.code() != "invalid_request" {
					t.Errorf("%s with headers %v: %d %s", op, h, r.Status, r.Raw)
				}
				// D12 owner decision 2026-11-09: no valid request_id, no
				// request_id field; every other error keeps it.
				rid, has := r.Body["request_id"]
				if h["request_id"] == "9001" && (!has || fmt.Sprint(rid) != "9001") {
					t.Errorf("%s with headers %v: %s, want request_id 9001", op, h, r.Raw)
				}
				if h["request_id"] != "9001" && has {
					t.Errorf("%s with headers %v: %s, want no request_id field", op, h, r.Raw)
				}
			}
		}
	})
}
