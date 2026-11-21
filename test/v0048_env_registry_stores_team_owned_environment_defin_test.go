package test

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/pandops/flowai-env-registry/internal/broker"
	"github.com/pandops/flowai-env-registry/internal/service"
)

// Requirement: env-registry stores team-owned environment definitions.
func TestEnvRegistryStoresTeamOwnedEnvironmentDefinitions(t *testing.T) {
	t.Run("Same-team operator stores team-wide launch parameters", func(t *testing.T) {
		e := newEnv(t)
		r := e.ui("create", 3, map[string]any{"team_id": 3}, map[string]any{"scope": "team", "name": "Team defaults", "env": map[string]string{"LOG_LEVEL": "debug"}})
		if r.Status != 201 {
			t.Fatalf("create: %d %s", r.Status, r.Raw)
		}
		if num(t, r.Body, "environment_id") != 1 || num(t, r.Body, "team_id") != 3 || r.Body["scope"] != "team" || r.Body["flow_id"] != nil {
			t.Fatalf("stored definition %s", r.Raw)
		}
		// Applies to every Flow and task of team 3.
		for i, flow := range []int64{1, 2} {
			c := claim(int64(100+i), 1, 1)
			e.setClaim(c, flow, true)
			if got := openValues(t, e.open(itoa(c.TaskID), e.token(c))); got["LOG_LEVEL"] != "debug" {
				t.Fatalf("flow %d task values %v", flow, got)
			}
		}
		audits := e.outboxPayloads("env-registry.audit.")
		if len(audits) != 1 || audits[0]["action"] != "launch_parameters_created" || audits[0]["outcome"] != "succeeded" {
			t.Fatalf("audit messages %v", audits)
		}
		e.assertNoCanary(t, "debug")
	})

	t.Run("Definitions and secrets are numbered per team", func(t *testing.T) {
		e := newEnv(t)
		e.createTeam(3, "first", map[string]string{})
		e.addFlow(3, 1)
		r := e.ui("create", 3, map[string]any{"team_id": 3}, map[string]any{"scope": "flow", "flow_id": 1, "name": "second", "env": map[string]string{}})
		if r.Status != 201 {
			t.Fatalf("second: %d %s", r.Status, r.Raw)
		}
		for i := 0; i < 6; i++ {
			e.createSecret(3, 1, "K"+itoa(int64(i)), secretCanary)
		}
		e.addFlow(3, 2)
		third := e.ui("create", 3, map[string]any{"team_id": 3}, map[string]any{"scope": "flow", "flow_id": 2, "name": "third", "env": map[string]string{}})
		if num(t, third.Body, "environment_id") != 3 {
			t.Fatalf("team 3 third definition %s", third.Raw)
		}
		if s := e.createSecret(3, 3, "DB_PASSWORD", secretCanary); s != 7 {
			t.Fatalf("team 3 secret_id %d, want 7", s)
		}
		if id := e.createTeam(4, "team 4 first", map[string]string{}); id != 1 {
			t.Fatalf("team 4 environment_id %d, want 1", id)
		}
		if s := e.createSecret(4, 1, "DB_PASSWORD", secretCanary); s != 1 {
			t.Fatalf("team 4 secret_id %d, want 1", s)
		}
		got := e.ui("get", 4, map[string]any{"team_id": 4, "environment_id": 3}, nil)
		if got.Status != 404 || got.code() != "environment_unknown_or_unavailable" {
			t.Fatalf("team 4 reading environment 3: %d %s", got.Status, got.Raw)
		}
	})

	t.Run("Non-integer launch-parameter identifier is rejected", func(t *testing.T) {
		bad := []any{"env-1", 0, -1, 1.5, "5d2e8c1a-3f4b-4a6c-9d7e-8f0a1b2c3d4e", "1", 9.223372036854775808e18}
		for _, v := range bad {
			e := newEnv(t)
			id := e.createTeam(3, "base", map[string]string{"A": "1"})
			e.createSecret(3, id, "S", secretCanary)
			before := len(e.store.Outbox())
			beforeDecrypts := e.decrypts()
			cases := []struct {
				op     string
				params map[string]any
				body   any
			}{
				{"get", map[string]any{"team_id": 3, "environment_id": v}, nil},
				{"replace", map[string]any{"team_id": 3, "environment_id": v}, map[string]any{"scope": "team", "name": "x", "env": map[string]string{}}},
				{"delete", map[string]any{"team_id": 3, "environment_id": v}, nil},
				{"list-revisions", map[string]any{"team_id": 3, "environment_id": v}, nil},
				{"replace-secret", map[string]any{"team_id": 3, "environment_id": id, "secret_id": v}, map[string]any{"value": secretCanary2}},
				{"revoke-secret", map[string]any{"team_id": 3, "environment_id": id, "secret_id": v}, nil},
				{"list-secret-versions", map[string]any{"team_id": 3, "environment_id": id, "secret_id": v}, nil},
				{"create", map[string]any{"team_id": 3}, map[string]any{"scope": "flow", "flow_id": v, "name": "f", "env": map[string]string{}}},
				{"list", map[string]any{"team_id": 3, "flow_id": v}, nil},
			}
			for _, c := range cases {
				r := e.ui(c.op, 3, c.params, c.body)
				if r.Status != 400 || r.code() != "invalid_request" {
					t.Errorf("%s with identifier %v: %d %s, want 400 invalid_request", c.op, v, r.Status, r.Raw)
				}
			}
			if n := len(e.broker.RequestsTo(service.FlowOwnerSubject)); n != 0 {
				t.Errorf("identifier %v: %d flow-owner requests, want none", v, n)
			}
			if len(e.store.Outbox()) != before || e.decrypts() != beforeDecrypts {
				t.Errorf("identifier %v: something was written or decrypted", v)
			}
			if d := e.store.Definitions(); len(d) != 1 || d[0].Revision != 1 || d[0].Deleted {
				t.Errorf("identifier %v changed definitions: %+v", v, d)
			}
			if s := e.store.Secrets(); len(s) != 1 || s[0].LatestVersion != 1 || s[0].Revoked {
				t.Errorf("identifier %v changed secrets: %+v", v, s)
			}
		}
	})

	t.Run("Operator-supplied key is preserved", func(t *testing.T) {
		e := newEnv(t)
		id := e.createTeam(3, "keys", map[string]string{"MY__Custom_KEY9": "v1", "_LEADING": "v2"})
		sid := e.createSecret(3, id, "API_TOKEN__X", secretCanary)
		got := e.ui("get", 3, map[string]any{"team_id": 3, "environment_id": id}, nil)
		envMap := got.Body["env"].(map[string]any)
		if envMap["MY__Custom_KEY9"] != "v1" || envMap["_LEADING"] != "v2" || len(envMap) != 2 {
			t.Fatalf("stored keys %v", envMap)
		}
		secrets := got.Body["secrets"].([]any)
		if len(secrets) != 1 || secrets[0].(map[string]any)["name"] != "API_TOKEN__X" || num(t, secrets[0].(map[string]any), "secret_id") != sid {
			t.Fatalf("stored secret keys %v", secrets)
		}
		c := claim(10, 1, 1)
		e.setClaim(c, 1, true)
		vals := openValues(t, e.open("10", e.token(c)))
		if vals["MY__Custom_KEY9"] != "v1" || vals["_LEADING"] != "v2" || vals["API_TOKEN__X"] != secretCanary || len(vals) != 3 {
			t.Fatalf("resolved values %v", vals)
		}
		// A display-name-like key is refused rather than normalized.
		bad := e.ui("create-secret", 3, map[string]any{"team_id": 3, "environment_id": id}, map[string]any{"key": "api token", "value": "x"})
		if bad.Status != 400 {
			t.Fatalf("invalid key accepted: %d %s", bad.Status, bad.Raw)
		}
	})

	t.Run("Same-team operator stores Flow launch parameters", func(t *testing.T) {
		e := newEnv(t)
		e.addFlow(3, 2)
		r := e.ui("create", 3, map[string]any{"team_id": 3}, map[string]any{"scope": "flow", "flow_id": 2, "name": "Flow 2", "env": map[string]string{"MODE": "flow2"}})
		if r.Status != 201 || num(t, r.Body, "flow_id") != 2 || r.Body["scope"] != "flow" || num(t, r.Body, "team_id") != 3 {
			t.Fatalf("create flow definition: %d %s", r.Status, r.Raw)
		}
		owner := e.broker.RequestsTo(service.FlowOwnerSubject)
		if len(owner) != 1 || owner[0].Header["team"] != "3" {
			t.Fatalf("flow-owner requests %+v", owner)
		}
		var req map[string]map[string]int64
		if err := json.Unmarshal(owner[0].Data, &req); err != nil || req["params"]["team_id"] != 3 || req["params"]["flow_id"] != 2 || len(req) != 1 {
			t.Fatalf("flow-owner request %s", owner[0].Data)
		}
		in := claim(20, 1, 1)
		e.setClaim(in, 2, true)
		if got := openValues(t, e.open("20", e.token(in))); got["MODE"] != "flow2" {
			t.Fatalf("Flow 2 task values %v", got)
		}
		other := claim(21, 1, 1)
		e.setClaim(other, 1, true)
		if got := openValues(t, e.open("21", e.token(other))); len(got) != 0 {
			t.Fatalf("Flow 1 task received Flow 2 values %v", got)
		}
		// The Flow binding is immutable.
		id := num(t, r.Body, "environment_id")
		e.addFlow(3, 1)
		moved := e.ui("replace", 3, map[string]any{"team_id": 3, "environment_id": id}, map[string]any{"scope": "flow", "flow_id": 1, "name": "Flow 2", "env": map[string]string{}})
		if moved.Status < 400 {
			t.Fatalf("Flow binding changed: %d %s", moved.Status, moved.Raw)
		}
		if d := e.store.Definitions(); d[0].FlowID != 2 {
			t.Fatalf("stored Flow binding %d", d[0].FlowID)
		}
	})

	t.Run("Referenced Flow belongs to another team", func(t *testing.T) {
		for _, variant := range []string{"404", "other team"} {
			e := newEnv(t)
			if variant == "other team" {
				e.addFlowOwnedBy(3, 9, 4)
			}
			r := e.ui("create", 3, map[string]any{"team_id": 3}, map[string]any{"scope": "flow", "flow_id": 9, "name": "x", "env": map[string]string{"A": "1"}})
			unknown := e.ui("create", 3, map[string]any{"team_id": 3}, map[string]any{"scope": "flow", "flow_id": 99, "name": "x", "env": map[string]string{"A": "1"}})
			if r.Status != 404 || r.code() != "environment_unknown_or_unavailable" {
				t.Fatalf("%s: %d %s", variant, r.Status, r.Raw)
			}
			if unknown.Status != r.Status || unknown.code() != r.code() || unknown.Body["message"] != r.Body["message"] {
				t.Fatalf("%s: foreign %s differs from unknown %s", variant, r.Raw, unknown.Raw)
			}
			if len(e.store.Definitions()) != 0 || len(e.store.Revisions()) != 0 || len(e.store.Secrets()) != 0 {
				t.Fatalf("%s: something was stored", variant)
			}
		}
	})

	t.Run("Gateway route maps to its operation", func(t *testing.T) {
		e := newEnv(t)
		id := e.createTeam(3, "base", map[string]string{})
		sid := e.createSecret(3, id, "S", secretCanary)
		// PUT /ui/v1/teams/3/launch-parameters/{id}/secrets/{sid} arrives as replace-secret.
		r := e.ui("replace-secret", 3, map[string]any{"team_id": 3, "environment_id": id, "secret_id": sid}, map[string]any{"value": secretCanary2})
		if r.Status != 200 || num(t, r.Body, "current_version") != 2 {
			t.Fatalf("replace-secret: %d %s", r.Status, r.Raw)
		}
		ops := []string{"list", "create", "get", "replace", "delete", "list-revisions", "create-secret", "replace-secret", "revoke-secret", "list-secret-versions"}
		for _, op := range ops {
			if r := e.ui(op, 3, map[string]any{"team_id": 3}, nil); r.Status == 404 && r.code() == "not_found" {
				t.Errorf("operation %s is not served", op)
			}
		}
		before := len(e.store.Outbox())
		for _, op := range []string{"secrets-replace", "replace_secret", "open", "admin", "_test"} {
			r := e.ui(op, 3, map[string]any{"team_id": 3, "environment_id": id, "secret_id": sid}, map[string]any{"value": "x"})
			if r.Status != 404 || r.code() != "not_found" {
				t.Errorf("undefined operation %s: %d %s", op, r.Status, r.Raw)
			}
		}
		if len(e.store.Outbox()) != before || e.store.Secrets()[0].LatestVersion != 2 {
			t.Fatal("undefined operation read or mutated something")
		}
	})

	t.Run("Operator attempts task-scoped launch parameters", func(t *testing.T) {
		e := newEnv(t)
		id := e.createTeam(3, "base", map[string]string{})
		bodies := []struct {
			op     string
			params map[string]any
			body   map[string]any
		}{
			{"create", map[string]any{"team_id": 3}, map[string]any{"scope": "task", "task_id": 5, "name": "t", "env": map[string]string{}}},
			{"create", map[string]any{"team_id": 3}, map[string]any{"scope": "team", "task_id": 5, "name": "t", "env": map[string]string{}}},
			{"create", map[string]any{"team_id": 3}, map[string]any{"scope": "team", "name": "t", "env": map[string]string{}, "image": "registry/x:1"}},
			{"create", map[string]any{"team_id": 3}, map[string]any{"scope": "team", "name": "t", "env": map[string]string{}, "default_image": "registry/x:1"}},
			{"replace", map[string]any{"team_id": 3, "environment_id": id}, map[string]any{"scope": "team", "task_id": 5, "name": "t", "env": map[string]string{}}},
			{"create-secret", map[string]any{"team_id": 3, "environment_id": id}, map[string]any{"key": "K", "value": "v", "task_id": 5}},
		}
		before := len(e.store.Outbox())
		for _, b := range bodies {
			if r := e.ui(b.op, 3, b.params, b.body); r.Status != 400 {
				t.Errorf("%s %v accepted: %d %s", b.op, b.body, r.Status, r.Raw)
			}
		}
		if len(e.store.Definitions()) != 1 || len(e.store.Secrets()) != 0 || len(e.store.Outbox()) != before {
			t.Fatal("a task-scoped write mutated something")
		}
	})

	t.Run("Operator attempts global mutation", func(t *testing.T) {
		e := newEnv(t)
		gid := e.seedGlobal(map[string]string{"G": "1"})
		before := len(e.store.Outbox())
		cr := e.ui("create", 3, map[string]any{"team_id": 3}, map[string]any{"scope": "global", "name": "g", "env": map[string]string{}})
		if cr.Status != 400 {
			t.Errorf("global create: %d %s", cr.Status, cr.Raw)
		}
		if r := e.ui("replace", 3, map[string]any{"team_id": 3, "environment_id": gid}, map[string]any{"scope": "global", "name": "g", "env": map[string]string{"G": "2"}}); r.Status < 400 {
			t.Errorf("global replace: %d %s", r.Status, r.Raw)
		}
		if r := e.ui("replace", 3, map[string]any{"team_id": 3, "environment_id": gid}, map[string]any{"scope": "team", "name": "g", "env": map[string]string{"G": "2"}}); r.Status < 400 {
			t.Errorf("global replace as team: %d %s", r.Status, r.Raw)
		}
		if r := e.ui("delete", 3, map[string]any{"team_id": 3, "environment_id": gid}, nil); r.Status < 400 {
			t.Errorf("global delete: %d %s", r.Status, r.Raw)
		}
		d := e.store.Definitions()
		if len(d) != 1 || d[0].Env["G"] != "1" || d[0].Deleted || d[0].Revision != 1 {
			t.Fatalf("global definition changed: %+v", d)
		}
		for _, a := range e.outboxPayloads("env-registry.audit.")[before:] {
			if a["outcome"] == "succeeded" {
				t.Fatalf("succeeded audit for a global mutation: %v", a)
			}
		}
	})

	t.Run("Operator stores a reserved model name", func(t *testing.T) {
		e := newEnv(t)
		id := e.createTeam(3, "base", map[string]string{})
		before := len(e.store.Outbox())
		e.addFlow(3, 2)
		for _, name := range []string{"OPENAI_API_KEY", "OPENAI_BASE_URL", "OPENAI_MODEL"} {
			cases := []struct {
				op     string
				params map[string]any
				body   map[string]any
			}{
				{"create-secret", map[string]any{"team_id": 3, "environment_id": id}, map[string]any{"key": name, "value": secretCanary}},
				{"create", map[string]any{"team_id": 3}, map[string]any{"scope": "flow", "flow_id": 2, "name": "f", "env": map[string]string{name: "x"}}},
				{"replace", map[string]any{"team_id": 3, "environment_id": id}, map[string]any{"scope": "team", "name": "base", "env": map[string]string{name: "x"}}},
			}
			for _, c := range cases {
				r := e.ui(c.op, 3, c.params, c.body)
				if r.Status != 400 || r.code() != "invalid_request" {
					t.Errorf("%s with %s: %d %s", c.op, name, r.Status, r.Raw)
				}
			}
		}
		if len(e.store.Secrets()) != 0 || len(e.store.Definitions()) != 1 || len(e.store.Revisions()) != 1 || len(e.store.Outbox()) != before {
			t.Fatal("a reserved model name stored a definition, secret, revision or audit")
		}
	})

	t.Run("Request without Gateway context is refused", func(t *testing.T) {
		e := newEnv(t)
		id := e.createTeam(3, "base", map[string]string{"A": "1"})
		before := len(e.store.Outbox())
		headers := []broker.Header{
			{"operator_id": "41", "request_id": "9001"},
			{"team": "admin", "operator_id": "41", "request_id": "9001"},
			{"team": "3", "request_id": "9001"},
			{"team": "3", "operator_id": "41"},
			{"team": "03", "operator_id": "41", "request_id": "9001"},
			{"team": "3", "operator_id": "abc", "request_id": "9001"},
		}
		for _, h := range headers {
			for _, op := range []string{"get", "delete", "list"} {
				r := e.uiWith(op, h, map[string]any{"team_id": 3, "environment_id": id}, nil)
				if r.Status != 400 || r.code() != "invalid_request" {
					t.Errorf("%s with headers %v: %d %s", op, h, r.Status, r.Raw)
				}
				if strings.Contains(string(r.Raw), `"A"`) {
					t.Errorf("%s with headers %v revealed data", op, h)
				}
			}
		}
		if d := e.store.Definitions(); d[0].Deleted || len(e.store.Outbox()) != before {
			t.Fatal("request without context mutated something")
		}
	})
}

func itoa(v int64) string { return strconv.FormatInt(v, 10) }
