package test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// forbiddenField matches a schema property name that could carry a value,
// ciphertext, key material or a token.
var forbiddenField = regexp.MustCompile(`(?i)(^value$|values|^env$|plaintext|ciphertext|nonce|^tag$|auth_tag|secret_value|^key$|key_material|data_key|api_key|token|jwt|seed|password)`)

// Requirement: env-registry keeps secrets and values out of the broker and logs.
func TestEnvRegistryKeepsSecretsAndValuesOutOfBrokerAndLogs(t *testing.T) {
	t.Run("Secret write audit carries no value", func(t *testing.T) {
		e := newEnv(t)
		id := e.createTeam(3, "team", map[string]string{"PLAIN": "plain-canary-value"})
		sid := e.createSecret(3, id, "DB_PASSWORD", secretCanary)
		a := e.outboxPayloads("env-registry.audit.secret_created.pub")
		if len(a) != 1 {
			t.Fatalf("secret_created audits %v", a)
		}
		m := a[0]
		if num(t, m, "team_id") != 3 || num(t, m, "actor_id") != 41 || m["action"] != "secret_created" || m["resource_type"] != "secret" ||
			num(t, m, "resource_id") != sid || num(t, m, "request_id") != 9001 || m["outcome"] != "succeeded" || m["actor_type"] != "operator" {
			t.Fatalf("audit %v", m)
		}
		row := e.store.Outbox()[1]
		if row.Header["team"] != "3" || row.Header["request_id"] != "9001" {
			t.Fatalf("audit headers %v", row.Header)
		}
		e.assertNoCanary(t, secretCanary, "plain-canary-value")
	})

	t.Run("Open event carries no value", func(t *testing.T) {
		e := newEnv(t)
		id := e.createTeam(3, "team", map[string]string{"PLAIN": "plain-canary-value"})
		e.createSecret(3, id, "DB_PASSWORD", secretCanary)
		c := claim(12, 2, 3)
		e.setClaim(c, 5, true)
		tok := e.token(c)
		openValues(t, e.open("12", tok))
		ev := e.outboxPayloads("env-registry.event.")
		if len(ev) != 1 {
			t.Fatalf("events %v", ev)
		}
		m := ev[0]
		if num(t, m, "team_id") != 3 || num(t, m, "task_id") != 12 || num(t, m, "attempt") != 2 || num(t, m, "claim_seq") != 3 ||
			num(t, m, "executor_id") != 7 || m["outcome"] != "opened" || m["kind"] != "launch_parameters_open" {
			t.Fatalf("open event %v", m)
		}
		e.assertNoCanary(t, secretCanary, "plain-canary-value", tok, strings.Split(tok, ".")[1])
	})

	t.Run("Published message schemas have no value field", func(t *testing.T) {
		dir := filepath.Join(serviceDir(t), "schemas")
		kinds := map[string][]string{}
		for _, sub := range []string{"audit", "event"} {
			files, err := filepath.Glob(filepath.Join(dir, sub+".*.schema.json"))
			if err != nil {
				t.Fatal(err)
			}
			for _, f := range files {
				kinds[sub] = append(kinds[sub], strings.TrimSuffix(strings.TrimPrefix(filepath.Base(f), sub+"."), ".schema.json"))
				raw, err := os.ReadFile(f)
				if err != nil {
					t.Fatal(err)
				}
				var doc any
				if err := json.Unmarshal(raw, &doc); err != nil {
					t.Fatalf("%s: %v", f, err)
				}
				for _, name := range propertyNames(doc) {
					if forbiddenField.MatchString(name) {
						t.Errorf("%s defines field %q", filepath.Base(f), name)
					}
				}
				compileSchema(t, filepath.Base(f))
			}
		}
		for k := range kinds {
			sort.Strings(kinds[k])
		}
		wantAudit := []string{"launch_parameter_revisions_listed", "launch_parameters_created", "launch_parameters_deleted",
			"launch_parameters_read", "launch_parameters_replaced", "secret_created", "secret_replaced", "secret_revoked", "secret_versions_listed"}
		if strings.Join(kinds["audit"], ",") != strings.Join(wantAudit, ",") {
			t.Errorf("audit schemas %v, want one per action %v", kinds["audit"], wantAudit)
		}
		if strings.Join(kinds["event"], ",") != "launch_parameters_open" {
			t.Errorf("event schemas %v", kinds["event"])
		}
		// Every action the service publishes has its schema: drive each operation once.
		e := newEnv(t)
		id := e.createTeam(3, "team", map[string]string{})
		sid := e.createSecret(3, id, "S", secretCanary)
		e.ui("replace", 3, map[string]any{"team_id": 3, "environment_id": id}, map[string]any{"scope": "team", "name": "team", "env": map[string]string{}})
		e.ui("replace-secret", 3, map[string]any{"team_id": 3, "environment_id": id, "secret_id": sid}, map[string]any{"value": secretCanary2})
		e.ui("revoke-secret", 3, map[string]any{"team_id": 3, "environment_id": id, "secret_id": sid}, nil)
		e.ui("delete", 3, map[string]any{"team_id": 3, "environment_id": id}, nil)
		for _, op := range []string{"list", "get", "list-revisions"} {
			e.ui(op, 4, map[string]any{"team_id": 4, "environment_id": id}, nil) // listed reads of team 4 succeed; get/history of foreign id are rejected
		}
		e.ui("list-secret-versions", 4, map[string]any{"team_id": 4, "environment_id": id, "secret_id": sid}, nil)
		seen := map[string]bool{}
		for _, row := range e.store.Outbox() {
			seen[row.Subject] = true
		}
		for _, a := range []string{"launch_parameters_created", "launch_parameters_replaced", "launch_parameters_deleted", "secret_created", "secret_replaced", "secret_revoked",
			"launch_parameters_read", "launch_parameter_revisions_listed", "secret_versions_listed"} {
			if !seen["env-registry.audit."+a+".pub"] {
				t.Errorf("action %s was not published", a)
			}
		}
	})
}

// propertyNames collects every key under any "properties" object of a schema.
func propertyNames(doc any) []string {
	out := []string{}
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, child := range x {
				if k == "properties" {
					if props, ok := child.(map[string]any); ok {
						for name := range props {
							out = append(out, name)
						}
					}
				}
				walk(child)
			}
		case []any:
			for _, child := range x {
				walk(child)
			}
		}
	}
	walk(doc)
	return out
}
