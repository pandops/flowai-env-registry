package test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Requirement: message-broker message payloads follow publisher-owned JSON Schemas.
func TestMessageBrokerPayloadsFollowPublisherSchemas(t *testing.T) {
	t.Run("Publisher message violates its own schema", func(t *testing.T) {
		e := newEnv(t)
		e.createTeam(3, "team", map[string]string{"A": "1"})
		c := claim(1, 1, 1)
		e.setClaim(c, 1, true)
		openValues(t, e.open("1", e.token(c)))
		ev := e.outboxPayloads("env-registry.event.launch_parameters_open.pub")
		if len(ev) != 1 {
			t.Fatalf("events %v", ev)
		}
		for _, drop := range []string{"task_id", "publisher_seq", "team_id", "outcome", "kind"} {
			m := map[string]any{}
			for k, v := range ev[0] {
				m[k] = v
			}
			delete(m, drop)
			data, _ := json.Marshal(m)
			if validateJSON(t, "event.launch_parameters_open.schema.json", data) == nil {
				t.Errorf("open event without %s passes its schema", drop)
			}
		}
		a := e.outboxPayloads("env-registry.audit.launch_parameters_created.pub")[0]
		a["value"] = "x"
		data, _ := json.Marshal(a)
		if validateJSON(t, "audit.launch_parameters_created.schema.json", data) == nil {
			t.Error("audit with an extra value field passes its schema")
		}
	})

	t.Run("Consumer contract test reads the publisher schema", func(t *testing.T) {
		// env-registry consumes task-manager's archived event and the flow-owner
		// and claim-current replies; each is checked against the publisher's file.
		for _, seq := range []int64{1, 50} {
			if err := validateJSON(t, archivedEventSchema, archivedMsg(seq, 3, 1).Data); err != nil {
				t.Fatalf("archived event of the contract test violates task-manager's schema: %v", err)
			}
		}
		e := newEnv(t)
		e.addFlow(3, 2)
		e.createFlow(3, 2, "f", map[string]string{"A": "1"})
		c := claim(1, 1, 1)
		e.setClaim(c, 2, true)
		openValues(t, e.open("1", e.token(c))) // the fakes validate both directions
		inputs := sharedInputs(t)
		for _, f := range []string{flowOwnerRequestSchema, flowOwnerReplySchema, claimCurrentRequestSchema, claimCurrentReplySchema, archivedEventSchema} {
			rel := "svc/" + f
			if !contains(inputs[rel], "env-registry") {
				t.Errorf("shared-test-inputs.json does not name env-registry for %s", rel)
			}
		}
		out := goListDeps(t, "./test", true)
		for _, pkg := range out {
			if strings.Contains(pkg, "/task-manager") || strings.Contains(pkg, "/flow-registry") ||
				strings.Contains(pkg, "/flowai-task-manager") || strings.Contains(pkg, "/flowai-flow-registry") {
				t.Fatalf("contract test imports %s", pkg)
			}
		}
	})

	t.Run("Schema change selects its consumers", func(t *testing.T) {
		inputs := sharedInputs(t)
		files, err := filepath.Glob(filepath.Join(serviceDir(t), "schemas", "*.schema.json"))
		if err != nil || len(files) == 0 {
			t.Fatalf("schemas: %v", err)
		}
		// Consumers by file-name class (rule 17).
		consumers := map[string][]string{"audit": {"audit"}, "event": {"journal", "task-manager"}, "ui": {"api-gateway"},
			"error":    {"api-gateway", "executor_docker_openhands", "executor_k8s_openhands"},
			"executor": {"executor_docker_openhands", "executor_k8s_openhands"}}
		for _, f := range files {
			rel := "svc/env-registry/schemas/" + filepath.Base(f)
			got := inputs[rel]
			if !contains(got, "env-registry") {
				t.Errorf("%s does not select env-registry", rel)
			}
			for _, c := range consumers[strings.SplitN(filepath.Base(f), ".", 2)[0]] {
				if !contains(got, c) {
					t.Errorf("%s does not select consumer %s (has %v)", rel, c, got)
				}
			}
		}
		for rel := range inputs {
			if strings.HasPrefix(rel, "svc/env-registry/") {
				if _, err := os.Stat(filepath.Join(serviceDir(t), strings.TrimPrefix(rel, "svc/env-registry/"))); err != nil {
					t.Errorf("shared-test-inputs.json names missing %s", rel)
				}
			}
		}
	})
}

func sharedInputs(t *testing.T) map[string][]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(serviceDir(t), "qualification", "gitea-declarations.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Schemas map[string][]string `json:"schemas"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, v := range doc.Schemas {
		sort.Strings(v)
	}
	return doc.Schemas
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
