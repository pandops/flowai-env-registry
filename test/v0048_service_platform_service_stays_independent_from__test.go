package test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/pandops/flowai-env-registry/internal/service"
	"github.com/pandops/flowai-env-registry/internal/store"
)

// Requirement: service-platform service stays independent from execution and identity.
// "Executor capacity is not decided centrally" is not applicable to env-registry:
// it handles no task messages and has no capacity input.
func TestServicePlatformServiceStaysIndependentFromExecutionAndIdentity(t *testing.T) {
	t.Run("Image equality across teams grants no authority", func(t *testing.T) {
		e := newEnv(t)
		for _, field := range []string{"image", "default_image", "image_ref"} {
			r := e.ui("create", 3, map[string]any{"team_id": 3}, map[string]any{"scope": "team", "name": "x", "env": map[string]string{}, field: "ghcr.io/acme/agent:1"})
			if r.Status != 400 || r.code() != "invalid_request" {
				t.Errorf("create with %s: %d %s", field, r.Status, r.Raw)
			}
		}
		// Identical names and values in two teams give neither access to the other.
		three := e.createTeam(3, "same", map[string]string{"IMAGE": "ghcr.io/acme/agent:1"})
		e.createTeam(4, "same", map[string]string{"IMAGE": "ghcr.io/acme/agent:1"})
		e.createSecret(4, 1, "S", secretCanary)
		got := e.ui("get", 3, map[string]any{"team_id": 3, "environment_id": three}, nil)
		if got.Status != 200 || len(got.Body["secrets"].([]any)) != 0 {
			t.Fatalf("team 3 sees team 4's secret: %s", got.Raw)
		}
		c := claim(1, 1, 1)
		e.setClaim(c, 1, true)
		v := openValues(t, e.open("1", e.token(c)))
		if _, ok := v["S"]; ok || len(v) != 1 {
			t.Fatalf("team 3 open got %v", v)
		}
		st := reflect.TypeOf(store.Snapshot{})
		for i := 0; i < st.NumField(); i++ {
			if strings.Contains(strings.ToLower(st.Field(i).Name), "image") {
				t.Fatalf("snapshot has image field %s", st.Field(i).Name)
			}
		}
	})

	t.Run("Flow cannot be created from a Source path", func(t *testing.T) {
		e := newEnv(t)
		r := e.ui("create", 3, map[string]any{"team_id": 3}, map[string]any{"scope": "flow", "flow_id": 404, "name": "f", "env": map[string]string{}})
		if r.Status != 404 || r.code() != "environment_unknown_or_unavailable" {
			t.Fatalf("definition for an unknown Flow: %d %s", r.Status, r.Raw)
		}
		for _, m := range e.broker.Requests() {
			if m.Subject != service.FlowOwnerSubject {
				t.Fatalf("env-registry sent %s", m.Subject)
			}
		}
		if len(e.store.Definitions()) != 0 {
			t.Fatal("a definition was stored for an unknown Flow")
		}
	})
}
