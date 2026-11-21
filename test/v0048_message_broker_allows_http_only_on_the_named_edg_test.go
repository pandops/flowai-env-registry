package test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pandops/flowai-env-registry/internal/httpapi"
	"github.com/pandops/flowai-env-registry/internal/store"
)

// Requirement: message-broker allows HTTP only on the named edges.
// "Source system reads its settings on the public edge" and "Journal stream
// edge requires the Gateway token" are not applicable to env-registry.
func TestMessageBrokerAllowsHTTPOnlyOnTheNamedEdges(t *testing.T) {
	t.Run("Service offers no internal HTTP API", func(t *testing.T) {
		e := newEnv(t)
		e.createTeam(3, "team", map[string]string{"A": "1"})
		h := httpapi.NewRouter(e.svc, alwaysReady{})
		before := len(e.store.Outbox())
		guardReads(e)
		for _, c := range []struct{ method, path string }{
			{"GET", "/v1/environments"}, {"GET", "/v1/environments/1"}, {"POST", "/v1/environments"},
			{"PUT", "/v1/environments/1"}, {"DELETE", "/v1/environments/1"}, {"GET", "/ui/v1/environments"},
			{"GET", "/v1/secrets/1"}, {"POST", "/v1/tasks/1/launch-parameters/open"}, {"GET", "/v1/tasks/1/launch-parameters"},
			{"GET", "/metrics"}, {"GET", "/"}, {"GET", "/debug/pprof/"},
		} {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(c.method, c.path, strings.NewReader(`{"scope":"team","name":"x","env":{}}`)))
			if rec.Code != http.StatusNotFound {
				t.Errorf("%s %s: %d", c.method, c.path, rec.Code)
			}
			if strings.Contains(rec.Body.String(), `"A"`) {
				t.Errorf("%s %s revealed data", c.method, c.path)
			}
		}
		if len(e.store.Outbox()) != before || len(e.store.Definitions()) != 1 {
			t.Fatal("an HTTP call changed data")
		}
		for _, p := range []string{"/v1/livez", "/v1/readyz"} {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest("GET", p, nil))
			if rec.Code != http.StatusOK {
				t.Errorf("probe %s: %d", p, rec.Code)
			}
		}
	})

	t.Run("Executor edge errors are distinguishable", func(t *testing.T) {
		e := newEnv(t)
		id := e.createTeam(3, "team", map[string]string{"A": "a-value"})
		e.createSecret(3, id, "S", secretCanary)
		h := httpapi.NewRouter(e.svc, alwaysReady{})
		get := func(task, tok string) (int, map[string]any, string) {
			req := httptest.NewRequest("GET", "/v1/tasks/"+task+"/launch-parameters/open", nil)
			req.Header.Set("Authorization", "Bearer "+tok)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			var b map[string]any
			_ = json.Unmarshal(rec.Body.Bytes(), &b)
			return rec.Code, b, rec.Body.String()
		}
		released := claim(1, 1, 1)
		e.setClaim(released, 1, false)
		if code, b, raw := get("1", e.token(released)); code != 404 || b["code"] != "claim_not_current" || strings.Contains(raw, "a-value") {
			t.Errorf("released claim: %d %s", code, raw)
		}
		e2 := newEnv(t)
		id2 := e2.createTeam(3, "team", map[string]string{"A": "a-value"})
		_ = e2.store.InTx(t.Context(), func(tx store.Tx) error {
			sid, err := tx.NextTeamNumber(t.Context(), 3, store.KindSecret)
			if err != nil {
				return err
			}
			return tx.InsertSecret(t.Context(), store.Secret{TeamID: 3, SecretID: sid, EnvironmentID: id2, Key: "REQUIRED", LatestVersion: 0})
		})
		missing := claim(3, 1, 1)
		e2.setClaim(missing, 1, true)
		h2 := httpapi.NewRouter(e2.svc, alwaysReady{})
		req := httptest.NewRequest("GET", "/v1/tasks/3/launch-parameters/open", nil)
		req.Header.Set("Authorization", "Bearer "+e2.token(missing))
		rec := httptest.NewRecorder()
		h2.ServeHTTP(rec, req)
		var b map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &b)
		if rec.Code != 422 || b["code"] != "configuration_error" || b["failure_reason"] != "missing_required_parameter" || strings.Contains(rec.Body.String(), "a-value") {
			t.Errorf("missing parameter: %d %s", rec.Code, rec.Body.String())
		}
		if err := validateJSON(t, "error.reply.schema.json", rec.Body.Bytes()); err != nil {
			t.Errorf("edge error body: %v", err)
		}
		ok := claim(4, 1, 1)
		e.setClaim(ok, 1, true)
		if code, b, raw := get("4", e.token(ok)); code != 200 || b["values"] == nil {
			t.Errorf("current claim: %d %s", code, raw)
		}
	})
}
