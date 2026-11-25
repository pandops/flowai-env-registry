package test

import (
	"strconv"
	"testing"

	"github.com/pandops/flowai-env-registry/internal/broker"
)

// Survivors of deleted State Registry cases (ledger M58, M110, M114, M116,
// M358) on env-registry's own operations.

// clearGuards drops read guards that the rejected request did not consume.
func clearGuards(e *env) {
	for _, m := range []string{"ListDefinitions", "ListRevisions", "ListSecretVersions", "GetDefinition", "GetSecret"} {
		e.store.FailNext(m, nil)
	}
}

// secretWithVersions creates a team-3 definition with one secret holding n versions.
func secretWithVersions(t *testing.T, e *env, n int) (int64, int64) {
	t.Helper()
	envID := e.createTeam(3, "team", map[string]string{})
	sid := e.createSecret(3, envID, "DB_PASSWORD", secretCanary)
	for i := 2; i <= n; i++ {
		r := e.ui("replace-secret", 3, map[string]any{"team_id": 3, "environment_id": envID, "secret_id": sid}, map[string]any{"value": secretCanary2})
		if r.Status != 200 || num(t, r.Body, "current_version") != int64(i) {
			t.Fatalf("replace %d: %d %s", i, r.Status, r.Raw)
		}
	}
	return envID, sid
}

// Requirement: service-platform service binds opaque cursors to their read,
// on list-secret-versions (M58, M110, M116).
func TestV0048EnvRegistrySecretVersionListPagination(t *testing.T) {
	t.Run("Secret version cursor round-trips its position", func(t *testing.T) {
		e := newEnv(t)
		envID, sid := secretWithVersions(t, e, 12)
		base := map[string]any{"team_id": 3, "environment_id": envID, "secret_id": sid, "limit": 10}
		params := base
		seen := []int64{}
		pages := 0
		for ; pages < 5; pages++ {
			r := e.ui("list-secret-versions", 3, params, nil)
			if r.Status != 200 {
				t.Fatalf("page %d: %d %s", pages, r.Status, r.Raw)
			}
			for _, it := range r.Body["items"].([]any) {
				seen = append(seen, num(t, it.(map[string]any), "version"))
			}
			if r.Body["next_cursor"] == nil {
				break
			}
			params = withParams(base, "cursor", r.Body["next_cursor"])
		}
		want := []int64{12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}
		if pages != 1 || len(seen) != len(want) {
			t.Fatalf("pages %d, versions %v, want %v", pages+1, seen, want)
		}
		for i := range want {
			if seen[i] != want[i] {
				t.Fatalf("versions %v, want %v", seen, want)
			}
		}
	})

	t.Run("Tampered secret version cursor", func(t *testing.T) {
		e := newEnv(t)
		envID, sid := secretWithVersions(t, e, 12)
		base := map[string]any{"team_id": 3, "environment_id": envID, "secret_id": sid, "limit": 10}
		cur := e.ui("list-secret-versions", 3, base, nil).Body["next_cursor"].(string)
		for i := 0; i < len(cur)-1; i += 3 {
			b := []byte(cur)
			if b[i] == 'A' {
				b[i] = 'B'
			} else {
				b[i] = 'A'
			}
			guardReads(e)
			r := e.ui("list-secret-versions", 3, withParams(base, "cursor", string(b)), nil)
			if r.Status != 400 || r.code() != cursorErrorCode {
				t.Fatalf("cursor with byte %d changed: %d %s", i, r.Status, r.Raw)
			}
		}
		// A cursor of the definition list and one of another secret are refused too.
		clearGuards(e)
		for i := int64(0); i < 11; i++ {
			e.createFlow(3, 100+i, "f", map[string]string{})
		}
		listCur := e.ui("list", 3, map[string]any{"team_id": 3, "limit": 10}, nil).Body["next_cursor"].(string)
		other := e.createSecret(3, envID, "OTHER", secretCanary)
		for name, params := range map[string]map[string]any{
			"list cursor":  withParams(base, "cursor", listCur),
			"other secret": withParams(base, "secret_id", other, "cursor", cur),
		} {
			guardReads(e)
			if r := e.ui("list-secret-versions", 3, params, nil); r.Status != 400 || r.code() != cursorErrorCode {
				t.Fatalf("%s: %d %s", name, r.Status, r.Raw)
			}
		}
		clearGuards(e)
		if r := e.ui("list-secret-versions", 3, withParams(base, "cursor", cur), nil); r.Status != 200 || len(r.Body["items"].([]any)) != 2 {
			t.Fatalf("untampered cursor: %d %s", r.Status, r.Raw)
		}
	})

	t.Run("Malformed secret version limit", func(t *testing.T) {
		e := newEnv(t)
		envID, sid := secretWithVersions(t, e, 2)
		for _, raw := range []string{`0`, `201`, `-1`, `"abc"`, `"01"`, `1.5`, `"10"`, `7`, `true`, `null`} {
			guardReads(e)
			body := []byte(`{"params":{"team_id":3,"environment_id":` + strconv.FormatInt(envID, 10) + `,"secret_id":` + strconv.FormatInt(sid, 10) + `,"limit":` + raw + `}}`)
			r := e.uiRaw("list-secret-versions", ctxHeaders(3), body)
			if r.Status != 400 || r.code() != limitErrorCode {
				t.Fatalf("limit %s: %d %s", raw, r.Status, r.Raw)
			}
		}
	})
}

// Requirement: env-registry stores team-owned environment definitions,
// scenario "Request without Gateway context is refused", on revoke-secret (M114).
func TestV0048EnvRegistryRevokeWithoutGatewayContextIsRefused(t *testing.T) {
	e := newEnv(t)
	envID, sid := secretWithVersions(t, e, 1)
	params := map[string]any{"team_id": 3, "environment_id": envID, "secret_id": sid}
	before := len(e.store.Outbox())
	revisions := len(e.store.Revisions())
	cases := map[string]broker.Header{"no headers": {}}
	for _, drop := range []string{"team", "operator_id", "request_id"} {
		h := ctxHeaders(3)
		delete(h, drop)
		cases["without "+drop] = h
	}
	for _, v := range []string{"", " 3", "admin", "0", "abc"} {
		h := ctxHeaders(3)
		h["team"] = v
		cases["team "+v] = h
	}
	for name, h := range cases {
		guardReads(e)
		e.store.FailNext("UpdateSecret", errInjected)
		r := e.uiWith("revoke-secret", h, params, nil)
		if r.Status != 400 || r.code() != "invalid_request" {
			t.Fatalf("%s: %d %s", name, r.Status, r.Raw)
		}
	}
	clearGuards(e)
	e.store.FailNext("UpdateSecret", nil)
	if n := len(e.store.Outbox()); n != before {
		t.Fatalf("refused revokes wrote %d outbox rows", n-before)
	}
	if n := len(e.store.Revisions()); n != revisions {
		t.Fatalf("refused revokes appended %d revisions", n-revisions)
	}
	for _, s := range e.store.Secrets() {
		if s.Revoked {
			t.Fatalf("secret %d revoked by an anonymous request", s.SecretID)
		}
	}
	if r := e.ui("revoke-secret", 3, params, nil); r.Status != 204 {
		t.Fatalf("revoke with Gateway context: %d %s", r.Status, r.Raw)
	}
}

// Requirement: api-gateway collection operations default limit to 10, on
// env-registry's launch-parameter list (M358).
func TestV0048EnvRegistryLaunchParameterListDefaultLimitIsTen(t *testing.T) {
	e := newEnv(t)
	for i := int64(0); i < 11; i++ {
		e.createFlow(3, 100+i, "p", map[string]string{})
	}
	r := e.ui("list", 3, map[string]any{"team_id": 3}, nil)
	if r.Status != 200 {
		t.Fatalf("list: %d %s", r.Status, r.Raw)
	}
	if n := len(r.Body["items"].([]any)); n != 10 || r.Body["next_cursor"] == nil {
		t.Fatalf("default page has %d items, next_cursor %v; want 10 and a cursor", n, r.Body["next_cursor"])
	}
	r = e.ui("list", 3, map[string]any{"team_id": 3, "cursor": r.Body["next_cursor"]}, nil)
	if r.Status != 200 || len(r.Body["items"].([]any)) != 1 || r.Body["next_cursor"] != nil {
		t.Fatalf("second default page: %d %s", r.Status, r.Raw)
	}
}
