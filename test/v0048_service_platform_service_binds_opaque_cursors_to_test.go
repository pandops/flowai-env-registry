package test

import (
	"testing"
)

// The pagination error codes of env-registry's existing REST contract.
const (
	cursorErrorCode = "invalid_cursor"
	limitErrorCode  = "invalid_limit"
)

// pagedTeam stores 25 team-3 Flow definitions (Flows 100-124, one active
// definition per Flow), one team-3 team definition, and three of team 4.
func pagedTeam(t *testing.T) *env {
	e := newEnv(t)
	for i := int64(0); i < 25; i++ {
		e.createFlow(3, 100+i, "p", map[string]string{})
	}
	e.createTeam(3, "q", map[string]string{})
	for i := int64(0); i < 3; i++ {
		e.createFlow(4, 100+i, "r", map[string]string{})
	}
	return e
}

func withParams(base map[string]any, kv ...any) map[string]any {
	out := map[string]any{}
	for k, v := range base {
		out[k] = v
	}
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] == nil {
			delete(out, kv[i].(string))
			continue
		}
		out[kv[i].(string)] = kv[i+1]
	}
	return out
}

// guardReads makes a protected read fail loudly if it runs.
func guardReads(e *env) {
	for _, m := range []string{"ListDefinitions", "ListRevisions", "ListSecretVersions", "GetDefinition", "GetSecret"} {
		e.store.FailNext(m, errInjected)
	}
}

// Requirement: service-platform service binds opaque cursors to their read.
func TestServicePlatformServiceBindsOpaqueCursorsToTheirRead(t *testing.T) {
	base := map[string]any{"team_id": 3, "scope": "flow", "limit": 10}

	t.Run("Forward page advances", func(t *testing.T) {
		e := pagedTeam(t)
		seen := map[int64]bool{}
		var last int64
		params := base
		sizes := []int{}
		for page := 0; page < 5; page++ {
			r := e.ui("list", 3, params, nil)
			if r.Status != 200 {
				t.Fatalf("page %d: %d %s", page, r.Status, r.Raw)
			}
			items := r.Body["items"].([]any)
			sizes = append(sizes, len(items))
			for _, it := range items {
				m := it.(map[string]any)
				id := num(t, m, "environment_id")
				if seen[id] || id <= last || num(t, m, "team_id") != 3 || m["scope"] != "flow" || m["name"] != "p" {
					t.Fatalf("page %d row %v (last %d)", page, m, last)
				}
				seen[id], last = true, id
			}
			if r.Body["next_cursor"] == nil {
				break
			}
			params = withParams(base, "cursor", r.Body["next_cursor"])
		}
		if len(sizes) != 3 || sizes[0] != 10 || sizes[1] != 10 || sizes[2] != 5 || len(seen) != 25 {
			t.Fatalf("page sizes %v, rows %d", sizes, len(seen))
		}
	})

	t.Run("Tampered cursor", func(t *testing.T) {
		e := pagedTeam(t)
		cur := e.ui("list", 3, base, nil).Body["next_cursor"].(string)
		// The last character may carry unused padding bits, so it is not flipped.
		for i := 0; i < len(cur)-1; i += 3 {
			b := []byte(cur)
			if b[i] == 'A' {
				b[i] = 'B'
			} else {
				b[i] = 'A'
			}
			guardReads(e)
			r := e.ui("list", 3, withParams(base, "cursor", string(b)), nil)
			if r.Status != 400 || r.code() != cursorErrorCode {
				t.Fatalf("cursor with byte %d changed: %d %s", i, r.Status, r.Raw)
			}
		}
		for _, bad := range []string{"x", "....", cur + "A", "eyJ0ZWFtX2lkIjozfQ"} {
			guardReads(e)
			if r := e.ui("list", 3, withParams(base, "cursor", bad), nil); r.Status != 400 || r.code() != cursorErrorCode {
				t.Fatalf("cursor %q: %d %s", bad, r.Status, r.Raw)
			}
		}
	})

	t.Run("Cursor reused for another operation or team", func(t *testing.T) {
		e := pagedTeam(t)
		cur := e.ui("list", 3, base, nil).Body["next_cursor"].(string)
		guardReads(e)
		if r := e.ui("list-revisions", 3, map[string]any{"team_id": 3, "environment_id": 1, "cursor": cur}, nil); r.Status != 400 || r.code() != cursorErrorCode {
			t.Fatalf("list cursor on list-revisions: %d %s", r.Status, r.Raw)
		}
		guardReads(e)
		if r := e.ui("list", 4, withParams(base, "team_id", 4, "cursor", cur), nil); r.Status != 400 || r.code() != cursorErrorCode {
			t.Fatalf("team 3 cursor in team 4 context: %d %s", r.Status, r.Raw)
		}
		h := ctxHeaders(3)
		h["operator_id"] = "42"
		guardReads(e)
		if r := e.uiWith("list", h, withParams(base, "cursor", cur), nil); r.Status != 400 || r.code() != cursorErrorCode {
			t.Fatalf("cursor of operator 41 used by operator 42: %d %s", r.Status, r.Raw)
		}
	})

	t.Run("Changed filter", func(t *testing.T) {
		e := pagedTeam(t)
		cur := e.ui("list", 3, base, nil).Body["next_cursor"].(string)
		for _, p := range []map[string]any{
			withParams(base, "flow_id", 100, "cursor", cur),
			withParams(base, "scope", nil, "cursor", cur),
			withParams(base, "scope", "team", "cursor", cur),
		} {
			guardReads(e)
			r := e.ui("list", 3, p, nil)
			if r.Status != 400 || r.code() != cursorErrorCode || r.Body["items"] != nil {
				t.Fatalf("changed filter %v: %d %s", p, r.Status, r.Raw)
			}
		}
	})

	t.Run("Limit out of range", func(t *testing.T) {
		e := pagedTeam(t)
		for _, raw := range []string{`0`, `201`, `1.5`, `"10"`, `7`, `-10`, `true`} {
			guardReads(e)
			r := e.uiRaw("list", ctxHeaders(3), []byte(`{"params":{"team_id":3,"limit":`+raw+`}}`))
			if r.Status != 400 || r.code() != limitErrorCode {
				t.Fatalf("limit %s: %d %s", raw, r.Status, r.Raw)
			}
		}
	})
}
