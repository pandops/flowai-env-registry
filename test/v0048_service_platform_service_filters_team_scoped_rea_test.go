package test

import (
	"testing"
)

// Requirement: service-platform service filters team-scoped reads before shaping.
// "Concurrent team streams" is not applicable to env-registry: it serves no stream.
func TestServicePlatformServiceFiltersTeamScopedReadsBeforeShaping(t *testing.T) {
	t.Run("Teams share filter values", func(t *testing.T) {
		// Both teams use the same Flow numbers; each Flow has one active definition.
		e := newEnv(t)
		for i := int64(1); i <= 15; i++ {
			e.createFlow(4, i, "four", map[string]string{})
		}
		for i := int64(1); i <= 12; i++ {
			e.createFlow(3, i, "three", map[string]string{})
		}
		e.createTeam(3, "three", map[string]string{})
		e.createTeam(4, "four", map[string]string{})
		filters := []struct {
			params map[string]any
			second int
		}{
			{map[string]any{"team_id": 3, "scope": "flow", "limit": 10}, 2},
			{map[string]any{"team_id": 3, "limit": 10}, 3},
		}
		for _, c := range filters {
			f := c.params
			p1 := e.ui("list", 3, f, nil)
			items := p1.Body["items"].([]any)
			if p1.Status != 200 || len(items) != 10 || p1.Body["next_cursor"] == nil {
				t.Fatalf("page 1 %v: %d %s", f, p1.Status, p1.Raw)
			}
			f2 := map[string]any{}
			for k, v := range f {
				f2[k] = v
			}
			f2["cursor"] = p1.Body["next_cursor"]
			p2 := e.ui("list", 3, f2, nil)
			items2 := p2.Body["items"].([]any)
			if p2.Status != 200 || len(items2) != c.second || p2.Body["next_cursor"] != nil {
				t.Fatalf("page 2 %v: %d %s", f, p2.Status, p2.Raw)
			}
			for _, it := range append(items, items2...) {
				m := it.(map[string]any)
				if num(t, m, "team_id") != 3 || m["name"] != "three" {
					t.Fatalf("foreign or unfiltered row %v", m)
				}
			}
		}
	})
}
