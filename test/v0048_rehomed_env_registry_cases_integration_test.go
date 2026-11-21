//go:build integration

package test

import (
	"database/sql"
	"strings"
	"testing"

	"github.com/pandops/flowai-env-registry/internal/secretbox"
)

// Survivors of deleted State Registry PostgreSQL cases (ledger M187, M188,
// M189, M192, M194, M403, M414) on env-registry's own store.

func pgEnv(t *testing.T) (*env, *sql.DB) {
	t.Helper()
	d := newTestDB(t, true)
	s, db := d.openStore(t)
	return newEnv(t, withStore(s)), db
}

func pgCount(t *testing.T, db *sql.DB, q string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return n
}

// walkList pages env-registry.ui.list for team with limit 10 and returns
// every item and the page sizes.
func walkList(t *testing.T, e *env, team int64) ([]map[string]any, []int) {
	t.Helper()
	base := map[string]any{"team_id": team, "limit": 10}
	params := base
	var items []map[string]any
	var sizes []int
	for page := 0; page < 10; page++ {
		r := e.ui("list", team, params, nil)
		if r.Status != 200 {
			t.Fatalf("team %d page %d: %d %s", team, page, r.Status, r.Raw)
		}
		got := r.Body["items"].([]any)
		sizes = append(sizes, len(got))
		for _, it := range got {
			items = append(items, it.(map[string]any))
		}
		if r.Body["next_cursor"] == nil {
			return items, sizes
		}
		params = withParams(base, "cursor", r.Body["next_cursor"])
	}
	t.Fatalf("team %d list did not end", team)
	return nil, nil
}

func TestV0048EnvRegistryPostgresDefinitionReads(t *testing.T) {
	// M187, M188: deterministic environment_id order, no overlap or skip,
	// and no foreign row on PostgreSQL pages.
	t.Run("Environment pages walk in order without foreign rows", func(t *testing.T) {
		e, _ := pgEnv(t)
		for i := int64(0); i < 25; i++ {
			e.createFlow(3, 100+i, "p", map[string]string{})
		}
		e.createTeam(3, "q", map[string]string{})
		for i := int64(0); i < 3; i++ {
			e.createFlow(4, 100+i, "r", map[string]string{})
		}
		items, sizes := walkList(t, e, 3)
		if len(sizes) != 3 || sizes[0] != 10 || sizes[1] != 10 || sizes[2] != 6 {
			t.Fatalf("team 3 page sizes %v", sizes)
		}
		for i, it := range items {
			if num(t, it, "environment_id") != int64(i+1) || num(t, it, "team_id") != 3 || it["name"] == "r" {
				t.Fatalf("team 3 row %d: %v", i, it)
			}
		}
		items, sizes = walkList(t, e, 4)
		if len(sizes) != 1 || len(items) != 3 {
			t.Fatalf("team 4 page sizes %v", sizes)
		}
		for i, it := range items {
			if num(t, it, "environment_id") != int64(i+1) || num(t, it, "team_id") != 4 || it["name"] != "r" {
				t.Fatalf("team 4 row %d: %v", i, it)
			}
		}
		if items, _ := walkList(t, e, 5); len(items) != 0 {
			t.Fatalf("team 5 sees %v", items)
		}
	})

	// M189: every list item carries its own secret summaries.
	t.Run("Environment list items carry their secret summaries", func(t *testing.T) {
		e, _ := pgEnv(t)
		team := e.createTeam(3, "team", map[string]string{})
		flow := e.createFlow(3, 100, "flow", map[string]string{})
		e.createSecret(3, team, "ALPHA", secretCanary)
		e.createSecret(3, flow, "BETA", secretCanary)
		revoked := e.createSecret(3, flow, "GAMMA", secretCanary)
		if r := e.ui("revoke-secret", 3, map[string]any{"team_id": 3, "environment_id": flow, "secret_id": revoked}, nil); r.Status != 204 {
			t.Fatalf("revoke: %d %s", r.Status, r.Raw)
		}
		four := e.createTeam(4, "four", map[string]string{})
		e.createSecret(4, four, "DELTA", secretCanary)
		items, _ := walkList(t, e, 3)
		want := map[int64]string{team: "ALPHA", flow: "BETA"}
		if len(items) != 2 {
			t.Fatalf("items %v", items)
		}
		for _, it := range items {
			secrets := it["secrets"].([]any)
			id := num(t, it, "environment_id")
			if len(secrets) != 1 {
				t.Fatalf("environment %d secrets %v", id, secrets)
			}
			s := secrets[0].(map[string]any)
			if s["name"] != want[id] || num(t, s, "team_id") != 3 || num(t, s, "environment_id") != id || num(t, s, "latest_version") != 1 || s["revoked"] != false {
				t.Fatalf("environment %d secret summary %v", id, s)
			}
		}
	})

	// M403: same-team create, read and list; foreign read 404; replace bumps
	// the revision; delete hides the definition.
	t.Run("Team definition lifecycle on PostgreSQL", func(t *testing.T) {
		e, db := pgEnv(t)
		r := e.ui("create", 3, map[string]any{"team_id": 3}, map[string]any{"scope": "team", "name": "team-wide-env", "env": map[string]string{"K1": "v1"}})
		if r.Status != 201 || num(t, r.Body, "team_id") != 3 || r.Body["flow_id"] != nil || r.Body["scope"] != "team" || num(t, r.Body, "revision") != 1 {
			t.Fatalf("create: %d %s", r.Status, r.Raw)
		}
		id := num(t, r.Body, "environment_id")
		get := map[string]any{"team_id": 3, "environment_id": id}
		if r := e.ui("get", 3, get, nil); r.Status != 200 || r.Body["name"] != "team-wide-env" || r.Body["env"].(map[string]any)["K1"] != "v1" {
			t.Fatalf("get: %d %s", r.Status, r.Raw)
		}
		if items, _ := walkList(t, e, 3); len(items) != 1 {
			t.Fatalf("list %v", items)
		}
		if r := e.ui("get", 4, map[string]any{"team_id": 4, "environment_id": id}, nil); r.Status != 404 || r.code() != "environment_unknown_or_unavailable" {
			t.Fatalf("foreign read: %d %s", r.Status, r.Raw)
		}
		r = e.ui("replace", 3, get, map[string]any{"scope": "team", "name": "after", "env": map[string]string{"K1": "v2"}})
		if r.Status != 200 || r.Body["name"] != "after" || num(t, r.Body, "revision") != 2 {
			t.Fatalf("replace: %d %s", r.Status, r.Raw)
		}
		if r := e.ui("delete", 3, get, nil); r.Status != 204 {
			t.Fatalf("delete: %d %s", r.Status, r.Raw)
		}
		if r := e.ui("get", 3, get, nil); r.Status != 404 {
			t.Fatalf("get after delete: %d %s", r.Status, r.Raw)
		}
		if items, _ := walkList(t, e, 3); len(items) != 0 {
			t.Fatalf("list after delete %v", items)
		}
		if n := pgCount(t, db, `SELECT count(*) FROM revisions WHERE team_id = 3 AND environment_id = $1`, id); n != 3 {
			t.Fatalf("%d revisions, want 3", n)
		}
		if n := pgCount(t, db, `SELECT count(*) FROM definitions WHERE team_id = 3 AND environment_id = $1 AND deleted AND revision = 3`, id); n != 1 {
			t.Fatal("definition row is not a deleted revision-3 tombstone")
		}
		// Ordinary updates pass the ownership trigger; a binding change does not.
		if _, err := db.Exec(`UPDATE definitions SET scope = 'flow', flow_id = 9 WHERE team_id = 3 AND environment_id = $1`, id); err == nil || !strings.Contains(err.Error(), "definition ownership and binding are immutable") {
			t.Fatalf("binding change: %v", err)
		}
	})
}

func TestV0048EnvRegistryPostgresSecretVersions(t *testing.T) {
	// M414: each stored version records the provider and key_id.
	t.Run("Secret versions record key metadata", func(t *testing.T) {
		e, db := pgEnv(t)
		envID, sid := secretWithVersions(t, e, 2)
		rows, err := db.Query(`SELECT version, provider, key_id FROM secret_versions WHERE team_id = 3 AND secret_id = $1 ORDER BY version`, sid)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		n := 0
		for rows.Next() {
			var version int
			var provider string
			var keyID int64
			if err := rows.Scan(&version, &provider, &keyID); err != nil {
				t.Fatal(err)
			}
			n++
			if version != n || provider != secretbox.ProviderLocal || keyID != 1 {
				t.Fatalf("version row %d: provider %q key_id %d", version, provider, keyID)
			}
		}
		if err := rows.Err(); err != nil || n != 2 {
			t.Fatalf("%d version rows (%v), want 2", n, err)
		}
		r := e.ui("list-secret-versions", 3, map[string]any{"team_id": 3, "environment_id": envID, "secret_id": sid}, nil)
		if r.Status != 200 || len(r.Body["items"].([]any)) != 2 {
			t.Fatalf("list versions: %d %s", r.Status, r.Raw)
		}
	})

	// M192: version pages in a deterministic order with no overlap on PostgreSQL.
	t.Run("Secret version pages walk in order", func(t *testing.T) {
		e, _ := pgEnv(t)
		envID, sid := secretWithVersions(t, e, 12)
		base := map[string]any{"team_id": 3, "environment_id": envID, "secret_id": sid, "limit": 10}
		params := base
		var seen []int64
		var sizes []int
		for page := 0; page < 5; page++ {
			r := e.ui("list-secret-versions", 3, params, nil)
			if r.Status != 200 {
				t.Fatalf("page %d: %d %s", page, r.Status, r.Raw)
			}
			items := r.Body["items"].([]any)
			sizes = append(sizes, len(items))
			for _, it := range items {
				seen = append(seen, num(t, it.(map[string]any), "version"))
			}
			if r.Body["next_cursor"] == nil {
				break
			}
			params = withParams(base, "cursor", r.Body["next_cursor"])
		}
		if len(sizes) != 2 || sizes[0] != 10 || sizes[1] != 2 || len(seen) != 12 {
			t.Fatalf("page sizes %v, versions %v", sizes, seen)
		}
		for i, v := range seen {
			if v != int64(12-i) {
				t.Fatalf("versions %v, want 12 down to 1", seen)
			}
		}
	})

	// M194: revoke marks the secret revoked, keeps latest_version and every
	// version, audits once; a repeated revoke changes nothing and adds no
	// second succeeded audit.
	t.Run("Revoke keeps versions and audits once", func(t *testing.T) {
		e, db := pgEnv(t)
		envID, sid := secretWithVersions(t, e, 2)
		params := map[string]any{"team_id": 3, "environment_id": envID, "secret_id": sid}
		if r := e.ui("revoke-secret", 3, params, nil); r.Status != 204 || len(r.Raw) != 0 {
			t.Fatalf("revoke: %d %s", r.Status, r.Raw)
		}
		state := func() (int, bool, string, int) {
			var latest, revision int
			var revoked bool
			var updated string
			if err := db.QueryRow(`SELECT s.latest_version, s.revoked, s.updated_at::text, d.revision FROM secrets s JOIN definitions d USING (team_id, environment_id) WHERE s.team_id = 3 AND s.secret_id = $1`, sid).Scan(&latest, &revoked, &updated, &revision); err != nil {
				t.Fatal(err)
			}
			return latest, revoked, updated, revision
		}
		latest, revoked, updated, revision := state()
		if latest != 2 || !revoked {
			t.Fatalf("after revoke latest_version %d revoked %v", latest, revoked)
		}
		versions := `SELECT count(*) FROM secret_versions WHERE team_id = 3 AND secret_id = $1`
		audits := `SELECT count(*) FROM outbox WHERE subject = 'env-registry.audit.secret_revoked.pub' AND convert_from(payload, 'UTF8')::jsonb->>'outcome' = 'succeeded' AND (convert_from(payload, 'UTF8')::jsonb->>'resource_id')::bigint = $1`
		if n := pgCount(t, db, versions, sid); n != 2 {
			t.Fatalf("%d versions after revoke, want 2", n)
		}
		if n := pgCount(t, db, audits, sid); n != 1 {
			t.Fatalf("%d succeeded revoke audits, want 1", n)
		}
		r := e.ui("revoke-secret", 3, params, nil)
		if r.Status != 404 || r.code() != "environment_unknown_or_unavailable" {
			t.Fatalf("repeated revoke: %d %s", r.Status, r.Raw)
		}
		l2, r2, u2, rev2 := state()
		if l2 != latest || r2 != revoked || u2 != updated || rev2 != revision {
			t.Fatalf("repeated revoke changed state: %d %v %s %d", l2, r2, u2, rev2)
		}
		if n := pgCount(t, db, versions, sid); n != 2 {
			t.Fatalf("%d versions after repeated revoke, want 2", n)
		}
		if n := pgCount(t, db, audits, sid); n != 1 {
			t.Fatalf("%d succeeded revoke audits after a repeat, want 1", n)
		}
		if r := e.ui("list-secret-versions", 3, params, nil); r.Status != 200 || len(r.Body["items"].([]any)) != 2 {
			t.Fatalf("revoked secret versions: %d %s", r.Status, r.Raw)
		}
		if _, err := db.Exec(`UPDATE secrets SET key = 'OTHER' WHERE team_id = 3 AND secret_id = $1`, sid); err == nil || !strings.Contains(err.Error(), "secret ownership and key are immutable") {
			t.Fatalf("secret key change: %v", err)
		}
	})
}
