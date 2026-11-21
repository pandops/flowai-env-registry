package test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/pandops/flowai-env-registry/internal/secretbox"
)

// Requirement: env-registry stores logical secrets with immutable encrypted versions.
func TestEnvRegistryStoresLogicalSecretsWithImmutableVersions(t *testing.T) {
	t.Run("Operator stores a team-wide secret", func(t *testing.T) {
		e := newEnv(t)
		id := e.createTeam(3, "base", map[string]string{})
		r := e.ui("create-secret", 3, map[string]any{"team_id": 3, "environment_id": id}, map[string]any{"key": "DB_PASSWORD", "value": secretCanary})
		if r.Status != 201 || r.Body["key"] != "DB_PASSWORD" || num(t, r.Body, "current_version") != 1 || r.Body["revoked"] != false {
			t.Fatalf("create-secret: %d %s", r.Status, r.Raw)
		}
		if strings.Contains(string(r.Raw), secretCanary) {
			t.Fatal("reply returns the plaintext")
		}
		s := e.store.Secrets()
		v := e.store.Versions()
		if len(s) != 1 || s[0].TeamID != 3 || s[0].EnvironmentID != id || len(v) != 1 || v[0].Version != 1 {
			t.Fatalf("stored secret %+v versions %+v", s, v)
		}
		if bytes.Contains(v[0].Envelope.Ciphertext, []byte(secretCanary)) || v[0].Envelope.Provider != secretbox.ProviderLocal || v[0].Envelope.KeyID != 1 {
			t.Fatalf("stored envelope %+v", v[0].Envelope)
		}
		audits := e.outboxPayloads("env-registry.audit.secret_created")
		if len(audits) != 1 || audits[0]["resource_type"] != "secret" || num(t, audits[0], "resource_id") != s[0].SecretID {
			t.Fatalf("audit %v", audits)
		}
		e.assertNoCanary(t, secretCanary)
	})

	t.Run("Secret value changes", func(t *testing.T) {
		e := newEnv(t)
		id := e.createTeam(3, "base", map[string]string{})
		sid := e.createSecret(3, id, "DB_PASSWORD", secretCanary)
		first := e.store.Versions()[0]
		r := e.ui("replace-secret", 3, map[string]any{"team_id": 3, "environment_id": id, "secret_id": sid}, map[string]any{"value": secretCanary2})
		if r.Status != 200 || num(t, r.Body, "current_version") != 2 {
			t.Fatalf("replace-secret: %d %s", r.Status, r.Raw)
		}
		v := e.store.Versions()
		if len(v) != 2 || !bytes.Equal(v[0].Envelope.Ciphertext, first.Envelope.Ciphertext) || !bytes.Equal(v[0].Envelope.Nonce, first.Envelope.Nonce) {
			t.Fatalf("earlier version modified: %+v", v)
		}
		if bytes.Equal(v[0].Envelope.Nonce, v[1].Envelope.Nonce) {
			t.Fatal("nonce reused across versions")
		}
		list := e.ui("list-secret-versions", 3, map[string]any{"team_id": 3, "environment_id": id, "secret_id": sid}, nil)
		items := list.Body["items"].([]any)
		if list.Status != 200 || len(items) != 2 || num(t, items[0].(map[string]any), "version") != 2 || num(t, items[1].(map[string]any), "version") != 1 {
			t.Fatalf("versions: %d %s", list.Status, list.Raw)
		}
		for _, it := range items {
			if len(it.(map[string]any)) != 2 {
				t.Fatalf("version item exposes more than version metadata: %v", it)
			}
		}
		e.assertNoCanary(t, secretCanary, secretCanary2)
	})

	t.Run("Secret value crosses the broker only in request/reply", func(t *testing.T) {
		e := newEnv(t)
		id := e.createTeam(3, "base", map[string]string{})
		sid := e.createSecret(3, id, "DB_PASSWORD", secretCanary)
		e.ui("replace-secret", 3, map[string]any{"team_id": 3, "environment_id": id, "secret_id": sid}, map[string]any{"value": secretCanary2})
		flushAll(t, e)
		for _, m := range e.broker.Published() {
			if bytes.Contains(m.Data, []byte(secretCanary2)) || bytes.Contains(m.Data, []byte(secretCanary)) {
				t.Fatalf("stream message %s carries the value", m.Subject)
			}
		}
		if len(e.broker.Published()) == 0 {
			t.Fatal("no audit reached the stream")
		}
		for _, m := range e.broker.Requests() {
			if bytes.Contains(m.Data, []byte(secretCanary2)) {
				t.Fatalf("env-registry sent the value on in request %s", m.Subject)
			}
		}
		e.assertNoCanary(t, secretCanary, secretCanary2)
	})

	t.Run("Revoked secret is absent from later snapshots", func(t *testing.T) {
		e := newEnv(t)
		id := e.createTeam(3, "base", map[string]string{"A": "1"})
		sid := e.createSecret(3, id, "DB_PASSWORD", secretCanary)
		before := claim(1, 1, 1)
		e.setClaim(before, 1, true)
		if v := openValues(t, e.open("1", e.token(before))); v["DB_PASSWORD"] != secretCanary {
			t.Fatalf("before revoke %v", v)
		}
		r := e.ui("revoke-secret", 3, map[string]any{"team_id": 3, "environment_id": id, "secret_id": sid}, nil)
		if r.Status != 204 {
			t.Fatalf("revoke: %d %s", r.Status, r.Raw)
		}
		if s := e.store.Secrets()[0]; !s.Revoked {
			t.Fatalf("secret not revoked %+v", s)
		}
		if len(e.store.Versions()) != 1 {
			t.Fatal("revoke removed stored versions")
		}
		revs := e.store.Revisions()
		last := revs[len(revs)-1]
		// Creating the secret appends no revision; the revoke appends one.
		if len(last.SecretKeys) != 0 || len(revs) != 2 || last.Revision != 2 || last.Deleted {
			t.Fatalf("revoke history %+v", revs)
		}
		g := e.ui("get", 3, map[string]any{"team_id": 3, "environment_id": id}, nil)
		if len(g.Body["secrets"].([]any)) != 0 {
			t.Fatalf("current projection still lists the secret: %s", g.Raw)
		}
		decrypts := e.decrypts()
		after := claim(2, 1, 1)
		e.setClaim(after, 1, true)
		if v := openValues(t, e.open("2", e.token(after))); v["DB_PASSWORD"] != "" || v["A"] != "1" {
			t.Fatalf("after revoke %v", v)
		}
		if e.decrypts() != decrypts {
			t.Fatal("open after revoke decrypted the revoked secret")
		}
	})

	t.Run("Secret targets a foreign definition", func(t *testing.T) {
		e := newEnv(t)
		foreign := e.createTeam(4, "team 4", map[string]string{})
		fsid := e.createSecret(4, foreign, "DB_PASSWORD", secretCanary)
		encBefore, decBefore := e.crypto.Counts()
		revsBefore := len(e.store.Revisions())
		cases := []struct {
			op     string
			params map[string]any
			body   any
		}{
			{"create-secret", map[string]any{"team_id": 3, "environment_id": foreign}, map[string]any{"key": "X", "value": secretCanary2}},
			{"replace-secret", map[string]any{"team_id": 3, "environment_id": foreign, "secret_id": fsid}, map[string]any{"value": secretCanary2}},
			{"revoke-secret", map[string]any{"team_id": 3, "environment_id": foreign, "secret_id": fsid}, nil},
			{"list-secret-versions", map[string]any{"team_id": 3, "environment_id": foreign, "secret_id": fsid}, nil},
		}
		for _, c := range cases {
			r := e.ui(c.op, 3, c.params, c.body)
			if r.Status != 404 || r.code() != "environment_unknown_or_unavailable" {
				t.Errorf("%s on a foreign definition: %d %s", c.op, r.Status, r.Raw)
			}
		}
		// Own definition, foreign secret id.
		own := e.createTeam(3, "team 3", map[string]string{})
		if r := e.ui("replace-secret", 3, map[string]any{"team_id": 3, "environment_id": own, "secret_id": fsid}, map[string]any{"value": secretCanary2}); r.Status != 404 {
			t.Errorf("foreign secret id under own definition: %d %s", r.Status, r.Raw)
		}
		enc, dec := e.crypto.Counts()
		if enc != encBefore || dec != decBefore {
			t.Fatalf("encrypt/decrypt ran for a foreign target: %d/%d -> %d/%d", encBefore, decBefore, enc, dec)
		}
		if len(e.store.Secrets()) != 1 || len(e.store.Versions()) != 1 || e.store.Secrets()[0].Revoked || len(e.store.Revisions()) != revsBefore+1 {
			t.Fatal("a foreign secret write stored a secret, version or revision")
		}
	})

	t.Run("Global secret mutation is refused", func(t *testing.T) {
		e := newEnv(t)
		gid := e.seedGlobal(map[string]string{})
		encBefore, _ := e.crypto.Counts()
		r := e.ui("create-secret", 3, map[string]any{"team_id": 3, "environment_id": gid}, map[string]any{"key": "G", "value": secretCanary})
		if r.Status < 400 {
			t.Fatalf("global secret create: %d %s", r.Status, r.Raw)
		}
		if enc, _ := e.crypto.Counts(); enc != encBefore || len(e.store.Secrets()) != 0 {
			t.Fatal("global secret was stored or encrypted")
		}
	})
}
