//go:build integration

package test

import (
	"context"
	"database/sql"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/pandops/flowai-env-registry/internal/migrations"
	"github.com/pandops/flowai-env-registry/internal/secretbox"
	"github.com/pandops/flowai-env-registry/internal/store"
)

// Coverage: "Each service writes only its own <name>_schema with its own
// role; another schema is refused" (1.7; service-platform), plus the
// env-registry constraints a unit test cannot prove: immutable secret
// versions and revisions, and the composite team foreign keys.

func TestSchemaIsolation(t *testing.T) {
	ctx := context.Background()

	t.Run("Migration runs in the deployment-created schema without CREATE on the database", func(t *testing.T) {
		d := newTestDB(t, true)
		_, db := d.openStore(t)
		if err := migrations.Apply(ctx, db, serviceSchema); err != nil {
			t.Fatalf("second migrate: %v", err)
		}
		rows, err := d.admin.Query(`SELECT DISTINCT table_schema FROM information_schema.tables WHERE table_schema NOT IN ('pg_catalog','information_schema') ORDER BY 1`)
		if err != nil {
			t.Fatal(err)
		}
		var schemas []string
		for rows.Next() {
			var n string
			_ = rows.Scan(&n)
			schemas = append(schemas, n)
		}
		rows.Close()
		want := []string{serviceSchema, foreignSchema}
		sort.Strings(want) // the query orders schema names
		if strings.Join(schemas, ",") != strings.Join(want, ",") {
			t.Fatalf("tables in schemas %v", schemas)
		}
		var owner string
		if err := d.admin.QueryRow(`SELECT DISTINCT tableowner FROM pg_tables WHERE schemaname = $1`, serviceSchema).Scan(&owner); err != nil || owner != serviceRole {
			t.Fatalf("table owner %q %v", owner, err)
		}
		var n int
		_ = d.admin.QueryRow(`SELECT count(*) FROM information_schema.columns WHERE table_schema = $1 AND (column_name ILIKE '%plaintext%' OR column_name ILIKE '%data_key%' OR column_name = 'value')`, serviceSchema).Scan(&n)
		if n != 0 {
			t.Fatalf("%d plaintext-like columns", n)
		}
	})

	t.Run("Missing schema is created", func(t *testing.T) {
		d := newTestDB(t, false)
		d.openStoreAs(t, "flowai", pg.password)
		var ok bool
		_ = d.admin.QueryRow(`SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = $1)`, serviceSchema).Scan(&ok)
		if !ok {
			t.Fatal("schema not created")
		}
	})

	t.Run("Access to a foreign schema is denied", func(t *testing.T) {
		d := newTestDB(t, true)
		d.openStore(t)
		role, err := sql.Open("pgx", pg.dsn(serviceRole, rolePassword, d.name))
		if err != nil {
			t.Fatal(err)
		}
		defer role.Close()
		for _, q := range []string{
			`SELECT * FROM ` + foreignSchema + `.teams`,
			`INSERT INTO ` + foreignSchema + `.teams VALUES (1)`,
			`CREATE TABLE ` + foreignSchema + `.x (a int)`,
			`CREATE TABLE public.x (a int)`,
			`CREATE SCHEMA other_schema`,
		} {
			if _, err := role.Exec(q); err == nil || !strings.Contains(err.Error(), "permission denied") {
				t.Errorf("%s: %v", q, err)
			}
		}
		foreign, _ := sql.Open("pgx", pg.dsn(foreignRole, rolePassword, d.name))
		defer foreign.Close()
		var table string
		_ = d.admin.QueryRow(`SELECT tablename FROM pg_tables WHERE schemaname = $1 ORDER BY 1 LIMIT 1`, serviceSchema).Scan(&table)
		if _, err := foreign.Exec(`SELECT * FROM ` + serviceSchema + `.` + table); err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Errorf("foreign role read env-registry: %v", err)
		}
	})

	t.Run("Secret versions and revisions are immutable and children keep their team", func(t *testing.T) {
		d := newTestDB(t, true)
		s, db := d.openStore(t)
		now := time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC)
		env := store.Definition{TeamID: 3, Scope: store.ScopeTeam, Name: "t", Env: map[string]string{"A": "1"}, Revision: 1, CreatedAt: now, UpdatedAt: now}
		err := s.InTx(ctx, func(tx store.Tx) error {
			id, err := tx.NextTeamNumber(ctx, 3, store.KindEnvironment)
			if err != nil {
				return err
			}
			env.EnvironmentID = id
			if err := tx.InsertDefinition(ctx, env); err != nil {
				return err
			}
			if err := tx.AppendRevision(ctx, store.Revision{TeamID: 3, EnvironmentID: id, Revision: 1, Scope: store.ScopeTeam, Name: "t", Env: env.Env, ActorID: 41, RequestID: 9001, CreatedAt: now}); err != nil {
				return err
			}
			if err := tx.InsertSecret(ctx, store.Secret{TeamID: 3, SecretID: 1, EnvironmentID: id, Key: "S", LatestVersion: 1, CreatedAt: now, UpdatedAt: now}); err != nil {
				return err
			}
			return tx.InsertSecretVersion(ctx, store.SecretVersion{TeamID: 3, SecretID: 1, Version: 1, CreatedAt: now,
				Envelope: secretbox.Envelope{Provider: secretbox.ProviderLocal, KeyID: 1, Nonce: make([]byte, 12), Ciphertext: make([]byte, 20)}})
		})
		if err != nil {
			t.Fatalf("seed: %v", err)
		}
		for _, q := range []string{
			`UPDATE secret_versions SET created_at = now()`,
			`DELETE FROM secret_versions`,
			`UPDATE revisions SET name = 'x'`,
			`DELETE FROM revisions`,
			`UPDATE definitions SET team_id = 4`,
			`UPDATE secrets SET team_id = 4`,
		} {
			if _, err := db.Exec(q); err == nil {
				t.Errorf("%s succeeded", q)
			}
		}
		// A child attached to a parent of another team is refused by the constraints.
		children := map[string]func(tx store.Tx) error{
			"secret on a team-4 parent id": func(tx store.Tx) error {
				return tx.InsertSecret(ctx, store.Secret{TeamID: 4, SecretID: 1, EnvironmentID: env.EnvironmentID, Key: "S", CreatedAt: now, UpdatedAt: now})
			},
			"version of a team-4 secret": func(tx store.Tx) error {
				return tx.InsertSecretVersion(ctx, store.SecretVersion{TeamID: 4, SecretID: 1, Version: 2, CreatedAt: now,
					Envelope: secretbox.Envelope{Provider: secretbox.ProviderLocal, KeyID: 1, Nonce: make([]byte, 12), Ciphertext: make([]byte, 20)}})
			},
			"revision of a team-4 definition": func(tx store.Tx) error {
				return tx.AppendRevision(ctx, store.Revision{TeamID: 4, EnvironmentID: env.EnvironmentID, Revision: 2, Scope: store.ScopeTeam, Name: "t", CreatedAt: now})
			},
		}
		for name, fn := range children {
			if err := s.InTx(ctx, fn); err == nil {
				t.Errorf("%s accepted", name)
			}
		}
		var n int
		_ = db.QueryRow(`SELECT count(*) FROM secrets WHERE team_id = 4`).Scan(&n)
		if n != 0 {
			t.Fatal("a foreign-team child was created")
		}
	})
}
