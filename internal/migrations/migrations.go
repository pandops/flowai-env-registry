// Package migrations creates and changes env-registry's own schema only.
package migrations

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// DefaultSchema is env-registry's schema name.
const DefaultSchema = "env_registry_schema"

//go:embed sql/*.sql
var files embed.FS

var schemaPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,55}_schema$`)

type migration struct {
	version    int
	statements []string
}

func load(schema string) ([]migration, error) {
	if !schemaPattern.MatchString(schema) {
		return nil, fmt.Errorf("migrations: invalid schema name %q", schema)
	}
	names, err := files.ReadDir("sql")
	if err != nil {
		return nil, err
	}
	sort.Slice(names, func(i, j int) bool { return names[i].Name() < names[j].Name() })
	var out []migration
	for i, n := range names {
		raw, err := files.ReadFile("sql/" + n.Name())
		if err != nil {
			return nil, err
		}
		text := strings.ReplaceAll(string(raw), "{{schema}}", schema)
		out = append(out, migration{version: i + 1, statements: split(text)})
	}
	return out, nil
}

// split separates statements on ";" at line ends outside $$ bodies and drops comments.
func split(text string) []string {
	var out []string
	var cur strings.Builder
	inBody := false
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if !inBody && (trimmed == "" || strings.HasPrefix(trimmed, "--")) {
			continue
		}
		if strings.Count(line, "$$")%2 == 1 {
			inBody = !inBody
		}
		cur.WriteString(line)
		cur.WriteString("\n")
		if !inBody && strings.HasSuffix(trimmed, ";") {
			out = append(out, strings.TrimSpace(cur.String()))
			cur.Reset()
		}
	}
	return out
}

// Statements returns every migration statement rendered for schema, in order.
func Statements(schema string) ([]string, error) {
	ms, err := load(schema)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, m := range ms {
		out = append(out, m.statements...)
	}
	return out, nil
}

// Apply creates schema only when it is missing (the deployment pre-creates
// it and the role has no CREATE on the database) and applies every pending
// migration inside it, one transaction each, under an advisory lock.
func Apply(ctx context.Context, db *sql.DB, schema string) error {
	ms, err := load(schema)
	if err != nil {
		return err
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock(hashtext($1))`, "env-registry-migrations:"+schema); err != nil {
		return err
	}
	defer conn.ExecContext(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock(hashtext($1))`, "env-registry-migrations:"+schema)
	var exists bool
	if err := conn.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = $1)`, schema).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		if _, err := conn.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
			return fmt.Errorf("create schema %s: %w", schema, err)
		}
	}
	if _, err := conn.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS `+schema+`.schema_migrations (version integer PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	for _, m := range ms {
		var done bool
		if err := conn.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM `+schema+`.schema_migrations WHERE version = $1)`, m.version).Scan(&done); err != nil {
			return err
		}
		if done {
			continue
		}
		tx, err := conn.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		for _, st := range m.statements {
			if _, err := tx.ExecContext(ctx, st); err != nil {
				_ = tx.Rollback()
				return fmt.Errorf("migration %d: %w", m.version, err)
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO `+schema+`.schema_migrations (version) VALUES ($1)`, m.version); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}
