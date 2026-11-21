package test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/pandops/flowai-env-registry/internal/migrations"
)

// Requirement: service-platform service owns one PostgreSQL schema and role.
func TestServicePlatformServiceOwnsOnePostgreSQLSchema(t *testing.T) {
	t.Run("Access to a foreign schema is denied", func(t *testing.T) {
		// env-registry's migrations name no other service's schema, grant
		// nothing to other roles and never touch public; the database denial
		// itself is the integration test TestIntegrationOwnSchemaRole.
		stmts, err := migrations.Statements(migrations.DefaultSchema)
		if err != nil {
			t.Fatal(err)
		}
		all := strings.Join(stmts, "\n")
		for _, m := range regexp.MustCompile(`\b([a-z][a-z0-9_]*_schema)\b`).FindAllStringSubmatch(all, -1) {
			if m[1] != migrations.DefaultSchema {
				t.Errorf("migrations reference foreign schema %s", m[1])
			}
		}
		if regexp.MustCompile(`(?i)\bpublic\.|GRANT\s+.*\bTO\s+PUBLIC\b|\bstate_registry\b`).MatchString(all) {
			t.Error("migrations reach public or the old State Registry schema")
		}
	})
}
