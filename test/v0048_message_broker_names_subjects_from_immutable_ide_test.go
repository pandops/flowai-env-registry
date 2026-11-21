package test

import (
	"strings"
	"testing"
)

// Requirement: message-broker names subjects from immutable identifiers.
func TestMessageBrokerNamesSubjectsFromImmutableIdentifiers(t *testing.T) {
	t.Run("Team appears as a subject token only in the task queue and Source intake", func(t *testing.T) {
		e := newEnv(t)
		e.addFlow(3, 2)
		id := e.createFlow(3, 2, "f", map[string]string{"A": "1"})
		sid := e.createSecret(3, id, "S", secretCanary)
		e.ui("replace-secret", 3, map[string]any{"team_id": 3, "environment_id": id, "secret_id": sid}, map[string]any{"value": secretCanary2})
		c := claim(1, 1, 1)
		e.setClaim(c, 2, true)
		openValues(t, e.open("1", e.token(c)))
		e.ui("delete", 3, map[string]any{"team_id": 3, "environment_id": id}, nil)
		flushAll(t, e)
		subjects := []string{}
		for _, m := range e.broker.Published() {
			subjects = append(subjects, m.Subject)
		}
		for _, m := range e.broker.Requests() {
			subjects = append(subjects, m.Subject)
		}
		if len(subjects) < 5 {
			t.Fatalf("subjects %v", subjects)
		}
		for _, s := range subjects {
			if strings.HasPrefix(s, "flowai.") || !strings.HasSuffix(s, ".pub") {
				t.Errorf("subject %s", s)
			}
			for _, tok := range strings.Split(s, ".") {
				if strings.Trim(tok, "0123456789") == "" {
					t.Errorf("subject %s carries an identifier token", s)
				}
			}
		}
	})
}
