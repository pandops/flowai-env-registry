package test

import (
	"context"
	"strings"
	"testing"
)

// Requirement: message-broker never carries secrets in streams or logs.
func TestMessageBrokerNeverCarriesSecretsInStreamsOrLogs(t *testing.T) {
	t.Run("Secret write passes through the broker without storage", func(t *testing.T) {
		e := newEnv(t)
		id := e.createTeam(3, "team", map[string]string{})
		sid := e.createSecret(3, id, "DB_PASSWORD", secretCanary)
		r := e.ui("replace-secret", 3, map[string]any{"team_id": 3, "environment_id": id, "secret_id": sid}, map[string]any{"value": secretCanary2})
		if r.Status != 200 || strings.Contains(string(r.Raw), secretCanary2) {
			t.Fatalf("replace-secret: %d %s", r.Status, r.Raw)
		}
		a := e.outboxPayloads("env-registry.audit.secret_replaced.pub")
		if len(a) != 1 || num(t, a[0], "resource_id") != sid || a[0]["resource_type"] != "secret" {
			t.Fatalf("secret_replaced audit %v", a)
		}
		changes, _ := a[0]["changes"].(map[string]any)
		if changes == nil || num(t, changes, "version") != 2 {
			t.Fatalf("audit changes %v, want the new version 2", a[0]["changes"])
		}
		flushAll(t, e)
		for _, m := range e.broker.Published() {
			if strings.Contains(string(m.Data), secretCanary2) || strings.Contains(string(m.Data), secretCanary) {
				t.Fatalf("stream message %s carries the value", m.Subject)
			}
		}
		e.assertNoCanary(t, secretCanary, secretCanary2)
	})

	t.Run("Stream content inspection", func(t *testing.T) {
		e := newEnv(t)
		e.addFlow(3, 2)
		team := e.createTeam(3, "team", map[string]string{"PLAIN": "plain-canary-value"})
		flow := e.createFlow(3, 2, "flow", map[string]string{"FLOWVAL": "flow-canary-value"})
		sid := e.createSecret(3, team, "S", secretCanary)
		e.createSecret(3, flow, "T", secretCanary2)
		e.ui("revoke-secret", 3, map[string]any{"team_id": 3, "environment_id": team, "secret_id": sid}, nil)
		c := claim(1, 1, 1)
		e.setClaim(c, 2, true)
		tok := e.token(c)
		openValues(t, e.open("1", tok))
		e.setClaim(c, 2, false)
		e.open("1", tok)
		e.svc.HandleArchived(context.Background(), archivedMsg(9, 3, 1))
		flushAll(t, e)
		forbidden := []string{secretCanary, secretCanary2, "plain-canary-value", "flow-canary-value", tok, strings.Split(tok, ".")[1], "BEGIN NATS USER JWT", "SUAFAKESEED"}
		forbidden = append(forbidden, encodings(testDataKey)...)
		for _, m := range e.broker.Published() {
			for _, f := range forbidden {
				if strings.Contains(string(m.Data), f) {
					t.Errorf("%s carries %q", m.Subject, f)
				}
				for k, v := range m.Header {
					if strings.Contains(v, f) {
						t.Errorf("%s header %s carries %q", m.Subject, k, f)
					}
				}
			}
		}
		for _, m := range e.broker.Requests() {
			for _, f := range forbidden {
				if strings.Contains(string(m.Data), f) {
					t.Errorf("request %s carries %q", m.Subject, f)
				}
			}
		}
		logs := e.logs.String()
		for _, f := range forbidden {
			if strings.Contains(logs, f) {
				t.Errorf("logs carry %q", f)
			}
		}
	})
}
