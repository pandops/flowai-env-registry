package test

import (
	"context"
	"encoding/json"
	"sort"
	"sync"
	"testing"

	"github.com/pandops/flowai-env-registry/internal/broker"
)

// Requirement: service-platform services use integer identifiers.
func TestServicePlatformServicesUseIntegerIdentifiers(t *testing.T) {
	t.Run("Invalid identifier is rejected", func(t *testing.T) {
		// environment_id and secret_id are covered by the env-registry
		// requirement; this covers team_id in params and in the header.
		e := newEnv(t)
		id := e.createTeam(3, "team", map[string]string{"A": "1"})
		before := len(e.store.Outbox())
		for _, m := range []string{"GetDefinition", "ListDefinitions", "InsertDefinition"} {
			e.store.FailNext(m, errInjected)
		}
		raw := []string{`"abc"`, `0`, `-1`, `1.5`, `9223372036854775808`, `"3f2c8a10-6b1e-4d2a-9c3e-5a7b8c9d0e1f"`, `"3"`, `null`}
		for _, v := range raw {
			for _, op := range []string{"list", "get", "create"} {
				body := `{"params":{"team_id":` + v + `,"environment_id":` + itoa(id) + `}}`
				if op == "create" {
					body = `{"params":{"team_id":` + v + `},"body":{"scope":"team","name":"x","env":{}}}`
				}
				r := e.uiRaw(op, ctxHeaders(3), []byte(body))
				if r.Status != 400 || r.code() != "invalid_request" {
					t.Errorf("%s team_id %s: %d %s", op, v, r.Status, r.Raw)
				}
			}
		}
		for _, v := range []string{"abc", "0", "-1", "1.5", "9223372036854775808", "3f2c8a10-6b1e-4d2a-9c3e-5a7b8c9d0e1f", "+3", " 3"} {
			h := ctxHeaders(3)
			h["team"] = v
			if r := e.uiWith("get", h, map[string]any{"team_id": 3, "environment_id": id}, nil); r.Status != 400 || r.code() != "invalid_request" {
				t.Errorf("header team %q: %d %s", v, r.Status, r.Raw)
			}
		}
		if len(e.store.Outbox()) != before || len(e.store.Definitions()) != 1 {
			t.Fatal("an invalid identifier wrote something")
		}
	})

	t.Run("First record in each team is 1", func(t *testing.T) {
		e := newEnv(t)
		a := e.createTeam(3, "a", map[string]string{})
		b := e.createTeam(4, "b", map[string]string{})
		e.addFlow(3, 9)
		c := e.createFlow(3, 9, "c", map[string]string{})
		if a != 1 || b != 1 || c != 2 {
			t.Fatalf("numbers (3,%d) (4,%d) (3,%d), want (3,1) (4,1) (3,2)", a, b, c)
		}
		s1 := e.createSecret(4, b, "S", secretCanary)
		s2 := e.createSecret(3, a, "S", secretCanary)
		s3 := e.createSecret(3, c, "S", secretCanary)
		if s1 != 1 || s2 != 1 || s3 != 2 {
			t.Fatalf("secret numbers %d %d %d", s1, s2, s3)
		}
	})

	t.Run("Equal numbers in two teams grant nothing", func(t *testing.T) {
		e := newEnv(t)
		e.createTeam(3, "three", map[string]string{"A": "3"})
		e.createTeam(4, "four", map[string]string{"A": "4"})
		r := e.ui("get", 3, map[string]any{"team_id": 3, "environment_id": 1}, nil)
		if r.Status != 200 || r.Body["name"] != "three" || num(t, r.Body, "team_id") != 3 {
			t.Fatalf("get (3,1): %d %s", r.Status, r.Raw)
		}
		e.ui("replace", 3, map[string]any{"team_id": 3, "environment_id": 1}, map[string]any{"scope": "team", "name": "three", "env": map[string]string{"A": "changed"}})
		e.createSecret(3, 1, "S", secretCanary)
		e.ui("delete", 3, map[string]any{"team_id": 3, "environment_id": 1}, nil)
		for _, d := range e.store.Definitions() {
			if d.TeamID == 4 && (d.Deleted || d.Revision != 1 || d.Env["A"] != "4") {
				t.Fatalf("team 4's definition 1 changed: %+v", d)
			}
		}
		for _, s := range e.store.Secrets() {
			if s.TeamID == 4 {
				t.Fatalf("secret attached to team 4: %+v", s)
			}
		}
	})

	t.Run("Concurrent creates get unique increasing numbers", func(t *testing.T) {
		e := newEnv(t)
		for i := 0; i < 20; i++ {
			e.addFlow(3, int64(100+i))
		}
		e.store.FailNextCommit(errInjected) // at least one rollback
		var wg sync.WaitGroup
		var mu sync.Mutex
		ids := []int64{}
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				if i%4 == 0 {
					e.store.FailNextCommit(errInjected)
				}
				r := e.svc.HandleUI(context.Background(), broker.Msg{
					Subject: "env-registry.ui.create.sub", Header: ctxHeaders(3),
					Data: []byte(`{"params":{"team_id":3},"body":{"scope":"flow","flow_id":` + itoa(int64(100+i)) + `,"name":"f","env":{}}}`),
				})
				if r.Header["status"] == "201" {
					var b map[string]any
					_ = json.Unmarshal(r.Data, &b)
					mu.Lock()
					ids = append(ids, int64(b["environment_id"].(float64)))
					mu.Unlock()
				}
			}(i)
		}
		wg.Wait()
		defs := e.store.Definitions()
		if len(defs) != len(ids) || len(ids) == 0 || len(ids) == 20 {
			t.Fatalf("committed %d definitions, %d created replies", len(defs), len(ids))
		}
		seen := map[int64]bool{}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		sort.Slice(defs, func(i, j int) bool { return defs[i].EnvironmentID < defs[j].EnvironmentID })
		for i, d := range defs {
			if seen[d.EnvironmentID] {
				t.Fatalf("number %d reused", d.EnvironmentID)
			}
			seen[d.EnvironmentID] = true
			if d.EnvironmentID != ids[i] || d.EnvironmentID < 1 {
				t.Fatalf("committed numbers %v differ from replies %v", d.EnvironmentID, ids)
			}
		}
		// Each create allocated one number from 1..20; a rolled-back create
		// leaves a gap that no later create fills.
		if last := defs[len(defs)-1].EnvironmentID; last > 20 {
			t.Fatalf("numbers beyond the 20 allocations: %d", last)
		}
		gaps := 0
		for n := int64(1); n <= 20; n++ {
			if !seen[n] {
				gaps++
			}
		}
		if gaps != 20-len(ids) {
			t.Fatalf("%d gaps for %d rolled-back creates: a rolled-back number was reused", gaps, 20-len(ids))
		}
		e.addFlow(3, 999)
		if r := e.ui("create", 3, map[string]any{"team_id": 3}, map[string]any{"scope": "flow", "flow_id": 999, "name": "f", "env": map[string]string{}}); r.Status != 201 || num(t, r.Body, "environment_id") != 21 {
			t.Fatalf("create after the rollbacks: %d %s", r.Status, r.Raw)
		}
	})

	t.Run("Rolled-back transaction neither publishes nor reuses its sequence", func(t *testing.T) {
		e := newEnv(t)
		e.store.SetPublisherSeq(76)
		e.store.FailNextCommit(errInjected)
		if r := e.ui("create", 3, map[string]any{"team_id": 3}, map[string]any{"scope": "team", "name": "x", "env": map[string]string{}}); r.Status < 500 {
			t.Fatalf("create with failed commit: %d %s", r.Status, r.Raw)
		}
		e.createTeam(3, "y", map[string]string{})
		flushAll(t, e)
		pub := e.broker.Published()
		if len(pub) != 1 || pub[0].Header["Nats-Msg-Id"] == "env-registry-77" {
			t.Fatalf("published %+v", pub)
		}
		var p map[string]any
		_ = json.Unmarshal(pub[0].Data, &p)
		if num(t, p, "publisher_seq") <= 77 {
			t.Fatalf("next message seq %d, want > 77", num(t, p, "publisher_seq"))
		}
	})

	t.Run("Redelivered message is deduplicated by publisher sequence", func(t *testing.T) {
		e := newEnv(t)
		e.createTeam(3, "team", map[string]string{"A": "1"})
		c := claim(5, 1, 1)
		e.setClaim(c, 1, true)
		openValues(t, e.open("5", e.token(c)))
		if got := e.svc.HandleArchived(context.Background(), archivedMsg(120, 3, 5)); got != broker.Ack {
			t.Fatalf("first %v", got)
		}
		c2 := claim(5, 2, 1)
		e.setClaim(c2, 1, true)
		openValues(t, e.open("5", e.token(c2)))
		if got := e.svc.HandleArchived(context.Background(), archivedMsg(120, 3, 5)); got != broker.Ack {
			t.Fatalf("redelivery %v, want Ack", got)
		}
		if len(e.store.Snapshots()) != 1 {
			t.Fatal("redelivered message applied again")
		}
		// Another publisher's equal sequence is a distinct message.
		other := archivedMsg(120, 3, 5)
		var p map[string]any
		_ = json.Unmarshal(other.Data, &p)
		p["publisher"] = "task-manager-other"
		other.Data, _ = json.Marshal(p)
		_ = e.svc.HandleArchived(context.Background(), other)
		if len(e.store.Snapshots()) != 1 {
			t.Fatal("a message from an unexpected publisher was applied")
		}
	})
}
