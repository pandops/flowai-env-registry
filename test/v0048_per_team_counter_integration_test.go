//go:build integration

package test

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/pandops/flowai-env-registry/internal/store"
)

// Coverage: "Per-team counters under concurrent creates of one kind in one
// team give unique, increasing numbers; gaps after a rollback are allowed and
// no number is reused; the first record in a new team is 1" (1.7).

func insertFlowDefinition(ctx context.Context, s store.Store, team, flow int64, fail error) (int64, error) {
	var id int64
	err := s.InTx(ctx, func(tx store.Tx) error {
		var err error
		if id, err = tx.NextTeamNumber(ctx, team, store.KindEnvironment); err != nil {
			return err
		}
		now := time.Now().UTC()
		if err := tx.InsertDefinition(ctx, store.Definition{TeamID: team, EnvironmentID: id, Scope: store.ScopeFlow, FlowID: flow, Name: "f", Env: map[string]string{}, Revision: 1, CreatedAt: now, UpdatedAt: now}); err != nil {
			return err
		}
		return fail
	})
	return id, err
}

func insertSecret(ctx context.Context, s store.Store, team, env int64, key string, fail error) (int64, error) {
	var id int64
	err := s.InTx(ctx, func(tx store.Tx) error {
		var err error
		if id, err = tx.NextTeamNumber(ctx, team, store.KindSecret); err != nil {
			return err
		}
		if err := tx.InsertSecret(ctx, store.Secret{TeamID: team, SecretID: id, EnvironmentID: env, Key: key}); err != nil {
			return err
		}
		return fail
	})
	return id, err
}

// runConcurrent runs 20 creates at once; every fourth rolls back. It returns
// the committed numbers and the numbers the rolled-back transactions allocated.
func runConcurrent(t *testing.T, create func(i int, fail error) (int64, error)) (committed, rolledBack []int64) {
	t.Helper()
	var wg sync.WaitGroup
	var mu sync.Mutex
	rollback := errors.New("rollback")
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var fail error
			if i%4 == 0 {
				fail = rollback
			}
			id, err := create(i, fail)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case fail != nil && errors.Is(err, rollback) && id > 0:
				rolledBack = append(rolledBack, id)
			case fail != nil:
				t.Errorf("rolled-back create: id %d, %v", id, err)
			case err != nil:
				t.Errorf("create: %v", err)
			default:
				committed = append(committed, id)
			}
		}(i)
	}
	wg.Wait()
	if len(committed) != 15 || len(rolledBack) != 5 {
		t.Fatalf("committed %d, rolled back %d; want 15 and 5", len(committed), len(rolledBack))
	}
	sort.Slice(committed, func(i, j int) bool { return committed[i] < committed[j] })
	for i := 1; i < len(committed); i++ {
		if committed[i] == committed[i-1] {
			t.Fatalf("number %d given to two commits", committed[i])
		}
	}
	return committed, rolledBack
}

func assertNotReused(t *testing.T, kind string, rolledBack, used []int64) {
	t.Helper()
	seen := map[int64]bool{}
	for _, id := range used {
		seen[id] = true
	}
	for _, id := range rolledBack {
		if seen[id] {
			t.Fatalf("%s number %d of a rolled-back create was reused", kind, id)
		}
	}
}

func TestPerTeamCounter(t *testing.T) {
	ctx := context.Background()
	d := newTestDB(t, true)
	s, db := d.openStore(t)
	if id, err := insertFlowDefinition(ctx, s, 3, 1, nil); err != nil || id != 1 {
		t.Fatalf("first team-3 id %d %v", id, err)
	}
	committed, rolledBack := runConcurrent(t, func(i int, fail error) (int64, error) {
		return insertFlowDefinition(ctx, s, 3, int64(100+i), fail)
	})
	rows, err := db.Query(`SELECT environment_id FROM definitions WHERE team_id = 3`)
	if err != nil {
		t.Fatal(err)
	}
	var stored []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		stored = append(stored, id)
	}
	rows.Close()
	if len(stored) != 16 {
		t.Fatalf("stored %d team-3 definitions, want 16", len(stored))
	}
	if id, err := insertFlowDefinition(ctx, s, 4, 1, nil); err != nil || id != 1 {
		t.Fatalf("first team-4 id %d %v", id, err)
	}
	var later []int64
	for i := int64(0); i < 6; i++ {
		id, err := insertFlowDefinition(ctx, s, 3, 500+i, nil)
		if err != nil || id <= committed[len(committed)-1] {
			t.Fatalf("next team-3 id %d %v", id, err)
		}
		later = append(later, id)
	}
	assertNotReused(t, "environment", rolledBack, append(append(committed, stored...), later...))

	// secret_id uses its own per-team counter.
	if id, err := insertSecret(ctx, s, 3, 1, "FIRST", nil); err != nil || id != 1 {
		t.Fatalf("first team-3 secret id %d %v", id, err)
	}
	sCommitted, sRolledBack := runConcurrent(t, func(i int, fail error) (int64, error) {
		return insertSecret(ctx, s, 3, 1, fmt.Sprintf("K%d", i), fail)
	})
	var sLater []int64
	for i := 0; i < 6; i++ {
		id, err := insertSecret(ctx, s, 3, 1, fmt.Sprintf("L%d", i), nil)
		if err != nil || id <= sCommitted[len(sCommitted)-1] {
			t.Fatalf("next team-3 secret id %d %v", id, err)
		}
		sLater = append(sLater, id)
	}
	assertNotReused(t, "secret", sRolledBack, append(sCommitted, sLater...))
	if id, err := insertSecret(ctx, s, 4, 1, "FIRST", nil); err != nil || id != 1 {
		t.Fatalf("first team-4 secret id %d %v", id, err)
	}
}
