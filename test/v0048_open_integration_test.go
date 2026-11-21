//go:build integration

package test

import (
	"testing"
)

// Coverage: "A refused launch-parameter open (claim not current, or
// task-manager down) decrypts no secret version" (1.7) and developer-tooling
// "Refused environment open decrypts nothing", on real encrypted rows.

func TestOpenIntegration(t *testing.T) {
	t.Run("Refused environment open decrypts nothing", func(t *testing.T) {
		d := newTestDB(t, true)
		s, db := d.openStore(t)
		e := newEnv(t, withStore(s))
		id := e.createTeam(3, "team", map[string]string{"PLAIN": "plain-value"})
		e.createSecret(3, id, "DB_PASSWORD", secretCanary)
		var stored []byte
		if err := db.QueryRow(`SELECT ciphertext FROM secret_versions WHERE team_id = 3`).Scan(&stored); err != nil || len(stored) == 0 {
			t.Fatalf("encrypted row: %v", err)
		}
		if string(stored) == secretCanary {
			t.Fatal("secret stored in plaintext")
		}
		released := claim(1, 1, 1)
		e.setClaim(released, 1, false)
		foreign := claim(1, 1, 1)
		foreign.TeamID = 4
		e.setClaim(foreign, 1, true)
		refusals := []struct {
			name   string
			path   string
			token  string
			status int
		}{
			{"released claim", "1", e.token(released), 404},
			{"foreign team gets nothing of team 3", "1", e.token(foreign), 200},
			{"invalid token", "1", e.token(released) + "x", 404},
			{"other task", "2", e.token(released), 404},
		}
		for _, r := range refusals {
			got := e.open(r.path, r.token)
			if got.Status != r.status {
				t.Errorf("%s: %d %s", r.name, got.Status, got.Body)
			}
			if r.status == 200 && len(openValues(t, got)) != 0 {
				t.Errorf("%s received team 3 values: %s", r.name, got.Body)
			}
		}
		if n := e.decrypts(); n != 0 {
			t.Fatalf("refused opens decrypted %d versions", n)
		}
		var snaps int
		_ = db.QueryRow(`SELECT count(*) FROM snapshots WHERE team_id = 3`).Scan(&snaps)
		if snaps != 0 {
			t.Fatalf("%d team-3 snapshots after refusals", snaps)
		}
		current := claim(1, 1, 2)
		e.setClaim(current, 1, true)
		v := openValues(t, e.open("1", e.token(current)))
		if v["DB_PASSWORD"] != secretCanary || e.decrypts() != 1 {
			t.Fatalf("current open %v, decrypts %d", v, e.decrypts())
		}
	})
}
