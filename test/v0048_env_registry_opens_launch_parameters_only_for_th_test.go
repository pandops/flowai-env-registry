package test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/pandops/flowai-env-registry/internal/broker"
	"github.com/pandops/flowai-env-registry/internal/secretbox"
	"github.com/pandops/flowai-env-registry/internal/service"
)

// Requirement: env-registry opens launch parameters only for the current claim holder.
func TestEnvRegistryOpensLaunchParametersOnlyForCurrentClaimHolder(t *testing.T) {
	setup := func(t *testing.T) *env {
		e := newEnv(t)
		id := e.createTeam(3, "team", map[string]string{"PLAIN": "plain-value"})
		e.createSecret(3, id, "DB_PASSWORD", secretCanary)
		return e
	}
	assertRefused := func(t *testing.T, e *env, r service.OpenResult, status int, code string) {
		t.Helper()
		if r.Status != status || openCode(t, r) != code {
			t.Fatalf("open: %d %s, want %d %s", r.Status, r.Body, status, code)
		}
		if strings.Contains(string(r.Body), secretCanary) || strings.Contains(string(r.Body), "plain-value") || strings.Contains(string(r.Body), "values") {
			t.Fatalf("refused open returned a value: %s", r.Body)
		}
		if err := validateJSON(t, "error.reply.schema.json", r.Body); err != nil {
			t.Fatal(err)
		}
		if e.decrypts() != 0 {
			t.Fatalf("refused open decrypted %d versions", e.decrypts())
		}
	}

	t.Run("Current claim holder opens its attempt snapshot", func(t *testing.T) {
		e := setup(t)
		c := claim(11, 1, 1)
		e.setClaim(c, 1, true)
		r := e.open("11", e.token(c))
		v := openValues(t, r)
		if v["PLAIN"] != "plain-value" || v["DB_PASSWORD"] != secretCanary || len(v) != 2 {
			t.Fatalf("values %v", v)
		}
		var body map[string]any
		_ = json.Unmarshal(r.Body, &body)
		if len(body) != 1 {
			t.Fatalf("open body carries more than values: %s", r.Body)
		}
		for _, leak := range []string{"environment_id", "secret_id", "version", "key_id", "provider"} {
			if strings.Contains(string(r.Body), leak) {
				t.Fatalf("open body carries %s: %s", leak, r.Body)
			}
		}
		cc := e.broker.RequestsTo(service.ClaimCurrentSubject)
		if len(cc) != 1 || cc[0].Header["team"] != "3" || strings.Contains(string(cc[0].Data), e.token(c)) {
			t.Fatalf("claim-current requests %+v", cc)
		}
		var req struct {
			Params map[string]int64 `json:"params"`
		}
		if err := json.Unmarshal(cc[0].Data, &req); err != nil || req.Params["task_id"] != 11 || req.Params["attempt"] != 1 || req.Params["claim_seq"] != 1 || req.Params["executor_id"] != 7 || req.Params["team_id"] != 3 || len(req.Params) != 5 {
			t.Fatalf("claim-current request %s", cc[0].Data)
		}
		events := e.outboxPayloads("env-registry.event.launch_parameters_open.pub")
		if len(events) != 1 || events[0]["outcome"] != "opened" || num(t, events[0], "task_id") != 11 || num(t, events[0], "executor_id") != 7 {
			t.Fatalf("open events %v", events)
		}
	})

	t.Run("Token minted by task-manager's signer opens", func(t *testing.T) {
		e := setup(t)
		c := claim(11, 2, 5)
		e.setClaim(c, 1, true)
		seed := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x07}, ed25519.SeedSize))
		tok, err := taskManagerSign(seed, taskManagerPayload{TeamID: 3, TaskID: 11, Attempt: 2, ClaimSeq: 5, ExecutorID: 7})
		if err != nil {
			t.Fatal(err)
		}
		// Fixed vector: the exact bytes task-manager produces for this claim
		// with the stand-shaped seed 0x07 x 32.
		if tok != taskManagerVector {
			t.Fatalf("task-manager token %s, want the fixed vector %s", tok, taskManagerVector)
		}
		// The same claim signed over the base64url text does not verify.
		payload := mustDecodeB64URL(t, strings.Split(tok, ".")[0])
		assertRefused(t, e, e.open("11", signOverText(e.signKey, payload)), 404, "claim_not_current")
		if n := len(e.broker.RequestsTo(service.ClaimCurrentSubject)); n != 0 {
			t.Fatalf("claim-current asked %d times for a text-signed token", n)
		}
		if v := openValues(t, e.open("11", tok)); v["DB_PASSWORD"] != secretCanary || v["PLAIN"] != "plain-value" {
			t.Fatalf("values %v", v)
		}
		if n := len(e.broker.RequestsTo(service.ClaimCurrentSubject)); n != 1 {
			t.Fatalf("claim-current asked %d times, want once for the valid token", n)
		}
	})

	t.Run("Released claim token is refused", func(t *testing.T) {
		e := setup(t)
		c := claim(11, 1, 1)
		e.setClaim(c, 1, false)
		assertRefused(t, e, e.open("11", e.token(c)), 404, "claim_not_current")
		// task-manager naming another team in a positive reply is not current either.
		e.broker.Respond(service.ClaimCurrentSubject, func(broker.Msg) (broker.Msg, error) {
			return reply(200, map[string]any{"current": true, "team_id": 4, "flow_id": 1, "execution_revision_id": 1}), nil
		})
		assertRefused(t, e, e.open("11", e.token(c)), 404, "claim_not_current")
		events := e.outboxPayloads("env-registry.event.launch_parameters_open.pub")
		if len(events) != 2 || events[0]["outcome"] != "claim_not_current" {
			t.Fatalf("refusal events %v", events)
		}
	})

	t.Run("Token for another task is refused", func(t *testing.T) {
		e := setup(t)
		c := claim(1, 1, 1)
		e.setClaim(c, 1, true)
		for _, path := range []string{"2", "01", "abc", "0", "-1", "1.0", "9223372036854775808"} {
			assertRefused(t, e, e.open(path, e.token(c)), 404, "claim_not_current")
		}
		if n := len(e.broker.RequestsTo(service.ClaimCurrentSubject)); n != 0 {
			t.Fatalf("claim-current asked %d times", n)
		}
	})

	t.Run("Forged token is refused", func(t *testing.T) {
		e := setup(t)
		c := claim(1, 1, 1)
		e.setClaim(c, 1, true)
		good := e.token(c)
		other := ed25519.NewKeyFromSeed(make([]byte, 32))
		parts := strings.Split(good, ".")
		tamperedPayload, _ := json.Marshal(map[string]int64{"team_id": 3, "task_id": 1, "attempt": 1, "claim_seq": 1, "executor_id": 8})
		unknownClaim, _ := json.Marshal(map[string]any{"team_id": 3, "task_id": 1, "attempt": 1, "claim_seq": 1, "executor_id": 7, "expires_at": 1})
		stringIDs, _ := json.Marshal(map[string]any{"team_id": "3", "task_id": "1", "attempt": 1, "claim_seq": 1, "executor_id": 7})
		forged := []string{
			signToken(other, c),
			base64.RawURLEncoding.EncodeToString(tamperedPayload) + "." + parts[1],
			parts[0] + "." + flipFirst(parts[1]),
			parts[0],
			parts[0] + "." + parts[1] + ".x",
			"",
			"not-a-token",
			resign(e.signKey, unknownClaim),
			resign(e.signKey, stringIDs),
			parts[0] + "=." + parts[1],
			signOverText(e.signKey, mustDecodeB64URL(t, parts[0])),
		}
		for _, tok := range forged {
			assertRefused(t, e, e.open("1", tok), 404, "claim_not_current")
		}
		// A wrong authorization scheme is refused too.
		assertRefused(t, e, e.svc.Open(t.Context(), "1", "Basic "+good), 404, "claim_not_current")
		if n := len(e.broker.RequestsTo(service.ClaimCurrentSubject)); n != 0 {
			t.Fatalf("claim-current asked %d times for forged tokens", n)
		}
		if len(e.outboxPayloads("env-registry.event.")) != 0 {
			t.Fatal("an unverified token produced an event with an untrusted team")
		}
	})

	t.Run("Decryption fails at open", func(t *testing.T) {
		sw := &switchProvider{}
		e := newEnv(t, func(d *service.Deps, e *env) { sw.inner = d.Crypto; d.Crypto = sw })
		id := e.createTeam(3, "team", map[string]string{"PLAIN": "plain-value"})
		e.createSecret(3, id, "DB_PASSWORD", secretCanary)
		c := claim(1, 1, 1)
		e.setClaim(c, 1, true)
		sw.setMissing(true) // the data key is no longer loadable
		r := e.open("1", e.token(c))
		if r.Status != 503 || openCode(t, r) != "service_unavailable" {
			t.Fatalf("open with missing data key: %d %s", r.Status, r.Body)
		}
		if strings.Contains(string(r.Body), "plain-value") || strings.Contains(string(r.Body), "values") {
			t.Fatalf("503 returned values: %s", r.Body)
		}
		if len(e.store.Snapshots()) != 0 {
			t.Fatal("a failed open froze a snapshot")
		}
		events := e.outboxPayloads("env-registry.event.launch_parameters_open.pub")
		if len(events) != 1 || events[0]["outcome"] != "service_unavailable" {
			t.Fatalf("events %v", events)
		}
		sw.setMissing(false)
		if v := openValues(t, e.open("1", e.token(c))); v["DB_PASSWORD"] != secretCanary {
			t.Fatalf("open after the key returned: %v", v)
		}
	})

	t.Run("Definition-addressed opening is unavailable", func(t *testing.T) {
		e := setup(t)
		for _, auth := range []string{"Bearer 1", "Bearer environment_id=1", "1", ""} {
			r := e.svc.Open(t.Context(), "1", auth)
			assertRefused(t, e, r, 404, "claim_not_current")
		}
	})
}

// switchProvider fails every call while its data key is "missing".
type switchProvider struct {
	mu      sync.Mutex
	inner   secretbox.Provider
	missing bool
}

func (p *switchProvider) setMissing(v bool) { p.mu.Lock(); p.missing = v; p.mu.Unlock() }

func (p *switchProvider) Encrypt(a secretbox.AAD, b []byte) (secretbox.Envelope, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.missing {
		return secretbox.Envelope{}, secretbox.ErrUnavailable
	}
	return p.inner.Encrypt(a, b)
}

func (p *switchProvider) Decrypt(a secretbox.AAD, env secretbox.Envelope) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.missing {
		return nil, secretbox.ErrUnavailable
	}
	return p.inner.Decrypt(a, env)
}

// resign signs payload the rule 12 way: over the JSON bytes.
func resign(key ed25519.PrivateKey, payload []byte) string {
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, payload))
}

// signOverText signs the base64url payload text instead of its bytes, the
// wrong reading of rule 12.
func signOverText(key ed25519.PrivateKey, payload []byte) string {
	p := base64.RawURLEncoding.EncodeToString(payload)
	return p + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(p)))
}

// taskManagerPayload and taskManagerSign copy task-manager's
// claimtoken.Signer.Sign (svc/task-manager/internal/claimtoken); services
// share no code, so the algorithm is duplicated here as a fixed vector.
type taskManagerPayload struct {
	TeamID     int64 `json:"team_id"`
	TaskID     int64 `json:"task_id"`
	Attempt    int64 `json:"attempt"`
	ClaimSeq   int64 `json:"claim_seq"`
	ExecutorID int64 `json:"executor_id"`
}

func taskManagerSign(seed string, p taskManagerPayload) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(seed)
	if err != nil || len(raw) != ed25519.SeedSize {
		return "", errors.New("signing key must be a base64 32-byte Ed25519 seed")
	}
	key := ed25519.NewKeyFromSeed(raw)
	body, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString(body) + "." + enc.EncodeToString(ed25519.Sign(key, body)), nil
}

func mustDecodeB64URL(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil {
		t.Fatalf("decode %q: %v", s, err)
	}
	return b
}

// taskManagerVector is task-manager's token for team 3, task 11, attempt 2,
// claim_seq 5, executor 7 under seed 0x07 x 32 (Ed25519 is deterministic).
const taskManagerVector = "eyJ0ZWFtX2lkIjozLCJ0YXNrX2lkIjoxMSwiYXR0ZW1wdCI6MiwiY2xhaW1fc2VxIjo1LCJleGVjdXRvcl9pZCI6N30" +
	".xyJ5PAYpGq68Eqqxra0pZmQWH8M4C9fdW9uycrDo1nz9-vMv3yNb9apovCdAYssVoJbRYVfU92poEV7DYORsBA"

// flipFirst changes the first character, so the decoded bytes always differ
// (editing the last characters can leave a signature unchanged).
func flipFirst(s string) string {
	if s[0] == 'A' {
		return "B" + s[1:]
	}
	return "A" + s[1:]
}
