package test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/pandops/flowai-env-registry/internal/broker"
	"github.com/pandops/flowai-env-registry/internal/claimtoken"
	"github.com/pandops/flowai-env-registry/internal/cursor"
	"github.com/pandops/flowai-env-registry/internal/mocks"
	"github.com/pandops/flowai-env-registry/internal/secretbox"
	"github.com/pandops/flowai-env-registry/internal/service"
	"github.com/pandops/flowai-env-registry/internal/store"
)

// Canary plaintexts. No log line, stream message, audit or event may contain them.
const (
	secretCanary  = "s3cr3t-CANARY-value-9f1c"
	secretCanary2 = "s3cr3t-CANARY-value-rotated-77aa"
)

var testDataKey = bytes.Repeat([]byte{0x42}, 32)

// errInjected is the fault injected into the fake store.
var errInjected = errors.New("injected store fault")

// serviceDir is the standalone module root.
func serviceDir(t testing.TB) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller unknown")
	}
	return filepath.Dir(filepath.Dir(file))
}

func publisherSchemaDir(t testing.TB) string {
	t.Helper()
	dir := os.Getenv("FLOWAI_ENV_REGISTRY_SCHEMA_DIR")
	if !filepath.IsAbs(dir) {
		t.Fatal("FLOWAI_ENV_REGISTRY_SCHEMA_DIR must point to an absolute fixture directory")
	}
	return dir
}

// syncBuffer collects log output from concurrent writers.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// flowOwner is one flow-registry Flow known to the fake flow-owner responder.
type flowKey struct{ team, flow int64 }

// claimKey identifies one claim for the fake claim-current responder.
type claimKey struct{ team, task, attempt, claimSeq, executor int64 }

// env is one in-process env-registry with every dependency faked.
type env struct {
	t       *testing.T
	store   *mocks.MemStore
	broker  *mocks.FakeBroker
	crypto  *mocks.CountingProvider
	svc     *service.Service
	logs    *syncBuffer
	signKey ed25519.PrivateKey
	verKey  ed25519.PublicKey

	mu     sync.Mutex
	flows  map[flowKey]int64  // (asked team, flow) -> owning team; absent = 404
	claims map[claimKey]int64 // current claims -> flow_id
	now    time.Time
}

type envOption func(*service.Deps, *env)

// withProvider replaces the cryptography provider (nil: no loadable data key).
func withProvider(p secretbox.Provider) envOption {
	return func(d *service.Deps, e *env) { d.Crypto = p }
}

// withStore replaces the in-memory store (integration tests pass PostgreSQL).
func withStore(st store.Store) envOption {
	return func(d *service.Deps, e *env) { d.Store = st }
}

func newEnv(t *testing.T, opts ...envOption) *env {
	t.Helper()
	seed := bytes.Repeat([]byte{0x07}, ed25519.SeedSize)
	priv := ed25519.NewKeyFromSeed(seed)
	e := &env{
		t:       t,
		store:   mocks.NewMemStore(),
		broker:  mocks.NewFakeBroker(),
		logs:    &syncBuffer{},
		signKey: priv,
		verKey:  priv.Public().(ed25519.PublicKey),
		flows:   map[flowKey]int64{},
		claims:  map[claimKey]int64{},
		now:     time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC),
	}
	local, err := secretbox.NewLocal([]secretbox.Key{{ID: 1, Material: testDataKey}}, 1)
	if err != nil {
		t.Fatalf("local AES-256-GCM provider: %v", err)
	}
	e.crypto = &mocks.CountingProvider{Inner: local}
	verifier, err := claimtoken.NewVerifier(e.verKey)
	if err != nil {
		t.Fatalf("claim token verifier: %v", err)
	}
	codec, err := cursor.NewCodec([]cursor.Key{{ID: 1, Secret: bytes.Repeat([]byte{0x11}, 32)}}, 1)
	if err != nil {
		t.Fatalf("cursor codec: %v", err)
	}
	deps := service.Deps{
		Store:          e.store,
		Crypto:         e.crypto,
		Claims:         verifier,
		Broker:         e.broker,
		Cursor:         codec,
		Clock:          e.clock,
		Logger:         slog.New(slog.NewJSONHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		RequestTimeout: 5 * time.Second,
	}
	for _, opt := range opts {
		opt(&deps, e)
	}
	e.svc = service.New(deps)
	e.broker.Respond(service.FlowOwnerSubject, e.flowOwner)
	e.broker.Respond(service.ClaimCurrentSubject, e.claimCurrent)
	t.Cleanup(func() { e.assertPublishedValid(t) })
	return e
}

func (e *env) clock() time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.now = e.now.Add(time.Second)
	return e.now
}

// addFlow makes flow-registry answer flow-owner for (team, flow) with owner.
func (e *env) addFlow(team, flow int64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.flows[flowKey{team, flow}] = team
}

// addFlowOwnedBy makes flow-registry answer (asked, flow) with another owner team.
func (e *env) addFlowOwnedBy(asked, flow, owner int64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.flows[flowKey{asked, flow}] = owner
}

func (e *env) flowOwner(m broker.Msg) (broker.Msg, error) {
	if err := validateJSON(e.t, flowOwnerRequestSchema, m.Data); err != nil {
		e.t.Errorf("flow-owner request violates flow-registry's schema: %v\n%s", err, m.Data)
		return foreignReply(e.t, 400, "", map[string]any{"code": "invalid_request", "message": "bad", "request_id": nil}), nil
	}
	var req struct {
		Params struct {
			TeamID int64 `json:"team_id"`
			FlowID int64 `json:"flow_id"`
		} `json:"params"`
	}
	_ = json.Unmarshal(m.Data, &req)
	e.mu.Lock()
	owner, ok := e.flows[flowKey{req.Params.TeamID, req.Params.FlowID}]
	e.mu.Unlock()
	if !ok {
		return foreignReply(e.t, 404, flowRegistryErrorSchema, map[string]any{"code": "flow_not_found", "message": "flow not found", "request_id": 9001}), nil
	}
	return foreignReply(e.t, 200, flowOwnerReplySchema, map[string]any{"team_id": owner}), nil
}

// Publisher-owned schemas env-registry consumes, read as files (named for
// env-registry in qa-e2e/scripts/shared-test-inputs.json); no package is imported.
const (
	flowOwnerRequestSchema    = "flow-registry/schemas/service.flow-owner.request.schema.json"
	flowOwnerReplySchema      = "flow-registry/schemas/service.flow-owner.reply.schema.json"
	flowRegistryErrorSchema   = "flow-registry/schemas/error.reply.schema.json"
	claimCurrentRequestSchema = "task-manager/schemas/service.claim-current.request.schema.json"
	claimCurrentReplySchema   = "task-manager/schemas/service.claim-current.reply.schema.json"
	taskManagerErrorSchema    = "task-manager/schemas/error.reply.schema.json"
	archivedEventSchema       = "task-manager/schemas/event.archived.schema.json"
)

// foreignReply builds a fake owner reply and checks it against the owner's schema.
func foreignReply(t testing.TB, status int, schema string, body any) broker.Msg {
	m := reply(status, body)
	if schema != "" {
		if err := validateJSON(t, schema, m.Data); err != nil {
			t.Fatalf("fake reply violates %s: %v", schema, err)
		}
	}
	return m
}

// setClaim marks a claim current (with its Flow) or not current.
func (e *env) setClaim(c claimtoken.Claims, flow int64, current bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	k := claimKey{c.TeamID, c.TaskID, c.Attempt, c.ClaimSeq, c.ExecutorID}
	if current {
		e.claims[k] = flow
	} else {
		delete(e.claims, k)
	}
}

func (e *env) claimCurrent(m broker.Msg) (broker.Msg, error) {
	if err := validateJSON(e.t, claimCurrentRequestSchema, m.Data); err != nil {
		e.t.Errorf("claim-current request violates task-manager's schema: %v\n%s", err, m.Data)
		return foreignReply(e.t, 400, taskManagerErrorSchema, map[string]any{"code": "invalid_request", "message": "bad", "request_id": nil}), nil
	}
	var req struct {
		Params struct {
			TeamID     int64 `json:"team_id"`
			TaskID     int64 `json:"task_id"`
			Attempt    int64 `json:"attempt"`
			ClaimSeq   int64 `json:"claim_seq"`
			ExecutorID int64 `json:"executor_id"`
		} `json:"params"`
	}
	_ = json.Unmarshal(m.Data, &req)
	p := req.Params
	e.mu.Lock()
	flow, ok := e.claims[claimKey{p.TeamID, p.TaskID, p.Attempt, p.ClaimSeq, p.ExecutorID}]
	e.mu.Unlock()
	if !ok {
		return foreignReply(e.t, 200, claimCurrentReplySchema, map[string]any{"current": false, "reason": "claim_ended"}), nil
	}
	return foreignReply(e.t, 200, claimCurrentReplySchema, map[string]any{"current": true, "team_id": p.TeamID, "flow_id": flow, "execution_revision_id": 1}), nil
}

func reply(status int, body any) broker.Msg {
	data, _ := json.Marshal(body)
	return broker.Msg{Header: broker.Header{"status": strconv.Itoa(status)}, Data: data}
}

// token signs a claim token in task-manager's format (agents.md rule 12).
func (e *env) token(c claimtoken.Claims) string {
	return signToken(e.signKey, c)
}

// signToken signs the payload JSON bytes, not their base64url text.
func signToken(key ed25519.PrivateKey, c claimtoken.Claims) string {
	payload, _ := json.Marshal(map[string]int64{
		"team_id": c.TeamID, "task_id": c.TaskID, "attempt": c.Attempt,
		"claim_seq": c.ClaimSeq, "executor_id": c.ExecutorID,
	})
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, payload))
}

// uiReply is a decoded reply.
type uiReply struct {
	Status int
	Body   map[string]any
	Raw    []byte
}

func (r uiReply) code() string {
	c, _ := r.Body["code"].(string)
	return c
}

// ctxHeaders are the verified Gateway context headers of a team-3 operator.
func ctxHeaders(team int64) broker.Header {
	return broker.Header{"team": strconv.FormatInt(team, 10), "operator_id": "41", "request_id": "9001", "team_name": "Operations"}
}

// ui sends one env-registry.ui.<op> request for team with params and body.
func (e *env) ui(op string, team int64, params map[string]any, body any) uiReply {
	e.t.Helper()
	return e.uiWith(op, ctxHeaders(team), params, body)
}

func (e *env) uiWith(op string, header broker.Header, params map[string]any, body any) uiReply {
	e.t.Helper()
	req := map[string]any{"params": params}
	if body != nil {
		req["body"] = body
	}
	data, err := json.Marshal(req)
	if err != nil {
		e.t.Fatalf("marshal request: %v", err)
	}
	return e.uiRaw(op, header, data)
}

func (e *env) uiRaw(op string, header broker.Header, data []byte) uiReply {
	e.t.Helper()
	m := e.svc.HandleUI(context.Background(), broker.Msg{Subject: "env-registry.ui." + op + ".sub", Header: header, Data: data})
	status, err := strconv.Atoi(m.Header["status"])
	if err != nil {
		e.t.Fatalf("reply to %s has no decimal status header: %v (%q)", op, m.Header, m.Data)
	}
	r := uiReply{Status: status, Raw: m.Data}
	if len(m.Data) > 0 {
		var body any
		if err := json.Unmarshal(m.Data, &body); err != nil {
			e.t.Fatalf("reply body is not JSON: %q", m.Data)
		}
		r.Body, _ = body.(map[string]any)
	}
	validateReply(e.t, op, r)
	return r
}

// num reads a JSON number field as int64.
func num(t *testing.T, m map[string]any, key string) int64 {
	t.Helper()
	v, ok := m[key].(float64)
	if !ok {
		t.Fatalf("field %q is %T (%v), want a JSON number", key, m[key], m[key])
	}
	return int64(v)
}

// createTeamParams creates a team-scoped definition and returns its id.
func (e *env) createTeam(team int64, name string, values map[string]string) int64 {
	e.t.Helper()
	r := e.ui("create", team, map[string]any{"team_id": team}, map[string]any{"scope": "team", "name": name, "env": values})
	if r.Status != 201 {
		e.t.Fatalf("create team definition: %d %s", r.Status, r.Raw)
	}
	return num(e.t, r.Body, "environment_id")
}

func (e *env) createFlow(team, flow int64, name string, values map[string]string) int64 {
	e.t.Helper()
	e.addFlow(team, flow)
	r := e.ui("create", team, map[string]any{"team_id": team}, map[string]any{"scope": "flow", "flow_id": flow, "name": name, "env": values})
	if r.Status != 201 {
		e.t.Fatalf("create flow definition: %d %s", r.Status, r.Raw)
	}
	return num(e.t, r.Body, "environment_id")
}

func (e *env) createSecret(team, environmentID int64, key, value string) int64 {
	e.t.Helper()
	r := e.ui("create-secret", team, map[string]any{"team_id": team, "environment_id": environmentID}, map[string]any{"key": key, "value": value})
	if r.Status != 201 {
		e.t.Fatalf("create secret: %d %s", r.Status, r.Raw)
	}
	return num(e.t, r.Body, "secret_id")
}

// seedGlobal stores a global definition directly; no operator subject can.
func (e *env) seedGlobal(values map[string]string) int64 {
	e.t.Helper()
	var id int64
	err := e.store.InTx(context.Background(), func(tx store.Tx) error {
		var err error
		id, err = tx.NextGlobalEnvironmentID(context.Background())
		if err != nil {
			return err
		}
		return tx.InsertDefinition(context.Background(), store.Definition{
			TeamID: store.GlobalTeam, EnvironmentID: id, Scope: store.ScopeGlobal,
			Name: "global", Env: values, Revision: 1, CreatedAt: e.now, UpdatedAt: e.now,
		})
	})
	if err != nil {
		e.t.Fatalf("seed global definition: %v", err)
	}
	return id
}

// open calls the Executor edge with a bearer token.
func (e *env) open(taskPath string, token string) service.OpenResult {
	e.t.Helper()
	auth := ""
	if token != "" {
		auth = "Bearer " + token
	}
	return e.svc.Open(context.Background(), taskPath, auth)
}

func openBody(t *testing.T, r service.OpenResult) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(r.Body, &body); err != nil {
		t.Fatalf("open body is not JSON: %q", r.Body)
	}
	return body
}

func openValues(t *testing.T, r service.OpenResult) map[string]string {
	t.Helper()
	if r.Status != 200 {
		t.Fatalf("open status %d body %s", r.Status, r.Body)
	}
	var body struct {
		Values map[string]string `json:"values"`
	}
	if err := json.Unmarshal(r.Body, &body); err != nil {
		t.Fatalf("open body: %v", err)
	}
	return body.Values
}

func openCode(t *testing.T, r service.OpenResult) string {
	t.Helper()
	b := openBody(t, r)
	c, _ := b["code"].(string)
	return c
}

// flush runs the outbox relay once and returns the published messages.
func (e *env) outboxPayloads(prefix string) []map[string]any {
	e.t.Helper()
	out := []map[string]any{}
	for _, row := range e.store.Outbox() {
		if strings.HasPrefix(row.Subject, prefix) {
			var m map[string]any
			if err := json.Unmarshal(row.Payload, &m); err != nil {
				e.t.Fatalf("outbox payload not JSON: %v", err)
			}
			out = append(out, m)
		}
	}
	return out
}

func (e *env) auditActions() []string {
	out := []string{}
	for _, row := range e.store.Outbox() {
		if strings.HasPrefix(row.Subject, "env-registry.audit.") {
			out = append(out, row.Subject)
		}
	}
	return out
}

func (e *env) decrypts() int {
	_, d := e.crypto.Counts()
	return d
}

// assertNoCanary checks that nothing env-registry wrote outside the open
// response contains the given plaintexts.
func (e *env) assertNoCanary(t *testing.T, canaries ...string) {
	t.Helper()
	logs := e.logs.String()
	for _, c := range canaries {
		if strings.Contains(logs, c) {
			t.Errorf("log output contains plaintext %q", c)
		}
		for _, row := range e.store.Outbox() {
			if bytes.Contains(row.Payload, []byte(c)) {
				t.Errorf("outbox message %s contains plaintext", row.Subject)
			}
			for k, v := range row.Header {
				if strings.Contains(v, c) {
					t.Errorf("outbox header %s of %s contains plaintext", k, row.Subject)
				}
			}
		}
		for _, r := range e.store.Revisions() {
			if c != secretCanary && c != secretCanary2 {
				continue // revisions keep ordinary values by design
			}
			b, _ := json.Marshal(r)
			if bytes.Contains(b, []byte(c)) {
				t.Errorf("revision %d contains plaintext", r.Revision)
			}
		}
		for _, v := range e.store.Versions() {
			if bytes.Contains(v.Envelope.Ciphertext, []byte(c)) {
				t.Errorf("secret version %d stores plaintext", v.Version)
			}
		}
	}
}

// ---- JSON Schema validation of everything env-registry publishes ----

var (
	schemaOnce sync.Once
	schemaComp *jsonschema.Compiler
	schemaErr  error
	schemaDir  string
	schemaMu   sync.Mutex
	compiled   = map[string]*jsonschema.Schema{}
)

func compileSchema(t testing.TB, rel string) *jsonschema.Schema {
	t.Helper()
	schemaOnce.Do(func() {
		schemaDir = filepath.Join(serviceDir(t), "schemas")
		schemaComp = jsonschema.NewCompiler()
		schemaComp.AssertFormat()
	})
	if schemaErr != nil {
		t.Fatal(schemaErr)
	}
	schemaMu.Lock()
	defer schemaMu.Unlock()
	if s, ok := compiled[rel]; ok {
		return s
	}
	path := filepath.Join(schemaDir, rel)
	if filepath.ToSlash(rel) != filepath.Base(rel) {
		path = filepath.Join(publisherSchemaDir(t), rel)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("schema %s: %v", rel, err)
	}
	doc, err := jsonschema.UnmarshalJSON(f)
	f.Close()
	if err != nil {
		t.Fatalf("schema %s: %v", rel, err)
	}
	url := "file://" + filepath.ToSlash(path)
	if err := schemaComp.AddResource(url, doc); err != nil {
		t.Fatalf("schema %s: %v", rel, err)
	}
	s, err := schemaComp.Compile(url)
	if err != nil {
		t.Fatalf("compile schema %s: %v", rel, err)
	}
	compiled[rel] = s
	return s
}

// schemaFor maps a published subject to its schema file.
func schemaFor(subject string) (string, error) {
	parts := strings.Split(subject, ".")
	if len(parts) != 4 || parts[0] != "env-registry" || parts[3] != "pub" {
		return "", fmt.Errorf("subject %q is not an env-registry stream subject", subject)
	}
	switch parts[1] {
	case "audit":
		return "audit." + parts[2] + ".schema.json", nil
	case "event":
		return "event." + parts[2] + ".schema.json", nil
	}
	return "", fmt.Errorf("subject %q has no stream schema", subject)
}

func validateJSON(t testing.TB, rel string, data []byte) error {
	t.Helper()
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return err
	}
	return compileSchema(t, rel).Validate(inst)
}

// assertPublishedValid validates every outbox row against its schema and
// checks its headers (rule 10).
func (e *env) assertPublishedValid(t *testing.T) {
	for _, row := range e.store.Outbox() {
		rel, err := schemaFor(row.Subject)
		if err != nil {
			t.Errorf("published %s: %v", row.Subject, err)
			continue
		}
		if err := validateJSON(t, rel, row.Payload); err != nil {
			t.Errorf("published %s violates %s: %v\n%s", row.Subject, rel, err, row.Payload)
		}
		var env struct {
			Publisher    string `json:"publisher"`
			PublisherSeq int64  `json:"publisher_seq"`
			TeamID       int64  `json:"team_id"`
		}
		_ = json.Unmarshal(row.Payload, &env)
		if want := fmt.Sprintf("env-registry-%d", row.PublisherSeq); row.Header["Nats-Msg-Id"] != want {
			t.Errorf("%s Nats-Msg-Id = %q, want %q", row.Subject, row.Header["Nats-Msg-Id"], want)
		}
		if env.PublisherSeq != row.PublisherSeq || env.Publisher != "env-registry" {
			t.Errorf("%s payload publisher/seq %s/%d, row seq %d", row.Subject, env.Publisher, env.PublisherSeq, row.PublisherSeq)
		}
		if row.Header["team"] != strconv.FormatInt(env.TeamID, 10) {
			t.Errorf("%s header team %q, payload team_id %d", row.Subject, row.Header["team"], env.TeamID)
		}
	}
}

func validateReply(t *testing.T, op string, r uiReply) {
	t.Helper()
	if r.Status >= 400 {
		if err := validateJSON(t, "error.reply.schema.json", r.Raw); err != nil {
			t.Errorf("%s error reply violates error.reply.schema.json: %v\n%s", op, err, r.Raw)
		}
		return
	}
	if _, err := os.Stat(filepath.Join(serviceDir(t), "schemas", "ui."+op+".reply.schema.json")); err != nil {
		return // unknown operation: no schema
	}
	data := r.Raw
	if len(data) == 0 {
		data = []byte("null")
	}
	if err := validateJSON(t, "ui."+op+".reply.schema.json", data); err != nil {
		t.Errorf("%s reply violates ui.%s.reply.schema.json: %v\n%s", op, op, err, r.Raw)
	}
}

// claim is a convenient claim for team 3.
func claim(task, attempt, claimSeq int64) claimtoken.Claims {
	return claimtoken.Claims{TeamID: 3, TaskID: task, Attempt: attempt, ClaimSeq: claimSeq, ExecutorID: 7}
}
