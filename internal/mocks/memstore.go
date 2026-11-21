// Package mocks holds in-process test fakes of env-registry's store, broker
// and cryptography provider. Production wiring never uses them.
package mocks

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/pandops/flowai-env-registry/internal/store"
)

type memState struct {
	defs      map[[2]int64]store.Definition
	secrets   map[[2]int64]store.Secret
	versions  map[[3]int64]store.SecretVersion
	revisions []store.Revision
	snapshots map[[3]int64]store.Snapshot
	consumed  map[string]bool
	outbox    []store.OutboxMessage
}

func newMemState() *memState {
	return &memState{
		defs:      map[[2]int64]store.Definition{},
		secrets:   map[[2]int64]store.Secret{},
		versions:  map[[3]int64]store.SecretVersion{},
		snapshots: map[[3]int64]store.Snapshot{},
		consumed:  map[string]bool{},
	}
}

func (s *memState) clone() *memState {
	c := newMemState()
	for k, v := range s.defs {
		v.Env = copyMap(v.Env)
		c.defs[k] = v
	}
	for k, v := range s.secrets {
		c.secrets[k] = v
	}
	for k, v := range s.versions {
		c.versions[k] = v
	}
	c.revisions = append([]store.Revision(nil), s.revisions...)
	for k, v := range s.snapshots {
		c.snapshots[k] = v
	}
	for k, v := range s.consumed {
		c.consumed[k] = v
	}
	c.outbox = append([]store.OutboxMessage(nil), s.outbox...)
	return c
}

// MemStore is an in-memory store.Store. Transactions are serialized and
// copy-on-write: a failed transaction leaves no trace except consumed
// sequence and per-team counter values, which are never handed out again.
type MemStore struct {
	mu         sync.Mutex
	st         *memState
	pubSeq     int64
	globalEnv  int64
	counters   map[string]int64 // per-team numbers: allocated outside the transaction
	outboxID   int64
	failNext   map[string]error
	failSent   error
	failCommit error
	pingErr    error
}

// NewMemStore returns an empty store.
func NewMemStore() *MemStore {
	return &MemStore{st: newMemState(), failNext: map[string]error{}, counters: map[string]int64{}}
}

// FailNext makes the next call of the named Tx method return err.
func (m *MemStore) FailNext(method string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failNext[method] = err
}

// FailNextCommit makes the next transaction roll back with err after its
// function succeeded, as a failed COMMIT.
func (m *MemStore) FailNextCommit(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failCommit = err
}

// SetMarkSentError makes MarkOutboxSent fail with err (nil to succeed).
func (m *MemStore) SetMarkSentError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failSent = err
}

// SetPingError sets the error Ping returns.
func (m *MemStore) SetPingError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pingErr = err
}

// SetPublisherSeq sets the last allocated publisher_seq.
func (m *MemStore) SetPublisherSeq(v int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pubSeq = v
}

// InTx implements store.Store.
func (m *MemStore) InTx(ctx context.Context, fn func(store.Tx) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	work := m.st.clone()
	tx := &memTx{m: m, st: work}
	if err := fn(tx); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := m.failCommit; err != nil {
		m.failCommit = nil
		return err
	}
	m.st = work
	return nil
}

// PendingOutbox implements store.Store.
func (m *MemStore) PendingOutbox(ctx context.Context, limit int) ([]store.OutboxMessage, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]store.OutboxMessage, 0)
	for _, row := range m.st.outbox {
		if row.SentAt == nil {
			out = append(out, row)
			if len(out) == limit {
				break
			}
		}
	}
	return out, nil
}

// MarkOutboxSent implements store.Store.
func (m *MemStore) MarkOutboxSent(ctx context.Context, id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failSent != nil {
		return m.failSent
	}
	for i := range m.st.outbox {
		if m.st.outbox[i].ID == id {
			now := time.Now().UTC()
			m.st.outbox[i].SentAt = &now
			return nil
		}
	}
	return store.ErrNotFound
}

// Ping implements store.Store.
func (m *MemStore) Ping(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.pingErr
}

// Outbox returns every outbox row in commit order.
func (m *MemStore) Outbox() []store.OutboxMessage {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]store.OutboxMessage(nil), m.st.outbox...)
}

// Definitions returns every definition row, ordered by team and id.
func (m *MemStore) Definitions() []store.Definition {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]store.Definition, 0, len(m.st.defs))
	for _, d := range m.st.defs {
		d.Env = copyMap(d.Env)
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].TeamID != out[j].TeamID {
			return out[i].TeamID < out[j].TeamID
		}
		return out[i].EnvironmentID < out[j].EnvironmentID
	})
	return out
}

// Secrets returns every logical secret row.
func (m *MemStore) Secrets() []store.Secret {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]store.Secret, 0, len(m.st.secrets))
	for _, s := range m.st.secrets {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].TeamID != out[j].TeamID {
			return out[i].TeamID < out[j].TeamID
		}
		return out[i].SecretID < out[j].SecretID
	})
	return out
}

// Versions returns every secret version row.
func (m *MemStore) Versions() []store.SecretVersion {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]store.SecretVersion, 0, len(m.st.versions))
	for _, v := range m.st.versions {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.TeamID != b.TeamID {
			return a.TeamID < b.TeamID
		}
		if a.SecretID != b.SecretID {
			return a.SecretID < b.SecretID
		}
		return a.Version < b.Version
	})
	return out
}

// Revisions returns every revision row in append order.
func (m *MemStore) Revisions() []store.Revision {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]store.Revision(nil), m.st.revisions...)
}

// Snapshots returns every snapshot row.
func (m *MemStore) Snapshots() []store.Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]store.Snapshot, 0, len(m.st.snapshots))
	for _, s := range m.st.snapshots {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.TeamID != b.TeamID {
			return a.TeamID < b.TeamID
		}
		if a.TaskID != b.TaskID {
			return a.TaskID < b.TaskID
		}
		return a.Attempt < b.Attempt
	})
	return out
}

type memTx struct {
	m  *MemStore
	st *memState
}

func (t *memTx) fail(method string) error {
	if err, ok := t.m.failNext[method]; ok {
		delete(t.m.failNext, method)
		return err
	}
	return nil
}

func (t *memTx) NextTeamNumber(ctx context.Context, teamID int64, kind string) (int64, error) {
	if err := t.fail("NextTeamNumber"); err != nil {
		return 0, err
	}
	key := fmt.Sprintf("%d/%s", teamID, kind)
	t.m.counters[key]++
	return t.m.counters[key], nil
}

func (t *memTx) NextGlobalEnvironmentID(ctx context.Context) (int64, error) {
	if err := t.fail("NextGlobalEnvironmentID"); err != nil {
		return 0, err
	}
	t.m.globalEnv++
	return t.m.globalEnv, nil
}

func (t *memTx) scopeTaken(d store.Definition) bool {
	for k, other := range t.st.defs {
		if k == [2]int64{d.TeamID, d.EnvironmentID} || other.Deleted {
			continue
		}
		if other.TeamID == d.TeamID && other.Scope == d.Scope && other.FlowID == d.FlowID {
			return true
		}
	}
	return false
}

func (t *memTx) InsertDefinition(ctx context.Context, d store.Definition) error {
	if err := t.fail("InsertDefinition"); err != nil {
		return err
	}
	key := [2]int64{d.TeamID, d.EnvironmentID}
	if _, ok := t.st.defs[key]; ok {
		return fmt.Errorf("duplicate definition %v", key)
	}
	if !d.Deleted && t.scopeTaken(d) {
		return store.ErrScopeConflict
	}
	d.Env = copyMap(d.Env)
	t.st.defs[key] = d
	return nil
}

func (t *memTx) GetDefinition(ctx context.Context, teamID, environmentID int64) (store.Definition, error) {
	if err := t.fail("GetDefinition"); err != nil {
		return store.Definition{}, err
	}
	d, ok := t.st.defs[[2]int64{teamID, environmentID}]
	if !ok {
		return store.Definition{}, store.ErrNotFound
	}
	d.Env = copyMap(d.Env)
	return d, nil
}

func (t *memTx) UpdateDefinition(ctx context.Context, d store.Definition) error {
	if err := t.fail("UpdateDefinition"); err != nil {
		return err
	}
	key := [2]int64{d.TeamID, d.EnvironmentID}
	old, ok := t.st.defs[key]
	if !ok {
		return store.ErrNotFound
	}
	if old.Scope != d.Scope || old.FlowID != d.FlowID || old.TeamID != d.TeamID {
		return fmt.Errorf("immutable definition binding changed")
	}
	if !d.Deleted && t.scopeTaken(d) {
		return store.ErrScopeConflict
	}
	d.Env = copyMap(d.Env)
	t.st.defs[key] = d
	return nil
}

func (t *memTx) ListDefinitions(ctx context.Context, teamID int64, f store.DefinitionFilter, afterID int64, limit int) ([]store.Definition, error) {
	if err := t.fail("ListDefinitions"); err != nil {
		return nil, err
	}
	out := make([]store.Definition, 0)
	for _, d := range t.st.defs {
		if d.TeamID != teamID || d.Deleted || d.Scope == store.ScopeGlobal || d.EnvironmentID <= afterID {
			continue
		}
		if f.Scope != "" && d.Scope != f.Scope {
			continue
		}
		if f.FlowID != 0 && d.FlowID != f.FlowID {
			continue
		}
		d.Env = copyMap(d.Env)
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].EnvironmentID < out[j].EnvironmentID })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (t *memTx) ApplicableDefinitions(ctx context.Context, teamID, flowID int64) ([]store.Definition, error) {
	if err := t.fail("ApplicableDefinitions"); err != nil {
		return nil, err
	}
	rank := map[string]int{store.ScopeGlobal: 0, store.ScopeTeam: 1, store.ScopeFlow: 2}
	out := make([]store.Definition, 0)
	for _, d := range t.st.defs {
		if d.Deleted {
			continue
		}
		switch {
		case d.Scope == store.ScopeGlobal && d.TeamID == store.GlobalTeam:
		case d.Scope == store.ScopeTeam && d.TeamID == teamID:
		case d.Scope == store.ScopeFlow && d.TeamID == teamID && d.FlowID == flowID:
		default:
			continue
		}
		d.Env = copyMap(d.Env)
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool {
		if rank[out[i].Scope] != rank[out[j].Scope] {
			return rank[out[i].Scope] < rank[out[j].Scope]
		}
		return out[i].EnvironmentID < out[j].EnvironmentID
	})
	return out, nil
}

func (t *memTx) InsertSecret(ctx context.Context, s store.Secret) error {
	if err := t.fail("InsertSecret"); err != nil {
		return err
	}
	if _, ok := t.st.defs[[2]int64{s.TeamID, s.EnvironmentID}]; !ok {
		return fmt.Errorf("secret parent %d/%d is not a definition of the same team", s.TeamID, s.EnvironmentID)
	}
	key := [2]int64{s.TeamID, s.SecretID}
	if _, ok := t.st.secrets[key]; ok {
		return fmt.Errorf("duplicate secret %v", key)
	}
	t.st.secrets[key] = s
	return nil
}

func (t *memTx) GetSecret(ctx context.Context, teamID, secretID int64) (store.Secret, error) {
	if err := t.fail("GetSecret"); err != nil {
		return store.Secret{}, err
	}
	s, ok := t.st.secrets[[2]int64{teamID, secretID}]
	if !ok {
		return store.Secret{}, store.ErrNotFound
	}
	return s, nil
}

func (t *memTx) UpdateSecret(ctx context.Context, s store.Secret) error {
	if err := t.fail("UpdateSecret"); err != nil {
		return err
	}
	key := [2]int64{s.TeamID, s.SecretID}
	old, ok := t.st.secrets[key]
	if !ok {
		return store.ErrNotFound
	}
	if old.EnvironmentID != s.EnvironmentID || old.Key != s.Key {
		return fmt.Errorf("immutable secret binding changed")
	}
	t.st.secrets[key] = s
	return nil
}

func (t *memTx) ListSecrets(ctx context.Context, teamID, environmentID int64) ([]store.Secret, error) {
	if err := t.fail("ListSecrets"); err != nil {
		return nil, err
	}
	out := make([]store.Secret, 0)
	for _, s := range t.st.secrets {
		if s.TeamID == teamID && s.EnvironmentID == environmentID && !s.Revoked {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SecretID < out[j].SecretID })
	return out, nil
}

func (t *memTx) InsertSecretVersion(ctx context.Context, v store.SecretVersion) error {
	if err := t.fail("InsertSecretVersion"); err != nil {
		return err
	}
	if _, ok := t.st.secrets[[2]int64{v.TeamID, v.SecretID}]; !ok {
		return fmt.Errorf("version parent %d/%d is not a secret of the same team", v.TeamID, v.SecretID)
	}
	key := [3]int64{v.TeamID, v.SecretID, int64(v.Version)}
	if _, ok := t.st.versions[key]; ok {
		return fmt.Errorf("secret version %v is immutable", key)
	}
	t.st.versions[key] = v
	return nil
}

func (t *memTx) GetSecretVersion(ctx context.Context, teamID, secretID int64, version int) (store.SecretVersion, error) {
	if err := t.fail("GetSecretVersion"); err != nil {
		return store.SecretVersion{}, err
	}
	v, ok := t.st.versions[[3]int64{teamID, secretID, int64(version)}]
	if !ok {
		return store.SecretVersion{}, store.ErrNotFound
	}
	return v, nil
}

func (t *memTx) ListSecretVersions(ctx context.Context, teamID, secretID int64, beforeVersion, limit int) ([]store.SecretVersion, error) {
	if err := t.fail("ListSecretVersions"); err != nil {
		return nil, err
	}
	out := make([]store.SecretVersion, 0)
	for _, v := range t.st.versions {
		if v.TeamID == teamID && v.SecretID == secretID && (beforeVersion == 0 || v.Version < beforeVersion) {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version > out[j].Version })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (t *memTx) AppendRevision(ctx context.Context, r store.Revision) error {
	if err := t.fail("AppendRevision"); err != nil {
		return err
	}
	for _, old := range t.st.revisions {
		if old.TeamID == r.TeamID && old.EnvironmentID == r.EnvironmentID && old.Revision == r.Revision {
			return fmt.Errorf("revision %d of %d/%d is immutable", r.Revision, r.TeamID, r.EnvironmentID)
		}
	}
	r.Env = copyMap(r.Env)
	r.SecretKeys = append([]string(nil), r.SecretKeys...)
	t.st.revisions = append(t.st.revisions, r)
	return nil
}

func (t *memTx) ListRevisions(ctx context.Context, teamID, environmentID int64, beforeRevision, limit int) ([]store.Revision, error) {
	if err := t.fail("ListRevisions"); err != nil {
		return nil, err
	}
	out := make([]store.Revision, 0)
	for _, r := range t.st.revisions {
		if r.TeamID == teamID && r.EnvironmentID == environmentID && (beforeRevision == 0 || r.Revision < beforeRevision) {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Revision > out[j].Revision })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (t *memTx) GetSnapshot(ctx context.Context, teamID, taskID, attempt int64) (store.Snapshot, error) {
	if err := t.fail("GetSnapshot"); err != nil {
		return store.Snapshot{}, err
	}
	s, ok := t.st.snapshots[[3]int64{teamID, taskID, attempt}]
	if !ok {
		return store.Snapshot{}, store.ErrNotFound
	}
	s.Values = copyMap(s.Values)
	s.Secrets = append([]store.SnapshotSecretRef(nil), s.Secrets...)
	return s, nil
}

func (t *memTx) LatestSnapshot(ctx context.Context, teamID, taskID int64) (store.Snapshot, error) {
	if err := t.fail("LatestSnapshot"); err != nil {
		return store.Snapshot{}, err
	}
	var best store.Snapshot
	found := false
	for k, s := range t.st.snapshots {
		if k[0] == teamID && k[1] == taskID && (!found || s.Attempt > best.Attempt) {
			best, found = s, true
		}
	}
	if !found {
		return store.Snapshot{}, store.ErrNotFound
	}
	best.Values = copyMap(best.Values)
	best.Secrets = append([]store.SnapshotSecretRef(nil), best.Secrets...)
	return best, nil
}

func (t *memTx) InsertSnapshot(ctx context.Context, s store.Snapshot) (bool, error) {
	if err := t.fail("InsertSnapshot"); err != nil {
		return false, err
	}
	key := [3]int64{s.TeamID, s.TaskID, s.Attempt}
	if _, ok := t.st.snapshots[key]; ok {
		return false, nil
	}
	s.Values = copyMap(s.Values)
	s.Secrets = append([]store.SnapshotSecretRef(nil), s.Secrets...)
	t.st.snapshots[key] = s
	return true, nil
}

func (t *memTx) DeleteTaskSnapshots(ctx context.Context, teamID, taskID int64) (int, error) {
	if err := t.fail("DeleteTaskSnapshots"); err != nil {
		return 0, err
	}
	n := 0
	for k := range t.st.snapshots {
		if k[0] == teamID && k[1] == taskID {
			delete(t.st.snapshots, k)
			n++
		}
	}
	return n, nil
}

func (t *memTx) RecordConsumed(ctx context.Context, publisher string, publisherSeq int64) (bool, error) {
	if err := t.fail("RecordConsumed"); err != nil {
		return false, err
	}
	key := fmt.Sprintf("%s/%d", publisher, publisherSeq)
	if t.st.consumed[key] {
		return false, nil
	}
	t.st.consumed[key] = true
	return true, nil
}

func (t *memTx) Enqueue(ctx context.Context, subject string, header map[string]string, build func(int64) ([]byte, error)) (int64, error) {
	if err := t.fail("Enqueue"); err != nil {
		return 0, err
	}
	t.m.pubSeq++
	seq := t.m.pubSeq
	payload, err := build(seq)
	if err != nil {
		return 0, err
	}
	t.m.outboxID++
	h := map[string]string{}
	for k, v := range header {
		h[k] = v
	}
	h["Nats-Msg-Id"] = fmt.Sprintf("env-registry-%d", seq)
	t.st.outbox = append(t.st.outbox, store.OutboxMessage{
		ID: t.m.outboxID, PublisherSeq: seq, Subject: subject, Header: h,
		Payload: append([]byte(nil), payload...), CreatedAt: time.Now().UTC(),
	})
	return seq, nil
}

func copyMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

var _ store.Store = (*MemStore)(nil)
