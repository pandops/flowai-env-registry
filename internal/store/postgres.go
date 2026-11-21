package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/pandops/flowai-env-registry/internal/secretbox"
)

// Postgres is the PostgreSQL store. Every statement names the service schema.
type Postgres struct {
	db     *sql.DB
	schema string
}

// NewPostgres wraps an open database; schema is the migrated service schema.
func NewPostgres(db *sql.DB, schema string) *Postgres {
	return &Postgres{db: db, schema: schema}
}

func (p *Postgres) t(name string) string { return p.schema + "." + name }

// InTx implements Store.
func (p *Postgres) InTx(ctx context.Context, fn func(Tx) error) error {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(&pgTx{p: p, tx: tx}); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// PendingOutbox implements Store.
func (p *Postgres) PendingOutbox(ctx context.Context, limit int) ([]OutboxMessage, error) {
	rows, err := p.db.QueryContext(ctx, `SELECT id, publisher_seq, subject, header, payload, created_at FROM `+p.t("outbox")+` WHERE sent_at IS NULL ORDER BY id LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []OutboxMessage{}
	for rows.Next() {
		var m OutboxMessage
		var header []byte
		if err := rows.Scan(&m.ID, &m.PublisherSeq, &m.Subject, &header, &m.Payload, &m.CreatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(header, &m.Header); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// MarkOutboxSent implements Store.
func (p *Postgres) MarkOutboxSent(ctx context.Context, id int64) error {
	res, err := p.db.ExecContext(ctx, `UPDATE `+p.t("outbox")+` SET sent_at = now() WHERE id = $1 AND sent_at IS NULL`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Ping implements Store.
func (p *Postgres) Ping(ctx context.Context) error { return p.db.PingContext(ctx) }

var _ Store = (*Postgres)(nil)

type pgTx struct {
	p  *Postgres
	tx *sql.Tx
}

func (t *pgTx) tb(name string) string { return t.p.t(name) }

func uniqueViolation(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && pg.Code == "23505"
}

func nullFlow(id int64) any {
	if id == 0 {
		return nil
	}
	return id
}

// NextTeamNumber allocates outside the caller's transaction, in its own
// committed statement: a rolled-back create leaves a gap and its number is
// never handed out again.
func (t *pgTx) NextTeamNumber(ctx context.Context, teamID int64, kind string) (int64, error) {
	var v int64
	err := t.p.db.QueryRowContext(ctx, `INSERT INTO `+t.tb("team_counters")+` (team_id, kind, last_value) VALUES ($1, $2, 1)
		ON CONFLICT (team_id, kind) DO UPDATE SET last_value = `+t.tb("team_counters")+`.last_value + 1 RETURNING last_value`, teamID, kind).Scan(&v)
	return v, err
}

func (t *pgTx) NextGlobalEnvironmentID(ctx context.Context) (int64, error) {
	var v int64
	err := t.tx.QueryRowContext(ctx, `SELECT nextval('`+t.tb("global_environment_seq")+`')`).Scan(&v)
	return v, err
}

const defCols = `team_id, environment_id, scope, COALESCE(flow_id, 0), name, env, revision, deleted, created_at, updated_at`

func scanDef(sc interface{ Scan(...any) error }) (Definition, error) {
	var d Definition
	var env []byte
	if err := sc.Scan(&d.TeamID, &d.EnvironmentID, &d.Scope, &d.FlowID, &d.Name, &env, &d.Revision, &d.Deleted, &d.CreatedAt, &d.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return d, ErrNotFound
		}
		return d, err
	}
	if err := json.Unmarshal(env, &d.Env); err != nil {
		return d, err
	}
	d.CreatedAt, d.UpdatedAt = d.CreatedAt.UTC(), d.UpdatedAt.UTC()
	return d, nil
}

func (t *pgTx) InsertDefinition(ctx context.Context, d Definition) error {
	env, err := json.Marshal(nonNil(d.Env))
	if err != nil {
		return err
	}
	_, err = t.tx.ExecContext(ctx, `INSERT INTO `+t.tb("definitions")+` (team_id, environment_id, scope, flow_id, name, env, revision, deleted, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`, d.TeamID, d.EnvironmentID, d.Scope, nullFlow(d.FlowID), d.Name, env, d.Revision, d.Deleted, d.CreatedAt, d.UpdatedAt)
	if uniqueViolation(err) {
		return ErrScopeConflict
	}
	return err
}

func (t *pgTx) GetDefinition(ctx context.Context, teamID, environmentID int64) (Definition, error) {
	return scanDef(t.tx.QueryRowContext(ctx, `SELECT `+defCols+` FROM `+t.tb("definitions")+` WHERE team_id = $1 AND environment_id = $2 FOR UPDATE`, teamID, environmentID))
}

func (t *pgTx) UpdateDefinition(ctx context.Context, d Definition) error {
	env, err := json.Marshal(nonNil(d.Env))
	if err != nil {
		return err
	}
	res, err := t.tx.ExecContext(ctx, `UPDATE `+t.tb("definitions")+` SET name = $3, env = $4, revision = $5, deleted = $6, updated_at = $7
		WHERE team_id = $1 AND environment_id = $2`, d.TeamID, d.EnvironmentID, d.Name, env, d.Revision, d.Deleted, d.UpdatedAt)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (t *pgTx) ListDefinitions(ctx context.Context, teamID int64, f DefinitionFilter, afterID int64, limit int) ([]Definition, error) {
	q := `SELECT ` + defCols + ` FROM ` + t.tb("definitions") + ` WHERE team_id = $1 AND NOT deleted AND scope <> 'global' AND environment_id > $2`
	args := []any{teamID, afterID}
	if f.Scope != "" {
		args = append(args, f.Scope)
		q += ` AND scope = $` + strconv.Itoa(len(args))
	}
	if f.FlowID != 0 {
		args = append(args, f.FlowID)
		q += ` AND flow_id = $` + strconv.Itoa(len(args))
	}
	args = append(args, limit)
	q += ` ORDER BY environment_id LIMIT $` + strconv.Itoa(len(args))
	return t.defs(ctx, q, args...)
}

func (t *pgTx) defs(ctx context.Context, q string, args ...any) ([]Definition, error) {
	rows, err := t.tx.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Definition{}
	for rows.Next() {
		d, err := scanDef(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// ApplicableDefinitions returns global, team and flow definitions, broadest first.
func (t *pgTx) ApplicableDefinitions(ctx context.Context, teamID, flowID int64) ([]Definition, error) {
	return t.defs(ctx, `SELECT `+defCols+` FROM `+t.tb("definitions")+` WHERE NOT deleted AND (
		(team_id = 0 AND scope = 'global') OR (team_id = $1 AND scope = 'team') OR (team_id = $1 AND scope = 'flow' AND flow_id = $2))
		ORDER BY CASE scope WHEN 'global' THEN 0 WHEN 'team' THEN 1 ELSE 2 END, environment_id`, teamID, flowID)
}

const secretCols = `team_id, secret_id, environment_id, key, latest_version, revoked, created_at, updated_at`

func scanSecret(sc interface{ Scan(...any) error }) (Secret, error) {
	var s Secret
	if err := sc.Scan(&s.TeamID, &s.SecretID, &s.EnvironmentID, &s.Key, &s.LatestVersion, &s.Revoked, &s.CreatedAt, &s.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return s, ErrNotFound
		}
		return s, err
	}
	s.CreatedAt, s.UpdatedAt = s.CreatedAt.UTC(), s.UpdatedAt.UTC()
	return s, nil
}

func (t *pgTx) InsertSecret(ctx context.Context, s Secret) error {
	_, err := t.tx.ExecContext(ctx, `INSERT INTO `+t.tb("secrets")+` (`+secretCols+`) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		s.TeamID, s.SecretID, s.EnvironmentID, s.Key, s.LatestVersion, s.Revoked, s.CreatedAt, s.UpdatedAt)
	if uniqueViolation(err) {
		return ErrScopeConflict
	}
	return err
}

func (t *pgTx) GetSecret(ctx context.Context, teamID, secretID int64) (Secret, error) {
	return scanSecret(t.tx.QueryRowContext(ctx, `SELECT `+secretCols+` FROM `+t.tb("secrets")+` WHERE team_id = $1 AND secret_id = $2 FOR UPDATE`, teamID, secretID))
}

func (t *pgTx) UpdateSecret(ctx context.Context, s Secret) error {
	res, err := t.tx.ExecContext(ctx, `UPDATE `+t.tb("secrets")+` SET latest_version = $3, revoked = $4, updated_at = $5 WHERE team_id = $1 AND secret_id = $2`,
		s.TeamID, s.SecretID, s.LatestVersion, s.Revoked, s.UpdatedAt)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (t *pgTx) ListSecrets(ctx context.Context, teamID, environmentID int64) ([]Secret, error) {
	rows, err := t.tx.QueryContext(ctx, `SELECT `+secretCols+` FROM `+t.tb("secrets")+` WHERE team_id = $1 AND environment_id = $2 AND NOT revoked ORDER BY secret_id`, teamID, environmentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Secret{}
	for rows.Next() {
		s, err := scanSecret(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (t *pgTx) InsertSecretVersion(ctx context.Context, v SecretVersion) error {
	_, err := t.tx.ExecContext(ctx, `INSERT INTO `+t.tb("secret_versions")+` (team_id, secret_id, version, provider, key_id, nonce, ciphertext, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, v.TeamID, v.SecretID, v.Version, v.Envelope.Provider, v.Envelope.KeyID, v.Envelope.Nonce, v.Envelope.Ciphertext, v.CreatedAt)
	return err
}

func scanVersion(sc interface{ Scan(...any) error }) (SecretVersion, error) {
	var v SecretVersion
	if err := sc.Scan(&v.TeamID, &v.SecretID, &v.Version, &v.Envelope.Provider, &v.Envelope.KeyID, &v.Envelope.Nonce, &v.Envelope.Ciphertext, &v.CreatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return v, ErrNotFound
		}
		return v, err
	}
	v.CreatedAt = v.CreatedAt.UTC()
	return v, nil
}

const versionCols = `team_id, secret_id, version, provider, key_id, nonce, ciphertext, created_at`

func (t *pgTx) GetSecretVersion(ctx context.Context, teamID, secretID int64, version int) (SecretVersion, error) {
	return scanVersion(t.tx.QueryRowContext(ctx, `SELECT `+versionCols+` FROM `+t.tb("secret_versions")+` WHERE team_id = $1 AND secret_id = $2 AND version = $3`, teamID, secretID, version))
}

func (t *pgTx) ListSecretVersions(ctx context.Context, teamID, secretID int64, beforeVersion, limit int) ([]SecretVersion, error) {
	if beforeVersion == 0 {
		beforeVersion = 1 << 30
	}
	rows, err := t.tx.QueryContext(ctx, `SELECT `+versionCols+` FROM `+t.tb("secret_versions")+` WHERE team_id = $1 AND secret_id = $2 AND version < $3 ORDER BY version DESC LIMIT $4`, teamID, secretID, beforeVersion, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SecretVersion{}
	for rows.Next() {
		v, err := scanVersion(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (t *pgTx) AppendRevision(ctx context.Context, r Revision) error {
	env, err := json.Marshal(nonNil(r.Env))
	if err != nil {
		return err
	}
	keys := r.SecretKeys
	if keys == nil {
		keys = []string{}
	}
	sk, _ := json.Marshal(keys)
	_, err = t.tx.ExecContext(ctx, `INSERT INTO `+t.tb("revisions")+` (team_id, environment_id, revision, scope, flow_id, name, env, secret_keys, deleted, actor_id, request_id, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`, r.TeamID, r.EnvironmentID, r.Revision, r.Scope, nullFlow(r.FlowID), r.Name, env, sk, r.Deleted, r.ActorID, r.RequestID, r.CreatedAt)
	return err
}

func (t *pgTx) ListRevisions(ctx context.Context, teamID, environmentID int64, beforeRevision, limit int) ([]Revision, error) {
	if beforeRevision == 0 {
		beforeRevision = 1 << 30
	}
	rows, err := t.tx.QueryContext(ctx, `SELECT team_id, environment_id, revision, scope, COALESCE(flow_id, 0), name, env, secret_keys, deleted, actor_id, request_id, created_at
		FROM `+t.tb("revisions")+` WHERE team_id = $1 AND environment_id = $2 AND revision < $3 ORDER BY revision DESC LIMIT $4`, teamID, environmentID, beforeRevision, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Revision{}
	for rows.Next() {
		var r Revision
		var env, sk []byte
		if err := rows.Scan(&r.TeamID, &r.EnvironmentID, &r.Revision, &r.Scope, &r.FlowID, &r.Name, &env, &sk, &r.Deleted, &r.ActorID, &r.RequestID, &r.CreatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(env, &r.Env); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(sk, &r.SecretKeys); err != nil {
			return nil, err
		}
		r.CreatedAt = r.CreatedAt.UTC()
		out = append(out, r)
	}
	return out, rows.Err()
}

type refJSON struct {
	Key      string `json:"key"`
	SecretID int64  `json:"secret_id"`
	TeamID   int64  `json:"team_id"`
	Version  int    `json:"version"`
}

func (t *pgTx) snapshot(ctx context.Context, q string, args ...any) (Snapshot, error) {
	var s Snapshot
	var vals, refs []byte
	err := t.tx.QueryRowContext(ctx, q, args...).Scan(&s.TeamID, &s.TaskID, &s.Attempt, &vals, &refs, &s.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return s, ErrNotFound
	}
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(vals, &s.Values); err != nil {
		return s, err
	}
	var rs []refJSON
	if err := json.Unmarshal(refs, &rs); err != nil {
		return s, err
	}
	for _, r := range rs {
		s.Secrets = append(s.Secrets, SnapshotSecretRef(r))
	}
	s.CreatedAt = s.CreatedAt.UTC()
	return s, nil
}

const snapCols = `team_id, task_id, attempt, env_values, secret_refs, created_at`

func (t *pgTx) GetSnapshot(ctx context.Context, teamID, taskID, attempt int64) (Snapshot, error) {
	return t.snapshot(ctx, `SELECT `+snapCols+` FROM `+t.tb("snapshots")+` WHERE team_id = $1 AND task_id = $2 AND attempt = $3`, teamID, taskID, attempt)
}

func (t *pgTx) LatestSnapshot(ctx context.Context, teamID, taskID int64) (Snapshot, error) {
	return t.snapshot(ctx, `SELECT `+snapCols+` FROM `+t.tb("snapshots")+` WHERE team_id = $1 AND task_id = $2 ORDER BY attempt DESC LIMIT 1`, teamID, taskID)
}

func (t *pgTx) InsertSnapshot(ctx context.Context, s Snapshot) (bool, error) {
	vals, err := json.Marshal(nonNil(s.Values))
	if err != nil {
		return false, err
	}
	rs := []refJSON{}
	for _, r := range s.Secrets {
		rs = append(rs, refJSON(r))
	}
	refs, _ := json.Marshal(rs)
	res, err := t.tx.ExecContext(ctx, `INSERT INTO `+t.tb("snapshots")+` (`+snapCols+`) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING`,
		s.TeamID, s.TaskID, s.Attempt, vals, refs, s.CreatedAt)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

func (t *pgTx) DeleteTaskSnapshots(ctx context.Context, teamID, taskID int64) (int, error) {
	res, err := t.tx.ExecContext(ctx, `DELETE FROM `+t.tb("snapshots")+` WHERE team_id = $1 AND task_id = $2`, teamID, taskID)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func (t *pgTx) RecordConsumed(ctx context.Context, publisher string, publisherSeq int64) (bool, error) {
	res, err := t.tx.ExecContext(ctx, `INSERT INTO `+t.tb("consumed_messages")+` (publisher, publisher_seq) VALUES ($1, $2) ON CONFLICT DO NOTHING`, publisher, publisherSeq)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// Enqueue takes the next publisher_seq from the sequence in this transaction;
// a rollback leaves a gap, never a reused Nats-Msg-Id.
func (t *pgTx) Enqueue(ctx context.Context, subject string, header map[string]string, build func(int64) ([]byte, error)) (int64, error) {
	var seq int64
	if err := t.tx.QueryRowContext(ctx, `SELECT nextval('`+t.tb("publisher_seq")+`')`).Scan(&seq); err != nil {
		return 0, err
	}
	payload, err := build(seq)
	if err != nil {
		return 0, err
	}
	h := map[string]string{}
	for k, v := range header {
		h[k] = v
	}
	h["Nats-Msg-Id"] = "env-registry-" + strconv.FormatInt(seq, 10)
	hj, _ := json.Marshal(h)
	if _, err := t.tx.ExecContext(ctx, `INSERT INTO `+t.tb("outbox")+` (publisher_seq, subject, header, payload, created_at) VALUES ($1, $2, $3, $4, $5)`,
		seq, subject, hj, payload, time.Now().UTC()); err != nil {
		return 0, fmt.Errorf("outbox: %w", err)
	}
	return seq, nil
}

func nonNil(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

var _ = secretbox.ProviderLocal
