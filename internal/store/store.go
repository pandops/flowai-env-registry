// Package store defines env-registry's persistence model and the
// transaction primitives the service layer composes. The PostgreSQL
// implementation is in postgres.go; unit tests use internal/mocks.
package store

import (
	"context"
	"errors"
	"time"

	"github.com/pandops/flowai-env-registry/internal/secretbox"
)

var (
	// ErrNotFound reports an absent row.
	ErrNotFound = errors.New("not found")
	// ErrScopeConflict reports a second active definition for one scope key.
	ErrScopeConflict = errors.New("active definition already exists for scope")
)

// Scopes of a definition.
const (
	ScopeGlobal = "global"
	ScopeTeam   = "team"
	ScopeFlow   = "flow"
)

// Counter kinds of per-team numbering.
const (
	KindEnvironment = "environment"
	KindSecret      = "secret"
)

// GlobalTeam is the team_id value of a global definition, which has no team.
const GlobalTeam int64 = 0

// Definition is the current projection of one launch-parameter definition.
type Definition struct {
	TeamID        int64
	EnvironmentID int64
	Scope         string
	FlowID        int64 // 0 unless Scope is flow
	Name          string
	Env           map[string]string
	Revision      int
	Deleted       bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// Secret is one logical secret under a definition.
type Secret struct {
	TeamID        int64
	SecretID      int64
	EnvironmentID int64
	Key           string
	LatestVersion int
	Revoked       bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// SecretVersion is one immutable encrypted version.
type SecretVersion struct {
	TeamID    int64
	SecretID  int64
	Version   int
	Envelope  secretbox.Envelope
	CreatedAt time.Time
}

// Revision is one immutable definition revision. It never holds secret material.
type Revision struct {
	TeamID        int64
	EnvironmentID int64
	Revision      int
	Scope         string
	FlowID        int64
	Name          string
	Env           map[string]string
	SecretKeys    []string
	Deleted       bool
	ActorID       int64
	RequestID     int64
	CreatedAt     time.Time
}

// SnapshotSecretRef is an exact secret version frozen into a snapshot.
type SnapshotSecretRef struct {
	Key      string
	SecretID int64
	TeamID   int64 // owner of the secret: the task's team, or GlobalTeam
	Version  int
}

// Snapshot is the frozen launch-parameter set of one task attempt.
type Snapshot struct {
	TeamID    int64
	TaskID    int64
	Attempt   int64
	Values    map[string]string
	Secrets   []SnapshotSecretRef
	CreatedAt time.Time
}

// OutboxMessage is one stream message waiting for, or past, publication.
type OutboxMessage struct {
	ID           int64
	PublisherSeq int64
	Subject      string
	Header       map[string]string
	Payload      []byte
	CreatedAt    time.Time
	SentAt       *time.Time
}

// DefinitionFilter narrows a list of team definitions.
type DefinitionFilter struct {
	Scope  string // "" for any team or flow scope
	FlowID int64  // 0 for any
}

// Store is the transactional store.
type Store interface {
	InTx(ctx context.Context, fn func(Tx) error) error
	PendingOutbox(ctx context.Context, limit int) ([]OutboxMessage, error)
	MarkOutboxSent(ctx context.Context, id int64) error
	Ping(ctx context.Context) error
}

// Tx is one transaction. Every read locks what it returns for update.
type Tx interface {
	// NextTeamNumber allocates the next per-team number of kind.
	NextTeamNumber(ctx context.Context, teamID int64, kind string) (int64, error)
	// NextGlobalEnvironmentID allocates a global definition's number.
	NextGlobalEnvironmentID(ctx context.Context) (int64, error)

	InsertDefinition(ctx context.Context, d Definition) error
	GetDefinition(ctx context.Context, teamID, environmentID int64) (Definition, error)
	UpdateDefinition(ctx context.Context, d Definition) error
	// ListDefinitions lists active team and flow definitions of a team in
	// environment_id order after afterID.
	ListDefinitions(ctx context.Context, teamID int64, f DefinitionFilter, afterID int64, limit int) ([]Definition, error)
	// ApplicableDefinitions returns the active global, team and flow
	// definitions for a task of teamID and flowID, broadest first.
	ApplicableDefinitions(ctx context.Context, teamID, flowID int64) ([]Definition, error)

	InsertSecret(ctx context.Context, s Secret) error
	GetSecret(ctx context.Context, teamID, secretID int64) (Secret, error)
	UpdateSecret(ctx context.Context, s Secret) error
	// ListSecrets lists the non-revoked secrets of a definition in secret_id order.
	ListSecrets(ctx context.Context, teamID, environmentID int64) ([]Secret, error)

	InsertSecretVersion(ctx context.Context, v SecretVersion) error
	GetSecretVersion(ctx context.Context, teamID, secretID int64, version int) (SecretVersion, error)
	// ListSecretVersions lists versions newest first below beforeVersion (0 = none).
	ListSecretVersions(ctx context.Context, teamID, secretID int64, beforeVersion, limit int) ([]SecretVersion, error)

	AppendRevision(ctx context.Context, r Revision) error
	// ListRevisions lists revisions newest first below beforeRevision (0 = none).
	ListRevisions(ctx context.Context, teamID, environmentID int64, beforeRevision, limit int) ([]Revision, error)

	GetSnapshot(ctx context.Context, teamID, taskID, attempt int64) (Snapshot, error)
	// LatestSnapshot returns the team's snapshot of the task with the highest attempt.
	LatestSnapshot(ctx context.Context, teamID, taskID int64) (Snapshot, error)
	// InsertSnapshot stores s unless one exists for its attempt; it reports whether it inserted.
	InsertSnapshot(ctx context.Context, s Snapshot) (bool, error)
	DeleteTaskSnapshots(ctx context.Context, teamID, taskID int64) (int, error)

	// RecordConsumed records a consumed message; false means it was already recorded.
	RecordConsumed(ctx context.Context, publisher string, publisherSeq int64) (bool, error)

	// Enqueue allocates publisher_seq from the service's sequence and writes
	// one outbox row whose payload build returns for that sequence.
	Enqueue(ctx context.Context, subject string, header map[string]string, build func(publisherSeq int64) ([]byte, error)) (int64, error)
}
