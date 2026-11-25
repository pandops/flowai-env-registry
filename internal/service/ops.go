package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"

	"github.com/pandops/flowai-env-registry/internal/secretbox"
	"github.com/pandops/flowai-env-registry/internal/store"
)

func itoa(v int64) string { return strconv.FormatInt(v, 10) }

// enqueueAudit writes one audit outbox row in tx.
func (s *Service) enqueueAudit(ctx context.Context, tx store.Tx, r *uiRequest, outcome, reason string, resourceID int64, changes map[string]any) error {
	subject := "env-registry.audit." + r.spec.action + ".pub"
	header := map[string]string{"team": itoa(r.team), "request_id": itoa(r.requestID)}
	occurred := stamp(s.now())
	_, err := tx.Enqueue(ctx, subject, header, func(seq int64) ([]byte, error) {
		p := map[string]any{
			"publisher": Publisher, "publisher_seq": seq, "team_id": r.team, "occurred_at": occurred,
			"source_service": Publisher, "actor_type": "operator", "actor_id": r.operator,
			"action": r.spec.action, "resource_type": r.spec.resource, "resource_id": nil,
			"request_id": r.requestID, "outcome": outcome,
		}
		if resourceID > 0 {
			p["resource_id"] = resourceID
		}
		if reason != "" {
			p["reason"] = reason
		}
		if len(changes) > 0 {
			p["changes"] = changes
		}
		return marshal(p)
	})
	return err
}

// auditRejected records an authorization or state rejection in its own transaction.
func (s *Service) auditRejected(ctx context.Context, r *uiRequest, code string) {
	resource := r.ids["environment_id"]
	if r.spec.resource == "secret" {
		resource = r.ids["secret_id"]
	}
	err := s.d.Store.InTx(ctx, func(tx store.Tx) error {
		return s.enqueueAudit(ctx, tx, r, "rejected", code, resource, nil)
	})
	if err != nil {
		s.d.Logger.Error("rejected-request audit not stored", "operation", r.op, "team_id", r.team, "request_id", r.requestID)
	}
}

func definitionChanges(d store.Definition) map[string]any {
	c := map[string]any{"environment_id": d.EnvironmentID, "scope": d.Scope, "revision": d.Revision}
	if d.FlowID != 0 {
		c["flow_id"] = d.FlowID
	}
	return c
}

func (s *Service) revisionOf(d store.Definition, keys []string, r *uiRequest) store.Revision {
	if keys == nil {
		keys = []string{}
	}
	env := map[string]string{}
	for k, v := range d.Env {
		env[k] = v
	}
	return store.Revision{TeamID: d.TeamID, EnvironmentID: d.EnvironmentID, Revision: d.Revision, Scope: d.Scope, FlowID: d.FlowID,
		Name: d.Name, Env: env, SecretKeys: keys, Deleted: d.Deleted, ActorID: r.operator, RequestID: r.requestID, CreatedAt: s.now()}
}

func (s *Service) list(ctx context.Context, r *uiRequest) (int, any, error) {
	var f store.DefinitionFilter
	if raw, ok := r.params["scope"]; ok {
		if json.Unmarshal(raw, &f.Scope) != nil || (f.Scope != store.ScopeTeam && f.Scope != store.ScopeFlow) {
			return 0, nil, invalid("scope must be team or flow")
		}
	}
	f.FlowID = r.ids["flow_id"]
	limit, after, b, apiErr := s.page(r, fmt.Sprintf("scope=%s;flow_id=%d", f.Scope, f.FlowID), "environment_id_asc")
	if apiErr != nil {
		return 0, nil, apiErr
	}
	items := []definitionBody{}
	more := false
	err := s.d.Store.InTx(ctx, func(tx store.Tx) error {
		defs, err := tx.ListDefinitions(ctx, r.team, f, after, limit+1)
		if err != nil {
			return err
		}
		if more = len(defs) > limit; more {
			defs = defs[:limit]
		}
		for _, d := range defs {
			if d.TeamID != r.team {
				continue
			}
			secrets, err := tx.ListSecrets(ctx, r.team, d.EnvironmentID)
			if err != nil {
				return err
			}
			items = append(items, definitionView(d, secrets))
		}
		return nil
	})
	if err != nil {
		return 0, nil, internalOnly(err)
	}
	var last int64
	if len(items) > 0 {
		last = items[len(items)-1].EnvironmentID
	}
	next, err := s.nextCursor(b, more, last)
	if err != nil {
		return 0, nil, err
	}
	return 200, map[string]any{"items": items, "next_cursor": next}, nil
}

// internalOnly maps a storage failure of a read that has no 404 to 500.
func internalOnly(err error) error {
	if errors.Is(err, store.ErrNotFound) {
		return errInternal
	}
	return err
}

func (s *Service) create(ctx context.Context, r *uiRequest) (int, any, error) {
	in, apiErr := parseDefinition(r.body)
	if apiErr != nil {
		return 0, nil, apiErr
	}
	if in.Scope == store.ScopeFlow {
		if err := s.checkFlowOwner(ctx, r.team, in.FlowID); err != nil {
			return 0, nil, err
		}
	}
	var out definitionBody
	err := s.d.Store.InTx(ctx, func(tx store.Tx) error {
		id, err := tx.NextTeamNumber(ctx, r.team, store.KindEnvironment)
		if err != nil {
			return err
		}
		now := s.now()
		d := store.Definition{TeamID: r.team, EnvironmentID: id, Scope: in.Scope, FlowID: in.FlowID, Name: in.Name, Env: in.Env, Revision: 1, CreatedAt: now, UpdatedAt: now}
		if err := tx.InsertDefinition(ctx, d); err != nil {
			return err
		}
		if err := tx.AppendRevision(ctx, s.revisionOf(d, nil, r)); err != nil {
			return err
		}
		r.ids["environment_id"] = id
		if err := s.enqueueAudit(ctx, tx, r, "succeeded", "", id, definitionChanges(d)); err != nil {
			return err
		}
		out = definitionView(d, nil)
		return nil
	})
	if err != nil {
		delete(r.ids, "environment_id")
		return 0, nil, err
	}
	return 201, out, nil
}

func (s *Service) get(ctx context.Context, r *uiRequest) (int, any, error) {
	var out definitionBody
	err := s.d.Store.InTx(ctx, func(tx store.Tx) error {
		d, err := ownDefinition(ctx, tx, r.team, r.id("environment_id"), false)
		if err != nil {
			return err
		}
		secrets, err := tx.ListSecrets(ctx, r.team, d.EnvironmentID)
		if err != nil {
			return err
		}
		out = definitionView(d, secrets)
		return nil
	})
	if err != nil {
		return 0, nil, err
	}
	return 200, out, nil
}

func (s *Service) replace(ctx context.Context, r *uiRequest) (int, any, error) {
	in, apiErr := parseDefinition(r.body)
	if apiErr != nil {
		return 0, nil, apiErr
	}
	var out definitionBody
	err := s.d.Store.InTx(ctx, func(tx store.Tx) error {
		d, err := ownDefinition(ctx, tx, r.team, r.id("environment_id"), false)
		if err != nil {
			return err
		}
		if in.Scope != d.Scope || in.FlowID != d.FlowID {
			return invalid("scope and flow_id cannot change")
		}
		d.Name, d.Env, d.Revision, d.UpdatedAt = in.Name, in.Env, d.Revision+1, s.now()
		if err := tx.UpdateDefinition(ctx, d); err != nil {
			return err
		}
		secrets, err := tx.ListSecrets(ctx, r.team, d.EnvironmentID)
		if err != nil {
			return err
		}
		if err := tx.AppendRevision(ctx, s.revisionOf(d, secretKeys(secrets), r)); err != nil {
			return err
		}
		if err := s.enqueueAudit(ctx, tx, r, "succeeded", "", d.EnvironmentID, definitionChanges(d)); err != nil {
			return err
		}
		out = definitionView(d, secrets)
		return nil
	})
	if err != nil {
		return 0, nil, err
	}
	return 200, out, nil
}

func (s *Service) delete(ctx context.Context, r *uiRequest) (int, any, error) {
	err := s.d.Store.InTx(ctx, func(tx store.Tx) error {
		d, err := ownDefinition(ctx, tx, r.team, r.id("environment_id"), false)
		if err != nil {
			return err
		}
		secrets, err := tx.ListSecrets(ctx, r.team, d.EnvironmentID)
		if err != nil {
			return err
		}
		d.Deleted, d.Revision, d.UpdatedAt = true, d.Revision+1, s.now()
		if err := tx.UpdateDefinition(ctx, d); err != nil {
			return err
		}
		if err := tx.AppendRevision(ctx, s.revisionOf(d, secretKeys(secrets), r)); err != nil {
			return err
		}
		return s.enqueueAudit(ctx, tx, r, "succeeded", "", d.EnvironmentID, definitionChanges(d))
	})
	if err != nil {
		return 0, nil, err
	}
	return 204, nil, nil
}

type revisionBody struct {
	EnvironmentID int64             `json:"environment_id"`
	Revision      int               `json:"revision"`
	TeamID        int64             `json:"team_id"`
	Scope         string            `json:"scope"`
	FlowID        *int64            `json:"flow_id"`
	Name          string            `json:"name"`
	Env           map[string]string `json:"env"`
	SecretKeys    []string          `json:"secret_keys"`
	Deleted       bool              `json:"deleted"`
	ActorID       int64             `json:"actor_id"`
	RequestID     int64             `json:"request_id"`
	CreatedAt     string            `json:"created_at"`
}

func (s *Service) listRevisions(ctx context.Context, r *uiRequest) (int, any, error) {
	envID := r.id("environment_id")
	limit, after, b, apiErr := s.page(r, "environment_id="+itoa(envID), "revision_desc")
	if apiErr != nil {
		return 0, nil, apiErr
	}
	items := []revisionBody{}
	more := false
	err := s.d.Store.InTx(ctx, func(tx store.Tx) error {
		if _, err := ownDefinition(ctx, tx, r.team, envID, true); err != nil {
			return err
		}
		revs, err := tx.ListRevisions(ctx, r.team, envID, int(after), limit+1)
		if err != nil {
			return err
		}
		if more = len(revs) > limit; more {
			revs = revs[:limit]
		}
		for _, rv := range revs {
			keys := rv.SecretKeys
			if keys == nil {
				keys = []string{}
			}
			items = append(items, revisionBody{EnvironmentID: rv.EnvironmentID, Revision: rv.Revision, TeamID: rv.TeamID, Scope: rv.Scope, FlowID: flowPtr(rv.FlowID),
				Name: rv.Name, Env: nonNil(rv.Env), SecretKeys: keys, Deleted: rv.Deleted, ActorID: rv.ActorID, RequestID: rv.RequestID, CreatedAt: stamp(rv.CreatedAt)})
		}
		return nil
	})
	if err != nil {
		return 0, nil, err
	}
	var last int64
	if len(items) > 0 {
		last = int64(items[len(items)-1].Revision)
	}
	next, err := s.nextCursor(b, more, last)
	if err != nil {
		return 0, nil, err
	}
	return 200, map[string]any{"items": items, "next_cursor": next}, nil
}

func secretView(sc store.Secret) map[string]any {
	return map[string]any{"secret_id": sc.SecretID, "key": sc.Key, "current_version": sc.LatestVersion, "revoked": sc.Revoked}
}

func (s *Service) encrypt(team, secret int64, version int, value string) (secretbox.Envelope, error) {
	if s.d.Crypto == nil {
		return secretbox.Envelope{}, errCrypto
	}
	env, err := s.d.Crypto.Encrypt(secretbox.AAD{TeamID: team, SecretID: secret, Version: version}, []byte(value))
	if err != nil {
		return env, errCrypto
	}
	return env, nil
}

func (s *Service) createSecret(ctx context.Context, r *uiRequest) (int, any, error) {
	key, value, apiErr := parseSecretBody(r.body, true)
	if apiErr != nil {
		return 0, nil, apiErr
	}
	var out map[string]any
	err := s.d.Store.InTx(ctx, func(tx store.Tx) error {
		d, err := ownDefinition(ctx, tx, r.team, r.id("environment_id"), false)
		if err != nil {
			return err
		}
		if s.d.Crypto == nil {
			return errCrypto
		}
		existing, err := tx.ListSecrets(ctx, r.team, d.EnvironmentID)
		if err != nil {
			return err
		}
		for _, sc := range existing {
			if sc.Key == key {
				return errConflict
			}
		}
		sid, err := tx.NextTeamNumber(ctx, r.team, store.KindSecret)
		if err != nil {
			return err
		}
		env, err := s.encrypt(r.team, sid, 1, value)
		if err != nil {
			return err
		}
		now := s.now()
		sc := store.Secret{TeamID: r.team, SecretID: sid, EnvironmentID: d.EnvironmentID, Key: key, LatestVersion: 1, CreatedAt: now, UpdatedAt: now}
		if err := tx.InsertSecret(ctx, sc); err != nil {
			return err
		}
		if err := tx.InsertSecretVersion(ctx, store.SecretVersion{TeamID: r.team, SecretID: sid, Version: 1, Envelope: env, CreatedAt: now}); err != nil {
			return err
		}
		r.ids["secret_id"] = sid
		if err := s.enqueueAudit(ctx, tx, r, "succeeded", "", sid, map[string]any{"environment_id": d.EnvironmentID, "version": 1, "parameter": key}); err != nil {
			return err
		}
		out = secretView(sc)
		return nil
	})
	if err != nil {
		delete(r.ids, "secret_id")
		return 0, nil, err
	}
	return 201, out, nil
}

// ownSecret reads a live secret of a live own definition.
func ownSecret(ctx context.Context, tx store.Tx, r *uiRequest, allowRevoked bool) (store.Definition, store.Secret, error) {
	d, err := ownDefinition(ctx, tx, r.team, r.id("environment_id"), false)
	if err != nil {
		return d, store.Secret{}, err
	}
	sc, err := tx.GetSecret(ctx, r.team, r.id("secret_id"))
	if err != nil {
		return d, sc, err
	}
	if sc.TeamID != r.team || sc.EnvironmentID != d.EnvironmentID || (sc.Revoked && !allowRevoked) {
		return d, sc, errUnknownEnv
	}
	return d, sc, nil
}

func (s *Service) replaceSecret(ctx context.Context, r *uiRequest) (int, any, error) {
	_, value, apiErr := parseSecretBody(r.body, false)
	if apiErr != nil {
		return 0, nil, apiErr
	}
	var out map[string]any
	err := s.d.Store.InTx(ctx, func(tx store.Tx) error {
		d, sc, err := ownSecret(ctx, tx, r, false)
		if err != nil {
			return err
		}
		v := sc.LatestVersion + 1
		env, err := s.encrypt(r.team, sc.SecretID, v, value)
		if err != nil {
			return err
		}
		now := s.now()
		if err := tx.InsertSecretVersion(ctx, store.SecretVersion{TeamID: r.team, SecretID: sc.SecretID, Version: v, Envelope: env, CreatedAt: now}); err != nil {
			return err
		}
		sc.LatestVersion, sc.UpdatedAt = v, now
		if err := tx.UpdateSecret(ctx, sc); err != nil {
			return err
		}
		if err := s.enqueueAudit(ctx, tx, r, "succeeded", "", sc.SecretID, map[string]any{"environment_id": d.EnvironmentID, "version": v, "parameter": sc.Key}); err != nil {
			return err
		}
		out = secretView(sc)
		return nil
	})
	if err != nil {
		return 0, nil, err
	}
	return 200, out, nil
}

func (s *Service) revokeSecret(ctx context.Context, r *uiRequest) (int, any, error) {
	err := s.d.Store.InTx(ctx, func(tx store.Tx) error {
		d, sc, err := ownSecret(ctx, tx, r, false)
		if err != nil {
			return err
		}
		now := s.now()
		sc.Revoked, sc.UpdatedAt = true, now
		if err := tx.UpdateSecret(ctx, sc); err != nil {
			return err
		}
		remaining, err := tx.ListSecrets(ctx, r.team, d.EnvironmentID)
		if err != nil {
			return err
		}
		d.Revision, d.UpdatedAt = d.Revision+1, now
		if err := tx.UpdateDefinition(ctx, d); err != nil {
			return err
		}
		if err := tx.AppendRevision(ctx, s.revisionOf(d, secretKeys(remaining), r)); err != nil {
			return err
		}
		return s.enqueueAudit(ctx, tx, r, "succeeded", "", sc.SecretID, map[string]any{"environment_id": d.EnvironmentID, "revision": d.Revision, "parameter": sc.Key})
	})
	if err != nil {
		return 0, nil, err
	}
	return 204, nil, nil
}

func (s *Service) listSecretVersions(ctx context.Context, r *uiRequest) (int, any, error) {
	limit, after, b, apiErr := s.page(r, "environment_id="+itoa(r.id("environment_id"))+";secret_id="+itoa(r.id("secret_id")), "version_desc")
	if apiErr != nil {
		return 0, nil, apiErr
	}
	items := []map[string]any{}
	more := false
	var last int64
	err := s.d.Store.InTx(ctx, func(tx store.Tx) error {
		_, sc, err := ownSecret(ctx, tx, r, true)
		if err != nil {
			return err
		}
		vs, err := tx.ListSecretVersions(ctx, r.team, sc.SecretID, int(after), limit+1)
		if err != nil {
			return err
		}
		if more = len(vs) > limit; more {
			vs = vs[:limit]
		}
		for _, v := range vs {
			items = append(items, map[string]any{"version": v.Version, "created_at": stamp(v.CreatedAt)})
			last = int64(v.Version)
		}
		return nil
	})
	if err != nil {
		return 0, nil, err
	}
	next, err := s.nextCursor(b, more, last)
	if err != nil {
		return 0, nil, err
	}
	return 200, map[string]any{"items": items, "next_cursor": next}, nil
}

func (s *Service) taskParameters(ctx context.Context, r *uiRequest) (int, any, error) {
	task := r.id("task_id")
	out := map[string]any{"task_id": task, "attempt": nil, "environment": map[string]string{}, "secret_keys": []string{}}
	err := s.d.Store.InTx(ctx, func(tx store.Tx) error {
		snap, err := tx.LatestSnapshot(ctx, r.team, task)
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if snap.TeamID != r.team {
			return nil
		}
		keys := []string{}
		for _, ref := range snap.Secrets {
			keys = append(keys, ref.Key)
		}
		sort.Strings(keys)
		out = map[string]any{"task_id": task, "attempt": snap.Attempt, "environment": nonNil(snap.Values), "secret_keys": keys}
		return nil
	})
	if err != nil {
		return 0, nil, internalOnly(err)
	}
	return 200, out, nil
}
