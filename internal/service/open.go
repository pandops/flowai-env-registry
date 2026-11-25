package service

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"github.com/pandops/flowai-env-registry/internal/broker"
	"github.com/pandops/flowai-env-registry/internal/claimtoken"
	"github.com/pandops/flowai-env-registry/internal/ids"
	"github.com/pandops/flowai-env-registry/internal/secretbox"
	"github.com/pandops/flowai-env-registry/internal/store"
)

// Open outcomes, as published in the open event.
const (
	outcomeOpened      = "opened"
	outcomeNotCurrent  = "claim_not_current"
	outcomeUnavailable = "service_unavailable"
	outcomeConfig      = "configuration_error"
)

// missingParameter aborts a snapshot freeze: a required value is absent.
type missingParameter struct{ name string }

func (m *missingParameter) Error() string { return "missing required parameter" }

type openFailure struct {
	status  int
	code    string
	message string
	missing string
}

var (
	failNotCurrent  = openFailure{404, outcomeNotCurrent, "the claim is not current", ""}
	failUnavailable = openFailure{503, outcomeUnavailable, "launch parameters are unavailable", ""}
)

func (s *Service) openError(f openFailure, requestID int64) OpenResult {
	body := map[string]any{"code": f.code, "message": f.message, "request_id": requestID}
	if f.missing != "" {
		body["failure_reason"] = "missing_required_parameter"
		body["missing_parameter"] = f.missing
	}
	data, _ := marshal(body)
	return OpenResult{Status: f.status, Body: data}
}

// Open serves GET /v1/tasks/{task_id}/launch-parameters/open.
func (s *Service) Open(ctx context.Context, rawTaskID, authorization string) OpenResult {
	requestID := s.reqSeq.Add(1)
	token, ok := strings.CutPrefix(authorization, "Bearer ")
	if !ok || s.d.Claims == nil {
		return s.openError(failNotCurrent, requestID)
	}
	c, err := s.d.Claims.Verify(token)
	if err != nil {
		// An unverified token names no trustworthy team: no event.
		s.d.Logger.Info("launch-parameter open refused", "outcome", outcomeNotCurrent, "reason", "token_not_verified")
		return s.openError(failNotCurrent, requestID)
	}
	task, err := ids.ParseDecimal(rawTaskID)
	if err != nil || task != c.TaskID {
		return s.refuseOpen(ctx, c, 0, failNotCurrent, requestID)
	}
	flow, f := s.claimCurrent(ctx, c)
	if f != nil {
		return s.refuseOpen(ctx, c, 0, *f, requestID)
	}
	values, err := s.openSnapshot(ctx, c, flow)
	var missing *missingParameter
	switch {
	case errors.As(err, &missing):
		return s.refuseOpen(ctx, c, flow, openFailure{422, outcomeConfig, "a required launch parameter is missing", missing.name}, requestID)
	case err != nil:
		if !errors.Is(err, errCrypto) {
			s.d.Logger.Error("launch-parameter open failed", "team_id", c.TeamID, "task_id", c.TaskID, "attempt", c.Attempt)
		}
		return s.refuseOpen(ctx, c, flow, failUnavailable, requestID)
	}
	s.d.Logger.Info("launch parameters opened", "team_id", c.TeamID, "task_id", c.TaskID, "attempt", c.Attempt, "count", len(values))
	data, err := marshal(map[string]any{"values": values})
	if err != nil {
		return s.openError(failUnavailable, requestID)
	}
	return OpenResult{Status: 200, Body: data}
}

// claimCurrent asks task-manager whether c is the current claim and returns the task's Flow.
func (s *Service) claimCurrent(ctx context.Context, c claimtoken.Claims) (int64, *openFailure) {
	params := map[string]int64{"team_id": c.TeamID, "task_id": c.TaskID, "attempt": c.Attempt, "claim_seq": c.ClaimSeq, "executor_id": c.ExecutorID}
	status, data, err := s.requestBroker(ctx, ClaimCurrentSubject, c.TeamID, map[string]any{"params": params})
	if err != nil {
		return 0, &failUnavailable
	}
	if status >= 500 {
		return 0, &failUnavailable
	}
	var reply struct {
		Current bool  `json:"current"`
		TeamID  int64 `json:"team_id"`
		FlowID  int64 `json:"flow_id"`
	}
	if status != 200 || json.Unmarshal(data, &reply) != nil || !reply.Current || reply.TeamID != c.TeamID || reply.FlowID < 1 {
		return 0, &failNotCurrent
	}
	return reply.FlowID, nil
}

// refuseOpen records the refusal event in its own transaction and answers f.
func (s *Service) refuseOpen(ctx context.Context, c claimtoken.Claims, flow int64, f openFailure, requestID int64) OpenResult {
	err := s.d.Store.InTx(ctx, func(tx store.Tx) error { return s.enqueueOpenEvent(ctx, tx, c, flow, f.code, f.missing) })
	if err != nil {
		s.d.Logger.Error("open event not stored", "team_id", c.TeamID, "task_id", c.TaskID)
	}
	s.d.Logger.Info("launch-parameter open refused", "team_id", c.TeamID, "task_id", c.TaskID, "attempt", c.Attempt, "outcome", f.code)
	return s.openError(f, requestID)
}

func (s *Service) enqueueOpenEvent(ctx context.Context, tx store.Tx, c claimtoken.Claims, flow int64, outcome, missing string) error {
	occurred := stamp(s.now())
	_, err := tx.Enqueue(ctx, openEventSubject, map[string]string{"team": itoa(c.TeamID)}, func(seq int64) ([]byte, error) {
		p := map[string]any{
			"publisher": Publisher, "publisher_seq": seq, "team_id": c.TeamID, "occurred_at": occurred,
			"kind": "launch_parameters_open", "task_id": c.TaskID, "attempt": c.Attempt,
			"claim_seq": c.ClaimSeq, "executor_id": c.ExecutorID, "outcome": outcome,
		}
		if flow > 0 {
			p["flow_id"] = flow
		}
		if missing != "" {
			p["failure_reason"] = "missing_required_parameter"
			p["missing_parameter"] = missing
		}
		return marshal(p)
	})
	return err
}

// openSnapshot freezes (once per attempt) and decrypts the attempt snapshot.
func (s *Service) openSnapshot(ctx context.Context, c claimtoken.Claims, flow int64) (map[string]string, error) {
	if s.d.Crypto == nil {
		return nil, errCrypto
	}
	var values map[string]string
	err := s.d.Store.InTx(ctx, func(tx store.Tx) error {
		snap, err := tx.GetSnapshot(ctx, c.TeamID, c.TaskID, c.Attempt)
		if errors.Is(err, store.ErrNotFound) {
			if snap, err = s.resolve(ctx, tx, c, flow); err != nil {
				return err
			}
			inserted, err := tx.InsertSnapshot(ctx, snap)
			if err != nil {
				return err
			}
			if !inserted { // a concurrent open froze it first
				if snap, err = tx.GetSnapshot(ctx, c.TeamID, c.TaskID, c.Attempt); err != nil {
					return err
				}
			}
		} else if err != nil {
			return err
		}
		if values, err = s.decryptSnapshot(ctx, tx, snap); err != nil {
			return err
		}
		return s.enqueueOpenEvent(ctx, tx, c, flow, outcomeOpened, "")
	})
	return values, err
}

// resolve merges the applicable definitions, broadest first, into a snapshot.
func (s *Service) resolve(ctx context.Context, tx store.Tx, c claimtoken.Claims, flow int64) (store.Snapshot, error) {
	defs, err := tx.ApplicableDefinitions(ctx, c.TeamID, flow)
	if err != nil {
		return store.Snapshot{}, err
	}
	type entry struct {
		value  string
		secret *store.SnapshotSecretRef
	}
	merged := map[string]entry{}
	for _, d := range defs {
		if d.Deleted || (d.TeamID != c.TeamID && d.TeamID != store.GlobalTeam) || (d.Scope == store.ScopeFlow && d.FlowID != flow) {
			continue
		}
		for k, v := range d.Env {
			if !reserved[k] {
				merged[k] = entry{value: v}
			}
		}
		secrets, err := tx.ListSecrets(ctx, d.TeamID, d.EnvironmentID)
		if err != nil {
			return store.Snapshot{}, err
		}
		for _, sc := range secrets {
			if sc.Revoked || reserved[sc.Key] {
				continue
			}
			merged[sc.Key] = entry{secret: &store.SnapshotSecretRef{Key: sc.Key, SecretID: sc.SecretID, TeamID: sc.TeamID, Version: sc.LatestVersion}}
		}
	}
	keys := make([]string, 0, len(merged))
	for k := range merged {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	snap := store.Snapshot{TeamID: c.TeamID, TaskID: c.TaskID, Attempt: c.Attempt, Values: map[string]string{}, Secrets: []store.SnapshotSecretRef{}, CreatedAt: s.now()}
	for _, k := range keys {
		e := merged[k]
		switch {
		case e.secret != nil && e.secret.Version < 1, e.secret == nil && e.value == "":
			return store.Snapshot{}, &missingParameter{name: k}
		case e.secret != nil:
			snap.Secrets = append(snap.Secrets, *e.secret)
		default:
			snap.Values[k] = e.value
		}
	}
	return snap, nil
}

func (s *Service) decryptSnapshot(ctx context.Context, tx store.Tx, snap store.Snapshot) (map[string]string, error) {
	values := map[string]string{}
	for k, v := range snap.Values {
		values[k] = v
	}
	for _, ref := range snap.Secrets {
		v, err := tx.GetSecretVersion(ctx, ref.TeamID, ref.SecretID, ref.Version)
		if err != nil {
			return nil, errCrypto
		}
		pt, err := s.d.Crypto.Decrypt(secretbox.AAD{TeamID: ref.TeamID, SecretID: ref.SecretID, Version: ref.Version}, v.Envelope)
		if err != nil {
			return nil, errCrypto
		}
		values[ref.Key] = string(pt)
	}
	return values, nil
}

// HandleArchived consumes task-manager's archived event: the task's snapshots are deleted once.
func (s *Service) HandleArchived(ctx context.Context, m broker.Msg) broker.AckDecision {
	var p struct {
		Publisher    string `json:"publisher"`
		PublisherSeq int64  `json:"publisher_seq"`
		TeamID       int64  `json:"team_id"`
		TaskID       int64  `json:"task_id"`
		Kind         string `json:"kind"`
	}
	if json.Unmarshal(m.Data, &p) != nil || p.Publisher != "task-manager" || p.Kind != "archived" || p.PublisherSeq < 1 || p.TeamID < 1 || p.TaskID < 1 || m.Header["team"] != itoa(p.TeamID) {
		s.d.Logger.Warn("archived event rejected", "subject", m.Subject)
		return broker.Term
	}
	err := s.d.Store.InTx(ctx, func(tx store.Tx) error {
		fresh, err := tx.RecordConsumed(ctx, p.Publisher, p.PublisherSeq)
		if err != nil || !fresh {
			return err
		}
		_, err = tx.DeleteTaskSnapshots(ctx, p.TeamID, p.TaskID)
		return err
	})
	if err != nil {
		s.d.Logger.Error("archived event not applied", "team_id", p.TeamID, "task_id", p.TaskID, "publisher_seq", p.PublisherSeq)
		return broker.Nak
	}
	return broker.Ack
}

// OpenResult is the HTTP answer of the open edge.
type OpenResult struct {
	Status int
	Body   []byte
}
