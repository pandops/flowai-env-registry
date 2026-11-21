// Package service implements env-registry's operations: the operator ui
// requests, the Executor open edge and the archived-task consumer.
package service

import (
	"context"
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/pandops/flowai-env-registry/internal/broker"
	"github.com/pandops/flowai-env-registry/internal/claimtoken"
	"github.com/pandops/flowai-env-registry/internal/cursor"
	"github.com/pandops/flowai-env-registry/internal/secretbox"
	"github.com/pandops/flowai-env-registry/internal/store"
)

// Publisher is the service name in every message env-registry publishes.
const Publisher = "env-registry"

// Subjects env-registry serves, consumes and requests.
const (
	UISubject           = "env-registry.ui.*.sub"
	UIQueue             = "env-registry"
	ArchivedSubject     = "task-manager.event.archived.sub"
	FlowOwnerSubject    = "flow-registry.service.flow-owner.pub"
	ClaimCurrentSubject = "task-manager.service.claim-current.pub"
	openEventSubject    = "env-registry.event.launch_parameters_open.pub"
)

// reserved names belong to model-registry's per-task LiteLLM key.
var reserved = map[string]bool{"OPENAI_API_KEY": true, "OPENAI_BASE_URL": true, "OPENAI_MODEL": true}

// Deps are the service's collaborators.
type Deps struct {
	Store          store.Store
	Crypto         secretbox.Provider // nil: no loadable data key
	Claims         *claimtoken.Verifier
	Broker         broker.Requester
	Cursor         *cursor.Codec
	Clock          func() time.Time
	Logger         *slog.Logger
	RequestTimeout time.Duration
}

// Service is env-registry's domain logic.
type Service struct {
	d      Deps
	reqSeq atomic.Int64 // request_id of requests env-registry originates
}

// New returns the service.
func New(d Deps) *Service {
	if d.Clock == nil {
		d.Clock = time.Now
	}
	if d.Logger == nil {
		d.Logger = slog.New(slog.DiscardHandler)
	}
	if d.RequestTimeout <= 0 {
		d.RequestTimeout = 5 * time.Second
	}
	return &Service{d: d}
}

func (s *Service) now() time.Time { return s.d.Clock().UTC() }

func stamp(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

// apiError is an operator-visible failure.
type apiError struct {
	status  int
	code    string
	message string
	audit   bool // authorization or state rejection: audited as rejected
}

func (e *apiError) Error() string { return e.code }

var (
	errUnknownEnv = &apiError{404, "environment_unknown_or_unavailable", "environment is unknown or unavailable", true}
	errConflict   = &apiError{409, "scope_conflict", "an active definition already exists for this scope", true}
	errOwnerDown  = &apiError{503, "service_unavailable", "a required service did not answer", true}
	errBrokerDown = &apiError{503, "broker_unavailable", "the message broker is unavailable", true}
	errCrypto     = &apiError{503, "service_unavailable", "secret storage is unavailable", false}
	errInternal   = &apiError{500, "internal_error", "internal error", false}
)

func invalid(msg string) *apiError { return &apiError{400, "invalid_request", msg, false} }

func asAPI(err error) *apiError {
	var a *apiError
	if errors.As(err, &a) {
		return a
	}
	switch {
	case errors.Is(err, store.ErrNotFound):
		return errUnknownEnv
	case errors.Is(err, store.ErrScopeConflict):
		return errConflict
	case errors.Is(err, secretbox.ErrUnavailable), errors.Is(err, secretbox.ErrDecrypt):
		return errCrypto
	}
	return errInternal
}

// requestBroker sends a service request whose JSON is envelope (the
// responder's request schema) and classifies transport failures.
func (s *Service) requestBroker(ctx context.Context, subject string, team int64, envelope any) (int, []byte, error) {
	data, err := marshal(envelope)
	if err != nil {
		return 0, nil, errInternal
	}
	header := broker.Header{"team": strconv.FormatInt(team, 10), "request_id": strconv.FormatInt(s.reqSeq.Add(1), 10)}
	reply, err := s.d.Broker.Request(ctx, subject, header, data, s.d.RequestTimeout)
	switch {
	case errors.Is(err, broker.ErrUnavailable):
		return 0, nil, errBrokerDown
	case err != nil:
		return 0, nil, errOwnerDown
	}
	status, err := strconv.Atoi(reply.Header["status"])
	if err != nil {
		return 0, nil, errOwnerDown
	}
	return status, reply.Data, nil
}

func trimSubject(subject string) (string, bool) {
	rest, ok := strings.CutPrefix(subject, "env-registry.ui.")
	if !ok {
		return "", false
	}
	for _, suffix := range []string{".sub", ".pub"} {
		if op, ok := strings.CutSuffix(rest, suffix); ok && op != "" && !strings.Contains(op, ".") {
			return op, true
		}
	}
	return "", false
}
