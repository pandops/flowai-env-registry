package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"

	"github.com/pandops/flowai-env-registry/internal/broker"
	"github.com/pandops/flowai-env-registry/internal/cursor"
	"github.com/pandops/flowai-env-registry/internal/ids"
	"github.com/pandops/flowai-env-registry/internal/store"
)

var keyPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

// opSpec describes one ui operation: its params, whether it takes a body,
// and the audit action of its rejections and (for mutations) successes.
type opSpec struct {
	ids      []string // required identifier params besides team_id
	optional []string // optional params
	body     bool
	action   string // "" for operations that are never audited
	resource string // launch_parameters | secret
	mutation bool
	run      func(s *Service, ctx context.Context, r *uiRequest) (int, any, error)
}

var ops = map[string]opSpec{
	"list":                 {optional: []string{"scope", "flow_id", "cursor", "limit"}, run: (*Service).list},
	"create":               {body: true, action: "launch_parameters_created", resource: "launch_parameters", mutation: true, run: (*Service).create},
	"get":                  {ids: []string{"environment_id"}, action: "launch_parameters_read", resource: "launch_parameters", run: (*Service).get},
	"replace":              {ids: []string{"environment_id"}, body: true, action: "launch_parameters_replaced", resource: "launch_parameters", mutation: true, run: (*Service).replace},
	"delete":               {ids: []string{"environment_id"}, action: "launch_parameters_deleted", resource: "launch_parameters", mutation: true, run: (*Service).delete},
	"list-revisions":       {ids: []string{"environment_id"}, optional: []string{"cursor", "limit"}, action: "launch_parameter_revisions_listed", resource: "launch_parameters", run: (*Service).listRevisions},
	"create-secret":        {ids: []string{"environment_id"}, body: true, action: "secret_created", resource: "secret", mutation: true, run: (*Service).createSecret},
	"replace-secret":       {ids: []string{"environment_id", "secret_id"}, body: true, action: "secret_replaced", resource: "secret", mutation: true, run: (*Service).replaceSecret},
	"revoke-secret":        {ids: []string{"environment_id", "secret_id"}, action: "secret_revoked", resource: "secret", mutation: true, run: (*Service).revokeSecret},
	"list-secret-versions": {ids: []string{"environment_id", "secret_id"}, optional: []string{"cursor", "limit"}, action: "secret_versions_listed", resource: "secret", run: (*Service).listSecretVersions},
	"task-parameters":      {ids: []string{"task_id"}, run: (*Service).taskParameters},
}

// uiRequest is a validated ui request.
type uiRequest struct {
	op         string
	spec       opSpec
	team       int64
	operator   int64
	requestID  int64
	ids        map[string]int64
	params     map[string]json.RawMessage
	body       json.RawMessage
	resourceID int64          // set by the handler for audit
	changes    map[string]any // non-secret audit changes
}

func (r *uiRequest) id(name string) int64 { return r.ids[name] }

// HandleUI answers one env-registry.ui.<operation>.sub request.
func (s *Service) HandleUI(ctx context.Context, m broker.Msg) broker.Msg {
	op, _ := trimSubject(m.Subject)
	spec, ok := ops[op]
	if !ok {
		return s.errorReply(&apiError{404, "not_found", "unknown operation", false}, requestIDOf(m.Header))
	}
	r, apiErr := parseUI(op, spec, m)
	if apiErr != nil {
		return s.errorReply(apiErr, requestIDOf(m.Header))
	}
	status, body, err := spec.run(s, ctx, r)
	if err != nil {
		a := asAPI(err)
		if a == errInternal {
			s.d.Logger.Error("ui request failed", "operation", op, "team_id", r.team, "request_id", r.requestID, "error_class", fmt.Sprintf("%T", err))
		}
		if a.audit && spec.action != "" {
			s.auditRejected(ctx, r, a.code)
		}
		return s.errorReply(a, r.requestID)
	}
	s.d.Logger.Info("ui request", "operation", op, "team_id", r.team, "request_id", r.requestID, "status", status)
	reply := broker.Msg{Header: broker.Header{"status": strconv.Itoa(status)}}
	if body != nil {
		data, err := marshal(body)
		if err != nil {
			return s.errorReply(errInternal, r.requestID)
		}
		reply.Data = data
	}
	return reply
}

func requestIDOf(h broker.Header) int64 {
	v, err := ids.ParseDecimal(h["request_id"])
	if err != nil {
		return 0
	}
	return v
}

func (s *Service) errorReply(a *apiError, requestID int64) broker.Msg {
	body := map[string]any{"code": a.code, "message": a.message}
	// No valid request_id header: the field is left out (D12).
	if requestID > 0 {
		body["request_id"] = requestID
	}
	data, _ := marshal(body)
	return broker.Msg{Header: broker.Header{"status": strconv.Itoa(a.status)}, Data: data}
}

func parseUI(op string, spec opSpec, m broker.Msg) (*uiRequest, *apiError) {
	team, err1 := ids.ParseDecimal(m.Header["team"])
	operator, err2 := ids.ParseDecimal(m.Header["operator_id"])
	requestID, err3 := ids.ParseDecimal(m.Header["request_id"])
	if err1 != nil || err2 != nil || err3 != nil {
		return nil, invalid("the verified team, operator and request context is required")
	}
	var envelope map[string]json.RawMessage
	if err := strictObject(m.Data, &envelope); err != nil {
		return nil, invalid("request must be a JSON object")
	}
	for k := range envelope {
		if k != "params" && k != "body" {
			return nil, invalid("unknown request field")
		}
	}
	r := &uiRequest{op: op, spec: spec, team: team, operator: operator, requestID: requestID, ids: map[string]int64{}, changes: map[string]any{}}
	if err := strictObject(envelope["params"], &r.params); err != nil {
		return nil, invalid("params must be an object")
	}
	allowed := map[string]bool{"team_id": true}
	for _, k := range append(append([]string{}, spec.ids...), spec.optional...) {
		allowed[k] = true
	}
	for k := range r.params {
		if !allowed[k] {
			return nil, invalid("unknown parameter " + k)
		}
	}
	for _, k := range append([]string{"team_id"}, spec.ids...) {
		v, err := ids.FromJSON(r.params[k])
		if err != nil {
			return nil, invalid(k + " must be a positive 64-bit integer")
		}
		r.ids[k] = v
	}
	if raw, ok := r.params["flow_id"]; ok {
		v, err := ids.FromJSON(raw)
		if err != nil {
			return nil, invalid("flow_id must be a positive 64-bit integer")
		}
		r.ids["flow_id"] = v
	}
	body, hasBody := envelope["body"]
	if hasBody && !bytes.Equal(bytes.TrimSpace(body), []byte("null")) && !spec.body {
		return nil, invalid("this operation takes no body")
	}
	if spec.body && (!hasBody || bytes.Equal(bytes.TrimSpace(body), []byte("null"))) {
		return nil, invalid("a request body is required")
	}
	r.body = body
	if r.ids["team_id"] != team {
		return r, errUnknownEnvFor(r)
	}
	return r, nil
}

// errUnknownEnvFor is the non-revealing answer to a request naming another
// team in its params; nothing is read.
func errUnknownEnvFor(*uiRequest) *apiError { return errUnknownEnv }

// strictObject decodes a JSON object, rejecting trailing data.
func strictObject(data []byte, dst *map[string]json.RawMessage) error {
	if len(bytes.TrimSpace(data)) == 0 {
		return fmt.Errorf("empty")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(dst); err != nil || *dst == nil {
		return fmt.Errorf("not an object")
	}
	if dec.More() {
		return fmt.Errorf("trailing data")
	}
	return nil
}

// page reads limit and cursor and verifies the cursor for its binding.
func (s *Service) page(r *uiRequest, filter, order string) (int, int64, cursor.Binding, *apiError) {
	limit := 10
	if raw, ok := r.params["limit"]; ok {
		switch string(bytes.TrimSpace(raw)) {
		case "10", "25", "50", "100":
			limit, _ = strconv.Atoi(string(bytes.TrimSpace(raw)))
		default:
			return 0, 0, cursor.Binding{}, &apiError{400, "invalid_limit", "limit must be 10, 25, 50, or 100", false}
		}
	}
	b := cursor.Binding{Operation: r.op, TeamID: r.team, OperatorID: r.operator, Filter: filter, Order: order}
	var after int64
	if raw, ok := r.params["cursor"]; ok {
		var tok string
		if json.Unmarshal(raw, &tok) != nil || tok == "" || len(tok) > 2048 {
			return 0, 0, b, &apiError{400, "invalid_cursor", "cursor is invalid", false}
		}
		v, err := s.d.Cursor.Decode(tok, b)
		if err != nil {
			return 0, 0, b, &apiError{400, "invalid_cursor", "cursor is invalid", false}
		}
		after = v
	}
	return limit, after, b, nil
}

func (s *Service) nextCursor(b cursor.Binding, more bool, last int64) (any, error) {
	if !more {
		return nil, nil
	}
	tok, err := s.d.Cursor.Encode(b, last)
	if err != nil {
		return nil, errInternal
	}
	return tok, nil
}

// definitionBody is the operator definition view. Plaintext of secrets never appears.
type definitionBody struct {
	EnvironmentID int64             `json:"environment_id"`
	TeamID        int64             `json:"team_id"`
	Revision      int               `json:"revision"`
	Scope         string            `json:"scope"`
	FlowID        *int64            `json:"flow_id"`
	Name          string            `json:"name"`
	Env           map[string]string `json:"env"`
	Secrets       []secretSummary   `json:"secrets"`
	CreatedAt     string            `json:"created_at"`
	UpdatedAt     string            `json:"updated_at"`
}

type secretSummary struct {
	SecretID      int64  `json:"secret_id"`
	TeamID        int64  `json:"team_id"`
	EnvironmentID int64  `json:"environment_id"`
	Name          string `json:"name"`
	LatestVersion int    `json:"latest_version"`
	Revoked       bool   `json:"revoked"`
}

func flowPtr(id int64) *int64 {
	if id == 0 {
		return nil
	}
	return &id
}

func definitionView(d store.Definition, secrets []store.Secret) definitionBody {
	out := definitionBody{EnvironmentID: d.EnvironmentID, TeamID: d.TeamID, Revision: d.Revision, Scope: d.Scope, FlowID: flowPtr(d.FlowID),
		Name: d.Name, Env: nonNil(d.Env), Secrets: []secretSummary{}, CreatedAt: stamp(d.CreatedAt), UpdatedAt: stamp(d.UpdatedAt)}
	for _, sc := range secrets {
		out.Secrets = append(out.Secrets, secretSummary{SecretID: sc.SecretID, TeamID: sc.TeamID, EnvironmentID: sc.EnvironmentID, Name: sc.Key, LatestVersion: sc.LatestVersion, Revoked: sc.Revoked})
	}
	return out
}

func nonNil(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

// definitionInput is a validated create or replace body.
type definitionInput struct {
	Scope  string
	FlowID int64
	Name   string
	Env    map[string]string
}

func parseDefinition(raw json.RawMessage) (definitionInput, *apiError) {
	var fields map[string]json.RawMessage
	if strictObject(raw, &fields) != nil {
		return definitionInput{}, invalid("body must be an object")
	}
	var in definitionInput
	for k, v := range fields {
		switch k {
		case "scope":
			if json.Unmarshal(v, &in.Scope) != nil || (in.Scope != store.ScopeTeam && in.Scope != store.ScopeFlow) {
				return in, invalid("scope must be team or flow")
			}
		case "flow_id":
			if string(bytes.TrimSpace(v)) == "null" {
				continue
			}
			id, err := ids.FromJSON(v)
			if err != nil {
				return in, invalid("flow_id must be a positive 64-bit integer")
			}
			in.FlowID = id
		case "name":
			if json.Unmarshal(v, &in.Name) != nil || in.Name == "" || len([]rune(in.Name)) > 200 {
				return in, invalid("name must have 1 to 200 characters")
			}
		case "env":
			if json.Unmarshal(v, &in.Env) != nil || in.Env == nil {
				return in, invalid("env must be an object of strings")
			}
		default:
			return in, invalid("unknown field " + k)
		}
	}
	if in.Scope == "" || in.Name == "" || in.Env == nil {
		return in, invalid("scope, name and env are required")
	}
	if (in.Scope == store.ScopeFlow) != (in.FlowID != 0) {
		return in, invalid("flow_id is required for flow scope and only for it")
	}
	for k, v := range in.Env {
		if !keyPattern.MatchString(k) || len(v) > 65536 {
			return in, invalid("invalid launch parameter name or value")
		}
		if reserved[k] {
			return in, invalid("this launch parameter name is reserved")
		}
	}
	return in, nil
}

func parseSecretBody(raw json.RawMessage, withKey bool) (string, string, *apiError) {
	var fields map[string]json.RawMessage
	if strictObject(raw, &fields) != nil {
		return "", "", invalid("body must be an object")
	}
	var key, value string
	for k, v := range fields {
		switch {
		case k == "key" && withKey:
			if json.Unmarshal(v, &key) != nil || !keyPattern.MatchString(key) {
				return "", "", invalid("invalid secret key")
			}
		case k == "value":
			if json.Unmarshal(v, &value) != nil || value == "" || len(value) > 65536 {
				return "", "", invalid("value must be a non-empty string")
			}
		default:
			return "", "", invalid("unknown field " + k)
		}
	}
	if value == "" || (withKey && key == "") {
		return "", "", invalid("key and value are required")
	}
	if reserved[key] {
		return "", "", invalid("this launch parameter name is reserved")
	}
	return key, value, nil
}

// checkFlowOwner asks flow-registry whether the Flow belongs to the team.
func (s *Service) checkFlowOwner(ctx context.Context, team, flow int64) error {
	status, data, err := s.requestBroker(ctx, FlowOwnerSubject, team, map[string]any{"params": map[string]int64{"team_id": team, "flow_id": flow}})
	if err != nil {
		return err
	}
	switch status {
	case 200:
		var owner struct {
			TeamID int64 `json:"team_id"`
		}
		if json.Unmarshal(data, &owner) != nil || owner.TeamID != team {
			return errUnknownEnv
		}
		return nil
	case 404:
		return errUnknownEnv
	}
	return errOwnerDown
}

// ownDefinition reads a live team or Flow definition of the team.
func ownDefinition(ctx context.Context, tx store.Tx, team, id int64, allowDeleted bool) (store.Definition, error) {
	d, err := tx.GetDefinition(ctx, team, id)
	if err != nil {
		return d, err
	}
	if d.TeamID != team || d.Scope == store.ScopeGlobal || (d.Deleted && !allowDeleted) {
		return d, errUnknownEnv
	}
	return d, nil
}

func secretKeys(secrets []store.Secret) []string {
	out := []string{}
	for _, sc := range secrets {
		out = append(out, sc.Key)
	}
	sort.Strings(out)
	return out
}

func marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
