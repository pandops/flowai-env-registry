// Package claimtoken verifies task-manager's Ed25519 claim tokens:
// <base64url(payload)>.<base64url(signature over the payload bytes)>, no
// padding (agents.md rule 12).
package claimtoken

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"github.com/pandops/flowai-env-registry/internal/ids"
)

// ErrInvalid reports a malformed, tampered or wrongly signed token.
var ErrInvalid = errors.New("claim token is invalid")

// Claims is the claim a token names.
type Claims struct {
	TeamID     int64 `json:"team_id"`
	TaskID     int64 `json:"task_id"`
	Attempt    int64 `json:"attempt"`
	ClaimSeq   int64 `json:"claim_seq"`
	ExecutorID int64 `json:"executor_id"`
}

// Verifier checks tokens against task-manager's public key.
type Verifier struct {
	key ed25519.PublicKey
}

// NewVerifier returns a verifier for the configured public key.
func NewVerifier(key ed25519.PublicKey) (*Verifier, error) {
	if len(key) != ed25519.PublicKeySize {
		return nil, errors.New("claim token verification key must be an Ed25519 public key")
	}
	return &Verifier{key: append(ed25519.PublicKey(nil), key...)}, nil
}

// Verify returns the token's claims when its signature and shape are valid.
func (v *Verifier) Verify(token string) (Claims, error) {
	payloadText, sigText, ok := strings.Cut(token, ".")
	if !ok || payloadText == "" || strings.Contains(sigText, ".") {
		return Claims{}, ErrInvalid
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(payloadText)
	if err != nil {
		return Claims{}, ErrInvalid
	}
	// The signature covers the decoded payload JSON bytes (agents.md rule 12).
	sig, err := base64.RawURLEncoding.Strict().DecodeString(sigText)
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(v.key, payload, sig) {
		return Claims{}, ErrInvalid
	}
	var fields map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(payload))
	if err := dec.Decode(&fields); err != nil || dec.More() || len(fields) != 5 {
		return Claims{}, ErrInvalid
	}
	var c Claims
	for name, dst := range map[string]*int64{"team_id": &c.TeamID, "task_id": &c.TaskID, "attempt": &c.Attempt, "claim_seq": &c.ClaimSeq, "executor_id": &c.ExecutorID} {
		raw, ok := fields[name]
		if !ok {
			return Claims{}, ErrInvalid
		}
		if *dst, err = ids.FromJSON(raw); err != nil {
			return Claims{}, ErrInvalid
		}
	}
	return c, nil
}
