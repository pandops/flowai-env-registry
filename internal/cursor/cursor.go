// Package cursor issues opaque, HMAC-protected pagination cursors bound to
// one read: operation, team, operator, filter, ordering and direction.
package cursor

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ErrInvalid reports any cursor that must be rejected before a query.
var ErrInvalid = errors.New("cursor is invalid")

// Key is one configured HMAC key; ID is a positive integer from configuration.
type Key struct {
	ID     int64
	Secret []byte
}

// Binding is what a cursor is bound to.
type Binding struct {
	Operation  string
	TeamID     int64
	OperatorID int64
	Filter     string
	Order      string
}

// Codec encodes and decodes cursors.
type Codec struct {
	active int64
	keys   map[int64][]byte
}

// NewCodec builds a codec; activeID signs new cursors.
func NewCodec(keys []Key, activeID int64) (*Codec, error) {
	c := &Codec{active: activeID, keys: map[int64][]byte{}}
	for _, k := range keys {
		if k.ID < 1 || len(k.Secret) < 32 {
			return nil, fmt.Errorf("cursor key %d: want a positive id and at least 32 bytes", k.ID)
		}
		if _, dup := c.keys[k.ID]; dup {
			return nil, fmt.Errorf("cursor key %d configured twice", k.ID)
		}
		c.keys[k.ID] = append([]byte(nil), k.Secret...)
	}
	if _, ok := c.keys[activeID]; !ok {
		return nil, fmt.Errorf("active cursor key %d is not configured", activeID)
	}
	return c, nil
}

type body struct {
	V     int   `json:"v"`
	Key   int64 `json:"k"`
	After int64 `json:"a"`
}

func mac(secret []byte, b Binding, payload []byte) []byte {
	h := hmac.New(sha256.New, secret)
	fmt.Fprintf(h, "%q|%d|%d|%q|%q|", b.Operation, b.TeamID, b.OperatorID, b.Filter, b.Order)
	h.Write(payload)
	return h.Sum(nil)
}

// Encode returns a cursor that continues after position after.
func (c *Codec) Encode(b Binding, after int64) (string, error) {
	payload, err := json.Marshal(body{V: 1, Key: c.active, After: after})
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(mac(c.keys[c.active], b, payload)), nil
}

// Decode verifies a cursor for b and returns its position.
func (c *Codec) Decode(token string, b Binding) (int64, error) {
	p, s, ok := strings.Cut(token, ".")
	if !ok {
		return 0, ErrInvalid
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(p)
	if err != nil {
		return 0, ErrInvalid
	}
	sig, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil {
		return 0, ErrInvalid
	}
	var fields map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(payload))
	if dec.Decode(&fields) != nil || dec.More() || len(fields) != 3 {
		return 0, ErrInvalid
	}
	keyID, err := strconv.ParseInt(string(fields["k"]), 10, 64)
	if err != nil {
		return 0, ErrInvalid // also rejects a non-integer key id
	}
	secret, ok := c.keys[keyID]
	if !ok || !hmac.Equal(sig, mac(secret, b, payload)) {
		return 0, ErrInvalid
	}
	var v body
	if json.Unmarshal(payload, &v) != nil || v.V != 1 || v.After < 1 {
		return 0, ErrInvalid
	}
	return v.After, nil
}
