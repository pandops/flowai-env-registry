// Package ids parses FlowAI integer identifiers: positive 64-bit integers
// written in decimal without sign or leading zeros.
package ids

import (
	"bytes"
	"encoding/json"
	"errors"
	"strconv"
)

// ErrInvalid reports an identifier that is not a positive int64.
var ErrInvalid = errors.New("identifier is not a positive 64-bit integer")

// ParseDecimal parses a decimal token such as a path segment or header.
func ParseDecimal(s string) (int64, error) {
	if s == "" || len(s) > 19 || s[0] == '0' {
		return 0, ErrInvalid
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, ErrInvalid
		}
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil || v < 1 {
		return 0, ErrInvalid
	}
	return v, nil
}

// FromJSON parses a JSON number that must be an integer literal in range.
func FromJSON(raw json.RawMessage) (int64, error) {
	return ParseDecimal(string(bytes.TrimSpace(raw)))
}
