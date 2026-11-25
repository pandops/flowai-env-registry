// Package broker defines env-registry's view of the message broker: core
// NATS request/reply and JetStream publish/consume. The NATS
// implementation lives in nats.go; tests use internal/mocks.
package broker

import (
	"context"
	"errors"
	"time"
)

// Header is a single-valued NATS header set.
type Header map[string]string

// Msg is one broker message, request or reply.
type Msg struct {
	Subject string
	Header  Header
	Data    []byte
}

var (
	// ErrNoResponders means no service answers the subject.
	ErrNoResponders = errors.New("no responders")
	// ErrTimeout means the request got no reply within its timeout.
	ErrTimeout = errors.New("request timed out")
	// ErrUnavailable means the caller's own broker connection is down.
	ErrUnavailable = errors.New("broker connection unavailable")
)

// Requester sends core NATS requests.
type Requester interface {
	Request(ctx context.Context, subject string, header Header, data []byte, timeout time.Duration) (Msg, error)
}

// StreamPublisher publishes one JetStream message and waits for its
// acknowledgement. The header carries Nats-Msg-Id.
type StreamPublisher interface {
	PublishStream(ctx context.Context, subject string, header Header, data []byte) error
}

// AckDecision is a consumer's answer to one stream message.
type AckDecision int

const (
	// Ack acknowledges the message.
	Ack AckDecision = iota
	// Nak asks for redelivery.
	Nak
	// Term terminates the message so it is never redelivered.
	Term
)

// RequestHandler answers one request; the reply carries header status.
type RequestHandler func(ctx context.Context, m Msg) Msg

// StreamHandler handles one stream message.
type StreamHandler func(ctx context.Context, m Msg) AckDecision
