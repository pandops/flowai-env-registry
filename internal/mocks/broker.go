package mocks

import (
	"context"
	"sync"
	"time"

	"github.com/pandops/flowai-env-registry/internal/broker"
	"github.com/pandops/flowai-env-registry/internal/secretbox"
)

// Responder answers one request on the fake broker. Returning an error
// such as broker.ErrTimeout simulates an owner that does not answer.
type Responder func(m broker.Msg) (broker.Msg, error)

// FakeBroker is an in-process broker: a broker.Requester and
// broker.StreamPublisher that records everything it carries.
type FakeBroker struct {
	mu         sync.Mutex
	responders map[string]Responder
	requests   []broker.Msg
	published  []broker.Msg
}

// NewFakeBroker returns a broker with no responders.
func NewFakeBroker() *FakeBroker {
	return &FakeBroker{responders: map[string]Responder{}}
}

// Respond registers the responder of subject; nil removes it (no responder).
func (b *FakeBroker) Respond(subject string, r Responder) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if r == nil {
		delete(b.responders, subject)
		return
	}
	b.responders[subject] = r
}

// Request implements broker.Requester.
func (b *FakeBroker) Request(ctx context.Context, subject string, header broker.Header, data []byte, timeout time.Duration) (broker.Msg, error) {
	b.mu.Lock()
	m := broker.Msg{Subject: subject, Header: copyHeader(header), Data: append([]byte(nil), data...)}
	b.requests = append(b.requests, m)
	r := b.responders[subject]
	b.mu.Unlock()
	if r == nil {
		return broker.Msg{}, broker.ErrNoResponders
	}
	return r(m)
}

// PublishStream implements broker.StreamPublisher.
func (b *FakeBroker) PublishStream(ctx context.Context, subject string, header broker.Header, data []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.published = append(b.published, broker.Msg{Subject: subject, Header: copyHeader(header), Data: append([]byte(nil), data...)})
	return nil
}

// Requests returns every request sent, in order.
func (b *FakeBroker) Requests() []broker.Msg {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]broker.Msg(nil), b.requests...)
}

// RequestsTo returns the requests sent to subject.
func (b *FakeBroker) RequestsTo(subject string) []broker.Msg {
	out := []broker.Msg{}
	for _, m := range b.Requests() {
		if m.Subject == subject {
			out = append(out, m)
		}
	}
	return out
}

// Published returns every acknowledged stream message, in order.
func (b *FakeBroker) Published() []broker.Msg {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]broker.Msg(nil), b.published...)
}

func copyHeader(h broker.Header) broker.Header {
	out := broker.Header{}
	for k, v := range h {
		out[k] = v
	}
	return out
}

// CountingProvider wraps a secretbox.Provider and counts its calls.
type CountingProvider struct {
	Inner    secretbox.Provider
	mu       sync.Mutex
	encrypts int
	decrypts int
}

// Encrypt implements secretbox.Provider.
func (c *CountingProvider) Encrypt(aad secretbox.AAD, plaintext []byte) (secretbox.Envelope, error) {
	c.mu.Lock()
	c.encrypts++
	c.mu.Unlock()
	return c.Inner.Encrypt(aad, plaintext)
}

// Decrypt implements secretbox.Provider.
func (c *CountingProvider) Decrypt(aad secretbox.AAD, env secretbox.Envelope) ([]byte, error) {
	c.mu.Lock()
	c.decrypts++
	c.mu.Unlock()
	return c.Inner.Decrypt(aad, env)
}

// Counts returns the number of Encrypt and Decrypt calls.
func (c *CountingProvider) Counts() (encrypts, decrypts int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.encrypts, c.decrypts
}

// FailingProvider fails every call, as a provider without a loadable key.
type FailingProvider struct{ Err error }

// Encrypt implements secretbox.Provider.
func (f FailingProvider) Encrypt(secretbox.AAD, []byte) (secretbox.Envelope, error) {
	return secretbox.Envelope{}, f.Err
}

// Decrypt implements secretbox.Provider.
func (f FailingProvider) Decrypt(secretbox.AAD, secretbox.Envelope) ([]byte, error) {
	return nil, f.Err
}
