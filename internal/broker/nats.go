package broker

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// NATSOptions configures the NATS connection.
type NATSOptions struct {
	URL             string
	CredentialsFile string // empty: no user credentials
	CAFile          string // empty: system roots
	InboxPrefix     string
	ReconnectWait   time.Duration
}

// NATS is env-registry's NATS connection.
type NATS struct {
	nc     *nats.Conn
	js     jetstream.JetStream
	status chan bool

	mu       sync.Mutex
	consumer jetstream.ConsumeContext
}

// DialNATS connects once; the connection then reconnects forever and
// reports every connected (true) and disconnected (false) change on Status.
func DialNATS(o NATSOptions) (*NATS, error) {
	n := &NATS{status: make(chan bool, 8)}
	wait := o.ReconnectWait
	if wait <= 0 {
		wait = 2 * time.Second
	}
	opts := []nats.Option{
		nats.Name("env-registry"),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(wait),
		nats.DisconnectErrHandler(func(*nats.Conn, error) { n.push(false) }),
		nats.ReconnectHandler(func(*nats.Conn) { n.push(true) }),
		nats.ClosedHandler(func(*nats.Conn) { n.push(false) }),
	}
	if o.InboxPrefix != "" {
		opts = append(opts, nats.CustomInboxPrefix(o.InboxPrefix))
	}
	if o.CredentialsFile != "" {
		opts = append(opts, nats.UserCredentials(o.CredentialsFile))
	}
	if o.CAFile != "" {
		opts = append(opts, nats.RootCAs(o.CAFile))
	}
	nc, err := nats.Connect(o.URL, opts...)
	if err != nil {
		return nil, err
	}
	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, err
	}
	n.nc, n.js = nc, js
	n.push(true)
	return n, nil
}

// push delivers v, dropping the oldest pending change when the buffer is full,
// so the latest state always arrives.
func (n *NATS) push(v bool) {
	for {
		select {
		case n.status <- v:
			return
		default:
			select {
			case <-n.status:
			default:
			}
		}
	}
}

// Status delivers connection state changes, starting with true after DialNATS.
func (n *NATS) Status() <-chan bool { return n.status }

// Close closes the connection.
func (n *NATS) Close() {
	if n == nil || n.nc == nil {
		return
	}
	n.mu.Lock()
	if n.consumer != nil {
		n.consumer.Stop()
	}
	n.mu.Unlock()
	n.nc.Close()
}

func header(h nats.Header) Header {
	out := Header{}
	for k, v := range h {
		if len(v) > 0 {
			out[k] = v[0]
		}
	}
	return out
}

func natsHeader(h Header) nats.Header {
	out := nats.Header{}
	for k, v := range h {
		out.Set(k, v)
	}
	return out
}

// Request implements Requester.
func (n *NATS) Request(ctx context.Context, subject string, h Header, data []byte, timeout time.Duration) (Msg, error) {
	if !n.nc.IsConnected() {
		return Msg{}, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	m := &nats.Msg{Subject: subject, Header: natsHeader(h), Data: data}
	reply, err := n.nc.RequestMsgWithContext(ctx, m)
	switch {
	case err == nil:
		return Msg{Subject: subject, Header: header(reply.Header), Data: reply.Data}, nil
	case errors.Is(err, nats.ErrNoResponders):
		return Msg{}, ErrNoResponders
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, nats.ErrTimeout):
		return Msg{}, ErrTimeout
	}
	return Msg{}, ErrUnavailable
}

// PublishStream implements StreamPublisher.
func (n *NATS) PublishStream(ctx context.Context, subject string, h Header, data []byte) error {
	_, err := n.js.PublishMsg(ctx, &nats.Msg{Subject: subject, Header: natsHeader(h), Data: data})
	return err
}

// ServeQueue answers requests on subject in queue group queue.
func (n *NATS) ServeQueue(ctx context.Context, subject, queue string, handle RequestHandler) error {
	_, err := n.nc.QueueSubscribe(subject, queue, func(m *nats.Msg) {
		reply := handle(ctx, Msg{Subject: m.Subject, Header: header(m.Header), Data: m.Data})
		_ = m.RespondMsg(&nats.Msg{Header: natsHeader(reply.Header), Data: reply.Data})
	})
	return err
}

// BindConsumer binds the deployment-created durable consumer and consumes it,
// replacing an earlier binding.
func (n *NATS) BindConsumer(ctx context.Context, stream, durable string, handle StreamHandler) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.consumer != nil {
		n.consumer.Stop()
		n.consumer = nil
	}
	c, err := n.js.Consumer(ctx, stream, durable)
	if err != nil {
		return err
	}
	cc, err := c.Consume(func(m jetstream.Msg) {
		switch handle(ctx, Msg{Subject: m.Subject(), Header: header(m.Headers()), Data: m.Data()}) {
		case Ack:
			_ = m.Ack()
		case Term:
			_ = m.Term()
		default:
			_ = m.Nak()
		}
	})
	if err != nil {
		return err
	}
	n.consumer = cc
	return nil
}
