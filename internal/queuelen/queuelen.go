// Package queuelen reads the length of a Redis list or a RabbitMQ queue for
// queue autoscaling rules (ADR 0034). The connection is made through a dialer
// the caller provides: the agent dials from inside a replica's network
// namespace, so a rule reaches nothing its app could not reach itself.
//
// URLs carry passwords. Errors never include the URL, the password, or
// anything the broker sent back.
package queuelen

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
)

// Dialer opens a connection; address is host:port, the host possibly a name.
type Dialer func(ctx context.Context, network, address string) (net.Conn, error)

// MaxLength bounds a length a broker reports.
const MaxLength = 1 << 40

// maxReplyLine bounds one line of a Redis reply.
const maxReplyLine = 512

var (
	errURL     = errors.New("the URL in the secret is not valid for this rule")
	errDial    = errors.New("cannot reach the broker from the replica")
	errAuth    = errors.New("the broker refused the URL's credentials")
	errReply   = errors.New("the broker answered something unexpected")
	errMissing = errors.New("the queue does not exist")
)

// RedisListLength returns LLEN of list on the server rawURL names:
// redis://[user[:password]@]host[:port][/db], or rediss:// for TLS.
func RedisListLength(ctx context.Context, dial Dialer, rawURL, list string) (int64, error) {
	u, db, port, err := redisURL(rawURL)
	if err != nil {
		return 0, err
	}
	conn, err := dial(ctx, "tcp", net.JoinHostPort(u.Hostname(), port))
	if err != nil {
		return 0, errDial
	}
	defer conn.Close()
	if d, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(d)
	}
	if u.Scheme == "rediss" {
		tc := tls.Client(conn, &tls.Config{ServerName: u.Hostname(), MinVersion: tls.VersionTLS12})
		if err := tc.HandshakeContext(ctx); err != nil {
			return 0, errDial
		}
		conn = tc
	}
	r := bufio.NewReaderSize(conn, maxReplyLine)
	call := func(args ...string) (byte, string, error) {
		var b strings.Builder
		fmt.Fprintf(&b, "*%d\r\n", len(args))
		for _, a := range args {
			fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(a), a)
		}
		if _, err := io.WriteString(conn, b.String()); err != nil {
			return 0, "", errDial
		}
		return readReply(r)
	}
	// redis://:password@host authenticates as the default user,
	// redis://user:password@host as user (ACLs).
	if pass, ok := u.User.Password(); ok {
		args := []string{"AUTH", pass}
		if name := u.User.Username(); name != "" {
			args = []string{"AUTH", name, pass}
		}
		if kind, _, err := call(args...); err != nil || kind != '+' {
			return 0, errAuth
		}
	}
	if db != 0 {
		if kind, _, err := call("SELECT", strconv.Itoa(db)); err != nil || kind != '+' {
			return 0, errReply
		}
	}
	kind, v, err := call("LLEN", list)
	if err != nil {
		return 0, err
	}
	if kind != ':' {
		return 0, errReply // an error reply: the key holds another type, or ACLs refuse it
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 0 || n > MaxLength {
		return 0, errReply
	}
	return n, nil
}

// redisURL checks a Redis URL as RedisListLength does before dialling:
// the URL, its database, and the port it dials.
func redisURL(rawURL string) (*url.URL, int, string, error) {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "redis" && u.Scheme != "rediss") || u.Hostname() == "" || u.Opaque != "" {
		return nil, 0, "", errURL
	}
	db := 0
	if p := strings.TrimPrefix(u.Path, "/"); p != "" {
		if db, err = strconv.Atoi(p); err != nil || db < 0 || db > 1<<16 {
			return nil, 0, "", errURL
		}
	}
	port := u.Port()
	if port == "" {
		port = "6379"
	}
	return u, db, port, nil
}

// Broker returns the host and port the reading of kind ("redis" or
// "rabbitmq") dials for rawURL, so a caller can resolve a name before
// handing the reading to armada-node (ADR 0054 step 5). Its error is the
// one the reading gives for the URL.
func Broker(kind, rawURL string) (host, port string, err error) {
	switch kind {
	case "redis":
		u, _, port, err := redisURL(rawURL)
		if err != nil {
			return "", "", err
		}
		return u.Hostname(), port, nil
	case "rabbitmq":
		uri, err := amqp.ParseURI(rawURL)
		if err != nil {
			return "", "", errURL
		}
		return uri.Host, strconv.Itoa(uri.Port), nil
	}
	return "", "", errURL
}

// ErrUnreachable is the reading's error for a broker it cannot dial.
var ErrUnreachable = errDial

// errTimeout is RabbitMQQueueLength's error once its context ends.
var errTimeout = errors.New("timed out")

// FromText returns the reading's error whose text s is (armada-node
// answers with these texts), so errors.Is finds it; another text is a new
// error.
func FromText(s string) error {
	for _, e := range []error{errURL, errDial, errAuth, errReply, errMissing, errTimeout} {
		if e.Error() == s {
			return e
		}
	}
	return errors.New(s)
}

// readReply reads one simple reply (+, -, :) and skips nothing else: the
// commands used here answer with one line.
func readReply(r *bufio.Reader) (byte, string, error) {
	line, err := r.ReadSlice('\n')
	if err != nil || len(line) < 3 || line[len(line)-2] != '\r' {
		return 0, "", errReply
	}
	switch line[0] {
	case '+', '-', ':':
		return line[0], string(line[1 : len(line)-2]), nil
	}
	return 0, "", errReply
}

// RabbitMQQueueLength returns the messages ready in queue on the broker
// rawURL names: amqp://user:password@host[:port]/[vhost], or amqps://.
func RabbitMQQueueLength(ctx context.Context, dial Dialer, rawURL, queue string) (int64, error) {
	uri, err := amqp.ParseURI(rawURL)
	if err != nil {
		return 0, errURL
	}
	cfg := amqp.Config{
		Dial: func(network, addr string) (net.Conn, error) {
			c, err := dial(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			if d, ok := ctx.Deadline(); ok {
				_ = c.SetDeadline(d)
			}
			return c, nil
		},
		// Always set: without it the library would read certificate files
		// that query parameters of the URL name, on the node.
		TLSClientConfig: &tls.Config{ServerName: uri.Host, MinVersion: tls.VersionTLS12},
		Properties:      amqp.Table{"connection_name": "armada-autoscaler"},
	}
	type result struct {
		n   int64
		err error
	}
	done := make(chan result, 1)
	go func() {
		conn, err := amqp.DialConfig(rawURL, cfg)
		if err != nil {
			var ae *amqp.Error
			if errors.As(err, &ae) && ae.Code == amqp.AccessRefused {
				done <- result{err: errAuth}
				return
			}
			done <- result{err: errDial}
			return
		}
		defer conn.Close()
		ch, err := conn.Channel()
		if err != nil {
			done <- result{err: errReply}
			return
		}
		q, err := ch.QueueDeclarePassive(queue, false, false, false, false, nil)
		if err != nil {
			var ae *amqp.Error
			if errors.As(err, &ae) && ae.Code == amqp.NotFound {
				done <- result{err: errMissing}
				return
			}
			done <- result{err: errReply}
			return
		}
		done <- result{n: int64(max(0, min(q.Messages, MaxLength)))}
	}()
	select {
	case r := <-done:
		return r.n, r.err
	case <-ctx.Done():
		return 0, errTimeout
	}
}

// Timeout is how long one reading may take.
const Timeout = 10 * time.Second
