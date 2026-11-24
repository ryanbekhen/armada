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
	// errVhost: the broker took the credentials but refused to open the
	// URL's virtual host (no access, or a connection limit).
	errVhost = errors.New("the broker refused the URL's virtual host")
	// errMechanism: the URL's auth_mechanism names one no reader knows.
	errMechanism = errors.New("the URL names an authentication mechanism other than PLAIN, AMQPLAIN, or EXTERNAL")
	// errNoMechanism: the broker offers none of the URL's mechanisms.
	errNoMechanism = errors.New("the broker offers none of the URL's authentication mechanisms")
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
	if args := redisAuth(u.User); args != nil {
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

// redisAuth is the AUTH command a Redis URL's user info asks for, or nil:
// redis://:password@host authenticates as the default user,
// redis://user:password@host as user (ACLs), and redis://user@host as user
// with an empty password, as the command-line client and the common client
// libraries do for a user given alone (an ACL user marked nopass takes any
// password; any other is refused, rather than reading the list as the
// default user).
func redisAuth(u *url.Userinfo) []string {
	if u == nil {
		return nil
	}
	name := u.Username()
	if pass, ok := u.Password(); ok {
		if name == "" {
			return []string{"AUTH", pass}
		}
		return []string{"AUTH", name, pass}
	}
	if name != "" {
		return []string{"AUTH", name, ""}
	}
	return nil
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
		uri, _, err := rabbitURI(rawURL)
		if err != nil {
			return "", "", err
		}
		return uri.Host, strconv.Itoa(uri.Port), nil
	}
	return "", "", errURL
}

// ErrUnreachable is the reading's error for a broker it cannot dial.
var ErrUnreachable = errDial

// errTimeout is RabbitMQQueueLength's error once its context ends.
var errTimeout = errors.New("timed out")

// Reason is err's text when it is one of the reading's own errors, which
// never hold the URL or anything the broker sent, and a fixed text
// otherwise: what a node may report to the leader about a failed reading.
func Reason(err error) string {
	if err == nil {
		return ""
	}
	for _, e := range []error{errURL, errDial, errAuth, errReply, errMissing, errTimeout, errVhost, errMechanism, errNoMechanism} {
		if errors.Is(err, e) {
			return e.Error()
		}
	}
	return "the queue could not be read"
}

// FromText returns the reading's error whose text s is (armada-node
// answers with these texts), so errors.Is finds it; another text is a new
// error.
func FromText(s string) error {
	for _, e := range []error{errURL, errDial, errAuth, errReply, errMissing, errTimeout, errVhost, errMechanism, errNoMechanism} {
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
	uri, sasl, err := rabbitURI(rawURL)
	if err != nil {
		return 0, err
	}
	cfg := amqp.Config{
		SASL: sasl,
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
			done <- result{err: dialError(err)}
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

// rabbitURI reads a RabbitMQ URL as amqp.ParseURI does, except where
// ParseURI reads it wrongly: a URL with no host is not valid (ParseURI
// dials localhost, the replica itself), and a user without a password logs
// in with an empty password (ParseURI keeps the default "guest", a
// password the URL never named). It returns the SASL mechanisms to offer,
// in the URL's order; an unknown auth_mechanism is errMechanism.
func rabbitURI(rawURL string) (amqp.URI, []amqp.Authentication, error) {
	uri, err := amqp.ParseURI(rawURL)
	if err != nil {
		return amqp.URI{}, nil, errURL
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		return amqp.URI{}, nil, errURL
	}
	if u.User != nil {
		if _, ok := u.User.Password(); !ok {
			uri.Password = ""
		}
	}
	plain := &amqp.PlainAuth{Username: uri.Username, Password: uri.Password}
	if uri.AuthMechanism == nil {
		return uri, []amqp.Authentication{plain}, nil
	}
	var sasl []amqp.Authentication
	for _, m := range uri.AuthMechanism {
		switch strings.ToUpper(m) {
		case "PLAIN":
			sasl = append(sasl, plain)
		case "AMQPLAIN":
			sasl = append(sasl, &amqp.AMQPlainAuth{Username: uri.Username, Password: uri.Password})
		case "EXTERNAL":
			sasl = append(sasl, &amqp.ExternalAuth{})
		default:
			return amqp.URI{}, nil, errMechanism
		}
	}
	return uri, sasl, nil
}

// dialError is the reading's error for amqp.DialConfig's: refused
// credentials, no shared mechanism, a refused virtual host (RabbitMQ
// closes Connection.Open with 530 NOT_ALLOWED; amqp091-go reports a
// hang-up there as ErrVhost), or a broker it could not reach or talk to.
func dialError(err error) error {
	var ae *amqp.Error
	switch {
	case errors.Is(err, amqp.ErrSASL):
		return errNoMechanism
	case errors.Is(err, amqp.ErrVhost), errors.As(err, &ae) && ae.Server && ae.Code == amqp.NotAllowed:
		return errVhost
	case errors.As(err, &ae) && ae.Code == amqp.AccessRefused:
		return errAuth
	}
	return errDial
}

// Timeout is how long one reading may take.
const Timeout = 10 * time.Second
