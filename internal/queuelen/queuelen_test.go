package queuelen

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeRedis answers AUTH, SELECT, and LLEN like a server with the given
// users ("" is the default user), lists, and databases.
func fakeRedis(t *testing.T, users map[string]string, lists map[string]int64, cmds *[]string) Dialer {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go serveRedis(c, users, lists, cmds)
		}
	}()
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, l.Addr().String())
	}
}

func serveRedis(c net.Conn, users map[string]string, lists map[string]int64, cmds *[]string) {
	defer c.Close()
	r := bufio.NewReader(c)
	authed := users == nil
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		n, _ := strconv.Atoi(strings.TrimSpace(line[1:]))
		args := make([]string, n)
		for i := range args {
			_, _ = r.ReadString('\n')
			a, _ := r.ReadString('\n')
			args[i] = strings.TrimSuffix(a, "\r\n")
		}
		*cmds = append(*cmds, strings.Join(args, " "))
		switch strings.ToUpper(args[0]) {
		case "AUTH":
			user, pass := "", args[len(args)-1]
			if len(args) == 3 {
				user = args[1]
			}
			if want, ok := users[user]; ok && want == pass {
				authed = true
				_, _ = c.Write([]byte("+OK\r\n"))
			} else {
				_, _ = c.Write([]byte("-WRONGPASS invalid username-password pair\r\n"))
			}
		case "SELECT":
			_, _ = c.Write([]byte("+OK\r\n"))
		case "LLEN":
			switch v, ok := lists[args[1]]; {
			case !authed:
				_, _ = c.Write([]byte("-NOAUTH Authentication required.\r\n"))
			case !ok:
				_, _ = c.Write([]byte(":0\r\n"))
			case v < 0:
				_, _ = c.Write([]byte("-WRONGTYPE Operation against a key holding the wrong kind of value\r\n"))
			default:
				fmt.Fprintf(c, ":%d\r\n", v)
			}
		}
	}
}

func TestRedisListLength(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var cmds []string
	lists := map[string]int64{"mail:outbox": 340, "a hash": -1}
	open := fakeRedis(t, nil, lists, &cmds)
	if n, err := RedisListLength(ctx, open, "redis://redis-01:6379", "mail:outbox"); err != nil || n != 340 {
		t.Errorf("open server: %d %v", n, err)
	}
	if n, err := RedisListLength(ctx, open, "redis://redis-01", "missing"); err != nil || n != 0 {
		t.Errorf("missing list: %d %v", n, err)
	}
	if _, err := RedisListLength(ctx, open, "redis://redis-01/3", "a hash"); !errors.Is(err, errReply) {
		t.Errorf("wrong type: %v", err)
	}
	if want := "SELECT 3"; !strings.Contains(strings.Join(cmds, "|"), want) {
		t.Errorf("commands %v lack %q", cmds, want)
	}

	cmds = nil
	secured := fakeRedis(t, map[string]string{"": "s3cret", "worker": "w-pass", "reader": ""}, lists, &cmds)
	if n, err := RedisListLength(ctx, secured, "redis://:s3cret@redis-01:6379/0", "mail:outbox"); err != nil || n != 340 {
		t.Errorf("password: %d %v", n, err)
	}
	if n, err := RedisListLength(ctx, secured, "redis://worker:w-pass@redis-01", "mail:outbox"); err != nil || n != 340 {
		t.Errorf("acl user: %d %v", n, err)
	}
	if _, err := RedisListLength(ctx, secured, "redis://:wrong-s3cret@redis-01", "mail:outbox"); !errors.Is(err, errAuth) || strings.Contains(err.Error(), "s3cret") {
		t.Errorf("wrong password: %v", err)
	}
	if _, err := RedisListLength(ctx, secured, "redis://redis-01", "mail:outbox"); !errors.Is(err, errReply) {
		t.Errorf("no password: %v", err)
	}
	// A user alone authenticates as that user with an empty password: a
	// nopass user reads, any other is refused, and neither reads as the
	// default user.
	cmds = nil
	if n, err := RedisListLength(ctx, secured, "redis://reader@redis-01", "mail:outbox"); err != nil || n != 340 {
		t.Errorf("nopass user: %d %v", n, err)
	}
	if _, err := RedisListLength(ctx, secured, "redis://worker@redis-01", "mail:outbox"); !errors.Is(err, errAuth) {
		t.Errorf("user without password: %v", err)
	}
	if got := strings.Join(cmds, "|"); got != "AUTH reader |LLEN mail:outbox|AUTH worker " {
		t.Errorf("commands %q", got)
	}

	for _, bad := range []string{"http://redis-01", "redis://", "redis://h/x", "redis://h/-1", "::"} {
		if _, err := RedisListLength(ctx, open, bad, "l"); !errors.Is(err, errURL) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	refuse := func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("dial tcp 10.0.0.1: s3cret")
	}
	if _, err := RedisListLength(ctx, refuse, "redis://:s3cret@redis-01", "l"); !errors.Is(err, errDial) || strings.Contains(err.Error(), "s3cret") {
		t.Errorf("unreachable: %v", err)
	}
}

// A reply line past the bound is refused, not read without end.
func TestRedisLongReply(t *testing.T) {
	t.Parallel()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = c.Write([]byte(":" + strings.Repeat("9", 4096) + "\r\n"))
		time.Sleep(time.Second)
	}()
	dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, l.Addr().String())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := RedisListLength(ctx, dial, "redis://h", "l"); !errors.Is(err, errReply) {
		t.Errorf("long reply: %v", err)
	}
}

func TestRabbitMQErrors(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	refuse := func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("refused") }
	if _, err := RabbitMQQueueLength(ctx, refuse, "redis://h", "q"); !errors.Is(err, errURL) {
		t.Errorf("bad scheme: %v", err)
	}
	if _, err := RabbitMQQueueLength(ctx, refuse, "amqp://user:s3cret@mq:5672/", "q"); !errors.Is(err, errDial) || strings.Contains(err.Error(), "s3cret") {
		t.Errorf("unreachable: %v", err)
	}
	// No host is not localhost; an unknown mechanism is the URL's mistake,
	// found before dialling.
	for _, bad := range []string{"amqp://", "amqp:///vhost", "amqps://u:p@:5671/"} {
		if _, err := RabbitMQQueueLength(ctx, refuse, bad, "q"); !errors.Is(err, errURL) {
			t.Errorf("%q: %v", bad, err)
		}
		if _, _, err := Broker("rabbitmq", bad); !errors.Is(err, errURL) {
			t.Errorf("Broker(%q): %v", bad, err)
		}
	}
	if _, err := RabbitMQQueueLength(ctx, refuse, "amqp://u:p@mq/?auth_mechanism=CRAM", "q"); !errors.Is(err, errMechanism) {
		t.Errorf("unknown mechanism: %v", err)
	}
	// A server that is not RabbitMQ.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		_, _ = c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		_ = c.Close()
	}()
	dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, l.Addr().String())
	}
	if _, err := RabbitMQQueueLength(ctx, dial, "amqp://user:s3cret@mq/", "q"); err == nil || strings.Contains(err.Error(), "s3cret") {
		t.Errorf("not a broker: %v", err)
	}
}

// A user without a password logs in with an empty one, never "guest".
func TestRabbitURI(t *testing.T) {
	t.Parallel()
	for raw, want := range map[string]string{
		"amqp://mq":             "guest:guest",
		"amqp://bob@mq":         "bob:",
		"amqp://bob:@mq":        "bob:",
		"amqp://bob:pw@mq/prod": "bob:pw",
	} {
		uri, sasl, err := rabbitURI(raw)
		if err != nil || len(sasl) != 1 {
			t.Fatalf("%q: %v %v", raw, sasl, err)
		}
		p := sasl[0].(interface{ Response() string }).Response()
		if got := uri.Username + ":" + uri.Password; got != want || p != "\x00"+strings.Replace(want, ":", "\x00", 1) {
			t.Errorf("%q: %q, response %q", raw, got, p)
		}
	}
}

// Reason passes the reading's own texts and hides anything else.
func TestReason(t *testing.T) {
	t.Parallel()
	if got := Reason(fmt.Errorf("wrapped: %w", errVhost)); got != errVhost.Error() {
		t.Errorf("vhost: %q", got)
	}
	if got := Reason(FromText(errMechanism.Error())); got != errMechanism.Error() {
		t.Errorf("mechanism: %q", got)
	}
	if got := Reason(errors.New("dial amqp://u:s3cret@h")); strings.Contains(got, "s3cret") {
		t.Errorf("other: %q", got)
	}
	if Reason(nil) != "" {
		t.Error("nil")
	}
}
