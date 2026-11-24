package supervisor

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ryanbekhen/armada/internal/queuelen"
	"github.com/ryanbekhen/armada/internal/runtime"
)

// queueStore is a store whose armada-node reads queues from the test's
// own network namespace, which needs no root (armada-node does not
// switch into the namespace it is in).
func queueStore(t *testing.T) (*Store, string) {
	t.Helper()
	n := openNative(t)
	s := &Store{Bundles: Bundles{Dir: t.TempDir()}, Shims: &Shims{Dir: t.TempDir(), Native: n}, Native: n}
	return s, fmt.Sprintf("/proc/%d/ns/net", os.Getpid())
}

// listen serves each connection with serve until the test ends.
func listen(t *testing.T, serve func(net.Conn)) string {
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
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				serve(c)
			}()
		}
	}()
	return l.Addr().String()
}

// recorder keeps what a fake broker was sent, per connection.
type recorder struct {
	mu   sync.Mutex
	seen []string
}

func (r *recorder) add(s string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen = append(r.seen, s)
}

func (r *recorder) take() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := strings.Join(r.seen, "|")
	r.seen = nil
	return s
}

// fakeRedis answers AUTH, SELECT, and LLEN like a server with the given
// users ("" is the default user) and lists (a negative length is a list of
// another type), or with reply for every command when it is set.
func fakeRedis(users map[string]string, lists map[string]int64, reply string, rec *recorder) func(net.Conn) {
	return func(c net.Conn) {
		r := bufio.NewReader(c)
		authed := users == nil
		for {
			line, err := r.ReadString('\n')
			if err != nil || len(line) < 2 {
				return
			}
			n, _ := strconv.Atoi(strings.TrimSpace(line[1:]))
			args := make([]string, n)
			for i := range args {
				_, _ = r.ReadString('\n')
				a, _ := r.ReadString('\n')
				args[i] = strings.TrimSuffix(a, "\r\n")
			}
			rec.add(strings.Join(args, " "))
			if reply != "" {
				_, _ = io.WriteString(c, reply)
				continue
			}
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
}

// readings compares armada-node's reading of each case with queuelen's.
type queueCase struct {
	name, kind, url, queue string
	// broker is the fake's address; a URL naming the broker by a name
	// gets it as its address.
	broker string
}

func compareReadings(t *testing.T, s *Store, own string, rec *recorder, cases []queueCase) {
	t.Helper()
	for _, c := range cases {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
			if c.broker != "" {
				addr = c.broker
			}
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		}
		var gn int64
		var gerr error
		if c.kind == "redis" {
			gn, gerr = queuelen.RedisListLength(ctx, dial, c.url, c.queue)
		} else {
			gn, gerr = queuelen.RabbitMQQueueLength(ctx, dial, c.url, c.queue)
		}
		goSeen := rec.take()
		q := runtime.QueueRead{Type: c.kind, URL: c.url, Name: c.queue}
		if host, _, err := queuelen.Broker(c.kind, c.url); err == nil && c.broker != "" {
			if _, err := netip.ParseAddr(host); err != nil {
				q.Addresses = []netip.AddrPort{netip.MustParseAddrPort(c.broker)}
			}
		}
		rn, handled, rerr := s.NativeQueue(ctx, "", own, "", q)
		rustSeen := rec.take()
		cancel()
		if !handled {
			t.Errorf("%s: armada-node left it to Go", c.name)
			continue
		}
		if gn != rn || errText(gerr) != errText(rerr) || goSeen != rustSeen {
			t.Errorf("%s:\nGo          %d %v, sent %q\narmada-node %d %v, sent %q", c.name, gn, gerr, goSeen, rn, rerr, rustSeen)
		}
		if gerr != nil && !errors.Is(rerr, gerr) {
			t.Errorf("%s: errors.Is(%v, %v) is false", c.name, rerr, gerr)
		}
		if strings.Contains(errText(rerr), "s3cret") {
			t.Errorf("%s: the error repeats the password: %v", c.name, rerr)
		}
	}
}

// armada-node queue redis reads a list's length as RedisListLength does:
// the same commands, lengths, and errors, the credentials never in them.
func TestArmadaNodeQueueRedisMatchesGo(t *testing.T) {
	s, own := queueStore(t)
	rec := &recorder{}
	lists := map[string]int64{"mail:outbox": 340, "a hash": -1, "big": 1 << 41}
	open := listen(t, fakeRedis(nil, lists, "", rec))
	// "reader" stands for an ACL user marked nopass, which takes the empty
	// password a URL with a user alone sends.
	secured := listen(t, fakeRedis(map[string]string{"": "s3cret", "worker": "w-pass", "reader": ""}, lists, "", rec))
	_, openPort, _ := net.SplitHostPort(open)
	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	refused := closed.Addr().String()
	_ = closed.Close()
	long := listen(t, func(c net.Conn) {
		_, _ = c.Write([]byte(":" + strings.Repeat("9", 4096) + "\r\n"))
		time.Sleep(time.Second)
	})
	hangUp := listen(t, func(net.Conn) {})
	replies := func(reply string) string { return listen(t, fakeRedis(nil, nil, reply, rec)) }
	cases := []queueCase{
		{"open by address", "redis", "redis://" + open, "mail:outbox", ""},
		{"open by name", "redis", "redis://redis-01:6379", "mail:outbox", open},
		{"missing list", "redis", "redis://redis-01", "missing", open},
		{"wrong type", "redis", "redis://redis-01/3", "a hash", open},
		{"too long", "redis", "redis://redis-01", "big", open},
		{"database 0", "redis", "redis://redis-01/0", "mail:outbox", open},
		{"database +7", "redis", "redis://redis-01/+7", "mail:outbox", open},
		{"password", "redis", "redis://:s3cret@redis-01:6379/0", "mail:outbox", secured},
		{"acl user", "redis", "redis://worker:w-pass@redis-01", "mail:outbox", secured},
		{"escaped password", "redis", "redis://worker:w%2Dpass@redis-01", "mail:outbox", secured},
		{"user without password", "redis", "redis://worker@redis-01", "mail:outbox", secured},
		{"nopass user", "redis", "redis://reader@redis-01", "mail:outbox", secured},
		{"empty user", "redis", "redis://@redis-01", "mail:outbox", open},
		{"wrong password", "redis", "redis://:wrong-s3cret@redis-01", "mail:outbox", secured},
		{"no password", "redis", "redis://redis-01", "mail:outbox", secured},
		{"empty password", "redis", "redis://:@redis-01", "mail:outbox", secured},
		{"refused", "redis", "redis://:s3cret@" + refused, "l", ""},
		{"refused by name", "redis", "redis://redis-01", "l", refused},
		{"port out of range", "redis", "redis://127.0.0.1:70000", "l", ""},
		{"long reply", "redis", "redis://redis-01", "l", long},
		{"hang up", "redis", "redis://:s3cret@redis-01", "l", hangUp},
		{"error reply", "redis", "redis://redis-01", "l", replies("-ERR no\r\n")},
		{"bulk reply", "redis", "redis://redis-01", "l", replies("$1\r\nx\r\n")},
		{"no CR", "redis", "redis://redis-01", "l", replies(":5\n")},
		{"signed", "redis", "redis://redis-01", "l", replies(":+5\r\n")},
		{"negative", "redis", "redis://redis-01", "l", replies(":-1\r\n")},
		{"spaced", "redis", "redis://redis-01", "l", replies(": 5\r\n")},
		{"auth answered with a number", "redis", "redis://:p@redis-01", "l", replies(":1\r\n")},
		{"select refused", "redis", "redis://redis-01/2", "l", replies("-ERR DB index is out of range\r\n")},
		{"TLS to a server that hangs up", "redis", "rediss://" + hangUp, "l", ""},
		{"IPv4-mapped", "redis", "redis://[::ffff:127.0.0.1]:" + openPort, "mail:outbox", ""},
	}
	for _, bad := range []string{"http://redis-01", "redis://", "redis://h/x", "redis://h/-1", "::", "redis://h/65537", "redis:h", "redis://h:x/", "redis://h%zz", "redis://[1.2.3.4]/", "redis://h/\x01", "redis://u@s@h/"} {
		cases = append(cases, queueCase{"URL " + strconv.Quote(bad), "redis", bad, "l", open})
	}
	compareReadings(t, s, own, rec, cases)
	if n := s.Native.StoodIn("queue redis"); n != 0 {
		t.Errorf("Go stood in %d times", n)
	}
}

// amqpBroker is a fake RabbitMQ: users, vhosts, and queues, and how it
// refuses.
type amqpBroker struct {
	mechanisms string
	users      map[string]string
	vhosts     map[string]bool
	queues     map[string]uint32
	// refuse: "close" answers bad credentials with Connection.Close 403
	// (what RabbitMQ does), "drop" hangs up.
	refuse string
	// vhostRefuse: "close" (530), "close403", or "drop".
	vhostRefuse string
	// start replaces Connection.Start: "close" a Connection.Close 541,
	// "garbage" HTTP, "big" a frame past 4096 bytes, "badtable" a field
	// of an unknown type, "badend" a wrong frame end.
	start                string
	channelMax, frameMax uint32
	heartbeat            uint16
	rec                  *recorder
}

func frame(typ byte, ch uint16, payload []byte) []byte {
	b := []byte{typ}
	b = binary.BigEndian.AppendUint16(b, ch)
	b = binary.BigEndian.AppendUint32(b, uint32(len(payload)))
	b = append(b, payload...)
	return append(b, 0xCE)
}

func method(class, m uint16, args ...[]byte) []byte {
	b := binary.BigEndian.AppendUint16(nil, class)
	b = binary.BigEndian.AppendUint16(b, m)
	for _, a := range args {
		b = append(b, a...)
	}
	return b
}

func shortStr(s string) []byte { return append([]byte{byte(len(s))}, s...) }
func longStr(s string) []byte {
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(s))), s...)
}
func u16(v uint16) []byte { return binary.BigEndian.AppendUint16(nil, v) }
func u32(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }

// serverProperties holds a field of every type amqp091-go reads.
func serverProperties() []byte {
	var t []byte
	field := func(k string, v ...byte) { t = append(append(t, shortStr(k)...), v...) }
	field("product", append([]byte{'S'}, longStr("RabbitMQ")...)...)
	field("t", 't', 1)
	field("b", 'b', 0xff)
	field("B", 'B', 7)
	field("s", 's', 0, 1)
	field("u", 'u', 0, 2)
	field("I", 'I', 0, 0, 0, 3)
	field("i", 'i', 0, 0, 0, 4)
	field("l", 'l', 0, 0, 0, 0, 0, 0, 0, 5)
	field("f", 'f', 0, 0, 0, 0)
	field("d", 'd', 0, 0, 0, 0, 0, 0, 0, 0)
	field("D", 'D', 2, 0, 0, 0, 9)
	field("T", 'T', 0, 0, 0, 0, 0, 0, 0, 1)
	field("x", append([]byte{'x'}, longStr("raw")...)...)
	field("V", 'V')
	field("A", append([]byte{'A'}, longStr("t\x01s\x00\x01")...)...)
	nested := append(shortStr("authentication_failure_close"), 't', 1)
	field("capabilities", append([]byte{'F'}, longStr(string(nested))...)...)
	return longStr(string(t))
}

// readFrame reads one frame, skipping heartbeats.
func readFrame(r io.Reader) (ch uint16, payload []byte, err error) {
	for {
		var head [7]byte
		if _, err := io.ReadFull(r, head[:]); err != nil {
			return 0, nil, err
		}
		payload = make([]byte, binary.BigEndian.Uint32(head[3:]))
		if _, err := io.ReadFull(r, payload); err != nil {
			return 0, nil, err
		}
		var end [1]byte
		if _, err := io.ReadFull(r, end[:]); err != nil {
			return 0, nil, err
		}
		if head[0] == 8 {
			continue
		}
		return binary.BigEndian.Uint16(head[1:]), payload, nil
	}
}

type argReader struct{ b []byte }

func (a *argReader) take(n int) []byte {
	if len(a.b) < n {
		a.b = nil
		return make([]byte, n)
	}
	v := a.b[:n]
	a.b = a.b[n:]
	return v
}
func (a *argReader) u16() uint16 { return binary.BigEndian.Uint16(a.take(2)) }
func (a *argReader) u32() uint32 { return binary.BigEndian.Uint32(a.take(4)) }
func (a *argReader) short() string {
	n := int(a.take(1)[0])
	return string(a.take(n))
}
func (a *argReader) long() string { return string(a.take(int(a.u32()))) }

// credentials reads a Start-Ok's response.
func credentials(mech, resp string) (string, string) {
	switch mech {
	case "PLAIN":
		parts := strings.SplitN(resp, "\x00", 3)
		if len(parts) == 3 {
			return parts[1], parts[2]
		}
	case "AMQPLAIN":
		a := &argReader{b: []byte(resp)}
		got := map[string]string{}
		for len(a.b) > 0 {
			k := a.short()
			a.take(1)
			got[k] = a.long()
		}
		return got["LOGIN"], got["PASSWORD"]
	}
	return "", ""
}

func (b *amqpBroker) serve(c net.Conn) {
	var header [8]byte
	if _, err := io.ReadFull(c, header[:]); err != nil {
		return
	}
	write := func(ch uint16, payload []byte) { _, _ = c.Write(frame(1, ch, payload)) }
	closeWith := func(code uint16, text string) {
		write(0, method(10, 50, u16(code), shortStr(text), u16(0), u16(0)))
	}
	mechs := b.mechanisms
	if mechs == "" {
		mechs = "PLAIN AMQPLAIN"
	}
	switch b.start {
	case "close":
		closeWith(541, "INTERNAL_ERROR")
		return
	case "garbage":
		_, _ = c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return
	case "big":
		write(0, method(10, 10, []byte{0, 9}, serverProperties(), longStr(mechs+strings.Repeat(" X", 3000)), longStr("en_US")))
		return
	case "badtable":
		write(0, method(10, 10, []byte{0, 9}, longStr("\x01k?"), longStr(mechs), longStr("en_US")))
		return
	case "badend":
		f := frame(1, 0, method(10, 10, []byte{0, 9}, serverProperties(), longStr(mechs), longStr("en_US")))
		f[len(f)-1] = 0
		_, _ = c.Write(f)
		return
	}
	write(0, method(10, 10, []byte{0, 9}, serverProperties(), longStr(mechs), longStr("en_US")))
	_, p, err := readFrame(c)
	if err != nil {
		return
	}
	a := &argReader{b: p[4:]}
	a.long() // client properties
	mech, resp := a.short(), a.long()
	user, pass := credentials(mech, resp)
	b.rec.add("start-ok " + mech + " " + user + ":" + pass + " " + a.short())
	if want, ok := b.users[user]; !ok || want != pass {
		if b.refuse == "close" {
			closeWith(403, "ACCESS_REFUSED - Login was refused")
		}
		return
	}
	write(0, method(10, 30, u16(uint16(b.channelMax)), u32(b.frameMax), u16(b.heartbeat)))
	_, p, err = readFrame(c)
	if err != nil {
		return
	}
	a = &argReader{b: p[4:]}
	b.rec.add(fmt.Sprintf("tune-ok %d %d %d", a.u16(), a.u32(), a.u16()))
	_, p, err = readFrame(c)
	if err != nil {
		return
	}
	a = &argReader{b: p[4:]}
	vhost := a.short()
	b.rec.add("open " + strconv.Quote(vhost))
	if !b.vhosts[vhost] {
		switch b.vhostRefuse {
		case "close":
			closeWith(530, "NOT_ALLOWED - access to vhost refused")
		case "close403":
			closeWith(403, "ACCESS_REFUSED")
		}
		return
	}
	write(0, method(10, 41, shortStr("")))
	ch, _, err := readFrame(c)
	if err != nil {
		return
	}
	write(ch, method(20, 11, longStr("")))
	_, p, err = readFrame(c)
	if err != nil || !bytes.Equal(p[:4], method(50, 10)) {
		// Go's client closes the connection in the background when it
		// fails to write the declare.
		return
	}
	a = &argReader{b: p[4:]}
	a.u16()
	queue := a.short()
	bits := a.take(1)[0]
	b.rec.add(fmt.Sprintf("declare %d %q %d", ch, queue, bits))
	n, ok := b.queues[queue]
	if !ok {
		write(ch, method(20, 40, u16(404), shortStr("NOT_FOUND - no queue"), u16(50), u16(10)))
		_, _, _ = readFrame(c)
		return
	}
	write(ch, method(50, 11, shortStr(queue), u32(n), u32(0)))
	// Close, then Close-Ok.
	if _, p, err := readFrame(c); err == nil && bytes.Equal(p[:4], method(10, 50)) {
		write(0, method(10, 51))
	}
}

// armada-node queue rabbitmq reads a queue's length as
// RabbitMQQueueLength does with amqp091-go: the same handshake as the
// broker sees it (mechanism, credentials, locale, negotiated limits,
// vhost, a passive declare on channel 1), lengths, and errors.
func TestArmadaNodeQueueRabbitMQMatchesGo(t *testing.T) {
	s, own := queueStore(t)
	rec := &recorder{}
	broker := func(mod func(*amqpBroker)) string {
		b := &amqpBroker{
			users:  map[string]string{"guest": "guest", "worker": "s3cret", "bob": "guest", "carol": ""},
			vhosts: map[string]bool{"/": true, "prod": true, "/prod": true},
			queues: map[string]uint32{"jobs": 42, "empty": 0, "huge": 1<<32 - 1},
			refuse: "close", vhostRefuse: "close",
			frameMax: 131072, heartbeat: 60, rec: rec,
		}
		if mod != nil {
			mod(b)
		}
		return listen(t, b.serve)
	}
	plain := broker(nil)
	_, plainPort, _ := net.SplitHostPort(plain)
	cases := []queueCase{
		{"jobs", "rabbitmq", "amqp://worker:s3cret@mq/", "jobs", plain},
		{"by address", "rabbitmq", "amqp://worker:s3cret@127.0.0.1:" + plainPort + "/", "jobs", ""},
		{"default credentials", "rabbitmq", "amqp://mq", "empty", plain},
		// A user alone logs in with an empty password, never "guest".
		{"user without password", "rabbitmq", "amqp://bob@mq", "jobs", plain},
		{"user with an empty password", "rabbitmq", "amqp://carol@mq", "jobs", plain},
		{"vhost", "rabbitmq", "amqp://worker:s3cret@mq/prod", "jobs", plain},
		{"escaped vhost", "rabbitmq", "amqp://worker:s3cret@mq/%2Fprod", "jobs", plain},
		{"huge", "rabbitmq", "amqp://worker:s3cret@mq/", "huge", plain},
		{"missing queue", "rabbitmq", "amqp://worker:s3cret@mq/", "nope", plain},
		{"long queue name", "rabbitmq", "amqp://worker:s3cret@mq/", strings.Repeat("q", 300), plain},
		{"wrong password", "rabbitmq", "amqp://worker:wrong-s3cret@mq/", "jobs", plain},
		{"vhost refused", "rabbitmq", "amqp://worker:s3cret@mq/other", "jobs", plain},
		{"amqplain", "rabbitmq", "amqp://worker:s3cret@mq/?auth_mechanism=amqplain", "jobs", plain},
		{"mechanisms in order", "rabbitmq", "amqp://worker:s3cret@mq/?auth_mechanism=EXTERNAL&auth_mechanism=PLAIN", "jobs", plain},
		{"unknown mechanism", "rabbitmq", "amqp://worker:s3cret@mq/?auth_mechanism=CRAM", "jobs", plain},
		{"limits from the URL", "rabbitmq", "amqp://worker:s3cret@mq/?heartbeat=5&channel_max=9&connection_timeout=1", "jobs", plain},
		{"no shared mechanism", "rabbitmq", "amqp://worker:s3cret@mq/", "jobs", broker(func(b *amqpBroker) { b.mechanisms = "SCRAM-SHA-256" })},
		{"dropped at credentials", "rabbitmq", "amqp://worker:bad@mq/", "jobs", broker(func(b *amqpBroker) { b.refuse = "drop" })},
		{"dropped at vhost", "rabbitmq", "amqp://worker:s3cret@mq/other", "jobs", broker(func(b *amqpBroker) { b.vhostRefuse = "drop" })},
		{"closed at start", "rabbitmq", "amqp://worker:s3cret@mq/", "jobs", broker(func(b *amqpBroker) { b.start = "close" })},
		{"not a broker", "rabbitmq", "amqp://worker:s3cret@mq/", "jobs", broker(func(b *amqpBroker) { b.start = "garbage" })},
		{"start too big", "rabbitmq", "amqp://worker:s3cret@mq/", "jobs", broker(func(b *amqpBroker) { b.start = "big" })},
		{"bad table", "rabbitmq", "amqp://worker:s3cret@mq/", "jobs", broker(func(b *amqpBroker) { b.start = "badtable" })},
		{"bad frame end", "rabbitmq", "amqp://worker:s3cret@mq/", "jobs", broker(func(b *amqpBroker) { b.start = "badend" })},
		{"small server limits", "rabbitmq", "amqp://worker:s3cret@mq/", "jobs", broker(func(b *amqpBroker) { b.channelMax, b.frameMax, b.heartbeat = 5, 1000, 0 })},
		{"zero server limits", "rabbitmq", "amqp://worker:s3cret@mq/?heartbeat=0", "jobs", broker(func(b *amqpBroker) { b.channelMax, b.frameMax, b.heartbeat = 0, 0, 0 })},
		{"TLS to a broker that hangs up", "rabbitmq", "amqps://worker:s3cret@" + listen(t, func(net.Conn) {}) + "/", "jobs", ""},
	}
	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	cases = append(cases, queueCase{"refused", "rabbitmq", "amqp://user:s3cret@mq:5672/", "q", closed.Addr().String()})
	_ = closed.Close()
	for _, bad := range []string{"amqp://", "amqp:///vhost", "amqps://u:p@:5671/", "redis://h", "amqp://h/ x", "amqp://h:99999999999/", "amqp://h/?heartbeat=x", "amqp://h/?channel_max=70000", "amqp://h/?connection_timeout=x", "amqp://h%zz/", "amqp://u@s@h/x\x7f"} {
		cases = append(cases, queueCase{"URL " + strconv.Quote(bad), "rabbitmq", bad, "q", plain})
	}
	compareReadings(t, s, own, rec, cases)
	if n := s.Native.StoodIn("queue rabbitmq"); n != 0 {
		t.Errorf("Go stood in %d times", n)
	}

	// A known difference: a broker closing Connection.Open with 403 is
	// the virtual host's refusal to armada-node, which knows the step it
	// was at; amqp091-go reports a 403 at any step alike, so queuelen
	// calls it refused credentials.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	vhost403 := broker(func(b *amqpBroker) { b.vhostRefuse = "close403" })
	_, _, err := s.NativeQueue(ctx, "", own, "", runtime.QueueRead{Type: "rabbitmq", URL: "amqp://worker:s3cret@mq/other", Name: "jobs", Addresses: []netip.AddrPort{netip.MustParseAddrPort(vhost403)}})
	if errText(err) != "the broker refused the URL's virtual host" {
		t.Errorf("vhost refused 403: %v", err)
	}
}

// A broker named by a name with no addresses, and a program that fails,
// leave the reading to Go, which counts it.
func TestNativeQueueLeftToGo(t *testing.T) {
	s, own := queueStore(t)
	ctx := context.Background()
	if _, handled, err := s.NativeQueue(ctx, "", own, "", runtime.QueueRead{Type: "redis", URL: "redis://redis-01", Name: "l"}); handled || err != nil {
		t.Errorf("a name: handled %v, %v", handled, err)
	}
	if n := s.Native.StoodIn("queue redis"); n != 1 {
		t.Errorf("stood in %d times", n)
	}
	bin := filepath.Join(t.TempDir(), "armada-node")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexit 3\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	broken := &Store{Native: &Native{Bin: bin}}
	if _, handled, _ := broken.NativeQueue(ctx, "", own, "", runtime.QueueRead{Type: "rabbitmq", URL: "amqp://h", Name: "q"}); handled {
		t.Error("a failed program's reading was handled")
	}
	if n := broken.Native.StoodIn("queue rabbitmq"); n != 1 {
		t.Errorf("stood in %d times", n)
	}
	if s := (runtime.QueueRead{Type: "redis", URL: "redis://:s3cret@h", Name: "l"}); strings.Contains(fmt.Sprint(s), "s3cret") || strings.Contains(fmt.Sprintf("%v", nativeQueue{URL: s.URL}), "s3cret") {
		t.Error("a reading prints its URL")
	}
}
