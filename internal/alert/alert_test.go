package alert

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const botToken = "123456:ABCdefGHIjklMNOpqrSTUvwx-yz_0123"

func notice() Notice {
	return Notice{Kind: KindEvent, Cluster: "example.com", Reason: "Lost", Object: "node app-02", Node: "app-02",
		Message: "no report for 2m", Count: 3, Time: time.Date(2026, 11, 13, 7, 40, 0, 0, time.UTC)}
}

func TestCheck(t *testing.T) {
	t.Parallel()
	good := []Channel{
		{Name: "ops", Type: Slack},
		{Name: "tg", Type: Telegram, ChatID: "-1001234567890"},
		{Name: "tg2", Type: Telegram, ChatID: "@armada_alerts"},
		{Name: "mail", Type: Email, SMTPHost: "smtp.example.com:587", From: "a@example.com", To: []string{"b@example.com"}, Spaces: []string{"shop"}, Reasons: []string{"all"}},
	}
	for _, c := range good {
		if err := c.Check(); err != nil {
			t.Errorf("%v: %v", c, err)
		}
	}
	bad := map[string]Channel{
		"name":           {Name: "Ops!", Type: Slack},
		"type":           {Name: "x", Type: "pager"},
		"chat on slack":  {Name: "x", Type: Slack, ChatID: "1"},
		"no chat":        {Name: "x", Type: Telegram},
		"no host":        {Name: "x", Type: Email, From: "a@example.com", To: []string{"b@example.com"}},
		"header in from": {Name: "x", Type: Email, SMTPHost: "h:25", From: "a@example.com\r\nBcc: c@evil.com", To: []string{"b@example.com"}},
		"no to":          {Name: "x", Type: Email, SMTPHost: "h:25", From: "a@example.com"},
		"named to":       {Name: "x", Type: Email, SMTPHost: "h:25", From: "a@example.com", To: []string{"Bob <b@example.com>"}},
		"reason":         {Name: "x", Type: Slack, Reasons: []string{"Lost;rm"}},
		"space":          {Name: "x", Type: Slack, Spaces: []string{"Shop"}},
	}
	for name, c := range bad {
		if err := c.Check(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	secrets := map[string]struct {
		c      Channel
		secret string
		ok     bool
	}{
		"https":        {Channel{Type: Slack}, "https://hooks.slack.com/services/T/B/x", true},
		"private http": {Channel{Type: Webhook}, "http://10.0.0.5:8080/hook", true},
		"public http":  {Channel{Type: Webhook}, "http://example.com/hook", false},
		"user in url":  {Channel{Type: Webhook}, "https://u:p@example.com/hook", false},
		"no url":       {Channel{Type: Discord}, "", false},
		"bot token":    {Channel{Type: Telegram}, botToken, true},
		"bad token":    {Channel{Type: Telegram}, "nope", false},
		"no password":  {Channel{Type: Email}, "", true},
		"newline":      {Channel{Type: Email}, "a\nb", false},
	}
	for name, c := range secrets {
		err := c.c.CheckSecret([]byte(c.secret))
		if (err == nil) != c.ok {
			t.Errorf("%s: %v", name, err)
		}
		if err != nil && c.secret != "" && strings.Contains(err.Error(), c.secret) {
			t.Errorf("%s: error repeats the secret", name)
		}
	}
}

func TestWants(t *testing.T) {
	t.Parallel()
	c := Channel{}
	if !c.Wants("Lost", "") || !c.Wants("OutOfMemory", "shop") || c.Wants("Deployed", "shop") {
		t.Error("default: warnings only")
	}
	c = Channel{Spaces: []string{"shop"}, Reasons: []string{"Deployed"}}
	if !c.Wants("Deployed", "shop") || c.Wants("Deployed", "billing") || c.Wants("Lost", "") || c.Wants("Crashed", "shop") {
		t.Error("filters")
	}
	if c := (Channel{Reasons: []string{"all"}}); !c.Wants("Scheduled", "x") {
		t.Error("all")
	}
}

func TestSendHTTP(t *testing.T) {
	var mu sync.Mutex
	var path string
	var body map[string]any
	answer := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		path = r.URL.Path
		body = nil
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.WriteHeader(answer)
		_, _ = io.WriteString(w, "nope "+botToken)
	}))
	defer srv.Close()
	ctx := context.Background()
	send := func(c Channel) error {
		t.Helper()
		return NewSender(c, nil, nil).Send(ctx, notice())
	}
	if err := send(Channel{Name: "w", Type: Webhook, Secret: []byte(srv.URL + "/hook")}); err != nil {
		t.Fatal(err)
	}
	if body["type"] != "event" || body["reason"] != "Lost" || body["node"] != "app-02" || body["count"] != float64(3) {
		t.Errorf("webhook body %v", body)
	}
	_ = send(Channel{Name: "s", Type: Slack, Secret: []byte(srv.URL)})
	if text, _ := body["text"].(string); !strings.Contains(text, "[armada example.com] Lost: node app-02") || !strings.Contains(text, "(3 times)") {
		t.Errorf("slack text %q", text)
	}
	_ = send(Channel{Name: "d", Type: Discord, Secret: []byte(srv.URL)})
	if _, ok := body["content"].(string); !ok || body["allowed_mentions"] == nil {
		t.Errorf("discord body %v", body)
	}
	old := TelegramAPI
	TelegramAPI = srv.URL
	defer func() { TelegramAPI = old }()
	_ = send(Channel{Name: "t", Type: Telegram, ChatID: "-100", Secret: []byte(botToken)})
	if path != "/bot"+botToken+"/sendMessage" || body["chat_id"] != "-100" {
		t.Errorf("telegram %s %v", path, body)
	}
	answer = http.StatusForbidden
	err := send(Channel{Name: "t", Type: Telegram, ChatID: "-100", Secret: []byte(botToken)})
	if err == nil || !strings.Contains(err.Error(), "403") || strings.Contains(err.Error(), botToken) {
		t.Errorf("error %v", err)
	}
	answer = http.StatusFound
	if err := send(Channel{Name: "w", Type: Webhook, Secret: []byte(srv.URL)}); err == nil {
		t.Error("a redirect counted as sent")
	}
}

// smtpServer is a minimal SMTP server with no TLS, on loopback.
func smtpServer(t *testing.T) (string, func() string) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	var mu sync.Mutex
	var got strings.Builder
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				r := bufio.NewReader(c)
				reply := func(s string) { _, _ = io.WriteString(c, s+"\r\n") }
				reply("220 test")
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					mu.Lock()
					got.WriteString(line)
					mu.Unlock()
					switch cmd := strings.ToUpper(strings.TrimSpace(line)); {
					case strings.HasPrefix(cmd, "EHLO"):
						reply("250-test")
						reply("250 8BITMIME")
					case cmd == "DATA":
						reply("354 go")
						for {
							l, err := r.ReadString('\n')
							if err != nil {
								return
							}
							mu.Lock()
							got.WriteString(l)
							mu.Unlock()
							if l == ".\r\n" {
								break
							}
						}
						reply("250 queued")
					case cmd == "QUIT":
						reply("221 bye")
						return
					default:
						reply("250 ok")
					}
				}
			}()
		}
	}()
	return l.Addr().String(), func() string {
		mu.Lock()
		defer mu.Unlock()
		return got.String()
	}
}

func TestSendEmail(t *testing.T) {
	t.Parallel()
	addr, got := smtpServer(t)
	n := notice()
	n.Object = "node app-02\r\nBcc: evil@example.com"
	c := Channel{Name: "m", Type: Email, SMTPHost: addr, From: "alerts@example.com", To: []string{"ops@example.com", "cto@example.com"}}
	if err := NewSender(c, nil, nil).Send(context.Background(), n); err != nil {
		t.Fatal(err)
	}
	s := got()
	for _, want := range []string{"MAIL FROM:<alerts@example.com>", "RCPT TO:<ops@example.com>", "RCPT TO:<cto@example.com>",
		"Subject: [armada example.com] Lost: node app-02  Bcc: evil@example.com\r\n", "no report for 2m"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in\n%s", want, s)
		}
	}
	if strings.Contains(s, "\r\nBcc:") {
		t.Errorf("a header was added:\n%s", s)
	}
	// A password never goes over a connection without TLS.
	c.SMTPUser, c.Secret = "u", []byte("pw")
	if err := NewSender(c, nil, nil).Send(context.Background(), n); err == nil || !strings.Contains(err.Error(), "without TLS") {
		t.Errorf("password without TLS: %v", err)
	}
	// Plain SMTP only to private addresses.
	c = Channel{Name: "m", Type: Email, SMTPHost: "mail.invalid:25", From: "a@example.com", To: []string{"b@example.com"}}
	s2 := NewSender(c, nil, nil)
	s2.dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	if err := s2.Send(context.Background(), n); err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Errorf("public host without STARTTLS: %v", err)
	}
}
