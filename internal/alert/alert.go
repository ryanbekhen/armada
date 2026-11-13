// Package alert sends notices about cluster events to people (ADR 0045):
// a JSON webhook, Slack, Discord, Telegram, or email over SMTP.
package alert

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/mail"
	"net/netip"
	"net/smtp"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Channel types.
const (
	Webhook  = "webhook"
	Slack    = "slack"
	Discord  = "discord"
	Telegram = "telegram"
	Email    = "email"
)

// Types lists the channel types.
var Types = []string{Webhook, Slack, Discord, Telegram, Email}

const (
	// MaxChannels bounds the channels of a cluster.
	MaxChannels = 32
	// MaxSecret bounds a URL, token, or password.
	MaxSecret     = 4096
	maxRecipients = 10
	maxFilters    = 64
	sendTimeout   = 30 * time.Second
	maxReply      = 256
	discordMax    = 2000
	telegramMax   = 4096
)

// TelegramAPI is the Bot API's address; tests replace it.
var TelegramAPI = "https://api.telegram.org"

var (
	validName   = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$`)
	validChatID = regexp.MustCompile(`^(-?[0-9]{1,20}|@[A-Za-z][A-Za-z0-9_]{4,31})$`)
	validReason = regexp.MustCompile(`^[A-Za-z]{1,64}$`)
	validSpace  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,28}[a-z0-9])?$`)
	validBotKey = regexp.MustCompile(`^[0-9]{1,20}:[A-Za-z0-9_-]{20,200}$`)
)

// Channel is where notices go. Secret is the URL (webhook, slack,
// discord), the bot token (telegram), or the SMTP password (email); it is
// never logged or shown.
type Channel struct {
	Name     string   `json:"name"`
	Type     string   `json:"type"`
	ChatID   string   `json:"chatId,omitempty"`
	SMTPHost string   `json:"smtpHost,omitempty"`
	SMTPUser string   `json:"smtpUser,omitempty"`
	From     string   `json:"from,omitempty"`
	To       []string `json:"to,omitempty"`
	// Spaces limits notices to events of these spaces' apps; empty means
	// every event. Reasons replaces the default (warnings only); "all"
	// means every reason.
	Spaces  []string `json:"spaces,omitempty"`
	Reasons []string `json:"reasons,omitempty"`
	Secret  []byte   `json:"-"`
}

// String leaves the secret out.
func (c Channel) String() string { return c.Name + " (" + c.Type + ")" }

// NeedsSecret reports whether the type cannot work without one.
func (c Channel) NeedsSecret() bool { return c.Type != Email }

// CheckName validates a channel name.
func CheckName(n string) error {
	if !validName.MatchString(n) {
		return fmt.Errorf("invalid channel name %q: lower case letters, digits, and dashes, at most 32", n)
	}
	return nil
}

// Check validates everything but the secret's presence.
func (c Channel) Check() error {
	if err := CheckName(c.Name); err != nil {
		return err
	}
	if !slices.Contains(Types, c.Type) {
		return fmt.Errorf("unknown channel type %q (want %s)", c.Type, strings.Join(Types, ", "))
	}
	if c.Type != Telegram && c.ChatID != "" {
		return errors.New("--chat-id is only for telegram")
	}
	if c.Type != Email && (c.SMTPHost != "" || c.SMTPUser != "" || c.From != "" || len(c.To) > 0) {
		return errors.New("--smtp-host, --smtp-user, --from, and --to are only for email")
	}
	switch c.Type {
	case Telegram:
		if !validChatID.MatchString(c.ChatID) {
			return errors.New("telegram needs --chat-id: a chat ID such as -1001234567890, or @channelname")
		}
	case Email:
		if err := CheckSMTPHost(c.SMTPHost); err != nil {
			return err
		}
		if err := checkPrintable("SMTP user", c.SMTPUser, 254); err != nil {
			return err
		}
		if err := CheckAddress(c.From); err != nil {
			return fmt.Errorf("--from: %w", err)
		}
		if len(c.To) == 0 || len(c.To) > maxRecipients {
			return fmt.Errorf("email needs --to: 1 to %d addresses", maxRecipients)
		}
		for _, a := range c.To {
			if err := CheckAddress(a); err != nil {
				return fmt.Errorf("--to: %w", err)
			}
		}
	}
	if len(c.Spaces) > maxFilters || len(c.Reasons) > maxFilters {
		return fmt.Errorf("at most %d spaces and %d reasons", maxFilters, maxFilters)
	}
	for _, s := range c.Spaces {
		if !validSpace.MatchString(s) {
			return fmt.Errorf("invalid space %q", s)
		}
	}
	for _, r := range c.Reasons {
		if !validReason.MatchString(r) {
			return fmt.Errorf("invalid reason %q", r)
		}
	}
	return nil
}

// CheckSecret validates the secret for the channel's type. Errors never
// repeat it.
func (c Channel) CheckSecret(secret []byte) error {
	if len(secret) > MaxSecret {
		return fmt.Errorf("secret is longer than %d bytes", MaxSecret)
	}
	if !utf8.Valid(secret) || bytes.ContainsFunc(secret, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return errors.New("secret must be one line of printable characters")
	}
	if len(secret) == 0 {
		if c.NeedsSecret() {
			return fmt.Errorf("%s needs %s from a file or stdin (--%s -)", c.Type, secretWhat(c.Type), SecretFlag(c.Type))
		}
		return nil
	}
	switch c.Type {
	case Webhook, Slack, Discord:
		return CheckURL(string(secret))
	case Telegram:
		if !validBotKey.Match(secret) {
			return errors.New("telegram bot token must look like 123456:ABC-DEF")
		}
	}
	return nil
}

func secretWhat(t string) string {
	switch t {
	case Telegram:
		return "a bot token"
	case Email:
		return "a password"
	}
	return "a URL"
}

// SecretFlag is the CLI flag that reads the type's secret.
func SecretFlag(t string) string {
	switch t {
	case Telegram:
		return "token"
	case Email:
		return "password"
	}
	return "url"
}

// CheckURL accepts https://, or http:// to a private or loopback IP.
func CheckURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Opaque != "" || u.User != nil {
		return errors.New("channel URL must be https://host/path, with no user and password in it")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if ip, err := netip.ParseAddr(u.Hostname()); err == nil && (ip.IsPrivate() || ip.IsLoopback()) {
			return nil
		}
		return errors.New("http:// channel URLs are only allowed for a private IP address; use https://")
	}
	return errors.New("channel URL must start with https://")
}

// CheckSMTPHost accepts host:port; port 465 is TLS, any other needs
// STARTTLS unless the host is a private IP address.
func CheckSMTPHost(hp string) error {
	host, port, err := net.SplitHostPort(hp)
	if err != nil || host == "" {
		return errors.New("--smtp-host must be host:port, such as smtp.example.com:587")
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return errors.New("--smtp-host has an invalid port")
	}
	if strings.ContainsAny(host, " /\\@") || len(host) > 253 {
		return errors.New("--smtp-host has an invalid host")
	}
	return nil
}

// CheckAddress accepts one plain email address.
func CheckAddress(a string) error {
	p, err := mail.ParseAddress(a)
	if err != nil || p.Address != a || strings.ContainsAny(a, "\r\n<>,;") || len(a) > 254 {
		return fmt.Errorf("invalid email address %q", a)
	}
	return nil
}

func checkPrintable(what, v string, max int) error {
	if len(v) > max {
		return fmt.Errorf("%s is too long", what)
	}
	for _, r := range v {
		if r < 0x21 || r == 0x7f {
			return fmt.Errorf("%s must be printable, with no spaces", what)
		}
	}
	return nil
}

// Notice is one thing to tell people.
type Notice struct {
	// Kind is event, resolved, test, or summary.
	Kind    string    `json:"type"`
	Cluster string    `json:"cluster,omitempty"`
	Reason  string    `json:"reason,omitempty"`
	Object  string    `json:"object,omitempty"` // e.g. node/app-02
	Space   string    `json:"space,omitempty"`
	App     string    `json:"app,omitempty"`
	Node    string    `json:"node,omitempty"`
	Message string    `json:"message,omitempty"`
	Count   int       `json:"count,omitempty"`
	Time    time.Time `json:"time"`
}

// Notice kinds.
const (
	KindEvent    = "event"
	KindResolved = "resolved"
	KindTest     = "test"
	KindSummary  = "summary"
)

// Title is one line for subjects and headings.
func (n Notice) Title() string { return oneLine(n.title()) }

func (n Notice) title() string {
	prefix := "[armada"
	if n.Cluster != "" {
		prefix += " " + n.Cluster
	}
	prefix += "] "
	switch n.Kind {
	case KindResolved:
		return prefix + "Resolved: " + n.Reason + ": " + n.Object
	case KindTest:
		return prefix + "Test notice"
	case KindSummary:
		return prefix + n.Message
	}
	return prefix + n.Reason + ": " + n.Object
}

// Text is the whole notice as plain text.
func (n Notice) Text() string {
	var b strings.Builder
	switch n.Kind {
	case KindResolved:
		b.WriteString("✅ ")
	case KindEvent:
		b.WriteString("⚠️ ")
	}
	b.WriteString(n.Title())
	if n.Message != "" && n.Kind != KindSummary {
		b.WriteString("\n" + n.Message)
	}
	var where []string
	for _, kv := range [][2]string{{"space", n.Space}, {"app", n.App}, {"node", n.Node}} {
		if kv[1] != "" {
			where = append(where, kv[0]+": "+kv[1])
		}
	}
	if len(where) > 0 {
		b.WriteString("\n" + strings.Join(where, " · "))
	}
	b.WriteString("\n" + n.Time.UTC().Format("2006-01-02 15:04:05 UTC"))
	if n.Count > 1 {
		fmt.Fprintf(&b, " (%d times)", n.Count)
	}
	return b.String()
}

// Sender delivers notices to one channel.
type Sender struct {
	c    Channel
	http *http.Client
	// dial opens SMTP connections; tests replace it.
	dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// tlsConfig is for SMTP; tests trust their own CA.
	tlsConfig *tls.Config
}

// NewSender returns a sender for c, which must be valid.
func NewSender(c Channel, hc *http.Client, tlsConfig *tls.Config) *Sender {
	if hc == nil {
		hc = &http.Client{Timeout: sendTimeout, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse // a redirect could take the secret elsewhere
		}}
	}
	d := &net.Dialer{Timeout: sendTimeout}
	return &Sender{c: c, http: hc, dial: d.DialContext, tlsConfig: tlsConfig}
}

// Send delivers n. Errors never carry the secret.
func (s *Sender) Send(ctx context.Context, n Notice) error {
	ctx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()
	var err error
	switch s.c.Type {
	case Webhook:
		err = s.post(ctx, string(s.c.Secret), n)
	case Slack:
		err = s.post(ctx, string(s.c.Secret), map[string]string{"text": n.Text()})
	case Discord:
		err = s.post(ctx, string(s.c.Secret), map[string]any{"content": cut(n.Text(), discordMax), "allowed_mentions": map[string]any{"parse": []string{}}})
	case Telegram:
		err = s.post(ctx, TelegramAPI+"/bot"+string(s.c.Secret)+"/sendMessage",
			map[string]any{"chat_id": s.c.ChatID, "text": cut(n.Text(), telegramMax), "disable_web_page_preview": true})
	case Email:
		err = s.mail(ctx, n)
	default:
		err = fmt.Errorf("unknown channel type %q", s.c.Type)
	}
	if err != nil {
		return errors.New(clean(err.Error(), s.c.Secret))
	}
	return nil
}

func (s *Sender) post(ctx context.Context, target string, body any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(b))
	if err != nil {
		return errors.New("invalid channel URL")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "armada")
	resp, err := s.http.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // the URL holds the secret
		}
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	reply, _ := io.ReadAll(io.LimitReader(resp.Body, maxReply))
	if resp.StatusCode/100 == 2 {
		return nil
	}
	msg := fmt.Sprintf("channel answered %d", resp.StatusCode)
	if r := clean(string(reply), s.c.Secret); r != "" {
		msg += ": " + r
	}
	return errors.New(msg)
}

func (s *Sender) mail(ctx context.Context, n Notice) error {
	host, port, _ := net.SplitHostPort(s.c.SMTPHost)
	conn, err := s.dial(ctx, "tcp", s.c.SMTPHost)
	if err != nil {
		return fmt.Errorf("smtp: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	tc := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	if s.tlsConfig != nil {
		tc = s.tlsConfig.Clone()
		tc.ServerName = host
	}
	encrypted := false
	if port == "465" {
		t := tls.Client(conn, tc)
		if err := t.HandshakeContext(ctx); err != nil {
			return fmt.Errorf("smtp: %w", err)
		}
		conn, encrypted = t, true
	}
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		return fmt.Errorf("smtp: %w", err)
	}
	defer func() { _ = c.Close() }()
	if !encrypted {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(tc); err != nil {
				return fmt.Errorf("smtp: %w", err)
			}
			encrypted = true
		} else if ip, err := netip.ParseAddr(host); err != nil || !ip.IsPrivate() && !ip.IsLoopback() {
			return errors.New("smtp: the server offers no STARTTLS; use port 465 or a server that does")
		}
	}
	if s.c.SMTPUser != "" {
		if !encrypted {
			return errors.New("smtp: refusing to send the password without TLS")
		}
		if err := c.Auth(smtpPlain{user: s.c.SMTPUser, pass: string(s.c.Secret)}); err != nil {
			return fmt.Errorf("smtp: %w", err)
		}
	}
	if err := c.Mail(s.c.From); err != nil {
		return fmt.Errorf("smtp: %w", err)
	}
	for _, to := range s.c.To {
		if err := c.Rcpt(to); err != nil {
			return fmt.Errorf("smtp: %w", err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp: %w", err)
	}
	if _, err := w.Write(message(s.c, n)); err != nil {
		return fmt.Errorf("smtp: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp: %w", err)
	}
	return c.Quit()
}

// smtpPlain is PLAIN authentication; the caller made sure the connection
// is encrypted (net/smtp's own refuses STARTTLS on a non-standard check of
// the server name).
type smtpPlain struct{ user, pass string }

func (a smtpPlain) Start(*smtp.ServerInfo) (string, []byte, error) {
	return "PLAIN", []byte("\x00" + a.user + "\x00" + a.pass), nil
}

func (a smtpPlain) Next(_ []byte, more bool) ([]byte, error) {
	if more {
		return nil, errors.New("unexpected SMTP challenge")
	}
	return nil, nil
}

// message renders n as an email; headers hold only checked addresses and
// an encoded subject, so no text can add a header.
func message(c Channel, n Notice) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "From: %s\r\n", c.From)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(c.To, ", "))
	fmt.Fprintf(&b, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", oneLine(n.Title())))
	fmt.Fprintf(&b, "Date: %s\r\n", n.Time.UTC().Format(time.RFC1123Z))
	b.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\nAuto-Submitted: auto-generated\r\n\r\n")
	qp := quotedprintable.NewWriter(&b)
	_, _ = qp.Write([]byte(strings.ReplaceAll(n.Text(), "\n", "\r\n")))
	_ = qp.Close()
	b.WriteString("\r\n")
	return b.Bytes()
}

func oneLine(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}

func cut(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}

// clean makes text one printable line without the secret.
func clean(s string, secret []byte) string {
	if len(secret) > 0 {
		s = strings.ReplaceAll(s, string(secret), "[secret]")
	}
	s = strings.Join(strings.Fields(oneLine(s)), " ")
	if len(s) > maxReply {
		s = s[:maxReply]
	}
	return strings.ToValidUTF8(s, "")
}

// warnings are the reasons a channel gets when it names none: what needs a
// person.
var warnings = map[string]bool{
	"Crashed": true, "Failed": true, "Lost": true, "OutOfMemory": true, "Unschedulable": true,
	"ReconcileFailed": true, "ProxyNotUpdated": true, "MostUnreachable": true, "NotVerified": true,
	"QueueUnread": true, "LogExportFailing": true,
	"VolumeUnavailable": true, "VolumesSplit": true, "VolumeOnCordonedNode": true,
	"VolumeBackupFailed": true, "VolumeBackupUnsupported": true, "VolumeFailedOver": true, "VolumeFailoverFailed": true,
}

// Warning reports whether reason needs a person.
func Warning(reason string) bool { return warnings[reason] }

// Wants reports whether c takes a notice about reason in space ("" for
// events with no app).
func (c Channel) Wants(reason, space string) bool {
	if len(c.Spaces) > 0 && !slices.Contains(c.Spaces, space) {
		return false
	}
	if len(c.Reasons) == 0 {
		return Warning(reason)
	}
	return slices.Contains(c.Reasons, "all") || slices.Contains(c.Reasons, reason)
}
