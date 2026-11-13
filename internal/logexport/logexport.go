// Package logexport sends app output to a log store outside the cluster
// (ADR 0044): a Loki push endpoint or an OTLP/HTTP logs endpoint, both as
// JSON, gzipped.
package logexport

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Formats.
const (
	Loki = "loki"
	OTLP = "otlp"
)

const (
	maxEndpoint = 2048
	maxName     = 256
	// MaxToken bounds the token.
	MaxToken = 4096
	// pushTimeout bounds one request.
	pushTimeout = 30 * time.Second
	// maxReply is how much of an error reply is read and shown.
	maxReply = 256
)

// Config says where logs go. Token is never logged.
type Config struct {
	Format   string
	Endpoint string
	User     string
	Tenant   string
	Token    []byte
}

// String leaves the token out.
func (c Config) String() string {
	return fmt.Sprintf("%s %s", c.Format, c.Endpoint)
}

// Check validates every field.
func (c Config) Check() error {
	if err := CheckFormat(c.Format); err != nil {
		return err
	}
	if c.Format == "" {
		return nil
	}
	if err := CheckEndpoint(c.Endpoint); err != nil {
		return err
	}
	if err := checkName("user", c.User); err != nil {
		return err
	}
	if err := checkName("tenant", c.Tenant); err != nil {
		return err
	}
	if c.Tenant != "" && c.Format != Loki {
		return errors.New("a log tenant is only for loki")
	}
	if c.User != "" && len(c.Token) == 0 {
		return errors.New("a log export user needs a token: --log-token - < FILE")
	}
	return CheckToken(c.Token)
}

// CheckFormat accepts loki, otlp, or empty (nothing is sent).
func CheckFormat(f string) error {
	if f != "" && f != Loki && f != OTLP {
		return fmt.Errorf("unsupported log export %q (want loki, otlp, or none)", f)
	}
	return nil
}

// CheckEndpoint accepts an https:// URL, or http:// to a private or
// loopback IP address, with no credentials in it. Errors never repeat it.
func CheckEndpoint(raw string) error {
	if raw == "" {
		return errors.New("log export needs --log-endpoint, the push URL")
	}
	if len(raw) > maxEndpoint {
		return errors.New("log endpoint is too long")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Opaque != "" || u.Fragment != "" {
		return errors.New("log endpoint must be a URL such as https://logs.example.com/loki/api/v1/push")
	}
	if u.User != nil || u.RawQuery != "" {
		return errors.New("log endpoint must not hold credentials or a query; use --log-export-user and --log-token")
	}
	switch u.Scheme {
	case "https":
	case "http":
		ip, err := netip.ParseAddr(u.Hostname())
		if err != nil || (!ip.IsPrivate() && !ip.IsLoopback()) {
			return errors.New("http:// log endpoints are only allowed for a private IP address; use https://")
		}
	default:
		return errors.New("log endpoint must start with https://")
	}
	return nil
}

// CheckToken bounds a token and refuses control characters.
func CheckToken(t []byte) error {
	if len(t) > MaxToken {
		return fmt.Errorf("log token is longer than %d bytes", MaxToken)
	}
	for _, b := range t {
		if b < 0x20 || b == 0x7f {
			return errors.New("log token must be one line of printable characters")
		}
	}
	return nil
}

func checkName(what, v string) error {
	if len(v) > maxName {
		return fmt.Errorf("log export %s is longer than %d bytes", what, maxName)
	}
	for _, r := range v {
		if r < 0x21 || r == 0x7f || r == ':' {
			return fmt.Errorf("log export %s must be printable, with no spaces or colons", what)
		}
	}
	return nil
}

// Record is one line of output with where it came from.
type Record struct {
	Time      time.Time
	Stderr    bool
	Line      string
	App       string // the app's name
	Space     string
	Revision  string
	Replica   string
	Container string
	Node      string
}

func (r Record) stream() string {
	if r.Stderr {
		return "stderr"
	}
	return "stdout"
}

// line drops the trailing newline and replaces invalid UTF-8.
func (r Record) line() string {
	return strings.ToValidUTF8(strings.TrimSuffix(r.Line, "\n"), string(utf8.RuneError))
}

// Encode renders records in format's JSON.
func Encode(format string, recs []Record) ([]byte, error) {
	switch format {
	case Loki:
		return encodeLoki(recs)
	case OTLP:
		return encodeOTLP(recs)
	}
	return nil, fmt.Errorf("unsupported log export %q", format)
}

// Loki: few labels per stream (app, space, container, stream, node), so
// streams stay few; revision and replica go in structured metadata.
type lokiStream struct {
	Stream map[string]string `json:"stream"`
	Values [][]any           `json:"values"`
}

func encodeLoki(recs []Record) ([]byte, error) {
	var streams []*lokiStream
	index := map[string]*lokiStream{}
	for _, r := range recs {
		labels := map[string]string{"app": r.App, "space": r.Space, "container": r.Container, "stream": r.stream(), "node": r.Node, "source": "armada"}
		key := strings.Join([]string{r.App, r.Space, r.Container, r.stream(), r.Node}, "\x00")
		s := index[key]
		if s == nil {
			s = &lokiStream{Stream: labels}
			index[key] = s
			streams = append(streams, s)
		}
		meta := map[string]string{"replica": r.Replica}
		if r.Revision != "" {
			meta["revision"] = r.Revision
		}
		s.Values = append(s.Values, []any{strconv.FormatInt(r.Time.UnixNano(), 10), r.line(), meta})
	}
	return json.Marshal(map[string]any{"streams": streams})
}

// OTLP: one resource per replica container, its output as log records.
type otlpAttr struct {
	Key   string            `json:"key"`
	Value map[string]string `json:"value"`
}

func attr(k, v string) otlpAttr { return otlpAttr{Key: k, Value: map[string]string{"stringValue": v}} }

type otlpRecord struct {
	TimeUnixNano         string            `json:"timeUnixNano"`
	ObservedTimeUnixNano string            `json:"observedTimeUnixNano"`
	Body                 map[string]string `json:"body"`
	Attributes           []otlpAttr        `json:"attributes"`
}

type otlpResource struct {
	Resource struct {
		Attributes []otlpAttr `json:"attributes"`
	} `json:"resource"`
	ScopeLogs []otlpScope `json:"scopeLogs"`
}

type otlpScope struct {
	Scope      map[string]string `json:"scope"`
	LogRecords []otlpRecord      `json:"logRecords"`
}

func encodeOTLP(recs []Record) ([]byte, error) {
	var out []*otlpResource
	index := map[string]*otlpResource{}
	now := strconv.FormatInt(time.Now().UnixNano(), 10)
	for _, r := range recs {
		key := strings.Join([]string{r.Space, r.App, r.Replica, r.Container, r.Node}, "\x00")
		res := index[key]
		if res == nil {
			res = &otlpResource{}
			res.Resource.Attributes = []otlpAttr{
				attr("service.name", r.App), attr("service.namespace", r.Space), attr("service.instance.id", r.Replica),
				attr("service.version", r.Revision), attr("host.name", r.Node), attr("container.name", r.Container),
				attr("armada.app", r.App), attr("armada.space", r.Space), attr("armada.replica", r.Replica),
				attr("armada.revision", r.Revision), attr("armada.node", r.Node),
			}
			res.ScopeLogs = []otlpScope{{Scope: map[string]string{"name": "armada"}}}
			index[key] = res
			out = append(out, res)
		}
		rec := otlpRecord{
			TimeUnixNano: strconv.FormatInt(r.Time.UnixNano(), 10), ObservedTimeUnixNano: now,
			Body:       map[string]string{"stringValue": r.line()},
			Attributes: []otlpAttr{attr("log.iostream", r.stream())},
		}
		// No severity: stderr is not always an error; log.iostream says
		// where a line came from.
		res.ScopeLogs[0].LogRecords = append(res.ScopeLogs[0].LogRecords, rec)
	}
	return json.Marshal(map[string]any{"resourceLogs": out})
}

// Client pushes records to one endpoint.
type Client struct {
	cfg  Config
	http *http.Client
}

// NewClient checks cfg and returns a client for it.
func NewClient(cfg Config, hc *http.Client) (*Client, error) {
	if cfg.Format == "" {
		return nil, errors.New("log export is off")
	}
	if err := cfg.Check(); err != nil {
		return nil, err
	}
	if hc == nil {
		hc = &http.Client{Timeout: pushTimeout, CheckRedirect: func(*http.Request, []*http.Request) error {
			// A redirect could carry the token elsewhere.
			return http.ErrUseLastResponse
		}}
	}
	return &Client{cfg: cfg, http: hc}, nil
}

// Push sends recs in one request. Errors never carry the token.
func (c *Client) Push(ctx context.Context, recs []Record) error {
	if len(recs) == 0 {
		return nil
	}
	body, err := Encode(c.cfg.Format, recs)
	if err != nil {
		return err
	}
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	if _, err := w.Write(body); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.Endpoint, &gz)
	if err != nil {
		return errors.New("log endpoint: invalid request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("User-Agent", "armada")
	switch {
	case c.cfg.User != "":
		req.SetBasicAuth(c.cfg.User, string(c.cfg.Token))
	case len(c.cfg.Token) > 0:
		req.Header.Set("Authorization", "Bearer "+string(c.cfg.Token))
	}
	if c.cfg.Tenant != "" {
		req.Header.Set("X-Scope-OrgID", c.cfg.Tenant)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // the URL is in the configuration already
		}
		return fmt.Errorf("log endpoint: %s", clean(err.Error(), c.cfg.Token))
	}
	defer func() { _ = resp.Body.Close() }()
	reply, _ := io.ReadAll(io.LimitReader(resp.Body, maxReply))
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 == 2 {
		return nil
	}
	msg := fmt.Sprintf("log endpoint answered %d", resp.StatusCode)
	if r := clean(string(reply), c.cfg.Token); r != "" {
		msg += ": " + r
	}
	return errors.New(msg)
}

// clean makes text one printable line without the token.
func clean(s string, token []byte) string {
	if len(token) > 0 {
		s = strings.ReplaceAll(s, string(token), "[token]")
	}
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == utf8.RuneError {
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > maxReply {
		s = s[:maxReply]
	}
	return strings.ToValidUTF8(s, "")
}

// Batches splits recs into requests of at most maxRecords records and about
// maxBytes of output each.
func Batches(recs []Record, maxRecords, maxBytes int) [][]Record {
	var out [][]Record
	start, size := 0, 0
	for i, r := range recs {
		if i > start && (i-start >= maxRecords || size+len(r.Line) > maxBytes) {
			out = append(out, recs[start:i])
			start, size = i, 0
		}
		size += len(r.Line)
	}
	if start < len(recs) {
		out = append(out, recs[start:])
	}
	return slices.Clip(out)
}
