package logexport

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func records() []Record {
	t := time.Unix(1700000000, 5)
	return []Record{
		{Time: t, Line: "hello\n", App: "web", Space: "shop", Revision: "web.shop-r3", Replica: "web.shop-a1", Container: "app", Node: "n1"},
		{Time: t.Add(time.Second), Stderr: true, Line: "oops \xff\n", App: "web", Space: "shop", Revision: "web.shop-r3", Replica: "web.shop-a1", Container: "app", Node: "n1"},
		{Time: t, Line: "b\n", App: "web", Space: "shop", Revision: "web.shop-r3", Replica: "web.shop-b2", Container: "app", Node: "n1"},
	}
}

func TestEncodeLoki(t *testing.T) {
	t.Parallel()
	b, err := Encode(Loki, records())
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Streams []struct {
			Stream map[string]string `json:"stream"`
			Values [][]any           `json:"values"`
		} `json:"streams"`
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	// stdout of both replicas share a stream; stderr has its own.
	if len(got.Streams) != 2 {
		t.Fatalf("streams: %s", b)
	}
	s := got.Streams[0]
	if s.Stream["app"] != "web" || s.Stream["space"] != "shop" || s.Stream["stream"] != "stdout" || s.Stream["node"] != "n1" || s.Stream["replica"] != "" {
		t.Errorf("labels %v", s.Stream)
	}
	if len(s.Values) != 2 || s.Values[0][0] != "1700000000000000005" || s.Values[0][1] != "hello" {
		t.Errorf("values %v", s.Values)
	}
	if meta := s.Values[1][2].(map[string]any); meta["replica"] != "web.shop-b2" || meta["revision"] != "web.shop-r3" {
		t.Errorf("structured metadata %v", meta)
	}
	if line := got.Streams[1].Values[0][1].(string); line != "oops �" {
		t.Errorf("invalid UTF-8 kept: %q", line)
	}
}

func TestEncodeOTLP(t *testing.T) {
	t.Parallel()
	b, err := Encode(OTLP, records())
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{`"resourceLogs"`, `{"key":"service.name","value":{"stringValue":"web"}}`,
		`{"key":"service.namespace","value":{"stringValue":"shop"}}`, `{"key":"armada.replica","value":{"stringValue":"web.shop-b2"}}`,
		`"timeUnixNano":"1700000000000000005"`, `"body":{"stringValue":"hello"}`, `{"key":"log.iostream","value":{"stringValue":"stderr"}}`} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %s in %s", want, s)
		}
	}
	if strings.Count(s, `"resource"`) != 2 {
		t.Errorf("one resource per replica: %s", s)
	}
}

func TestCheck(t *testing.T) {
	t.Parallel()
	ok := []Config{
		{},
		{Format: Loki, Endpoint: "https://logs.example.com/loki/api/v1/push"},
		{Format: Loki, Endpoint: "http://10.0.0.5:3100/loki/api/v1/push", Tenant: "team-a"},
		{Format: OTLP, Endpoint: "https://otlp.example.com/v1/logs", User: "123", Token: []byte("t")},
	}
	for _, c := range ok {
		if err := c.Check(); err != nil {
			t.Errorf("%v: %v", c, err)
		}
	}
	bad := map[string]Config{
		"format":        {Format: "syslog", Endpoint: "https://x"},
		"no endpoint":   {Format: Loki},
		"public http":   {Format: Loki, Endpoint: "http://logs.example.com/push"},
		"credentials":   {Format: Loki, Endpoint: "https://u:p@logs.example.com/push"},
		"query":         {Format: Loki, Endpoint: "https://logs.example.com/push?api_key=s"},
		"scheme":        {Format: Loki, Endpoint: "ftp://logs.example.com"},
		"user no token": {Format: Loki, Endpoint: "https://x/push", User: "u"},
		"user colon":    {Format: Loki, Endpoint: "https://x/push", User: "u:x", Token: []byte("t")},
		"tenant otlp":   {Format: OTLP, Endpoint: "https://x/v1/logs", Tenant: "t"},
		"token newline": {Format: Loki, Endpoint: "https://x/push", Token: []byte("a\nb")},
	}
	for name, c := range bad {
		err := c.Check()
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if strings.Contains(err.Error(), "api_key") || strings.Contains(err.Error(), "u:p") {
			t.Errorf("%s: error repeats the URL: %v", name, err)
		}
	}
}

func TestPush(t *testing.T) {
	t.Parallel()
	var got struct {
		auth, tenant, encoding string
		body                   []byte
	}
	answer := http.StatusNoContent
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.auth, got.tenant, got.encoding = r.Header.Get("Authorization"), r.Header.Get("X-Scope-OrgID"), r.Header.Get("Content-Encoding")
		zr, err := gzip.NewReader(r.Body)
		if err == nil {
			got.body, _ = io.ReadAll(zr)
		}
		w.WriteHeader(answer)
		_, _ = w.Write([]byte("bad token s3cret\n"))
	}))
	defer srv.Close()
	c, err := NewClient(Config{Format: Loki, Endpoint: srv.URL + "/loki/api/v1/push", Tenant: "t1", Token: []byte("s3cret")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Push(context.Background(), records()); err != nil {
		t.Fatal(err)
	}
	if got.auth != "Bearer s3cret" || got.tenant != "t1" || got.encoding != "gzip" || !strings.Contains(string(got.body), `"streams"`) {
		t.Errorf("request %+v", got)
	}
	c, _ = NewClient(Config{Format: OTLP, Endpoint: srv.URL + "/v1/logs", User: "42", Token: []byte("s3cret")}, nil)
	_ = c.Push(context.Background(), records())
	if !strings.HasPrefix(got.auth, "Basic ") || got.tenant != "" {
		t.Errorf("basic auth %+v", got)
	}
	answer = http.StatusUnauthorized
	err = c.Push(context.Background(), records())
	if err == nil || !strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "s3cret") {
		t.Errorf("error %v", err)
	}
	// A redirect is not followed: it could take the token elsewhere.
	answer = http.StatusFound
	if err := c.Push(context.Background(), records()); err == nil || !strings.Contains(err.Error(), "302") {
		t.Errorf("redirect: %v", err)
	}
}

func TestBatches(t *testing.T) {
	t.Parallel()
	recs := make([]Record, 7)
	for i := range recs {
		recs[i].Line = "0123456789"
	}
	if b := Batches(recs, 3, 1<<20); len(b) != 3 || len(b[2]) != 1 {
		t.Errorf("by count: %d", len(b))
	}
	if b := Batches(recs, 100, 25); len(b) != 4 {
		t.Errorf("by size: %d", len(b))
	}
}
