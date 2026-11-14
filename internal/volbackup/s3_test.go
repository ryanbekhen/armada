package volbackup

import (
	"context"
	"encoding/xml"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeS3 answers the few path-style requests the client makes.
type fakeS3 struct {
	mu      sync.Mutex
	objects map[string][]byte
	deny    bool
	auth    []string
}

func (f *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.auth = append(f.auth, r.Header.Get("Authorization"))
	fail := func(code int, s3code string) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(code)
		_, _ = io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>`+s3code+`</Code><Message>no</Message></Error>`)
	}
	if f.deny {
		fail(http.StatusForbidden, "AccessDenied")
		return
	}
	bucket, key, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if bucket != "bk1" {
		fail(http.StatusNotFound, "NoSuchBucket")
		return
	}
	switch {
	case r.Method == http.MethodPut:
		b, _ := io.ReadAll(r.Body)
		if strings.HasPrefix(r.Header.Get("X-Amz-Content-Sha256"), "STREAMING-") {
			b = unchunk(b)
		}
		f.objects[key] = b
	case r.Method == http.MethodGet && key == "":
		type content struct {
			Key          string
			Size         int64
			LastModified string
		}
		res := struct {
			XMLName  xml.Name `xml:"ListBucketResult"`
			Name     string
			Prefix   string
			KeyCount int
			MaxKeys  int
			Contents []content
		}{Name: "bk1", Prefix: r.URL.Query().Get("prefix"), MaxKeys: 1000}
		var keys []string
		for k := range f.objects {
			if strings.HasPrefix(k, res.Prefix) {
				keys = append(keys, k)
			}
		}
		slices.Sort(keys)
		for _, k := range keys {
			res.Contents = append(res.Contents, content{Key: k, Size: int64(len(f.objects[k])), LastModified: time.Now().UTC().Format(time.RFC3339)})
		}
		res.KeyCount = len(res.Contents)
		w.Header().Set("Content-Type", "application/xml")
		_ = xml.NewEncoder(w).Encode(res)
	case r.Method == http.MethodGet:
		b, ok := f.objects[key]
		if !ok {
			fail(http.StatusNotFound, "NoSuchKey")
			return
		}
		w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
		_, _ = w.Write(b)
	case r.Method == http.MethodDelete:
		delete(f.objects, key)
		w.WriteHeader(http.StatusNoContent)
	default:
		fail(http.StatusMethodNotAllowed, "MethodNotAllowed")
	}
}

// unchunk decodes an aws-chunked body: "<hex size>;chunk-signature=...\r\n<data>\r\n"...
func unchunk(b []byte) []byte {
	var out []byte
	for len(b) > 0 {
		line, rest, ok := strings.Cut(string(b), "\r\n")
		if !ok {
			break
		}
		sizeHex, _, _ := strings.Cut(line, ";")
		n, err := strconv.ParseInt(sizeHex, 16, 64)
		if err != nil || n == 0 {
			break
		}
		out = append(out, rest[:n]...)
		b = []byte(rest[n+2:])
	}
	return out
}

func TestS3Objects(t *testing.T) {
	t.Parallel()
	fake := &fakeS3{objects: map[string][]byte{}}
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	target, err := ParseTarget("http://AKID:topsecret@10.0.0.9/bk1/pre?region=us-east-1")
	if err != nil {
		t.Fatal(err)
	}
	target.Endpoint, target.loopback = strings.TrimPrefix(srv.URL, "http://"), true
	obj, err := S3(target)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := obj.Put(ctx, "pre/a", []byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := obj.Put(ctx, "pre/b/c", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if b, err := obj.Get(ctx, "pre/a", 100); err != nil || string(b) != "hello" {
		t.Fatalf("get = %q, %v", b, err)
	}
	if _, err := obj.Get(ctx, "pre/a", 2); err == nil {
		t.Error("an object over the limit was read")
	}
	if _, err := obj.Get(ctx, "pre/missing", 100); !errors.Is(err, ErrNotExist) {
		t.Errorf("missing = %v", err)
	}
	var listed []string
	if err := obj.List(ctx, "pre/", func(o Object) error { listed = append(listed, o.Key); return nil }); err != nil {
		t.Fatal(err)
	}
	if strings.Join(listed, ",") != "pre/a,pre/b/c" {
		t.Errorf("listed %v", listed)
	}
	if err := obj.Delete(ctx, "pre/a"); err != nil {
		t.Fatal(err)
	}
	if _, err := obj.Get(ctx, "pre/a", 100); !errors.Is(err, ErrNotExist) {
		t.Errorf("after delete: %v", err)
	}
	for _, a := range fake.auth {
		if !strings.HasPrefix(a, "AWS4-HMAC-SHA256 Credential=AKID/") || strings.Contains(a, "topsecret") {
			t.Fatalf("request not signed with the key: %q", a)
		}
	}

	// A whole repository works through it.
	r, err := Open(ctx, obj, Root(target, "web", "data"), testKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Snapshots(ctx); err != nil {
		t.Fatal(err)
	}

	fake.mu.Lock()
	fake.deny = true
	fake.mu.Unlock()
	err = obj.Put(ctx, "pre/z", []byte("x"))
	if err == nil || !strings.Contains(err.Error(), "AccessDenied") {
		t.Fatalf("denied write: %v", err)
	}
	if strings.Contains(err.Error(), "topsecret") || strings.Contains(err.Error(), srv.URL) {
		t.Errorf("the error repeats the URL: %v", err)
	}
}

// A bucket is never the node itself: loopback, link-local (cloud metadata),
// unspecified, and multicast addresses are refused in the URL and when a
// name resolves to one; private addresses are reported for the
// cluster-admin check.
func TestTargetRefusesNodeAddresses(t *testing.T) {
	t.Parallel()
	for _, u := range []string{
		"http://k:s@127.0.0.1:9000/bk1",
		"https://k:s@127.0.0.1/bk1",
		"https://k:s@[::1]/bk1",
		"http://k:s@169.254.169.254/bk1",
		"https://k:s@[fe80::1]/bk1",
		"https://k:s@0.0.0.0/bk1",
		"https://k:s@[::ffff:127.0.0.1]/bk1",
	} {
		if _, err := ParseTarget(u); err == nil {
			t.Errorf("%s accepted", strings.Replace(u, "k:s@", "", 1))
		}
	}
	for u, private := range map[string]bool{
		"http://k:s@10.0.0.9:9000/bk1":   true,
		"https://k:s@[fd00::5]/bk1":      true,
		"https://k:s@s3.example.com/bk1": false,
		"https://k:s@203.0.113.7/bk1":    false,
	} {
		tg, err := ParseTarget(u)
		if err != nil {
			t.Errorf("%s: %v", strings.Replace(u, "k:s@", "", 1), err)
			continue
		}
		if _, ok := tg.PrivateIP(); ok != private {
			t.Errorf("%s: private = %v", strings.Replace(u, "k:s@", "", 1), ok)
		}
	}
	// A name that resolves to the node is refused when dialled.
	srv := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	tg, err := ParseTarget("https://k:s@localhost:" + port + "/bk1")
	if err != nil {
		t.Fatal(err)
	}
	obj, err := S3(tg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := obj.Get(context.Background(), "x", 10); err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Errorf("dialled a name that resolves to loopback: %v", err)
	}
}
