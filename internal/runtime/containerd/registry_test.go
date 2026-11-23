package containerd

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// A registry cannot steer the agent to a plain-HTTP address with a
// redirect: the request is refused before anything reaches the target,
// while redirects that stay on HTTPS still work.
func TestRegistryClientRefusesPlainRedirects(t *testing.T) {
	var hits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer target.Close()
	var registry *httptest.Server
	registry = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/plain":
			http.Redirect(w, r, target.URL+"/admin", http.StatusFound)
		case "/v2/tls":
			http.Redirect(w, r, registry.URL+"/v2/ok", http.StatusFound)
		case "/v2/loop":
			http.Redirect(w, r, r.URL.Path, http.StatusFound)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer registry.Close()

	c := registry.Client()
	if err := guardRegistryClient(c); err != nil {
		t.Fatal(err)
	}
	get := func(url string) error {
		resp, err := c.Get(url)
		if err == nil {
			_ = resp.Body.Close()
		}
		return err
	}
	if err := get(registry.URL + "/v2/plain"); !errors.Is(err, errPlainRegistry) {
		t.Errorf("redirect to plain HTTP: %v", err)
	}
	if err := get(target.URL + "/v2/"); !errors.Is(err, errPlainRegistry) {
		t.Errorf("plain HTTP registry: %v", err)
	}
	if hits.Load() != 0 {
		t.Errorf("the plain-HTTP target got %d requests", hits.Load())
	}
	if err := get(registry.URL + "/v2/loop"); err == nil {
		t.Error("a redirect loop was followed to the end")
	}
	resp, err := c.Get(registry.URL + "/v2/tls")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Request.URL.Path != "/v2/ok" {
		t.Errorf("HTTPS redirect: %d %s", resp.StatusCode, resp.Request.URL)
	}
}

// Machines that reach registries through an HTTPS proxy keep it.
func TestRegistryClientKeepsProxy(t *testing.T) {
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyFromEnvironment}}
	if err := guardRegistryClient(c); err != nil {
		t.Fatal(err)
	}
	if c.Transport.(httpsOnly).next.(*http.Transport).Proxy == nil {
		t.Error("the registry client dropped the environment proxy")
	}
}

func TestRegistryDialControl(t *testing.T) {
	for addr, ok := range map[string]bool{
		"169.254.169.254:80":           false,
		"[fe80::1]:443":                false,
		"0.0.0.0:443":                  false,
		"[::]:443":                     false,
		"224.0.0.1:443":                false,
		"[::ffff:169.254.169.254]:443": false,
		"10.0.0.5:443":                 true,
		"127.0.0.1:5000":               true,
		"[2001:db8::1]:443":            true,
	} {
		err := registryDialControl("tcp", addr, nil)
		if (err == nil) != ok {
			t.Errorf("%s: %v", addr, err)
		}
	}
}

// fetchRecorder is a resolver whose fetchers record what they are asked.
type fetchRecorder struct {
	remotes.Resolver
	got []ocispec.Descriptor
}

func (r *fetchRecorder) Fetcher(context.Context, string) (remotes.Fetcher, error) { return r, nil }

func (r *fetchRecorder) Fetch(_ context.Context, desc ocispec.Descriptor) (io.ReadCloser, error) {
	r.got = append(r.got, desc)
	return io.NopCloser(strings.NewReader("")), nil
}

// A layer's other URLs ("foreign layers") would be fetched with a client
// outside the registry's rules (plain HTTP, any address): they are dropped,
// so every blob comes from the registry.
func TestResolverIgnoresForeignURLs(t *testing.T) {
	ctx := context.Background()
	if _, ok := newResolver(ctx, nil).(registryOnly); !ok {
		t.Fatalf("newResolver returns %T, want registryOnly", newResolver(ctx, nil))
	}
	rec := &fetchRecorder{}
	f, err := registryOnly{rec}.Fetcher(ctx, "registry.example/app:1")
	if err != nil {
		t.Fatal(err)
	}
	desc := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageLayerGzip, Digest: digest.Digest("sha256:" + strings.Repeat("a", 64)), Size: 1,
		URLs: []string{"http://169.254.169.254/latest/meta-data/", "http://10.0.0.1/"}}
	rc, err := f.Fetch(ctx, desc)
	if err != nil {
		t.Fatal(err)
	}
	_ = rc.Close()
	if len(rec.got) != 1 || len(rec.got[0].URLs) != 0 || rec.got[0].Digest != desc.Digest {
		t.Fatalf("fetched %+v", rec.got)
	}
	if len(desc.URLs) != 2 {
		t.Error("the caller's descriptor changed")
	}
}
