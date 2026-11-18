package release

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewer(t *testing.T) {
	order := []string{"v0.1.0-alpha.2", "v0.1.0-alpha.3", "v0.1.0-alpha.10", "v0.1.0-beta", "v0.1.0-beta.1", "v0.1.0-rc.1", "v0.1.0", "v0.1.1", "v0.2.0", "v1.0.0"}
	for i := range order {
		for j := range order {
			if got, want := Newer(order[i], order[j]), i > j; got != want {
				t.Errorf("Newer(%s, %s) = %v, want %v", order[i], order[j], got, want)
			}
		}
	}
	for _, notRelease := range []string{"dev", "v0.1.0-alpha.3-2-gabc1234-dirty", "0.1.0", ""} {
		if Newer(notRelease, "v0.0.1") || Newer("v9.0.0", notRelease) {
			t.Errorf("%q compared as a release", notRelease)
		}
	}
}

// fakeAPI answers the release list with body and status, and counts the
// requests it gets.
func fakeAPI(t *testing.T, status int, body string, header ...string) *atomic.Int32 {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/"+Repo+"/releases" {
			http.NotFound(w, r)
			return
		}
		calls.Add(1)
		for i := 0; i+1 < len(header); i += 2 {
			w.Header().Set(header[i], header[i+1])
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	old := apiBase
	apiBase = srv.URL
	t.Cleanup(func() { apiBase = old })
	return &calls
}

func TestLatest(t *testing.T) {
	// A stable release wins over newer pre-releases, in one request.
	calls := fakeAPI(t, http.StatusOK, `[{"tag_name":"v0.3.0-alpha.1"},{"tag_name":"v0.2.0"},{"tag_name":"v0.1.0"},{"tag_name":"v0.2.1","draft":true}]`)
	if got, err := Latest(context.Background()); err != nil || got != "v0.2.0" || calls.Load() != 1 {
		t.Errorf("stable: %q %v, %d requests", got, err, calls.Load())
	}
	// No stable release yet: the newest published pre-release.
	fakeAPI(t, http.StatusOK, `[{"tag_name":"v0.1.0-alpha.5","draft":true},{"tag_name":"v0.1.0-alpha.4"}]`)
	if got, err := Latest(context.Background()); err != nil || got != "v0.1.0-alpha.4" {
		t.Errorf("pre-release: %q %v", got, err)
	}
	// The API's order is not the versions': the newest by version wins.
	fakeAPI(t, http.StatusOK, `[{"tag_name":"v0.0.0-rehearsal.1","draft":true},{"tag_name":"v0.1.0-alpha.9"},{"tag_name":"v0.1.0-alpha.5"},{"tag_name":"v0.1.0-alpha.10"},{"tag_name":"v0.1.0-alpha.4"},{"tag_name":"v1; rm -rf /"}]`)
	if got, err := Latest(context.Background()); err != nil || got != "v0.1.0-alpha.10" {
		t.Errorf("out of order: %q %v", got, err)
	}
	fakeAPI(t, http.StatusOK, `[{"tag_name":"v1; rm -rf /"}]`)
	if _, err := Latest(context.Background()); err == nil {
		t.Error("a tag that is not a release accepted")
	}
	fakeAPI(t, http.StatusBadGateway, "")
	if _, err := Latest(context.Background()); err == nil {
		t.Error("502 accepted")
	}
	// GitHub's limit for requests without credentials.
	reset := time.Now().Add(40 * time.Minute).Truncate(time.Second)
	fakeAPI(t, http.StatusForbidden, `{"message":"API rate limit exceeded"}`, "X-RateLimit-Remaining", "0", "X-RateLimit-Reset", strconv.FormatInt(reset.Unix(), 10))
	var rl *RateLimitError
	if _, err := Latest(context.Background()); !errors.As(err, &rl) || !rl.Reset.Equal(reset) {
		t.Errorf("rate limit: %v", err)
	}
	fakeAPI(t, http.StatusForbidden, "")
	if _, err := Latest(context.Background()); errors.As(err, &rl) {
		t.Errorf("a 403 that is not the rate limit read as one: %v", err)
	}
}

// LatestCached asks GitHub at most once an hour per cache, and answers with
// the last release stored when a lookup fails.
func TestLatestCached(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)
	calls := fakeAPI(t, http.StatusOK, `[{"tag_name":"v0.1.0-alpha.31"}]`)
	for _, at := range []time.Duration{0, 30 * time.Minute, 59 * time.Minute} {
		f, err := LatestCached(context.Background(), dir, now.Add(at))
		if err != nil || f.Tag != "v0.1.0-alpha.31" || !f.Checked.Equal(now) {
			t.Fatalf("+%s: %+v %v", at, f, err)
		}
	}
	if calls.Load() != 1 {
		t.Errorf("%d requests within the hour, want 1", calls.Load())
	}
	if fi, err := os.Stat(filepath.Join(dir, "armada", "latest.json")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("cache file: %v %v", fi, err)
	}
	// An hour later it asks again.
	calls = fakeAPI(t, http.StatusOK, `[{"tag_name":"v0.1.0-alpha.32"}]`)
	if f, _ := LatestCached(context.Background(), dir, now.Add(61*time.Minute)); f.Tag != "v0.1.0-alpha.32" || calls.Load() != 1 {
		t.Errorf("after an hour: %+v, %d requests", f, calls.Load())
	}
	// Rate limited: the stored answer, with the error.
	fakeAPI(t, http.StatusTooManyRequests, "")
	f, err := LatestCached(context.Background(), dir, now.Add(3*time.Hour))
	if f.Tag != "v0.1.0-alpha.32" || err == nil {
		t.Errorf("rate limited: %+v %v", f, err)
	}
	// No cache directory: every call asks.
	calls = fakeAPI(t, http.StatusOK, `[{"tag_name":"v0.1.0-alpha.31"}]`)
	_, _ = LatestCached(context.Background(), "", now)
	_, _ = LatestCached(context.Background(), "", now)
	if calls.Load() != 2 {
		t.Errorf("without a cache: %d requests", calls.Load())
	}
	// A cache file that is not ours is ignored.
	if err := os.WriteFile(filepath.Join(dir, "armada", "latest.json"), []byte(`{"tag":"v1; rm -rf /","checked":1794996000}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if f, err := LatestCached(context.Background(), dir, now); err != nil || f.Tag != "v0.1.0-alpha.31" {
		t.Errorf("bad cache: %+v %v", f, err)
	}
}

func TestNoticeOncePerDay(t *testing.T) {
	t.Setenv(DisableEnv, "")
	t.Setenv("CI", "")
	fakeAPI(t, http.StatusOK, `[{"tag_name":"v0.2.0"}]`)
	dir := t.TempDir()
	now := time.Now()
	if got := StartNotice(context.Background(), "v0.1.0", dir, now)(5 * time.Second); !strings.Contains(got, "armada v0.2.0 is available (this is v0.1.0)") {
		t.Errorf("first notice: %q", got)
	}
	if fi, err := os.Stat(filepath.Join(dir, "armada", "release.json")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("cache: %v", err)
	}
	if got := StartNotice(context.Background(), "v0.1.0", dir, now.Add(time.Hour))(5 * time.Second); got != "" {
		t.Errorf("second notice the same day: %q", got)
	}
	if got := StartNotice(context.Background(), "v0.1.0", dir, now.Add(25*time.Hour))(5 * time.Second); got == "" {
		t.Error("no notice a day later")
	}
	if got := StartNotice(context.Background(), "v0.2.0", t.TempDir(), now)(5 * time.Second); got != "" {
		t.Errorf("up to date: %q", got)
	}
	if got := StartNotice(context.Background(), "v0.1.0-alpha.3-2-gabc", t.TempDir(), now)(5 * time.Second); got != "" {
		t.Errorf("development build: %q", got)
	}
	t.Setenv(DisableEnv, "1")
	if got := StartNotice(context.Background(), "v0.1.0", t.TempDir(), now)(5 * time.Second); got != "" {
		t.Errorf("disabled: %q", got)
	}
}
