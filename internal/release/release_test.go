package release

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

func fakeAPI(t *testing.T, latest int, body string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/" + Repo + "/releases/latest":
			w.WriteHeader(latest)
			if latest == http.StatusOK {
				_, _ = w.Write([]byte(`{"tag_name":"v0.2.0"}`))
			}
		case "/repos/" + Repo + "/releases":
			_, _ = w.Write([]byte(body))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	old := apiBase
	apiBase = srv.URL
	t.Cleanup(func() { apiBase = old })
}

func TestLatest(t *testing.T) {
	fakeAPI(t, http.StatusOK, "")
	if got, err := Latest(context.Background()); err != nil || got != "v0.2.0" {
		t.Errorf("stable: %q %v", got, err)
	}
	// No stable release yet: the newest published pre-release.
	fakeAPI(t, http.StatusNotFound, `[{"tag_name":"v0.1.0-alpha.5","draft":true},{"tag_name":"v0.1.0-alpha.4"}]`)
	if got, err := Latest(context.Background()); err != nil || got != "v0.1.0-alpha.4" {
		t.Errorf("pre-release: %q %v", got, err)
	}
	// The API's order is not the versions': the newest by version wins.
	fakeAPI(t, http.StatusNotFound, `[{"tag_name":"v0.0.0-rehearsal.1","draft":true},{"tag_name":"v0.1.0-alpha.9"},{"tag_name":"v0.1.0-alpha.5"},{"tag_name":"v0.1.0-alpha.10"},{"tag_name":"v0.1.0-alpha.4"},{"tag_name":"v1; rm -rf /"}]`)
	if got, err := Latest(context.Background()); err != nil || got != "v0.1.0-alpha.10" {
		t.Errorf("out of order: %q %v", got, err)
	}
	fakeAPI(t, http.StatusNotFound, `[{"tag_name":"v1; rm -rf /"}]`)
	if _, err := Latest(context.Background()); err == nil {
		t.Error("a tag that is not a release accepted")
	}
	fakeAPI(t, http.StatusBadGateway, "")
	if _, err := Latest(context.Background()); err == nil {
		t.Error("504 accepted")
	}
}

func TestNoticeOncePerDay(t *testing.T) {
	t.Setenv(DisableEnv, "")
	t.Setenv("CI", "")
	fakeAPI(t, http.StatusOK, "")
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
