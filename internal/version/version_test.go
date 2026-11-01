package version

import (
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
)

func TestResolve(t *testing.T) {
	t.Parallel()

	vcs := func(rev, when, modified string) []debug.BuildSetting {
		return []debug.BuildSetting{
			{Key: "vcs.revision", Value: rev},
			{Key: "vcs.time", Value: when},
			{Key: "vcs.modified", Value: modified},
		}
	}

	tests := []struct {
		name                string
		v, c, d             string
		bi                  *debug.BuildInfo
		wantV, wantC, wantD string
	}{
		{
			name: "defaults without build info",
			v:    defaultVersion, c: defaultCommit, d: defaultDate,
			wantV: defaultVersion, wantC: defaultCommit, wantD: defaultDate,
		},
		{
			name: "ldflags win over build info",
			v:    "v0.1.0", c: "abc123", d: "2026-10-30T00:00:00Z",
			bi:    &debug.BuildInfo{Main: debug.Module{Version: "v9.9.9"}, Settings: vcs("fff", "2020-01-01T00:00:00Z", "true")},
			wantV: "v0.1.0", wantC: "abc123", wantD: "2026-10-30T00:00:00Z",
		},
		{
			name: "go install module version and vcs",
			v:    defaultVersion, c: defaultCommit, d: defaultDate,
			bi:    &debug.BuildInfo{Main: debug.Module{Version: "v0.1.2"}, Settings: vcs("deadbeef", "2026-10-29T10:00:00Z", "false")},
			wantV: "v0.1.2", wantC: "deadbeef", wantD: "2026-10-29T10:00:00Z",
		},
		{
			name: "devel module version is ignored",
			v:    defaultVersion, c: defaultCommit, d: defaultDate,
			bi:    &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}},
			wantV: defaultVersion, wantC: defaultCommit, wantD: defaultDate,
		},
		{
			name: "modified worktree marks commit dirty",
			v:    defaultVersion, c: defaultCommit, d: defaultDate,
			bi:    &debug.BuildInfo{Settings: vcs("deadbeef", "2026-10-29T10:00:00Z", "true")},
			wantV: defaultVersion, wantC: "deadbeef-dirty", wantD: "2026-10-29T10:00:00Z",
		},
		{
			name: "modified flag without revision stays unknown",
			v:    defaultVersion, c: defaultCommit, d: defaultDate,
			bi:    &debug.BuildInfo{Settings: []debug.BuildSetting{{Key: "vcs.modified", Value: "true"}}},
			wantV: defaultVersion, wantC: defaultCommit, wantD: defaultDate,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := resolve(tt.v, tt.c, tt.d, tt.bi)
			if got.Version != tt.wantV || got.Commit != tt.wantC || got.Date != tt.wantD {
				t.Errorf("resolve() = {%q %q %q}, want {%q %q %q}",
					got.Version, got.Commit, got.Date, tt.wantV, tt.wantC, tt.wantD)
			}
			if got.GoVersion != runtime.Version() {
				t.Errorf("GoVersion = %q, want %q", got.GoVersion, runtime.Version())
			}
			if want := runtime.GOOS + "/" + runtime.GOARCH; got.Platform != want {
				t.Errorf("Platform = %q, want %q", got.Platform, want)
			}
		})
	}
}

func TestGet(t *testing.T) {
	t.Parallel()

	info := Get()
	if info.Version == "" || info.Commit == "" || info.Date == "" {
		t.Fatalf("Get() returned empty fields: %+v", info)
	}
}

func TestInfoString(t *testing.T) {
	t.Parallel()

	info := Info{Version: "v0.1.0", Commit: "abc123", Date: "2026-10-30", GoVersion: "go1.27.0", Platform: "linux/amd64"}
	got := info.String()
	want := "armada v0.1.0 (commit abc123, built 2026-10-30, go1.27.0, linux/amd64)"
	if got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
	if strings.Contains(got, "\n") {
		t.Error("String() must be a single line")
	}
}
