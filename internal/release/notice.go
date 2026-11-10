package release

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ryanbekhen/armada/internal/fsutil"
)

// noticeEvery is how often the client looks for a newer release.
const noticeEvery = 24 * time.Hour

type noticeState struct {
	Checked int64 `json:"checked"`
}

// StartNotice begins looking for a release newer than current, at most once
// a day per user (the time is kept in cacheDir/armada/release.json), unless
// DisableEnv or CI is set or current is not a release. The returned function
// waits up to wait for the answer and returns the line to show, or "" when
// there is nothing newer, the look failed, or it took too long; the next look
// is a day later either way, so a blocked network costs one try a day.
func StartNotice(ctx context.Context, current, cacheDir string, now time.Time) func(wait time.Duration) string {
	none := func(time.Duration) string { return "" }
	if os.Getenv(DisableEnv) != "" || os.Getenv("CI") != "" || !IsRelease(current) || cacheDir == "" {
		return none
	}
	dir := filepath.Join(cacheDir, "armada")
	path := filepath.Join(dir, "release.json")
	var st noticeState
	if b, err := os.ReadFile(path); err == nil && json.Unmarshal(b, &st) == nil { //nolint:gosec // our own cache file
		if last := time.Unix(st.Checked, 0); now.Sub(last) < noticeEvery && !last.After(now) {
			return none
		}
	}
	b, _ := json.Marshal(noticeState{Checked: now.Unix()})
	if fsutil.MkdirPrivate(dir) != nil || fsutil.WriteFileAtomic(path, b, 0o600) != nil {
		return none
	}
	found := make(chan string, 1)
	go func() {
		tag, err := Latest(ctx)
		if err != nil {
			tag = ""
		}
		found <- tag
	}()
	return func(wait time.Duration) string {
		select {
		case tag := <-found:
			if Newer(tag, current) {
				return fmt.Sprintf("armada %s is available (this is %s): %s", tag, current, URL(tag))
			}
		case <-time.After(wait):
		}
		return ""
	}
}
