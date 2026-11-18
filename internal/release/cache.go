package release

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/ryanbekhen/armada/internal/fsutil"
)

// cacheFor is how long a release found is used again without asking GitHub,
// which allows 60 requests an hour from one address without credentials.
const cacheFor = time.Hour

type latestState struct {
	Tag     string `json:"tag"`
	Checked int64  `json:"checked"`
}

// Found is the latest release and when it was looked up.
type Found struct {
	Tag     string
	Checked time.Time
}

// LatestCached is Latest through a cache in cacheDir/armada/latest.json: an
// answer less than an hour old is used as is. When looking up fails and an
// older answer is stored, it returns that answer along with the error, so
// callers can say what was found and when. An empty cacheDir looks up every
// time.
func LatestCached(ctx context.Context, cacheDir string, now time.Time) (Found, error) {
	dir := filepath.Join(cacheDir, "armada")
	path := filepath.Join(dir, "latest.json")
	var st latestState
	if cacheDir != "" {
		if b, err := os.ReadFile(path); err == nil && json.Unmarshal(b, &st) == nil && IsRelease(st.Tag) { //nolint:gosec // our own cache file
			if at := time.Unix(st.Checked, 0); now.Sub(at) < cacheFor && !at.After(now) {
				return Found{Tag: st.Tag, Checked: at}, nil
			}
		} else {
			st = latestState{}
		}
	}
	tag, err := Latest(ctx)
	if err != nil {
		if st.Tag != "" {
			return Found{Tag: st.Tag, Checked: time.Unix(st.Checked, 0)}, err
		}
		return Found{}, err
	}
	if cacheDir != "" {
		if b, err := json.Marshal(latestState{Tag: tag, Checked: now.Unix()}); err == nil && fsutil.MkdirPrivate(dir) == nil {
			_ = fsutil.WriteFileAtomic(path, b, 0o600)
		}
	}
	return Found{Tag: tag, Checked: now}, nil
}
