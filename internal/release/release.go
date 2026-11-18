// Package release finds Armada's latest release and compares versions
// (ADR 0030). Both binaries use it: the client to say when a newer release
// exists, armadad for doctor and `armadad upgrade`.
package release

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Repo is the repository releases come from.
const Repo = "ryanbekhen/armada"

// CheckTimeout bounds a look for the latest release, so a blocked or slow
// network never holds a command up for long.
const CheckTimeout = 3 * time.Second

// DisableEnv turns every look for a newer release off when set.
const DisableEnv = "ARMADA_NO_UPDATE_CHECK"

// apiBase is GitHub's API; tests point it elsewhere.
var apiBase = "https://api.github.com"

// tagRe is a release tag, the same rule as install.sh: builds between
// releases (v0.1.0-alpha.3-2-gabc1234) do not match.
var tagRe = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$`)

// IsRelease reports whether v names a release.
func IsRelease(v string) bool { return tagRe.MatchString(v) }

// URL is the page of release tag.
func URL(tag string) string { return "https://github.com/" + Repo + "/releases/tag/" + tag }

// Latest returns the newest release: the newest stable one by version, else,
// while there is none, the newest published pre-release, as install.sh
// picks. One request lists the last 100 releases (drafts are not public);
// the API does not list them by version (alpha.10 came after alpha.5), so
// the list is compared, not its first entry taken.
func Latest(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, CheckTimeout)
	defer cancel()
	var list []struct {
		Tag   string `json:"tag_name"`
		Draft bool   `json:"draft"`
	}
	if err := getJSON(ctx, apiBase+"/repos/"+Repo+"/releases?per_page=100", &list); err != nil {
		return "", err
	}
	stable, newest := "", ""
	for _, r := range list {
		if r.Draft || !IsRelease(r.Tag) {
			continue
		}
		if newest == "" || Newer(r.Tag, newest) {
			newest = r.Tag
		}
		if !strings.Contains(r.Tag, "-") && (stable == "" || Newer(r.Tag, stable)) {
			stable = r.Tag
		}
	}
	if tag := cmp.Or(stable, newest); tag != "" {
		return tag, nil
	}
	return "", errors.New("look for the latest release: no release found")
}

// RateLimitError says GitHub's limit for requests without credentials (60
// an hour for one address, shared by every machine behind it) is reached.
type RateLimitError struct {
	// Reset is when requests are allowed again; zero when GitHub did not say.
	Reset time.Time
}

func (e *RateLimitError) Error() string {
	msg := "look for the latest release: GitHub's limit for requests from this address is reached"
	if !e.Reset.IsZero() {
		msg += " until " + e.Reset.Local().Format("15:04")
	}
	return msg
}

func getJSON(ctx context.Context, url string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("look for the latest release: %w", err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusTooManyRequests,
		resp.StatusCode == http.StatusForbidden && resp.Header.Get("X-RateLimit-Remaining") == "0":
		e := &RateLimitError{}
		if n, err := strconv.ParseInt(resp.Header.Get("X-RateLimit-Reset"), 10, 64); err == nil && n > 0 {
			e.Reset = time.Unix(n, 0)
		}
		return e
	case resp.StatusCode != http.StatusOK:
		return fmt.Errorf("look for the latest release: %s", resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(v)
}

// Newer reports whether release a is newer than release b, by semantic
// versioning: v0.1.0 is newer than v0.1.0-alpha.4, which is newer than
// v0.1.0-alpha.3. Anything that is not a release is never newer, nor older.
func Newer(a, b string) bool {
	if !IsRelease(a) || !IsRelease(b) {
		return false
	}
	return compare(a, b) > 0
}

func compare(a, b string) int {
	ac, ap, _ := strings.Cut(a[1:], "-")
	bc, bp, _ := strings.Cut(b[1:], "-")
	if c := compareIdents(strings.Split(ac, "."), strings.Split(bc, ".")); c != 0 {
		return c
	}
	switch {
	case ap == bp:
		return 0
	case ap == "":
		return 1 // a release is newer than its pre-releases
	case bp == "":
		return -1
	}
	return compareIdents(strings.Split(ap, "."), strings.Split(bp, "."))
}

// compareIdents compares dot-separated identifiers: numbers numerically and
// before words, words in ASCII order, and a shorter list first when the
// rest is equal.
func compareIdents(a, b []string) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		an, aerr := strconv.ParseUint(a[i], 10, 64)
		bn, berr := strconv.ParseUint(b[i], 10, 64)
		switch {
		case aerr == nil && berr == nil:
			if an != bn {
				return cmpInt(an, bn)
			}
		case aerr == nil:
			return -1
		case berr == nil:
			return 1
		default:
			if c := strings.Compare(a[i], b[i]); c != 0 {
				return c
			}
		}
	}
	return cmpInt(uint64(len(a)), uint64(len(b)))
}

func cmpInt(a, b uint64) int {
	switch {
	case a > b:
		return 1
	case a < b:
		return -1
	}
	return 0
}
