package store

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"time"

	"github.com/ryanbekhen/armada/internal/spec"
)

var errBadToken = fmt.Errorf("join token is invalid, expired, or already used: %w", ErrNotFound)

func ms(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

func fromMS(v int64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return time.UnixMilli(v)
}

// sameRevision reports whether r runs exactly spec body with secret pins.
func sameRevision(r Revision, body []byte, pins map[string]int) bool {
	return sameSpec(r.Spec, body) && maps.Equal(r.Secrets, pins)
}

func sameSpec(a *spec.App, body []byte) bool {
	b, err := json.Marshal(a)
	return err == nil && bytes.Equal(b, body)
}

// routeKeys lists the host+path pairs an app routes on its custom domains.
func routeKeys(sp *spec.App) []string {
	if sp.Ingress == nil || sp.Ingress.Type != spec.IngressExternal {
		return nil
	}
	paths := []string{"/"}
	if len(sp.Ingress.Routes) > 0 {
		paths = paths[:0]
		for _, r := range sp.Ingress.Routes {
			paths = append(paths, r.Path)
		}
	}
	var keys []string
	for _, d := range sp.Ingress.Domains {
		for _, p := range paths {
			keys = append(keys, d+p)
		}
	}
	return keys
}

func randomToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
