package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/ryanbekhen/armada/internal/secrets"
	"github.com/ryanbekhen/armada/internal/store"
)

// metaSettings holds the server settings for the whole cluster (ADR 0031).
const metaSettings = "settings"

// The DNS token is sealed like an app secret, bound to this scope and name.
const (
	tokenScope = "cluster"
	tokenName  = "dns-token"
)

// Bounds of the settings.
const (
	MinNodeLostTimeout = 10 * time.Second
	maxNodeLostTimeout = 24 * time.Hour
	maxEmailLen        = 254
	maxTokenLen        = 4096
)

// Settings are the server settings that must be the same on every server,
// because any of them can lead: certificates, the DNS provider and its
// token, the metrics port, and the node-lost timeout. Unset fields fall back
// to each server's flags, then the defaults.
type Settings struct {
	TLS         *bool  `json:"tls,omitempty"`
	ACMECA      string `json:"acmeCa,omitempty"`
	ACMEEmail   string `json:"acmeEmail,omitempty"`
	DNSProvider string `json:"dnsProvider,omitempty"`
	// DNSProviderSet records "none" chosen on purpose, which a flag must not
	// override.
	DNSProviderSet  bool            `json:"dnsProviderSet,omitempty"`
	DNSToken        *secrets.Sealed `json:"dnsToken,omitempty"`
	DNSTokenVersion int             `json:"dnsTokenVersion,omitempty"`
	MetricsPort     *int            `json:"metricsPort,omitempty"`
	// NodeLostSeconds is the node-lost timeout; zero means unset.
	NodeLostSeconds int64 `json:"nodeLostSeconds,omitempty"`
}

// LoadSettings reads the cluster's settings; none stored yields zero.
func LoadSettings(ctx context.Context, st store.Store) (Settings, error) {
	var s Settings
	v, err := st.GetMeta(ctx, metaSettings)
	if errors.Is(err, store.ErrNotFound) || (err == nil && v == "") {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal([]byte(v), &s); err != nil {
		return s, fmt.Errorf("cluster settings: %w", err)
	}
	return s, nil
}

// SaveSettings stores the cluster's settings.
func SaveSettings(ctx context.Context, st store.Store, s Settings) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return st.SetMeta(ctx, metaSettings, string(b))
}

// SealToken stores token as the DNS token, a new version of it.
func (s *Settings) SealToken(keys *secrets.Keyring, token []byte) error {
	if len(token) == 0 {
		s.DNSToken = nil
		return nil
	}
	sealed, err := keys.Seal(tokenScope, tokenName, s.DNSTokenVersion+1, secrets.NewValue(token))
	if err != nil {
		return err
	}
	s.DNSTokenVersion++
	s.DNSToken = &sealed
	return nil
}

// Token opens the DNS token; ok is false when none is stored.
func (s Settings) Token(keys *secrets.Keyring) (v secrets.Value, ok bool, err error) {
	if s.DNSToken == nil {
		return v, false, nil
	}
	v, err = keys.Open(*s.DNSToken, tokenScope, tokenName, s.DNSTokenVersion)
	return v, err == nil, err
}

// CheckACMECA accepts letsencrypt, letsencrypt-staging, or an https:// URL.
func CheckACMECA(v string) error {
	switch v {
	case "letsencrypt", "letsencrypt-staging":
		return nil
	}
	u, err := url.Parse(v)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return errors.New("ACME CA must be letsencrypt, letsencrypt-staging, or an https:// URL")
	}
	return nil
}

// CheckDNSProvider accepts the providers Armada supports, or none.
func CheckDNSProvider(v string) error {
	if v != "" && v != "cloudflare" {
		return fmt.Errorf("unsupported DNS provider %q (want cloudflare or none)", v)
	}
	return nil
}

// CheckDNSToken bounds a DNS token and refuses control characters.
func CheckDNSToken(token []byte) error {
	t := strings.TrimSpace(string(token))
	if len(t) > maxTokenLen {
		return fmt.Errorf("DNS token is longer than %d bytes", maxTokenLen)
	}
	for _, r := range t {
		if r < 0x20 || r == 0x7f {
			return errors.New("DNS token must be one line of printable characters")
		}
	}
	return nil
}

// CheckEmail bounds the ACME email; ACME checks the rest.
func CheckEmail(v string) error {
	if len(v) > maxEmailLen || strings.ContainsAny(v, " \t\r\n<>") || (v != "" && !strings.Contains(v, "@")) {
		return errors.New("invalid ACME email")
	}
	return nil
}

// CheckNodeLostTimeout bounds the node-lost timeout.
func CheckNodeLostTimeout(d time.Duration) error {
	if d < MinNodeLostTimeout || d > maxNodeLostTimeout {
		return fmt.Errorf("node-lost timeout must be between %s and %s (a short network blip must not move every replica)", MinNodeLostTimeout, maxNodeLostTimeout)
	}
	return nil
}
