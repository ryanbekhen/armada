package daemon

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/pflag"

	"github.com/ryanbekhen/armada/internal/secrets"
	"github.com/ryanbekhen/armada/internal/server"
	"github.com/ryanbekhen/armada/internal/store"
)

// metaStore keeps meta records and audit entries in memory.
type metaStore struct {
	store.Store
	meta  map[string]string
	audit []string
}

func (m *metaStore) GetMeta(_ context.Context, k string) (string, error) {
	v, ok := m.meta[k]
	if !ok {
		return "", store.ErrNotFound
	}
	return v, nil
}

func (m *metaStore) SetMeta(_ context.Context, k, v string) error {
	m.meta[k] = v
	return nil
}

func (m *metaStore) RecordAudit(_ context.Context, actor, action, target, detail string) error {
	m.audit = append(m.audit, actor+" "+action+" "+target+" "+detail)
	return nil
}

func serverFlagSet(t *testing.T, args ...string) (*pflag.FlagSet, *tlsFlags, *string, *time.Duration) {
	t.Helper()
	fs := pflag.NewFlagSet("server", pflag.ContinueOnError)
	var tf tlsFlags
	fs.BoolVar(&tf.enabled, "tls", true, "")
	fs.StringVar(&tf.ca, "acme-ca", "letsencrypt", "")
	fs.StringVar(&tf.email, "acme-email", "", "")
	fs.StringVar(&tf.dnsProvider, "dns-provider", "", "")
	fs.StringVar(&tf.dnsTokenFile, "dns-token-file", "", "")
	metrics := new(string)
	fs.StringVar(metrics, "metrics-listen", "", "")
	lost := new(time.Duration)
	fs.DurationVar(lost, "node-lost-timeout", server.DefaultNodeLostTimeout, "")
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}
	return fs, &tf, metrics, lost
}

// The first leader moves its flags into the cluster's settings; after
// that the cluster's settings win over any server's flags.
func TestResolveSettings(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	st := &metaStore{meta: map[string]string{}}
	keys, err := secrets.NewKeyring(bytes.Repeat([]byte{5}, 32))
	if err != nil {
		t.Fatal(err)
	}
	token := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(token, []byte("cf-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))

	fs, tf, metrics, lost := serverFlagSet(t, "--acme-ca", "letsencrypt-staging", "--acme-email", "ops@example.org",
		"--dns-provider", "cloudflare", "--dns-token-file", token, "--metrics-listen", "10.0.0.1:9443", "--node-lost-timeout", "90s")
	ts, err := resolveSettings(ctx, st, keys, fs, *tf, *metrics, *lost, "10.0.0.1", log)
	if err != nil {
		t.Fatal(err)
	}
	if ts.certs.ca != "letsencrypt-staging" || ts.certs.token != "cf-secret" || ts.metrics != "10.0.0.1:9443" || ts.lostTimeout != 90*time.Second {
		t.Errorf("first server: %+v", ts)
	}
	set, err := server.LoadSettings(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	if set.ACMECA != "letsencrypt-staging" || set.DNSProvider != "cloudflare" || set.DNSToken == nil || *set.MetricsPort != 9443 || set.NodeLostSeconds != 90 {
		t.Errorf("adopted %+v", set)
	}

	// Another server with no flags gets the same settings, on its own IP.
	fs2, tf2, metrics2, lost2 := serverFlagSet(t)
	ts, err = resolveSettings(ctx, st, keys, fs2, *tf2, *metrics2, *lost2, "10.0.0.2", log)
	if err != nil {
		t.Fatal(err)
	}
	if ts.certs.ca != "letsencrypt-staging" || ts.certs.dnsProvider != "cloudflare" || ts.certs.token != "cf-secret" || ts.metrics != "10.0.0.2:9443" || ts.lostTimeout != 90*time.Second {
		t.Errorf("second server: %+v", ts)
	}

	// A server whose flags disagree uses the cluster's and says so.
	fs3, tf3, metrics3, lost3 := serverFlagSet(t, "--acme-ca", "letsencrypt")
	ts, err = resolveSettings(ctx, st, keys, fs3, *tf3, *metrics3, *lost3, "10.0.0.3", log)
	if err != nil {
		t.Fatal(err)
	}
	if ts.certs.ca != "letsencrypt-staging" || !strings.Contains(logs.String(), "--acme-ca") {
		t.Errorf("disagreeing server: ca %s, log %q", ts.certs.ca, logs.String())
	}
	if strings.Contains(logs.String(), "cf-secret") || strings.Contains(strings.Join(st.audit, "\n"), "cf-secret") || strings.Contains(st.meta["settings"], "cf-secret") {
		t.Error("token in the clear in the log, the audit log, or the state")
	}
}
