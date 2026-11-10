package daemon

import (
	"context"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/pflag"

	"github.com/ryanbekhen/armada/internal/secrets"
	"github.com/ryanbekhen/armada/internal/server"
	"github.com/ryanbekhen/armada/internal/store"
)

// clusterFlags are the armadad server flags that hold cluster-wide settings
// (ADR 0031): any server can lead, so they must be the same everywhere, and
// `armada cluster set` changes them for every server.
var clusterFlags = []string{"tls", "acme-ca", "acme-email", "dns-provider", "dns-token-file", "metrics-listen", "node-lost-timeout"}

// termSettings are what one term of the control plane uses.
type termSettings struct {
	certs       certSettings
	metrics     string // listen address; empty: off
	lostTimeout time.Duration
}

// resolveSettings gives the cluster's settings precedence over this
// server's flags, and the flags over the defaults. A setting the cluster
// does not have yet is taken from the flags given on this server and stored
// (a cluster from before ADR 0031 moves its server.env over once). A stored
// setting the flags disagree with is logged once per term.
func resolveSettings(ctx context.Context, st store.Store, keys *secrets.Keyring, fl *pflag.FlagSet, tf tlsFlags, metricsFlag string, lostFlag time.Duration, ip string, log *slog.Logger) (termSettings, error) {
	set, err := server.LoadSettings(ctx, st)
	if err != nil {
		return termSettings{}, err
	}
	given := fl.Changed
	adopted := []string{}
	disagree := func(flag string) {
		log.Warn("a flag in server.env differs from the cluster setting, which wins; change it with `armada cluster set`", "flag", "--"+flag)
	}

	if set.TLS == nil && given("tls") {
		v := tf.enabled
		set.TLS = &v
		adopted = append(adopted, "tls")
	} else if set.TLS != nil && given("tls") && *set.TLS != tf.enabled {
		disagree("tls")
	}
	if set.ACMECA == "" && given("acme-ca") {
		set.ACMECA = tf.ca
		adopted = append(adopted, "acme-ca")
	} else if set.ACMECA != "" && given("acme-ca") && set.ACMECA != tf.ca {
		disagree("acme-ca")
	}
	if set.ACMEEmail == "" && given("acme-email") {
		set.ACMEEmail = tf.email
		adopted = append(adopted, "acme-email")
	} else if set.ACMEEmail != "" && given("acme-email") && set.ACMEEmail != tf.email {
		disagree("acme-email")
	}
	if !set.DNSProviderSet && given("dns-provider") {
		token := ""
		if tf.dnsTokenFile != "" {
			if token, err = readTokenFile(tf.dnsTokenFile); err != nil {
				return termSettings{}, err
			}
		}
		if keys != nil && token != "" {
			if err := set.SealToken(keys, []byte(token)); err != nil {
				return termSettings{}, err
			}
		}
		set.DNSProvider, set.DNSProviderSet = tf.dnsProvider, true
		adopted = append(adopted, "dns-provider")
	} else if set.DNSProviderSet && given("dns-provider") && set.DNSProvider != tf.dnsProvider {
		disagree("dns-provider")
	}
	if set.MetricsPort == nil && given("metrics-listen") {
		if _, p, err := net.SplitHostPort(metricsFlag); err == nil {
			if port, err := strconv.Atoi(p); err == nil {
				set.MetricsPort = &port
				adopted = append(adopted, "metrics-listen")
			}
		}
	}
	if set.NodeLostSeconds == 0 && given("node-lost-timeout") {
		set.NodeLostSeconds = int64(lostFlag / time.Second)
		adopted = append(adopted, "node-lost-timeout")
	} else if set.NodeLostSeconds != 0 && given("node-lost-timeout") && set.NodeLostSeconds != int64(lostFlag/time.Second) {
		disagree("node-lost-timeout")
	}
	if len(adopted) > 0 {
		if err := server.SaveSettings(ctx, st, set); err != nil {
			return termSettings{}, err
		}
		if err := st.RecordAudit(ctx, "server", "cluster.settings", "cluster", "from server flags: "+strings.Join(adopted, " ")); err != nil {
			return termSettings{}, err
		}
		log.Info("cluster settings taken from this server's flags", "flags", strings.Join(adopted, ","))
	}

	out := termSettings{
		certs:       certSettings{enabled: tf.enabled, ca: tf.ca, email: tf.email, dnsProvider: tf.dnsProvider},
		metrics:     metricsFlag,
		lostTimeout: lostFlag,
	}
	if set.TLS != nil {
		out.certs.enabled = *set.TLS
	}
	if set.ACMECA != "" {
		out.certs.ca = set.ACMECA
	}
	if set.ACMEEmail != "" {
		out.certs.email = set.ACMEEmail
	}
	if set.DNSProviderSet {
		out.certs.dnsProvider = set.DNSProvider
	}
	if v, ok, err := set.Token(keys); err != nil {
		return termSettings{}, err
	} else if ok {
		out.certs.token = string(v.Bytes())
	} else if !set.DNSProviderSet && tf.dnsTokenFile != "" {
		if out.certs.token, err = readTokenFile(tf.dnsTokenFile); err != nil {
			return termSettings{}, err
		}
	}
	// The metrics port is the cluster's; the address is this server's own,
	// unless --metrics-listen names one.
	if set.MetricsPort != nil && !given("metrics-listen") {
		out.metrics = ""
		if *set.MetricsPort > 0 {
			out.metrics = net.JoinHostPort(ip, strconv.Itoa(*set.MetricsPort))
		}
	}
	if set.NodeLostSeconds > 0 {
		out.lostTimeout = time.Duration(set.NodeLostSeconds) * time.Second
	}
	return out, nil
}
