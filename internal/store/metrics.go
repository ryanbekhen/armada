package store

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"
)

// pfxMetrics holds the certificates issued to metrics scrapers (ADR 0017):
// metrics/<name>. A record with no certificates refuses every certificate
// of the name, the ones issued before schema 13 included.
const pfxMetrics = "metrics/"

// keyMetricsCutoff is when the keyspace moved to schema 13 (unix ms):
// metrics certificates issued before it were never recorded, and are
// accepted while their name has no record.
const keyMetricsCutoff = pfxMeta + "metrics-cutoff"

// MetricsCredential is a scraper's name and its certificates on record.
type MetricsCredential struct {
	Name  string
	Certs []NodeCert
}

type metricsRec struct {
	Name  string    `json:"name"`
	Certs []certRec `json:"certs,omitempty"`
}

// RecordMetricsCert records a certificate issued to the scraper name and
// drops expired ones (and the oldest beyond MaxServiceCerts).
func (s *Etcd) RecordMetricsCert(ctx context.Context, name string, c NodeCert, actor string) error {
	now := s.now()
	return s.tx(ctx, func(t *etx) error {
		r := metricsRec{Name: name}
		if _, err := t.get(pfxMetrics+name, &r); err != nil {
			return err
		}
		var certs []certRec
		for _, old := range r.Certs {
			if old.NotAfter > now.UnixMilli() {
				certs = append(certs, old)
			}
		}
		certs = append(certs, certRec{Serial: c.Serial, NotAfter: c.NotAfter.UnixMilli(), CreatedAt: now.UnixMilli()})
		if len(certs) > MaxServiceCerts {
			certs = certs[len(certs)-MaxServiceCerts:]
		}
		r.Certs = certs
		if err := t.put(pfxMetrics+name, r); err != nil {
			return err
		}
		return t.audit(now, actor, "metrics.certificate", name, "serial="+c.Serial)
	})
}

// RevokeMetricsCerts refuses every certificate of the scraper name from
// now on, the ones issued before schema 13 included. It keeps an empty
// record, so a name with nothing on record is still revoked.
func (s *Etcd) RevokeMetricsCerts(ctx context.Context, name, actor string) error {
	now := s.now()
	return s.tx(ctx, func(t *etx) error {
		if err := t.put(pfxMetrics+name, metricsRec{Name: name}); err != nil {
			return err
		}
		return t.audit(now, actor, "metrics.revoke", name, "")
	})
}

// ListMetricsCerts returns the scrapers with a certificate on record that
// has not expired, by name.
func (s *Etcd) ListMetricsCerts(ctx context.Context) ([]MetricsCredential, error) {
	var out []MetricsCredential
	now := s.now().UnixMilli()
	err := s.view(ctx, func(t *etx) error {
		out = nil
		kvs, err := t.list(pfxMetrics)
		if err != nil {
			return err
		}
		for _, e := range kvs {
			var r metricsRec
			if err := json.Unmarshal(e.val, &r); err != nil {
				return fmt.Errorf("decode %s: %w", e.key, err)
			}
			mc := MetricsCredential{Name: strings.TrimPrefix(e.key, pfxMetrics)}
			for _, c := range r.Certs {
				if c.NotAfter > now {
					mc.Certs = append(mc.Certs, NodeCert{Serial: c.Serial, NotAfter: time.UnixMilli(c.NotAfter)})
				}
			}
			if len(mc.Certs) > 0 {
				out = append(out, mc)
			}
		}
		return nil
	})
	slices.SortFunc(out, func(a, b MetricsCredential) int { return strings.Compare(a.Name, b.Name) })
	return out, err
}

// MetricsAccess reports whether a metrics certificate of name with serial
// that starts at notBefore is accepted: one on record, or, while the name
// has no record, one issued before the keyspace recorded them (any, while
// the keyspace is still at an older schema).
func (s *Etcd) MetricsAccess(ctx context.Context, name string, notBefore time.Time, serial string) (bool, error) {
	allowed := false
	err := s.view(ctx, func(t *etx) error {
		var r metricsRec
		ok, err := t.get(pfxMetrics+name, &r)
		if err != nil {
			return err
		}
		if ok {
			now := s.now().UnixMilli()
			allowed = slices.ContainsFunc(r.Certs, func(c certRec) bool { return c.Serial == serial && c.NotAfter > now })
			return nil
		}
		var cutoff int64
		found, err := t.get(keyMetricsCutoff, &cutoff)
		if err != nil || found {
			allowed = found && notBefore.UnixMilli() < cutoff
			return err
		}
		// Before the migration (servers still being upgraded) nothing is
		// recorded yet: accept as older servers do. A keyspace created at
		// schema 13 has no cutoff and nothing to accept.
		var v int
		if _, err := t.get(keySchema, &v); err != nil {
			return err
		}
		allowed = v < 13
		return nil
	})
	return allowed, err
}

// migrateMetrics (schema 12 -> 13) records when metrics certificates
// started being recorded; earlier ones stay accepted until their name is
// revoked or given a recorded certificate.
func migrateMetrics(t *etx) error {
	return t.put(keyMetricsCutoff, t.s.now().UnixMilli())
}
