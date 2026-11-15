package store

import (
	"context"
	"testing"
	"time"
)

// Certificates issued before the keyspace recorded them (schema 13) are
// accepted until their name is revoked or gets a recorded certificate;
// later unrecorded ones never are.
func TestMetricsAccess(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	now := time.Now()
	s.SetNow(func() time.Time { return now })
	allowed := func(name string, nb time.Time, serial string) bool {
		t.Helper()
		ok, err := s.MetricsAccess(ctx, name, nb, serial)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	old := now.Add(-time.Hour)
	if allowed("legacy", old, "1") {
		t.Error("a fresh keyspace accepted an unrecorded certificate")
	}

	atSchema(t, s, 12)
	if !allowed("legacy", now.Add(time.Second), "9") {
		t.Error("before the migration, an unrecorded certificate was refused")
	}
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if !allowed("legacy", old, "1") {
		t.Error("a certificate from before the migration was refused")
	}
	if allowed("legacy", now.Add(time.Second), "2") {
		t.Error("an unrecorded certificate from after the migration was accepted")
	}

	if err := s.RevokeMetricsCerts(ctx, "legacy", "user:ryan"); err != nil {
		t.Fatal(err)
	}
	if allowed("legacy", old, "1") {
		t.Error("a revoked legacy certificate was accepted")
	}

	exp := now.Add(24 * time.Hour)
	if err := s.RecordMetricsCert(ctx, "prom", NodeCert{Serial: "a", NotAfter: exp}, "user:ryan"); err != nil {
		t.Fatal(err)
	}
	if !allowed("prom", now, "a") || allowed("prom", old, "other") {
		t.Error("recorded serials only")
	}
	if l, err := s.ListMetricsCerts(ctx); err != nil || len(l) != 1 || l[0].Name != "prom" || l[0].Certs[0].Serial != "a" {
		t.Errorf("list: %+v %v", l, err)
	}

	// Expired ones are dropped from the record and refused.
	now = exp.Add(time.Minute)
	if allowed("prom", now, "a") {
		t.Error("an expired recorded certificate was accepted")
	}
	if err := s.RecordMetricsCert(ctx, "prom", NodeCert{Serial: "b", NotAfter: now.Add(time.Hour)}, "user:ryan"); err != nil {
		t.Fatal(err)
	}
	if l, _ := s.ListMetricsCerts(ctx); len(l) != 1 || len(l[0].Certs) != 1 || l[0].Certs[0].Serial != "b" {
		t.Errorf("after expiry: %+v", l)
	}
}
