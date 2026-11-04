package spec

import (
	"slices"
	"testing"
)

func TestParseQuota(t *testing.T) {
	q, err := ParseQuota("cpu=4,memory=8Gi,replicas=20,volumes=4,domains=2,secrets=50,jobs=2")
	want := Quota{CPUMillis: 4000, MemoryBytes: 8 << 30, Replicas: 20, Volumes: 4, Domains: 2, Secrets: 50, Jobs: 2}
	if err != nil || q != want {
		t.Fatalf("ParseQuota = %+v, %v", q, err)
	}
	if q.String() != "cpu=4,memory=8Gi,replicas=20,volumes=4,domains=2,secrets=50,jobs=2" {
		t.Errorf("String = %q", q.String())
	}
	if q, err := ParseQuota("cpu=500m, replicas=0"); err != nil || q != (Quota{CPUMillis: 500}) || q.String() != "cpu=500m" {
		t.Errorf("partial: %+v %v %q", q, err, q.String())
	}
	if q, err := ParseQuota("none"); err != nil || !q.IsZero() || q.String() != "none" {
		t.Errorf("none: %+v %v", q, err)
	}
	for _, bad := range []string{"", "cpu", "cpu=", "cpu=x", "memory=8GB", "replicas=-1", "replicas=1.5", "replicas=01",
		"replicas=1000001", "disk=10Gi", "cpu=1,cpu=2", "replicas=+3"} {
		if _, err := ParseQuota(bad); err == nil {
			t.Errorf("ParseQuota(%q) accepted", bad)
		}
	}
	if CheckQuota(Quota{Replicas: -1}) == nil || CheckQuota(Quota{CPUMillis: -1}) == nil || CheckQuota(Quota{Jobs: maxQuotaCount + 1}) == nil {
		t.Error("CheckQuota accepted bad values")
	}
}

func TestQuotaExceeded(t *testing.T) {
	q := Quota{CPUMillis: 1000, Replicas: 4}
	if got := q.Exceeded(Quota{Replicas: 2}, Quota{CPUMillis: 1500, Replicas: 5}); !slices.Equal(got, []string{"cpu 1.5 of 1", "replicas 5 of 4"}) {
		t.Errorf("growth = %v", got)
	}
	// Over a lowered quota: shrinking or staying the same is allowed.
	if got := q.Exceeded(Quota{Replicas: 8}, Quota{Replicas: 6}); got != nil {
		t.Errorf("shrinking = %v", got)
	}
	if got := q.Exceeded(Quota{Replicas: 6}, Quota{Replicas: 6, Secrets: 9}); got != nil {
		t.Errorf("unlimited secrets = %v", got)
	}
	if got := Usage(Quota{CPUMillis: 250, Replicas: 3, Secrets: 2}, q); got != "cpu=250m/1,replicas=3/4,secrets=2" {
		t.Errorf("Usage = %q", got)
	}
	if Usage(Quota{}, Quota{}) != "-" {
		t.Error("empty usage")
	}
}
