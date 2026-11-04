package spec

import (
	"fmt"
	"strconv"
	"strings"
)

// Quota bounds what a project may reserve (ADR 0029). A zero field is
// unlimited. The same type holds what a project uses.
type Quota struct {
	// CPUMillis and MemoryBytes bound the sum of the reservations of its
	// apps' replicas (an autoscaled app counts its scale.max) and of one
	// attempt of each job.
	CPUMillis   int64 `json:"cpuMillis,omitempty"`
	MemoryBytes int64 `json:"memoryBytes,omitempty"`
	// Replicas bounds the replicas of its apps, counted the same way.
	Replicas int `json:"replicas,omitempty"`
	// Volumes bounds the volumes its apps declare.
	Volumes int `json:"volumes,omitempty"`
	// Domains bounds the custom domains its apps route.
	Domains int `json:"domains,omitempty"`
	// Secrets bounds its secrets (names, not versions).
	Secrets int `json:"secrets,omitempty"`
	// Jobs bounds the job attempts that run at once.
	Jobs int `json:"jobs,omitempty"`
}

// maxQuotaCount keeps counts far from overflow and within reason.
const maxQuotaCount = 1_000_000

// quotaKeys lists the keys of ParseQuota in display order.
var quotaKeys = []string{"cpu", "memory", "replicas", "volumes", "domains", "secrets", "jobs"}

// IsZero reports whether q sets no limit.
func (q Quota) IsZero() bool { return q == Quota{} }

// ParseQuota parses "cpu=4,memory=8Gi,replicas=20,volumes=4,domains=2,
// secrets=50,jobs=2". Keys left out are unlimited, as is a value of 0;
// "none" clears every limit.
func ParseQuota(s string) (Quota, error) {
	var q Quota
	s = strings.TrimSpace(s)
	if s == "none" {
		return q, nil
	}
	if s == "" {
		return q, fmt.Errorf("empty quota: give KEY=VALUE pairs (%s) or none", strings.Join(quotaKeys, ", "))
	}
	seen := map[string]bool{}
	for _, part := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || v == "" {
			return Quota{}, fmt.Errorf("invalid quota entry %q: use KEY=VALUE", part)
		}
		if seen[k] {
			return Quota{}, fmt.Errorf("quota key %s given twice", k)
		}
		seen[k] = true
		switch k {
		case "cpu":
			if v == "0" {
				continue
			}
			n, err := ParseCPU(v)
			if err != nil {
				return Quota{}, err
			}
			q.CPUMillis = max(1, n/1_000_000)
		case "memory":
			if v == "0" {
				continue
			}
			n, err := ParseMemory(v)
			if err != nil {
				return Quota{}, err
			}
			q.MemoryBytes = n
		case "replicas", "volumes", "domains", "secrets", "jobs":
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 || n > maxQuotaCount || strconv.Itoa(n) != v {
				return Quota{}, fmt.Errorf("invalid quota %s=%s: a whole number from 0 to %d", k, v, maxQuotaCount)
			}
			*q.count(k) = n
		default:
			return Quota{}, fmt.Errorf("unknown quota key %q: use %s", k, strings.Join(quotaKeys, ", "))
		}
	}
	return q, nil
}

func (q *Quota) count(k string) *int {
	switch k {
	case "replicas":
		return &q.Replicas
	case "volumes":
		return &q.Volumes
	case "domains":
		return &q.Domains
	case "secrets":
		return &q.Secrets
	}
	return &q.Jobs
}

// CheckQuota validates a quota from outside: no negative values, counts
// within reason.
func CheckQuota(q Quota) error {
	if q.CPUMillis < 0 || q.MemoryBytes < 0 {
		return fmt.Errorf("quota values cannot be negative")
	}
	for _, n := range []int{q.Replicas, q.Volumes, q.Domains, q.Secrets, q.Jobs} {
		if n < 0 || n > maxQuotaCount {
			return fmt.Errorf("quota counts must be from 0 to %d", maxQuotaCount)
		}
	}
	return nil
}

// value returns field k of q as a number, and how to show it.
func (q Quota) value(k string) (int64, string) {
	switch k {
	case "cpu":
		return q.CPUMillis, FormatCPUMillis(q.CPUMillis)
	case "memory":
		return q.MemoryBytes, FormatMemory(q.MemoryBytes)
	}
	n := *q.count(k)
	return int64(n), strconv.Itoa(n)
}

// String shows the limits q sets, "none" when it sets none.
func (q Quota) String() string {
	var parts []string
	for _, k := range quotaKeys {
		if n, s := q.value(k); n > 0 {
			parts = append(parts, k+"="+s)
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ",")
}

// Exceeded lists what makes after break q where before did not already
// use at least as much: shrinking a project that is over a lowered quota
// is always allowed, growing past a limit never is.
func (q Quota) Exceeded(before, after Quota) []string {
	var out []string
	for _, k := range quotaKeys {
		limit, ls := q.value(k)
		now, ns := after.value(k)
		was, _ := before.value(k)
		if limit > 0 && now > limit && now > was {
			out = append(out, fmt.Sprintf("%s %s of %s", k, ns, ls))
		}
	}
	return out
}

// Usage shows used against q, key by key, for every key q limits or used
// sets: "cpu=500m/4,replicas=3/20,secrets=2".
func Usage(used, q Quota) string {
	var parts []string
	for _, k := range quotaKeys {
		u, us := used.value(k)
		l, ls := q.value(k)
		switch {
		case l > 0:
			parts = append(parts, k+"="+us+"/"+ls)
		case u > 0:
			parts = append(parts, k+"="+us)
		}
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, ",")
}

// FormatCPUMillis shows millicores as a CPU quantity: "4", "1.5", "250m".
func FormatCPUMillis(m int64) string {
	switch {
	case m%1000 == 0:
		return strconv.FormatInt(m/1000, 10)
	case m > 1000 && m%100 == 0:
		return strconv.FormatFloat(float64(m)/1000, 'f', -1, 64)
	}
	return strconv.FormatInt(m, 10) + "m"
}

// FormatMemory shows bytes as a memory quantity: "8Gi", "512Mi", or bytes.
func FormatMemory(b int64) string {
	switch {
	case b >= 1<<30 && b%(1<<30) == 0:
		return strconv.FormatInt(b>>30, 10) + "Gi"
	case b >= 1<<20 && b%(1<<20) == 0:
		return strconv.FormatInt(b>>20, 10) + "Mi"
	case b >= 1<<10 && b%(1<<10) == 0:
		return strconv.FormatInt(b>>10, 10) + "Ki"
	}
	return strconv.FormatInt(b, 10)
}
