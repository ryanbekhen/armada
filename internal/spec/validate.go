package spec

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ErrUnsupported marks fields that are part of the format but not yet
// implemented by this version of Armada.
var ErrUnsupported = errors.New("not supported in this version")

// FieldError describes one invalid field.
type FieldError struct {
	Field string
	Msg   string
	Err   error
}

func (e *FieldError) Error() string { return e.Field + ": " + e.Msg }

// Unwrap allows errors.Is(err, ErrUnsupported).
func (e *FieldError) Unwrap() error { return e.Err }

// Limits.
const (
	MaxReplicas     = 100
	MinMemoryBytes  = 16 << 20
	MaxMemoryBytes  = 64 << 30
	MinNanoCPUs     = 10_000_000 // 10m
	MaxNanoCPUs     = 64_000_000_000
	DefaultMemory   = "256Mi"
	DefaultPids     = 1024
	maxImageLen     = 512
	maxArgs         = 256
	maxArgLen       = 4096
	maxEnv          = 512
	maxEnvValueLen  = 32 << 10
	maxDomains      = 32
	maxRoutes       = 32
	maxPathLen      = 256
	maxDomainLen    = 253
	reservedEnvPfx  = "ARMADA_"
	defaultPeriod   = 10 * time.Second
	defaultTimeout  = time.Second
	defaultFailures = 3
	startupFailures = 30
)

var (
	// DNS label, no consecutive hyphens ("--" separates app and revision).
	nameRe     = regexp.MustCompile(`^[a-z]([a-z0-9]|-[a-z0-9])*$`)
	envNameRe  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	labelRe    = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)
	routePath  = regexp.MustCompile(`^/([A-Za-z0-9._~-]+(/[A-Za-z0-9._~-]+)*)?$`)
	probePath  = regexp.MustCompile(`^/[A-Za-z0-9._~/-]*(\?[A-Za-z0-9._~=&%-]*)?$`)
	imageRe    = regexp.MustCompile(`^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*(?::[0-9]+)?/)?[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*(?::[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127})?(?:@sha256:[a-f0-9]{64})?$`)
	memoryRe   = regexp.MustCompile(`^([0-9]+)(Ki|Mi|Gi|K|M|G)?$`)
	cpuMilliRe = regexp.MustCompile(`^([0-9]+)m$`)
	cpuCoreRe  = regexp.MustCompile(`^[0-9]+(\.[0-9]{1,3})?$`)
)

// SetDefaults fills optional fields. Parse calls it before Validate.
func (a *App) SetDefaults() {
	if a.Kind == "" {
		a.Kind = KindApp
	}
	if a.Ingress == nil {
		a.Ingress = &Ingress{Type: IngressNone}
	}
	if a.Revisions == nil {
		a.Revisions = &Revisions{}
	}
	if a.Revisions.Mode == "" {
		a.Revisions.Mode = RevisionsSingle
	}
	if a.Probes != nil {
		for _, p := range []struct {
			probe    *Probe
			failures int
		}{{a.Probes.Startup, startupFailures}, {a.Probes.Readiness, defaultFailures}, {a.Probes.Liveness, defaultFailures}} {
			if p.probe == nil {
				continue
			}
			if p.probe.Port == 0 {
				p.probe.Port = a.Ingress.Port
			}
			if p.probe.Period == 0 {
				p.probe.Period = Duration(defaultPeriod)
			}
			if p.probe.Timeout == 0 {
				p.probe.Timeout = Duration(defaultTimeout)
			}
			if p.probe.FailureThreshold == 0 {
				p.probe.FailureThreshold = p.failures
			}
		}
	}
	if a.Scale == nil {
		a.Scale = &Scale{}
	}
	if a.Scale.Min == nil {
		one := 1
		a.Scale.Min = &one
	}
	if a.Scale.Max == nil {
		m := *a.Scale.Min
		a.Scale.Max = &m
	}
	if a.Resources == nil {
		a.Resources = &Resources{}
	}
	if a.Resources.Memory == "" {
		a.Resources.Memory = DefaultMemory
	}
}

// Replicas is the number of replicas to run in v0.1 (scale.min).
func (a *App) Replicas() int {
	if a.Scale == nil || a.Scale.Min == nil {
		return 1
	}
	return *a.Scale.Min
}

// MemoryBytes returns the memory limit. It assumes a validated spec.
func (a *App) MemoryBytes() int64 {
	if a.Resources == nil {
		v, _ := ParseMemory(DefaultMemory)
		return v
	}
	v, _ := ParseMemory(a.Resources.Memory)
	return v
}

// NanoCPUs returns the CPU limit, or 0 for no limit. It assumes a validated spec.
func (a *App) NanoCPUs() int64 {
	if a.Resources == nil || a.Resources.CPU == "" {
		return 0
	}
	v, _ := ParseCPU(a.Resources.CPU)
	return v
}

// Validate checks the spec and returns all problems joined together.
func (a *App) Validate() error {
	var v validator

	if a.APIVersion != "" && a.APIVersion != APIVersion {
		v.add("apiVersion", "must be %q", APIVersion)
	}
	switch a.Kind {
	case KindApp:
	case KindJob:
		v.unsupported("kind", "jobs are planned for v0.2")
	default:
		v.add("kind", "must be %q", KindApp)
	}
	v.name("name", a.Name)
	v.image("image", a.Image)
	v.args("command", a.Command)
	v.args("args", a.Args)
	v.env(a.Env)
	v.secretFiles(a.SecretFiles)
	v.registry(a.Registry, a.Image)
	v.ingress(a.Ingress)
	v.revisions(a.Revisions)
	v.probes(a.Probes)
	v.scale(a.Scale)
	v.resources(a.Resources)
	v.placement(a.Placement)

	return errors.Join(v.errs...)
}

type validator struct{ errs []error }

func (v *validator) add(field, format string, args ...any) {
	v.errs = append(v.errs, &FieldError{Field: field, Msg: fmt.Sprintf(format, args...)})
}

func (v *validator) unsupported(field, msg string) {
	v.errs = append(v.errs, &FieldError{Field: field, Msg: msg, Err: ErrUnsupported})
}

func (v *validator) name(field, s string) {
	switch {
	case s == "":
		v.add(field, "is required")
	case len(s) > 63:
		v.add(field, "must be at most 63 characters")
	case !nameRe.MatchString(s):
		v.add(field, "must be lowercase letters, digits, and single hyphens, starting with a letter and not ending with a hyphen")
	}
}

func (v *validator) image(field, s string) {
	switch {
	case s == "":
		v.add(field, "is required")
	case len(s) > maxImageLen:
		v.add(field, "must be at most %d characters", maxImageLen)
	case !imageRe.MatchString(s):
		v.add(field, "is not a valid image reference")
	}
}

func (v *validator) args(field string, args []string) {
	if len(args) > maxArgs {
		v.add(field, "must have at most %d entries", maxArgs)
		return
	}
	for i, a := range args {
		if len(a) > maxArgLen {
			v.add(fmt.Sprintf("%s[%d]", field, i), "must be at most %d bytes", maxArgLen)
		}
		if strings.ContainsRune(a, 0) {
			v.add(fmt.Sprintf("%s[%d]", field, i), "must not contain NUL bytes")
		}
	}
}

func (v *validator) env(env []EnvVar) {
	if len(env) > maxEnv {
		v.add("env", "must have at most %d entries", maxEnv)
		return
	}
	seen := map[string]bool{}
	for i, e := range env {
		f := fmt.Sprintf("env[%d]", i)
		switch {
		case !envNameRe.MatchString(e.Name):
			v.add(f+".name", "must match %s", envNameRe)
		case strings.HasPrefix(e.Name, reservedEnvPfx) || e.Name == "PORT":
			v.add(f+".name", "%q is reserved for Armada", e.Name)
		case seen[e.Name]:
			v.add(f+".name", "duplicate variable %q", e.Name)
		}
		seen[e.Name] = true
		if e.SecretRef != "" {
			if e.Value != "" {
				v.add(f, "set either value or secretRef, not both")
			}
			v.secretName(f+".secretRef", e.SecretRef)
		}
		if len(e.Value) > maxEnvValueLen {
			v.add(f+".value", "must be at most %d bytes", maxEnvValueLen)
		}
		if strings.ContainsRune(e.Value, 0) {
			v.add(f+".value", "must not contain NUL bytes")
		}
	}
}

func (v *validator) ingress(in *Ingress) {
	if in == nil {
		return
	}
	switch in.Type {
	case IngressExternal:
	case IngressInternal:
		if len(in.Domains) > 0 {
			v.add("ingress.domains", "custom domains require type external; internal apps are reachable at http://<app>%s", InternalSuffix)
		}
	case IngressNone:
		if in.Port != 0 || len(in.Domains) > 0 || len(in.Routes) > 0 {
			v.add("ingress", "port, domains, and routes require type external or internal")
		}
		return
	case "":
		v.add("ingress.type", "is required (external, internal, or none)")
		return
	default:
		v.add("ingress.type", "must be external, internal, or none")
		return
	}

	if in.Port < 1 || in.Port > 65535 {
		v.add("ingress.port", "must be between 1 and 65535")
	}
	if len(in.Domains) > maxDomains {
		v.add("ingress.domains", "must have at most %d entries", maxDomains)
	}
	seen := map[string]bool{}
	for i, d := range in.Domains {
		f := fmt.Sprintf("ingress.domains[%d]", i)
		if err := ValidateDomain(d); err != nil {
			v.add(f, "%v", err)
		} else if seen[d] {
			v.add(f, "duplicate domain %q", d)
		}
		seen[d] = true
	}
	if len(in.Routes) > maxRoutes {
		v.add("ingress.routes", "must have at most %d entries", maxRoutes)
	}
	paths := map[string]bool{}
	for i, r := range in.Routes {
		f := fmt.Sprintf("ingress.routes[%d].path", i)
		if err := ValidateRoutePath(r.Path); err != nil {
			v.add(f, "%v", err)
			continue
		}
		if paths[r.Path] {
			v.add(f, "duplicate path %q", r.Path)
		}
		paths[r.Path] = true
		if r.Path == "/" && r.StripPrefix {
			v.add(fmt.Sprintf("ingress.routes[%d].stripPrefix", i), "cannot strip the root path")
		}
	}
}

// ValidateDomain checks that d is a lowercase, fully qualified hostname
// without a trailing dot or wildcard.
func ValidateDomain(d string) error {
	if d == "" {
		return errors.New("must not be empty")
	}
	if len(d) > maxDomainLen {
		return fmt.Errorf("must be at most %d characters", maxDomainLen)
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return errors.New("must be a fully qualified domain name")
	}
	for _, l := range labels {
		if len(l) == 0 || len(l) > 63 || !labelRe.MatchString(l) {
			return fmt.Errorf("%q is not a valid lowercase domain name", d)
		}
	}
	if _, err := strconv.Atoi(labels[len(labels)-1]); err == nil {
		return errors.New("must be a domain name, not an IP address")
	}
	if "."+labels[len(labels)-1] == InternalSuffix {
		return fmt.Errorf("the %s zone is reserved for names inside the cluster", InternalSuffix)
	}
	return nil
}

// InternalSuffix is the DNS zone of cluster-internal app names.
const InternalSuffix = ".internal"

// InternalHost returns the cluster-internal hostname of an app.
func InternalHost(app string) string { return app + InternalSuffix }

// ValidateRoutePath checks a route path prefix: it starts with "/", has no
// trailing slash (except "/"), no empty or dot segments, and only unreserved
// URL characters.
func ValidateRoutePath(p string) error {
	if len(p) > maxPathLen {
		return fmt.Errorf("must be at most %d characters", maxPathLen)
	}
	if !routePath.MatchString(p) {
		return errors.New(`must start with "/" and contain only letters, digits, and . _ ~ - separated by single "/", without a trailing "/"`)
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "." || seg == ".." {
			return errors.New(`must not contain "." or ".." segments`)
		}
	}
	return nil
}

func (v *validator) revisions(r *Revisions) {
	if r == nil {
		return
	}
	switch r.Mode {
	case RevisionsSingle:
		if len(r.Traffic) > 0 {
			v.add("revisions.traffic", "is only allowed in multiple mode")
		}
	case RevisionsMultiple:
		v.unsupported("revisions.mode", "multiple revision mode is planned for v0.2")
	default:
		v.add("revisions.mode", "must be single or multiple")
	}
}

func (v *validator) probes(p *Probes) {
	if p == nil {
		return
	}
	for _, c := range []struct {
		name  string
		probe *Probe
	}{{"startup", p.Startup}, {"readiness", p.Readiness}, {"liveness", p.Liveness}} {
		if c.probe == nil {
			continue
		}
		f := "probes." + c.name
		pr := c.probe
		if len(pr.Path) > maxPathLen || !probePath.MatchString(pr.Path) {
			v.add(f+".path", `must start with "/" and contain only URL-safe characters`)
		}
		if pr.Port < 1 || pr.Port > 65535 {
			v.add(f+".port", "must be between 1 and 65535 (defaults to ingress.port)")
		}
		if pr.InitialDelay < 0 || pr.InitialDelay.D() > 10*time.Minute {
			v.add(f+".initialDelay", "must be between 0 and 10m")
		}
		if pr.Period.D() < time.Second || pr.Period.D() > 5*time.Minute {
			v.add(f+".period", "must be between 1s and 5m")
		}
		if pr.Timeout.D() < time.Second || pr.Timeout > pr.Period {
			v.add(f+".timeout", "must be at least 1s and not longer than period")
		}
		if pr.FailureThreshold < 1 || pr.FailureThreshold > 100 {
			v.add(f+".failureThreshold", "must be between 1 and 100")
		}
	}
}

func (v *validator) scale(s *Scale) {
	if s == nil || s.Min == nil || s.Max == nil {
		return
	}
	minR, maxR := *s.Min, *s.Max
	switch {
	case minR == 0:
		v.unsupported("scale.min", "scale to zero is planned for v0.3")
	case minR < 0 || minR > MaxReplicas:
		v.add("scale.min", "must be between 1 and %d", MaxReplicas)
	}
	if maxR < minR || maxR > MaxReplicas {
		v.add("scale.max", "must be between scale.min and %d", MaxReplicas)
	}
	if len(s.Rules) > 0 {
		v.unsupported("scale.rules", "autoscaling is planned for v0.2; v0.1 runs scale.min replicas")
	}
}

func (v *validator) resources(r *Resources) {
	if r == nil {
		return
	}
	if r.Memory != "" {
		m, err := ParseMemory(r.Memory)
		switch {
		case err != nil:
			v.add("resources.memory", "%v", err)
		case m < MinMemoryBytes || m > MaxMemoryBytes:
			v.add("resources.memory", "must be between 16Mi and 64Gi")
		}
	}
	if r.CPU != "" {
		c, err := ParseCPU(r.CPU)
		switch {
		case err != nil:
			v.add("resources.cpu", "%v", err)
		case c < MinNanoCPUs || c > MaxNanoCPUs:
			v.add("resources.cpu", "must be between 10m and 64")
		}
	}
}

// ParseMemory parses quantities like "512Mi", "1G", or "1048576".
func ParseMemory(s string) (int64, error) {
	m := memoryRe.FindStringSubmatch(s)
	if m == nil {
		return 0, fmt.Errorf("invalid memory quantity %q (use e.g. 256Mi or 1Gi)", s)
	}
	n, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid memory quantity %q", s)
	}
	mult := map[string]int64{"": 1, "K": 1e3, "M": 1e6, "G": 1e9, "Ki": 1 << 10, "Mi": 1 << 20, "Gi": 1 << 30}[m[2]]
	if n > math.MaxInt64/mult {
		return 0, fmt.Errorf("memory quantity %q is too large", s)
	}
	return n * mult, nil
}

// ParseCPU parses "500m" or "0.5" into nano-CPUs.
func ParseCPU(s string) (int64, error) {
	if m := cpuMilliRe.FindStringSubmatch(s); m != nil {
		n, err := strconv.ParseInt(m[1], 10, 64)
		if err != nil || n > math.MaxInt64/1_000_000 {
			return 0, fmt.Errorf("invalid cpu quantity %q", s)
		}
		return n * 1e6, nil
	}
	if cpuCoreRe.MatchString(s) {
		f, err := strconv.ParseFloat(s, 64)
		if err != nil || f > 1e6 {
			return 0, fmt.Errorf("invalid cpu quantity %q", s)
		}
		return int64(math.Round(f * 1e9)), nil
	}
	return 0, fmt.Errorf("invalid cpu quantity %q (use e.g. 0.5 or 500m)", s)
}

// ValidateName checks an app name: a DNS label without consecutive hyphens.
func ValidateName(s string) error {
	var v validator
	v.name("name", s)
	return errors.Join(v.errs...)
}

// ValidateProbePath checks an HTTP health check path.
func ValidateProbePath(p string) error {
	if len(p) > maxPathLen || !probePath.MatchString(p) {
		return errors.New(`must start with "/" and contain only URL-safe characters`)
	}
	return nil
}
