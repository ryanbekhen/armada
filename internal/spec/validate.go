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
	MaxReplicas    = 100
	MinMemoryBytes = 16 << 20
	MaxMemoryBytes = 64 << 30
	MinNanoCPUs    = 10_000_000 // 10m
	MaxNanoCPUs    = 64_000_000_000
	DefaultMemory  = "256Mi"
	// DefaultCPUMillis is the CPU reserved for a replica whose spec sets no
	// resources.cpu; such a replica has no CPU limit.
	DefaultCPUMillis = 100
	DefaultPids      = 1024
	maxImageLen      = 512
	maxArgs          = 256
	maxArgLen        = 4096
	maxEnv           = 512
	maxEnvValueLen   = 32 << 10
	maxDomains       = 32
	maxRoutes        = 32
	maxPathLen       = 256
	maxDomainLen     = 253
	reservedEnvPfx   = "ARMADA_"
	defaultPeriod    = 10 * time.Second
	defaultTimeout   = time.Second
	defaultFailures  = 3
	startupFailures  = 30
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
	if a.Scale == nil && !a.IsJob() {
		a.Scale = &Scale{}
	}
	if a.Scale != nil && a.Scale.Min == nil {
		one := 1
		a.Scale.Min = &one
	}
	if a.Scale != nil && a.Scale.Max == nil {
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

// Autoscaled reports whether the autoscaler sets the app's replica count.
func (a *App) Autoscaled() bool {
	return !a.IsJob() && a.Scale != nil && len(a.Scale.Rules) > 0
}

// ScaleBounds returns scale.min and scale.max. It assumes a validated spec.
func (a *App) ScaleBounds() (lo, hi int) {
	if a.IsJob() {
		return 0, 0
	}
	lo = 1
	if a.Scale != nil && a.Scale.Min != nil {
		lo = *a.Scale.Min
	}
	hi = lo
	if a.Scale != nil && a.Scale.Max != nil {
		hi = *a.Scale.Max
	}
	return lo, hi
}

// ScalesToZero reports whether the app stops its last replica when idle
// (ADR 0021).
func (a *App) ScalesToZero() bool {
	lo, _ := a.ScaleBounds()
	return a.Autoscaled() && lo == 0
}

// IdleAfter returns how long an app that scales to zero may go without a
// request before it does.
func (a *App) IdleAfter() time.Duration {
	if a.Scale == nil || a.Scale.IdleAfter == 0 {
		return DefaultIdleAfter
	}
	return a.Scale.IdleAfter.D()
}

// Replicas is the number of replicas a deploy starts with (scale.min, and
// one for an app that scales to zero, so a deploy shows the image runs);
// the autoscaler may change it later. Jobs run none outside their runs.
func (a *App) Replicas() int {
	if a.IsJob() {
		return 0
	}
	lo, _ := a.ScaleBounds()
	return max(lo, 1)
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

// CPUMillis returns the CPU reserved for each replica on its node, in
// millicores: resources.cpu, or DefaultCPUMillis. It assumes a validated spec.
func (a *App) CPUMillis() int64 {
	if n := a.NanoCPUs(); n > 0 {
		return max(1, n/1_000_000)
	}
	return DefaultCPUMillis
}

// Validate checks the spec and returns all problems joined together.
// MaxDrain is the longest drain: what ingress keeps a connection after a reload.
const MaxDrain = time.Hour

func (a *App) Validate() error {
	var v validator

	if a.APIVersion != "" && a.APIVersion != APIVersion {
		v.add("apiVersion", "must be %q", APIVersion)
	}
	switch a.Kind {
	case KindApp, KindJob:
	default:
		v.add("kind", "must be %q or %q", KindApp, KindJob)
	}
	v.name("name", a.Name)
	v.project(a.Project)
	v.image("image", a.Image)
	v.args("command", a.Command)
	v.args("args", a.Args)
	v.env(a.Env)
	v.secretFiles(a.SecretFiles)
	v.registry(a.Registry, a.Image)
	v.ingress(a.Ingress, a.Name)
	if a.Drain != 0 && (a.Drain.D() < time.Second || a.Drain.D() > MaxDrain) {
		v.add("drain", "must be between 1s and %s", MaxDrain)
	}
	v.revisions(a)
	v.probes(a.Probes)
	v.scale(a.Scale, a.Ingress)
	v.resources(a.Resources)
	v.placement(a.Placement)
	v.volumes(a)
	v.job(a)

	return errors.Join(v.errs...)
}

// MaxAllow bounds ingress.allow.
const MaxAllow = 32

type validator struct{ errs []error }

func (v *validator) add(field, format string, args ...any) {
	v.errs = append(v.errs, &FieldError{Field: field, Msg: fmt.Sprintf(format, args...)})
}

func (v *validator) unsupported(field, msg string) {
	v.errs = append(v.errs, &FieldError{Field: field, Msg: msg, Err: ErrUnsupported})
}

// ValidName reports whether s is a valid app, job, or secret name.
func ValidName(s string) bool { return len(s) <= 63 && nameRe.MatchString(s) }

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

func (v *validator) ingress(in *Ingress, self string) {
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
		if in.Port != 0 || len(in.Domains) > 0 || len(in.Routes) > 0 || len(in.Allow) > 0 {
			v.add("ingress", "port, domains, routes, and allow require type external or internal")
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
	if len(in.Allow) > MaxAllow {
		v.add("ingress.allow", "must have at most %d entries", MaxAllow)
	}
	allowed := map[string]bool{}
	for i, a := range in.Allow {
		f := fmt.Sprintf("ingress.allow[%d]", i)
		switch {
		case !ValidName(a):
			v.add(f, "%q is not an app name of this project (lowercase letters, digits, and single hyphens)", a)
		case a == self:
			v.add(f, "the app itself may always call itself; leave it out")
		case allowed[a]:
			v.add(f, "duplicate app %q", a)
		}
		allowed[a] = true
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

// LabelHost is the host name label of a revision of app serves under
// (ADR 0022): <label>--<app>, with app an ID (<label>--<name>.<project>
// in other projects). App names cannot contain "--", so it never collides
// with another app's name.
func LabelHost(label, app string) string { return label + "--" + app }

// ValidHostName reports whether s is an app ID or a LabelHost of one.
func ValidHostName(s string) bool {
	if ValidAppID(s) {
		return true
	}
	label, app, ok := strings.Cut(s, "--")
	return ok && ValidName(label) && ValidAppID(app) && len(label)+2+len(hostLabel(app)) <= 63
}

// hostLabel is the first DNS label of an app ID's host name: its name.
func hostLabel(id string) string {
	name, _, _ := strings.Cut(id, ".")
	return name
}

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

// Traffic splitting (ADR 0022).
const (
	// LatestRevision in revisions.traffic names the revision the deploy
	// creates.
	LatestRevision    = "latest"
	MaxTrafficTargets = 10
)

func (v *validator) revisions(a *App) {
	r := a.Revisions
	if r == nil || a.IsJob() {
		return
	}
	switch r.Mode {
	case RevisionsSingle:
		if len(r.Traffic) > 0 {
			v.add("revisions.traffic", "is only allowed in multiple mode")
		}
	case RevisionsMultiple:
		if a.Ingress == nil || a.Ingress.Type == IngressNone || a.Ingress.Type == "" {
			v.add("revisions.mode", "multiple needs ingress (external or internal): traffic is split at the proxy")
		}
		if a.Scale != nil && a.Scale.Min != nil && *a.Scale.Min == 0 {
			v.add("revisions.mode", "multiple cannot be combined with scale.min: 0")
		}
		for _, e := range CheckTraffic(a.ID(), r.Traffic, true) {
			v.add(e.Field, "%s", e.Msg)
		}
	default:
		v.add("revisions.mode", "must be single or multiple")
	}
}

// CheckTraffic validates traffic targets of app: 1 to 10 of them, each
// revision once ("latest" only if allowLatest), weights 0 to 100 adding up
// to 100, and labels that are valid names, unique, short enough to prefix
// the app's host name (<label>--<app>), and required for weight 0.
func CheckTraffic(app string, traffic []TrafficTarget, allowLatest bool) []*FieldError {
	var errs []*FieldError
	add := func(field, format string, args ...any) {
		errs = append(errs, &FieldError{Field: field, Msg: fmt.Sprintf(format, args...)})
	}
	if len(traffic) == 0 || len(traffic) > MaxTrafficTargets {
		add("revisions.traffic", "needs 1 to %d targets", MaxTrafficTargets)
		return errs
	}
	sum := 0
	revs, labels := map[string]bool{}, map[string]bool{}
	for i, t := range traffic {
		f := fmt.Sprintf("revisions.traffic[%d]", i)
		switch {
		case t.Revision == LatestRevision && allowLatest:
		case !ValidRevisionName(app, t.Revision):
			if allowLatest {
				add(f+".revision", "must be %q or a revision of %s such as %s--r3", LatestRevision, app, app)
			} else {
				add(f+".revision", "must be a revision of %s such as %s--r3", app, app)
			}
		}
		if revs[t.Revision] {
			add(f+".revision", "%s is listed more than once", t.Revision)
		}
		revs[t.Revision] = true
		if t.Weight < 0 || t.Weight > 100 {
			add(f+".weight", "must be between 0 and 100")
		}
		sum += t.Weight
		switch {
		case t.Label == "":
			if t.Weight == 0 {
				add(f+".label", "is required for weight 0 (the revision is then reached only through its label)")
			}
		case !ValidName(t.Label):
			add(f+".label", "must be lowercase letters, digits, and single hyphens, starting with a letter")
		case len(t.Label)+2+len(hostLabel(app)) > 63:
			add(f+".label", "%s--%s must be at most 63 characters", t.Label, hostLabel(app))
		case labels[t.Label]:
			add(f+".label", "%q is used more than once", t.Label)
		}
		labels[t.Label] = true
	}
	if sum != 100 {
		add("revisions.traffic", "weights must add up to 100, not %d", sum)
	}
	return errs
}

// ValidRevisionName reports whether rev names a revision of app
// (<app>--r<number>).
func ValidRevisionName(app, rev string) bool {
	seq, ok := strings.CutPrefix(rev, app+"--r")
	if !ok || seq == "" || seq[0] == '0' || len(seq) > 9 {
		return false
	}
	for _, c := range seq {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// MultipleRevisions reports whether the app splits traffic between
// revisions (ADR 0022).
func (a *App) MultipleRevisions() bool {
	return !a.IsJob() && a.Revisions != nil && a.Revisions.Mode == RevisionsMultiple
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

func (v *validator) scale(s *Scale, ing *Ingress) {
	if s == nil || s.Min == nil || s.Max == nil {
		return
	}
	minR, maxR := *s.Min, *s.Max
	switch {
	case minR == 0:
		if len(s.Rules) == 0 {
			v.add("scale.min", "can be 0 only with scale.rules, which take over once the app has woken up")
		}
		if ing == nil || ing.Type == IngressNone || ing.Type == "" {
			v.add("scale.min", "can be 0 only with ingress (external or internal): a request wakes the app")
		}
	case minR < 0 || minR > MaxReplicas:
		v.add("scale.min", "must be between 0 and %d", MaxReplicas)
	}
	switch idle := s.IdleAfter.D(); {
	case idle == 0:
	case minR != 0:
		v.add("scale.idleAfter", "is only valid with scale.min: 0")
	case idle < MinIdleAfter || idle > MaxIdleAfter:
		v.add("scale.idleAfter", "must be between %s and %s", MinIdleAfter, MaxIdleAfter)
	}
	if maxR < minR || maxR > MaxReplicas {
		v.add("scale.max", "must be between scale.min and %d", MaxReplicas)
	}
	v.scaleRules(s, ing)
}

// Autoscaler rule types (ADR 0020).
const (
	ScaleHTTP   = "http"
	ScaleCPU    = "cpu"
	ScaleMemory = "memory"

	MaxConcurrent = 10000

	// Scale to zero (ADR 0021).
	DefaultIdleAfter = 15 * time.Minute
	MinIdleAfter     = time.Minute
	MaxIdleAfter     = 24 * time.Hour
)

func (v *validator) scaleRules(s *Scale, ing *Ingress) {
	if len(s.Rules) == 0 {
		return
	}
	if *s.Max <= *s.Min {
		v.add("scale.max", "must be greater than scale.min when scale.rules are set")
	}
	seen := map[string]bool{}
	for i, r := range s.Rules {
		f := fmt.Sprintf("scale.rules[%d]", i)
		if seen[r.Type] {
			v.add(f+".type", "%q is used more than once", r.Type)
		}
		seen[r.Type] = true
		if r.List != "" || r.Length != 0 || r.Schedule != "" || r.Timezone != "" || r.Replicas != 0 {
			v.unsupported(f, "queue and schedule rules are not implemented yet")
			continue
		}
		switch r.Type {
		case ScaleHTTP:
			if r.Concurrent < 1 || r.Concurrent > MaxConcurrent {
				v.add(f+".concurrent", "must be between 1 and %d", MaxConcurrent)
			}
			if r.Utilization != 0 {
				v.add(f+".utilization", "is only valid for cpu and memory rules")
			}
			if ing == nil || ing.Type == IngressNone || ing.Type == "" {
				v.add(f+".type", "http rules need ingress (external or internal): requests are counted at the proxy")
			}
		case ScaleCPU, ScaleMemory:
			if r.Utilization < 1 || r.Utilization > 100 {
				v.add(f+".utilization", "must be between 1 and 100 (percent of resources.%s)", r.Type)
			}
			if r.Concurrent != 0 {
				v.add(f+".concurrent", "is only valid for http rules")
			}
		case "queue", "schedule":
			v.unsupported(f+".type", r.Type+" rules are not implemented yet")
		default:
			v.add(f+".type", "must be %q, %q, or %q", ScaleHTTP, ScaleCPU, ScaleMemory)
		}
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
