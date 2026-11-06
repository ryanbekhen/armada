// Package spec defines the user-facing app configuration format, its strict
// YAML parsing, defaulting, and validation.
//
// Validation here is the first line of defense against configuration
// injection: every value that later reaches generated proxy configuration or
// container settings must be constrained by a whitelist in this package.
package spec

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"time"

	"go.yaml.in/yaml/v3"
)

// APIVersion is the only accepted value for the optional apiVersion field.
const APIVersion = "armada.dev/v1alpha1"

// MaxSpecBytes bounds the size of a spec document.
const MaxSpecBytes = 1 << 20

// Kinds.
const (
	KindApp = "app"
	KindJob = "job"
)

// Ingress types.
const (
	IngressExternal = "external"
	IngressInternal = "internal"
	IngressNone     = "none"
)

// Revision modes.
const (
	RevisionsSingle   = "single"
	RevisionsMultiple = "multiple"
)

// App is the configuration for a long-running containerized application.
type App struct {
	APIVersion string   `yaml:"apiVersion,omitempty" json:"apiVersion,omitempty"`
	Kind       string   `yaml:"kind,omitempty" json:"kind,omitempty"`
	Name       string   `yaml:"name" json:"name"`
	Image      string   `yaml:"image" json:"image"`
	Command    []string `yaml:"command,omitempty" json:"command,omitempty"`
	Args       []string `yaml:"args,omitempty" json:"args,omitempty"`
	Env        []EnvVar `yaml:"env,omitempty" json:"env,omitempty"`
	// SecretFiles mounts secrets as read-only files.
	SecretFiles []SecretFile `yaml:"secretFiles,omitempty" json:"secretFiles,omitempty"`
	// Registry holds credentials for pulling Image from a private registry.
	Registry  *Registry  `yaml:"registry,omitempty" json:"registry,omitempty"`
	Ingress   *Ingress   `yaml:"ingress,omitempty" json:"ingress,omitempty"`
	Revisions *Revisions `yaml:"revisions,omitempty" json:"revisions,omitempty"`
	Probes    *Probes    `yaml:"probes,omitempty" json:"probes,omitempty"`
	Scale     *Scale     `yaml:"scale,omitempty" json:"scale,omitempty"`
	Resources *Resources `yaml:"resources,omitempty" json:"resources,omitempty"`
	Placement *Placement `yaml:"placement,omitempty" json:"placement,omitempty"`
	// Volumes keep data across restarts on the replica's node (ADR 0023).
	Volumes []Volume `yaml:"volumes,omitempty" json:"volumes,omitempty"`
	// Drain is how long a replica leaving serves the requests it has before
	// it stops; zero means the default.
	Drain Duration `yaml:"drain,omitempty" json:"drain,omitempty"`

	// Project is the project the app belongs to (ADR 0026), set by the API
	// rather than the file; empty means the default project.
	Project string `yaml:"-" json:"project,omitempty"`

	// Job settings (kind: job, ADR 0019).
	Schedule    string   `yaml:"schedule,omitempty" json:"schedule,omitempty"`
	TimeZone    string   `yaml:"timeZone,omitempty" json:"timeZone,omitempty"`
	Timeout     Duration `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	Retries     int      `yaml:"retries,omitempty" json:"retries,omitempty"`
	Concurrency string   `yaml:"concurrency,omitempty" json:"concurrency,omitempty"`
	History     *int     `yaml:"history,omitempty" json:"history,omitempty"`
}

// EnvVar is an environment variable, either literal or from a secret.
type EnvVar struct {
	Name      string `yaml:"name" json:"name"`
	Value     string `yaml:"value,omitempty" json:"value,omitempty"`
	SecretRef string `yaml:"secretRef,omitempty" json:"secretRef,omitempty"`
}

// Ingress controls how the app receives traffic.
type Ingress struct {
	Type    string   `yaml:"type" json:"type"`
	Port    int      `yaml:"port,omitempty" json:"port,omitempty"`
	Domains []string `yaml:"domains,omitempty" json:"domains,omitempty"`
	Routes  []Route  `yaml:"routes,omitempty" json:"routes,omitempty"`
	// Allow names the apps and jobs of the same project that may call this
	// app through its internal name; empty lets every app of the project
	// (ADR 0025, ADR 0026). Replicas of the app itself always may.
	Allow []string `yaml:"allow,omitempty" json:"allow,omitempty"`
}

// Route maps a path prefix on the app's hosts to the app.
type Route struct {
	Path        string `yaml:"path" json:"path"`
	StripPrefix bool   `yaml:"stripPrefix,omitempty" json:"stripPrefix,omitempty"`
}

// Revisions controls how revisions receive traffic.
type Revisions struct {
	Mode    string          `yaml:"mode,omitempty" json:"mode,omitempty"`
	Traffic []TrafficTarget `yaml:"traffic,omitempty" json:"traffic,omitempty"`
}

// TrafficTarget assigns a traffic weight to a revision (multiple mode only).
type TrafficTarget struct {
	Revision string `yaml:"revision" json:"revision"`
	Weight   int    `yaml:"weight" json:"weight"`
	Label    string `yaml:"label,omitempty" json:"label,omitempty"`
}

// Probes configures container health checks.
type Probes struct {
	Startup   *Probe `yaml:"startup,omitempty" json:"startup,omitempty"`
	Readiness *Probe `yaml:"readiness,omitempty" json:"readiness,omitempty"`
	Liveness  *Probe `yaml:"liveness,omitempty" json:"liveness,omitempty"`
}

// Probe is an HTTP GET health check. In YAML it may be written as just the
// path, e.g. `readiness: /healthz`.
type Probe struct {
	Path             string   `yaml:"path" json:"path"`
	Port             int      `yaml:"port,omitempty" json:"port,omitempty"`
	InitialDelay     Duration `yaml:"initialDelay,omitempty" json:"initialDelay,omitempty"`
	Period           Duration `yaml:"period,omitempty" json:"period,omitempty"`
	Timeout          Duration `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	FailureThreshold int      `yaml:"failureThreshold,omitempty" json:"failureThreshold,omitempty"`
}

// UnmarshalYAML accepts either a mapping or a scalar path.
func (p *Probe) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		*p = Probe{Path: n.Value}
		return nil
	}
	type plain Probe
	var v plain
	if err := decodeStrict(n, &v); err != nil {
		return err
	}
	*p = Probe(v)
	return nil
}

// Scale controls replica counts. Without Rules the app runs Min replicas;
// with Rules the autoscaler keeps it between Min and Max (ADR 0020).
type Scale struct {
	Min   *int        `yaml:"min,omitempty" json:"min,omitempty"`
	Max   *int        `yaml:"max,omitempty" json:"max,omitempty"`
	Rules []ScaleRule `yaml:"rules,omitempty" json:"rules,omitempty"`
	// IdleAfter is how long an app with Min 0 may go without a request
	// before it scales to zero (ADR 0021).
	IdleAfter Duration `yaml:"idleAfter,omitempty" json:"idleAfter,omitempty"`
}

// ScaleRule is one autoscaler trigger. Which fields apply depends on Type:
// http takes Concurrent (requests in progress per replica), cpu and memory
// take Utilization (percent of the replica's reservation). The queue and
// schedule fields are reserved.
type ScaleRule struct {
	Type        string `yaml:"type" json:"type"`
	Concurrent  int    `yaml:"concurrent,omitempty" json:"concurrent,omitempty"`
	Utilization int    `yaml:"utilization,omitempty" json:"utilization,omitempty"`
	List        string `yaml:"list,omitempty" json:"list,omitempty"`
	Length      int    `yaml:"length,omitempty" json:"length,omitempty"`
	Schedule    string `yaml:"schedule,omitempty" json:"schedule,omitempty"`
	Timezone    string `yaml:"timezone,omitempty" json:"timezone,omitempty"`
	Replicas    int    `yaml:"replicas,omitempty" json:"replicas,omitempty"`
}

// Resources sets per-replica limits. CPU is in cores ("0.5") or millicores
// ("500m"); Memory uses binary or decimal suffixes ("256Mi", "1G").
type Resources struct {
	CPU    string `yaml:"cpu,omitempty" json:"cpu,omitempty"`
	Memory string `yaml:"memory,omitempty" json:"memory,omitempty"`
}

// Duration is a time.Duration written as a Go duration string ("10s").
type Duration time.Duration

// D returns the value as a time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

// UnmarshalYAML parses a duration string.
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode {
		return fmt.Errorf("line %d: duration must be a string like \"10s\"", n.Line)
	}
	v, err := time.ParseDuration(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: invalid duration %q", n.Line, n.Value)
	}
	*d = Duration(v)
	return nil
}

// MarshalJSON writes the duration as a string.
func (d Duration) MarshalJSON() ([]byte, error) {
	return []byte(`"` + time.Duration(d).String() + `"`), nil
}

// UnmarshalJSON reads a duration string.
func (d *Duration) UnmarshalJSON(b []byte) error {
	if len(b) < 2 || b[0] != '"' || b[len(b)-1] != '"' {
		return fmt.Errorf("duration must be a JSON string")
	}
	v, err := time.ParseDuration(string(b[1 : len(b)-1]))
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

// Parse decodes, defaults, and validates an app spec of the default
// project.
func Parse(data []byte) (*App, error) { return ParseIn(data, "") }

// ParseIn is Parse for an app of project (ADR 0026); empty means the
// default project.
func ParseIn(data []byte, project string) (*App, error) {
	if len(data) > MaxSpecBytes {
		return nil, fmt.Errorf("spec is larger than %d bytes", MaxSpecBytes)
	}

	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var app App
	if err := dec.Decode(&app); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("spec is empty")
		}
		return nil, fmt.Errorf("invalid spec: %w", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("spec must contain exactly one YAML document")
	}

	if project != DefaultProject {
		app.Project = project
	}
	app.SetDefaults()
	if err := app.Validate(); err != nil {
		return nil, err
	}
	return &app, nil
}

func decodeStrict(n *yaml.Node, v any) error {
	// yaml.Node.Decode does not honor KnownFields, so re-encode the node and
	// decode it with a strict decoder.
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	if err := enc.Encode(n); err != nil {
		return err
	}
	dec := yaml.NewDecoder(&buf)
	dec.KnownFields(true)
	return dec.Decode(v)
}
