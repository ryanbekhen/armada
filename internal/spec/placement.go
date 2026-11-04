package spec

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Node labels (ADR 0014). Keys may contain a "/" (e.g. "example.org/rack"),
// values may not. Keys starting with ReservedLabelPrefix are set by Armada.
const (
	ReservedLabelPrefix = "armada."
	LabelOS             = ReservedLabelPrefix + "os"
	LabelArch           = ReservedLabelPrefix + "arch"
	maxLabelLen         = 63
	// MaxNodeLabels is how many admin labels a node may carry.
	MaxNodeLabels = 32
	// maxRequire bounds placement.require: keys and values per key.
	maxRequire = 16
)

var (
	labelKeyRe   = regexp.MustCompile(`^[a-z0-9]([a-z0-9._/-]*[a-z0-9])?$`)
	labelValueRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$`)
)

// CheckLabelKey reports whether k is a valid label key.
func CheckLabelKey(k string) error {
	switch {
	case k == "":
		return errors.New("label key is empty")
	case len(k) > maxLabelLen:
		return fmt.Errorf("label key %q is longer than %d characters", k, maxLabelLen)
	case !labelKeyRe.MatchString(k) || strings.Contains(k, "//"):
		return fmt.Errorf("label key %q must be lowercase letters, digits, '.', '-', '_', or '/', starting and ending with a letter or digit", k)
	}
	return nil
}

// CheckLabelValue reports whether v is a valid label value.
func CheckLabelValue(v string) error {
	switch {
	case v == "":
		return errors.New("label value is empty")
	case len(v) > maxLabelLen:
		return fmt.Errorf("label value %q is longer than %d characters", v, maxLabelLen)
	case !labelValueRe.MatchString(v):
		return fmt.Errorf("label value %q must be lowercase letters, digits, '.', '-', or '_', starting and ending with a letter or digit", v)
	}
	return nil
}

// CheckAdminLabel validates a label an admin sets: a valid key outside the
// reserved prefix and a valid value.
func CheckAdminLabel(k, v string) error {
	if err := CheckLabelKey(k); err != nil {
		return err
	}
	if strings.HasPrefix(k, ReservedLabelPrefix) {
		return fmt.Errorf("label key %q: the %q prefix is reserved for labels Armada sets", k, ReservedLabelPrefix)
	}
	return CheckLabelValue(v)
}

// Placement restricts the nodes an app's replicas may run on (ADR 0014).
type Placement struct {
	// Require maps label keys to the values a node must have; a node
	// matches when it has every key with one of the listed values.
	Require map[string]LabelValues `yaml:"require,omitempty" json:"require,omitempty"`
	// SpreadBy is a label key: replicas are spread evenly over its values,
	// then over the nodes within each value. Only nodes with the label are
	// used. The spread yields to capacity: when the nodes of one value
	// have no room, replicas go to the others.
	SpreadBy string `yaml:"spreadBy,omitempty" json:"spreadBy,omitempty"`
}

// LabelValues is one or more label values. In YAML it may be written as a
// single value (`region: sulawesi`) or a list (`kind: [raspi, small]`).
type LabelValues []string

// UnmarshalYAML accepts a scalar or a sequence of scalars.
func (l *LabelValues) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		*l = LabelValues{n.Value}
		return nil
	}
	var v []string
	if err := n.Decode(&v); err != nil {
		return err
	}
	*l = v
	return nil
}

// Matches reports whether a node with labels satisfies the placement. A
// nil placement matches every node.
func (p *Placement) Matches(labels map[string]string) bool {
	if p == nil {
		return true
	}
	for k, vals := range p.Require {
		v, ok := labels[k]
		if !ok || !slices.Contains(vals, v) {
			return false
		}
	}
	if p.SpreadBy != "" {
		if _, ok := labels[p.SpreadBy]; !ok {
			return false
		}
	}
	return true
}

// SpreadKey returns the spreadBy label key, or "" (also for a nil placement).
func (p *Placement) SpreadKey() string {
	if p == nil {
		return ""
	}
	return p.SpreadBy
}

// Selects reports whether the placement names one of labels by key: a
// restricted node only runs apps that select one of its admin labels.
// SpreadBy does not select: spreading over racks is no request for the
// restricted machines among them.
func (p *Placement) Selects(labels map[string]string) bool {
	if p == nil {
		return false
	}
	for k := range p.Require {
		if strings.HasPrefix(k, ReservedLabelPrefix) {
			continue
		}
		if _, ok := labels[k]; ok {
			return true
		}
	}
	return false
}

// String renders the labels a node needs as "k=v, k2=a|b", sorted by key,
// with "k3=*" for a spreadBy key the requirement does not name.
func (p *Placement) String() string {
	if p == nil {
		return ""
	}
	values := map[string]string{}
	for k, vals := range p.Require {
		values[k] = strings.Join(vals, "|")
	}
	if _, ok := values[p.SpreadBy]; p.SpreadBy != "" && !ok {
		values[p.SpreadBy] = "*"
	}
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k + "=" + values[k]
	}
	return strings.Join(parts, ", ")
}

func (v *validator) placement(p *Placement) {
	if p == nil {
		return
	}
	if p.SpreadBy != "" {
		if err := CheckLabelKey(p.SpreadBy); err != nil {
			v.add("placement.spreadBy", "%v", err)
		}
	}
	if len(p.Require) == 0 {
		if p.SpreadBy == "" {
			v.add("placement", "must set require or spreadBy")
		}
		return
	}
	if len(p.Require) > maxRequire {
		v.add("placement.require", "must have at most %d labels", maxRequire)
		return
	}
	for k, vals := range p.Require {
		f := "placement.require." + k
		if err := CheckLabelKey(k); err != nil {
			v.add("placement.require", "%v", err)
			continue
		}
		if len(vals) == 0 || len(vals) > maxRequire {
			v.add(f, "must list between 1 and %d values", maxRequire)
			continue
		}
		for _, val := range vals {
			if err := CheckLabelValue(val); err != nil {
				v.add(f, "%v", err)
			}
		}
	}
}
