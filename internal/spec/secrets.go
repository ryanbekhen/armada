package spec

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// MaxSecretNameLen bounds secret names.
const MaxSecretNameLen = 63

const (
	maxSecretFiles  = 64
	maxUsernameLen  = 256
	defaultRegistry = "docker.io"
)

var (
	secretFilePath = regexp.MustCompile(`^(/[A-Za-z0-9._-]+)+$`)
	registryHostRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*(:[0-9]{1,5})?$`)
	// The runtime generates these files for every container.
	reservedFiles = []string{"/etc/hosts", "/etc/hostname", "/etc/resolv.conf"}
	reservedDirs  = []string{"/proc", "/sys", "/dev"}
)

// SecretFile mounts a secret as a read-only file in the container.
type SecretFile struct {
	SecretRef string `yaml:"secretRef" json:"secretRef"`
	Path      string `yaml:"path" json:"path"`
}

// Registry holds credentials for a private image registry. The password
// always comes from a secret.
type Registry struct {
	Server            string `yaml:"server" json:"server"`
	Username          string `yaml:"username" json:"username"`
	PasswordSecretRef string `yaml:"passwordSecretRef" json:"passwordSecretRef"`
}

// ValidateSecretName checks a secret name: lowercase letters, digits, and
// hyphens, at most 63 characters.
func ValidateSecretName(name string) error {
	switch {
	case name == "":
		return fmt.Errorf("secret name is required")
	case len(name) > MaxSecretNameLen:
		return fmt.Errorf("secret name must be at most %d characters", MaxSecretNameLen)
	case !labelRe.MatchString(name):
		return fmt.Errorf("secret name %q must be lowercase letters, digits, and hyphens, not starting or ending with a hyphen", name)
	}
	return nil
}

// SecretRefs returns the names of all secrets the app references, sorted and
// without duplicates.
func (a *App) SecretRefs() []string {
	var refs []string
	for _, e := range a.Env {
		if e.SecretRef != "" {
			refs = append(refs, e.SecretRef)
		}
	}
	for _, f := range a.SecretFiles {
		refs = append(refs, f.SecretRef)
	}
	for _, c := range slices.Concat(a.InitContainers, a.Sidecars) {
		for _, e := range c.Env {
			if e.SecretRef != "" {
				refs = append(refs, e.SecretRef)
			}
		}
	}
	if a.Registry != nil {
		refs = append(refs, a.Registry.PasswordSecretRef)
	}
	if a.Scale != nil {
		for _, r := range a.Scale.Rules {
			if r.URLSecretRef != "" {
				refs = append(refs, r.URLSecretRef)
			}
		}
	}
	if q := a.QueueTrigger(); q != nil {
		refs = append(refs, q.URLSecretRef)
	}
	slices.Sort(refs)
	return slices.Compact(refs)
}

// RegistryHost returns the registry an image reference pulls from, e.g.
// "ghcr.io" for ghcr.io/org/app:1 and "docker.io" for nginx:1.
func RegistryHost(image string) string {
	first, _, ok := strings.Cut(image, "/")
	if ok && (strings.ContainsAny(first, ".:") || first == "localhost") {
		return strings.ToLower(first)
	}
	return defaultRegistry
}

func (v *validator) secretName(field, name string) {
	if err := ValidateSecretName(name); err != nil {
		v.add(field, "%s", strings.TrimPrefix(err.Error(), "secret name "))
	}
}

func (v *validator) secretFiles(files []SecretFile) {
	if len(files) > maxSecretFiles {
		v.add("secretFiles", "must have at most %d entries", maxSecretFiles)
		return
	}
	var paths []string
	for i, f := range files {
		field := fmt.Sprintf("secretFiles[%d]", i)
		v.secretName(field+".secretRef", f.SecretRef)
		if msg := checkSecretFilePath(f.Path); msg != "" {
			v.add(field+".path", "%s", msg)
			continue
		}
		for _, p := range paths {
			if p == f.Path {
				v.add(field+".path", "duplicate path %q", f.Path)
			} else if strings.HasPrefix(f.Path, p+"/") || strings.HasPrefix(p, f.Path+"/") {
				v.add(field+".path", "%q and %q overlap", p, f.Path)
			}
		}
		paths = append(paths, f.Path)
	}
}

func checkSecretFilePath(p string) string {
	switch {
	case p == "":
		return "is required"
	case len(p) > maxPathLen:
		return fmt.Sprintf("must be at most %d characters", maxPathLen)
	case !secretFilePath.MatchString(p):
		return "must be an absolute path of letters, digits, '.', '_', '-', and '/'"
	}
	for _, part := range strings.Split(p[1:], "/") {
		if part == "." || part == ".." {
			return "must not contain . or .. components"
		}
	}
	if slices.Contains(reservedFiles, p) {
		return fmt.Sprintf("%s is managed by the container runtime", p)
	}
	for _, d := range reservedDirs {
		if p == d || strings.HasPrefix(p, d+"/") {
			return fmt.Sprintf("must not be under %s", d)
		}
	}
	return ""
}

func (v *validator) registry(r *Registry, image string) {
	if r == nil {
		return
	}
	switch {
	case r.Server == "":
		v.add("registry.server", "is required")
	case len(r.Server) > maxDomainLen || !registryHostRe.MatchString(r.Server):
		v.add("registry.server", "must be a lowercase host name with an optional port, e.g. ghcr.io")
	case r.Server != RegistryHost(image):
		v.add("registry.server", "must match the registry of image (%s)", RegistryHost(image))
	}
	switch {
	case r.Username == "":
		v.add("registry.username", "is required")
	case len(r.Username) > maxUsernameLen:
		v.add("registry.username", "must be at most %d characters", maxUsernameLen)
	case strings.ContainsFunc(r.Username, func(c rune) bool { return c < 0x21 || c == 0x7f }):
		v.add("registry.username", "must not contain spaces or control characters")
	}
	v.secretName("registry.passwordSecretRef", r.PasswordSecretRef)
}

// EnvFromSecrets is the envFrom value that turns every secret of the app
// into a variable.
const EnvFromSecrets = "secrets"

// SecretEnvName is the variable a secret becomes under envFrom: database-url
// becomes DATABASE_URL, the reverse of `armada secret import`.
func SecretEnvName(secret string) string {
	return strings.ToUpper(strings.ReplaceAll(secret, "-", "_"))
}

// WithSecretEnv returns a copy of a whose env also holds, for envFrom:
// secrets, a variable for each of secrets. Variables the spec sets itself
// win; secrets the spec uses for files or the registry, and names that are
// reserved or not valid variable names, are left out. The copy is validated
// again, so too many variables is an error.
func (a *App) WithSecretEnv(secrets []string) (*App, error) {
	if a.EnvFrom != EnvFromSecrets {
		return a, nil
	}
	used := map[string]bool{}
	for _, f := range a.SecretFiles {
		used[f.SecretRef] = true
	}
	if a.Registry != nil {
		used[a.Registry.PasswordSecretRef] = true
	}
	set := map[string]bool{}
	for _, e := range a.Env {
		set[e.Name] = true
	}
	c := *a
	c.Env = slices.Clone(a.Env)
	c.EnvFromAdded = nil
	for _, s := range slices.Sorted(slices.Values(secrets)) {
		name := SecretEnvName(s)
		if used[s] || set[name] || !envNameRe.MatchString(name) || name == "PORT" || strings.HasPrefix(name, reservedEnvPfx) {
			continue
		}
		set[name] = true
		c.Env = append(c.Env, EnvVar{Name: name, SecretRef: s})
		c.EnvFromAdded = append(c.EnvFromAdded, name)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}
