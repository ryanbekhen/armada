package spec

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
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
	refs = append(refs, a.BackupSecretRefs()...)
	if a.Ingress != nil && a.Ingress.DNS != nil {
		refs = append(refs, a.Ingress.DNS.TokenSecretRef)
	}
	slices.Sort(refs)
	return slices.Compact(refs)
}

// BackupSecretRefs lists the secrets the volumes' backups use (ADR 0041).
func (a *App) BackupSecretRefs() []string {
	var refs []string
	for _, v := range a.Volumes {
		if b := v.Backup; b != nil {
			refs = append(refs, b.URLSecretRef, b.KeySecretRef)
		}
	}
	return refs
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

// ValidateSecretKey checks the name of one key of a secret (ADR 0052): a
// name like a secret's (database-url), which envFrom turns into
// DATABASE_URL, or a variable name (DATABASE_URL), which it keeps.
func ValidateSecretKey(key string) error {
	switch {
	case key == "":
		return fmt.Errorf("key is required")
	case len(key) > MaxSecretNameLen:
		return fmt.Errorf("key must be at most %d characters", MaxSecretNameLen)
	case !labelRe.MatchString(key) && !envNameRe.MatchString(key):
		return fmt.Errorf("key %q must be lowercase letters, digits, and hyphens (database-url), or a variable name (DATABASE_URL)", key)
	}
	return nil
}

// SplitSecretRef splits a reference to a secret's key (ADR 0052): SECRET/KEY
// names a key of a secret of the app's space; a reference with no slash
// names a key of the secret with the app's own ID, and secret is "".
func SplitSecretRef(ref string) (secret, key string) {
	if s, k, ok := strings.Cut(ref, "/"); ok {
		return s, k
	}
	return "", ref
}

// ValidateSecretRef checks a reference to a secret's key: KEY or SECRET/KEY.
func ValidateSecretRef(ref string) error {
	secret, key := SplitSecretRef(ref)
	if strings.Count(ref, "/") > 1 {
		return fmt.Errorf("%q must be KEY or SECRET/KEY", ref)
	}
	if strings.Contains(ref, "/") {
		if err := ValidateSecretName(secret); err != nil {
			return err
		}
	}
	return ValidateSecretKey(key)
}

// SecretSource returns the ID of the secret ref names for the app or job
// with ID appID, and the key: the secret with the app's own ID when ref
// names no secret, else the named secret of the app's space.
func SecretSource(appID, ref string) (secretID, key string) {
	secret, key := SplitSecretRef(ref)
	if secret == "" {
		return appID, key
	}
	space, _, _ := SplitAppID(appID)
	return AppID(space, secret), key
}

// UsesSpaceSecrets reports whether the spec names a secret other than its
// own (a SECRET/KEY reference or a list under envFrom), which only servers
// that know ADR 0052 may run.
func (a *App) UsesSpaceSecrets() bool {
	if len(a.EnvFrom.Secrets) > 0 {
		return true
	}
	for _, r := range a.SecretRefs() {
		if strings.Contains(r, "/") {
			return true
		}
	}
	return false
}

func (v *validator) secretName(field, ref string) {
	if err := ValidateSecretRef(ref); err != nil {
		v.add(field, "%s", strings.TrimPrefix(strings.TrimPrefix(err.Error(), "secret name "), "key "))
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

// EnvFromSecrets is the envFrom value that turns every key of the app's own
// secret into a variable.
const EnvFromSecrets = "secrets"

// maxEnvFrom bounds the secrets envFrom lists.
const maxEnvFrom = 16

// EnvFrom names the secrets whose every key becomes a variable when the app
// is deployed: the word "secrets" (Own: the secret with the app's own ID),
// or a list of the space's secrets (ADR 0052).
type EnvFrom struct {
	Own     bool
	Secrets []EnvFromSecret
}

// EnvFromSecret is one entry of envFrom's list.
type EnvFromSecret struct {
	Secret string `yaml:"secret" json:"secret"`
}

// IsZero reports an envFrom that adds nothing, so it is left out of specs.
func (e EnvFrom) IsZero() bool { return !e.Own && len(e.Secrets) == 0 }

// UnmarshalYAML reads "secrets" or a list of {secret: NAME}.
func (e *EnvFrom) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		if n.Value != EnvFromSecrets {
			return fmt.Errorf("line %d: envFrom must be %q or a list of secrets (- secret: NAME)", n.Line, EnvFromSecrets)
		}
		*e = EnvFrom{Own: true}
		return nil
	}
	var list []EnvFromSecret
	if err := decodeStrict(n, &list); err != nil {
		return err
	}
	*e = EnvFrom{Secrets: list}
	return nil
}

// MarshalYAML writes the form the spec was written in.
func (e EnvFrom) MarshalYAML() (any, error) {
	if e.Own {
		return EnvFromSecrets, nil
	}
	return e.Secrets, nil
}

// UnmarshalJSON reads what MarshalJSON writes.
func (e *EnvFrom) UnmarshalJSON(b []byte) error {
	var word string
	if err := json.Unmarshal(b, &word); err == nil {
		if word != EnvFromSecrets {
			return fmt.Errorf("envFrom must be %q or a list of secrets", EnvFromSecrets)
		}
		*e = EnvFrom{Own: true}
		return nil
	}
	var list []EnvFromSecret
	if err := json.Unmarshal(b, &list); err != nil {
		return err
	}
	*e = EnvFrom{Secrets: list}
	return nil
}

// MarshalJSON writes "secrets" for the old form, so revisions stored before
// ADR 0052 and the same spec written now are the same bytes.
func (e EnvFrom) MarshalJSON() ([]byte, error) {
	if e.Own {
		return json.Marshal(EnvFromSecrets)
	}
	return json.Marshal(e.Secrets)
}

func (v *validator) envFrom(e EnvFrom) {
	switch {
	case e.Own && len(e.Secrets) > 0:
		v.add("envFrom", "must be %q or a list of secrets, not both", EnvFromSecrets)
	case len(e.Secrets) > maxEnvFrom:
		v.add("envFrom", "must list at most %d secrets", maxEnvFrom)
	}
	seen := map[string]bool{}
	for i, s := range e.Secrets {
		f := fmt.Sprintf("envFrom[%d].secret", i)
		if err := ValidateSecretName(s.Secret); err != nil {
			v.add(f, "%s", strings.TrimPrefix(err.Error(), "secret name "))
		} else if seen[s.Secret] {
			v.add(f, "secret %q is listed twice", s.Secret)
		}
		seen[s.Secret] = true
	}
}

// SecretEnvName is the variable a secret's key becomes under envFrom: a key
// written like a secret name (database-url) becomes DATABASE_URL, as keys
// were stored before ADR 0052; any other key (DATABASE_URL) is kept.
func SecretEnvName(key string) string {
	if !labelRe.MatchString(key) {
		return key
	}
	return strings.ToUpper(strings.ReplaceAll(key, "-", "_"))
}

// WithSecretEnv returns a copy of a whose env also holds a variable for
// each key of the secrets envFrom names. keys maps a secret's name to its
// keys, "" standing for the app's own secret (envFrom: secrets). Variables
// the spec sets itself win, then secrets in the order envFrom lists them;
// keys the spec uses for files, the registry, backups, or DNS, and names
// that are reserved or not valid variable names, are left out. The copy is
// validated again, so too many variables is an error.
func (a *App) WithSecretEnv(keys map[string][]string) (*App, error) {
	if a.EnvFrom.IsZero() {
		return a, nil
	}
	// source names a key the same way whatever the reference's form.
	source := func(ref string) string {
		secret, key := SplitSecretRef(ref)
		if secret == "" {
			secret = a.Name
		}
		return secret + "/" + key
	}
	used := map[string]bool{}
	for _, f := range a.SecretFiles {
		used[source(f.SecretRef)] = true
	}
	if a.Registry != nil {
		used[source(a.Registry.PasswordSecretRef)] = true
	}
	// The bucket's credentials and the backup key never reach the app.
	for _, s := range a.BackupSecretRefs() {
		used[source(s)] = true
	}
	// Nor does the DNS token, which only the control plane uses.
	if a.Ingress != nil && a.Ingress.DNS != nil {
		used[source(a.Ingress.DNS.TokenSecretRef)] = true
	}
	set := map[string]bool{}
	for _, e := range a.Env {
		set[e.Name] = true
	}
	c := *a
	c.Env = slices.Clone(a.Env)
	c.EnvFromAdded = nil
	add := func(ref string) {
		_, key := SplitSecretRef(ref)
		name := SecretEnvName(key)
		if used[source(ref)] || set[name] || !envNameRe.MatchString(name) || name == "PORT" || strings.HasPrefix(name, reservedEnvPfx) {
			return
		}
		set[name] = true
		c.Env = append(c.Env, EnvVar{Name: name, SecretRef: ref})
		c.EnvFromAdded = append(c.EnvFromAdded, name)
	}
	if a.EnvFrom.Own {
		for _, k := range slices.Sorted(slices.Values(keys[""])) {
			add(k)
		}
	}
	for _, s := range a.EnvFrom.Secrets {
		for _, k := range slices.Sorted(slices.Values(keys[s.Secret])) {
			add(s.Secret + "/" + k)
		}
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}
