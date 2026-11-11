package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/spec"
)

// specFlags are the flags of app and job create and update that write a
// spec (ADR 0032). A flag that is not given leaves its field alone.
type specFlags struct {
	job bool
	fs  *pflag.FlagSet

	file, varsFile string
	vars           []string

	image                        string
	command, args                []string
	env, secretEnv, removeEnv    []string
	envFromSecrets               bool
	cpu, memory                  string
	registryUser, registrySecret string

	// Apps.
	port                             int
	ingress                          string
	domains, removeDomains           []string
	ipAllow, ipDeny                  []string
	noIPRules                        bool
	replicas, minR, maxR             int
	scaleCPU, scaleMemory, scaleHTTP int
	healthPath                       string

	// Jobs.
	schedule, timeZone, concurrency string
	timeout                         time.Duration
	retries                         int
}

// Flags that change an app's spec, and a job's.
var (
	appSpecFlags = []string{"image", "command", "args", "env", "secret-env", "remove-env", "env-from-secrets", "cpu", "memory",
		"registry-user", "registry-secret", "port", "ingress", "domain", "remove-domain", "ip-allow", "ip-deny", "no-ip-rules", "replicas", "min", "max",
		"scale-cpu", "scale-memory", "scale-http", "health-path"}
	jobSpecFlags = []string{"image", "command", "args", "env", "secret-env", "remove-env", "env-from-secrets", "cpu", "memory",
		"registry-user", "registry-secret", "schedule", "time-zone", "timeout", "retries", "concurrency"}
)

func (f *specFlags) register(cmd *cobra.Command, job bool) {
	f.job, f.fs = job, cmd.Flags()
	fs := cmd.Flags()
	fs.StringVarP(&f.file, "file", "f", "", "spec file, or - for stdin")
	fs.StringVar(&f.varsFile, "vars", "", "with --file: file of NAME=VALUE lines for ${NAME} in the spec")
	fs.StringArrayVar(&f.vars, "var", nil, "with --file: NAME=VALUE for ${NAME} in the spec (repeatable; wins over --vars)")
	fs.StringVar(&f.image, "image", "", "container image")
	fs.StringArrayVar(&f.command, "command", nil, "command, replacing the image's entrypoint: one word per flag, kept as written (repeat it; \"\" clears)")
	fs.StringArrayVar(&f.args, "args", nil, "argument of the command: one per flag, kept as written (repeat it; \"\" clears)")
	fs.StringArrayVar(&f.env, "env", nil, "environment variable NAME=VALUE (repeatable)")
	fs.StringArrayVar(&f.secretEnv, "secret-env", nil, "environment variable NAME=SECRET from a secret of the "+kindWord(job)+" (repeatable)")
	fs.StringArrayVar(&f.removeEnv, "remove-env", nil, "remove an environment variable (repeatable)")
	fs.BoolVar(&f.envFromSecrets, "env-from-secrets", false, "give every secret of the "+kindWord(job)+" as a variable (database-url becomes DATABASE_URL)")
	fs.StringVar(&f.cpu, "cpu", "", "CPU reserved and its limit, e.g. 250m or 1")
	fs.StringVar(&f.memory, "memory", "", "memory limit, e.g. 256Mi")
	fs.StringVar(&f.registryUser, "registry-user", "", "user name for a private registry (the image's)")
	fs.StringVar(&f.registrySecret, "registry-secret", "", "secret holding the private registry's password")
	if job {
		fs.StringVar(&f.schedule, "schedule", "", "cron schedule that starts runs, e.g. \"0 3 * * *\" (empty to clear)")
		fs.StringVar(&f.timeZone, "time-zone", "", "time zone of the schedule, e.g. Asia/Jakarta")
		fs.DurationVar(&f.timeout, "timeout", 0, "how long one attempt may run")
		fs.IntVar(&f.retries, "retries", 0, "attempts after a failed one")
		fs.StringVar(&f.concurrency, "concurrency", "", "when a run is due while one runs: forbid or replace")
		return
	}
	fs.IntVar(&f.port, "port", 0, "port the app listens on")
	fs.StringVar(&f.ingress, "ingress", "", "who reaches the app: external, internal, or none")
	fs.StringArrayVar(&f.domains, "domain", nil, "custom domain (repeatable)")
	fs.StringArrayVar(&f.removeDomains, "remove-domain", nil, "remove a custom domain (repeatable)")
	fs.StringArrayVar(&f.ipAllow, "ip-allow", nil, "only clients from this address or prefix reach the app from outside (repeatable; replaces the list)")
	fs.StringArrayVar(&f.ipDeny, "ip-deny", nil, "clients from this address or prefix cannot reach the app from outside (repeatable; replaces the list)")
	fs.BoolVar(&f.noIPRules, "no-ip-rules", false, "let every client reach the app again")
	cmd.MarkFlagsMutuallyExclusive("ip-allow", "ip-deny", "no-ip-rules")
	fs.IntVar(&f.replicas, "replicas", 0, "number of replicas")
	fs.IntVar(&f.minR, "min", 0, "fewest replicas when autoscaling")
	fs.IntVar(&f.maxR, "max", 0, "most replicas when autoscaling")
	fs.IntVar(&f.scaleCPU, "scale-cpu", 0, "autoscale to this percent of reserved CPU")
	fs.IntVar(&f.scaleMemory, "scale-memory", 0, "autoscale to this percent of the memory limit")
	fs.IntVar(&f.scaleHTTP, "scale-http", 0, "autoscale to this many concurrent requests per replica")
	fs.StringVar(&f.healthPath, "health-path", "", "HTTP path that answers when the app is ready (empty to clear)")
}

func kindWord(job bool) string {
	if job {
		return "job"
	}
	return "app"
}

// specChanged reports whether a flag that changes the spec was given.
func (f *specFlags) specChanged() bool {
	names := appSpecFlags
	if f.job {
		names = jobSpecFlags
	}
	return slices.ContainsFunc(names, f.fs.Changed)
}

// check refuses flag combinations that cannot work.
func (f *specFlags) check() error {
	ch := f.fs.Changed
	if f.file != "" && f.specChanged() {
		return errors.New("give either --file or flags that change the spec, not both")
	}
	if f.file == "" && (ch("vars") || ch("var")) {
		return errors.New("--vars and --var fill in a spec file: use them with --file")
	}
	return nil
}

// readFile reads --file with its variables filled in.
func (f *specFlags) readFile(cmd *cobra.Command) ([]byte, error) {
	var r io.Reader
	if f.file == "-" {
		r = cmd.InOrStdin()
	} else {
		fh, err := os.Open(f.file)
		if err != nil {
			return nil, err
		}
		defer fh.Close()
		r = fh
	}
	data, err := io.ReadAll(io.LimitReader(r, spec.MaxSpecBytes+1))
	if err != nil {
		return nil, err
	}
	if f.varsFile != "" || len(f.vars) > 0 {
		vars, err := loadVars(f.varsFile, f.vars)
		if err != nil {
			return nil, err
		}
		if data, err = spec.Substitute(data, vars); err != nil {
			return nil, err
		}
	}
	return data, nil
}

// checkKind refuses an app spec for a job command and the other way round.
func checkKind(sp *spec.App, job bool, verb string) error {
	switch {
	case sp.IsJob() && !job:
		return fmt.Errorf("%s is a job (kind: job); use armada job %s", sp.Name, verb)
	case !sp.IsJob() && job:
		return fmt.Errorf("%s is an app, not a job; use armada app %s", sp.Name, verb)
	}
	return nil
}

// apply changes a to what the flags say.
func (f *specFlags) apply(a *spec.App) error {
	ch := f.fs.Changed
	if ch("image") {
		a.Image = f.image
		if a.Registry != nil {
			a.Registry.Server = spec.RegistryHost(a.Image)
		}
	}
	if ch("command") {
		a.Command = nonEmpty(f.command)
	}
	if ch("args") {
		a.Args = nonEmpty(f.args)
	}
	if err := f.applyEnv(a); err != nil {
		return err
	}
	if ch("env-from-secrets") {
		a.EnvFrom = ""
		if f.envFromSecrets {
			a.EnvFrom = spec.EnvFromSecrets
		}
	}
	if ch("cpu") || ch("memory") {
		if a.Resources == nil {
			a.Resources = &spec.Resources{}
		}
		if ch("cpu") {
			a.Resources.CPU = f.cpu
		}
		if ch("memory") {
			a.Resources.Memory = f.memory
		}
	}
	if ch("registry-user") || ch("registry-secret") {
		r := spec.Registry{}
		if a.Registry != nil {
			r = *a.Registry
		}
		if ch("registry-user") {
			r.Username = f.registryUser
		}
		if ch("registry-secret") {
			r.PasswordSecretRef = f.registrySecret
		}
		r.Server = spec.RegistryHost(a.Image)
		a.Registry = &r
		if r.Username == "" && r.PasswordSecretRef == "" {
			a.Registry = nil
		}
	}
	if f.job {
		f.applyJob(a)
		return nil
	}
	f.applyIngress(a)
	if ch("health-path") {
		f.applyHealthPath(a)
	}
	return f.applyScale(a)
}

func nonEmpty(s []string) []string {
	if len(s) == 0 || (len(s) == 1 && s[0] == "") {
		return nil
	}
	return slices.Clone(s)
}

// applyEnv removes, then sets, variables. Errors never quote a value.
func (f *specFlags) applyEnv(a *spec.App) error {
	for _, k := range f.removeEnv {
		if !slices.ContainsFunc(a.Env, func(e spec.EnvVar) bool { return e.Name == k }) {
			return fmt.Errorf("--remove-env %s: the %s has no such variable", k, kindWord(f.job))
		}
		a.Env = slices.DeleteFunc(a.Env, func(e spec.EnvVar) bool { return e.Name == k })
	}
	set := func(e spec.EnvVar) {
		if i := slices.IndexFunc(a.Env, func(o spec.EnvVar) bool { return o.Name == e.Name }); i >= 0 {
			a.Env[i] = e
			return
		}
		a.Env = append(a.Env, e)
	}
	for _, kv := range f.env {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			return errors.New("--env: want NAME=VALUE")
		}
		set(spec.EnvVar{Name: k, Value: v})
	}
	for _, kv := range f.secretEnv {
		k, s, ok := strings.Cut(kv, "=")
		if !ok || k == "" || s == "" {
			return errors.New("--secret-env: want NAME=SECRET, the name of a secret (never its value)")
		}
		set(spec.EnvVar{Name: k, SecretRef: s})
	}
	return nil
}

func (f *specFlags) applyJob(a *spec.App) {
	ch := f.fs.Changed
	if ch("schedule") {
		a.Schedule = f.schedule
	}
	if ch("time-zone") {
		a.TimeZone = f.timeZone
	}
	if ch("timeout") {
		a.Timeout = spec.Duration(f.timeout)
	}
	if ch("retries") {
		a.Retries = f.retries
	}
	if ch("concurrency") {
		a.Concurrency = f.concurrency
	}
}

func (f *specFlags) applyIngress(a *spec.App) {
	ch := f.fs.Changed
	if !ch("ingress") && !ch("port") && !ch("domain") && !ch("remove-domain") && !ch("ip-allow") && !ch("ip-deny") && !ch("no-ip-rules") {
		return
	}
	in := spec.Ingress{Type: spec.IngressNone}
	if a.Ingress != nil {
		in = *a.Ingress
	}
	oldPort := in.Port
	if ch("ingress") {
		in.Type = f.ingress
		if f.ingress == spec.IngressNone {
			in = spec.Ingress{Type: spec.IngressNone}
		}
	}
	if ch("port") {
		in.Port = f.port
	}
	in.Domains = slices.DeleteFunc(slices.Clone(in.Domains), func(d string) bool { return slices.Contains(f.removeDomains, d) })
	for _, d := range f.domains {
		if !slices.Contains(in.Domains, d) {
			in.Domains = append(in.Domains, d)
		}
	}
	if len(in.Domains) == 0 {
		in.Domains = nil
	}
	// Each list replaces the rules: who may reach an app is safer stated in
	// full than pieced together.
	switch {
	case f.noIPRules:
		in.IPAllow, in.IPDeny = nil, nil
	case ch("ip-allow"):
		in.IPAllow, in.IPDeny = slices.Clone(f.ipAllow), nil
	case ch("ip-deny"):
		in.IPAllow, in.IPDeny = nil, slices.Clone(f.ipDeny)
	}
	a.Ingress = &in
	// Probes that checked the app's port follow it.
	if in.Port != oldPort && a.Probes != nil {
		for _, p := range []*spec.Probe{a.Probes.Startup, a.Probes.Readiness, a.Probes.Liveness} {
			if p != nil && len(p.Command) == 0 && p.Port == oldPort {
				p.Port = in.Port
			}
		}
	}
}

func (f *specFlags) applyHealthPath(a *spec.App) {
	if f.healthPath == "" {
		if a.Probes != nil {
			a.Probes.Readiness = nil
			if a.Probes.Startup == nil && a.Probes.Liveness == nil {
				a.Probes = nil
			}
		}
		return
	}
	if a.Probes == nil {
		a.Probes = &spec.Probes{}
	}
	p := a.Probes.Readiness
	if p == nil || len(p.Command) > 0 {
		p = &spec.Probe{}
	}
	p.Path = f.healthPath
	if a.Ingress != nil && p.Port == 0 {
		p.Port = a.Ingress.Port
	}
	a.Probes.Readiness = p
}

func (f *specFlags) applyScale(a *spec.App) error {
	ch := f.fs.Changed
	var rules []spec.ScaleRule
	if ch("scale-cpu") {
		rules = append(rules, spec.ScaleRule{Type: spec.ScaleCPU, Utilization: f.scaleCPU})
	}
	if ch("scale-memory") {
		rules = append(rules, spec.ScaleRule{Type: spec.ScaleMemory, Utilization: f.scaleMemory})
	}
	if ch("scale-http") {
		rules = append(rules, spec.ScaleRule{Type: spec.ScaleHTTP, Concurrent: f.scaleHTTP})
	}
	auto := ch("min") || ch("max") || len(rules) > 0
	switch {
	case len(rules) > 1:
		return errors.New("give one of --scale-cpu, --scale-memory, and --scale-http")
	case ch("replicas") && auto:
		return errors.New("--replicas sets a fixed count: leave out --min, --max, and the --scale flags")
	case ch("replicas"):
		n := f.replicas
		a.Scale = &spec.Scale{Min: &n, Max: &n}
		return nil
	case !auto:
		return nil
	}
	s := spec.Scale{}
	if a.Scale != nil {
		s = *a.Scale
	}
	if ch("min") {
		n := f.minR
		s.Min = &n
	}
	if ch("max") {
		n := f.maxR
		s.Max = &n
	}
	if len(rules) > 0 {
		s.Rules = rules
	}
	if len(s.Rules) == 0 {
		return errors.New("--min and --max bound autoscaling: add one of --scale-cpu, --scale-memory, and --scale-http")
	}
	a.Scale = &s
	return nil
}

// deployFlags are what create and update share besides the spec flags.
type deployFlags struct {
	spec specFlags
	wait waitFlags
	// Update only.
	diff, createIfMissing bool
}

// appTarget splits the ID of NAME into the project and name a spec has.
func appTarget(id string) (project, name string) {
	p, n, _ := spec.SplitAppID(id)
	if p == spec.DefaultProject {
		p = ""
	}
	return p, n
}

// createSpec builds the spec create sends: from --file, or from the flags
// with name NAME (an ID, or "" with --file).
func createSpec(cmd *cobra.Command, f *specFlags, id, project string) ([]byte, *spec.App, error) {
	if f.file != "" {
		data, err := f.readFile(cmd)
		if err != nil {
			return nil, nil, err
		}
		sp, err := spec.ParseIn(data, project)
		if err != nil {
			return nil, nil, err
		}
		if err := checkKind(sp, f.job, "create"); err != nil {
			return nil, nil, err
		}
		if id != "" {
			if _, name := appTarget(id); sp.Name != name {
				return nil, nil, fmt.Errorf("the file names %s, not %s", sp.Name, name)
			}
		}
		return data, sp, nil
	}
	if id == "" {
		return nil, nil, fmt.Errorf("give the %s's name, or --file", kindWord(f.job))
	}
	if !f.fs.Changed("image") {
		return nil, nil, errors.New("--image is required (or give --file)")
	}
	_, name := appTarget(id)
	a := &spec.App{Name: name}
	if f.job {
		a.Kind = spec.KindJob
	}
	if err := f.apply(a); err != nil {
		return nil, nil, err
	}
	return specData(a, project)
}

// specData writes a as a file holds it and validates it here, for fast
// feedback; the server validates it again.
func specData(a *spec.App, project string) ([]byte, *spec.App, error) {
	data, err := a.Export()
	if err != nil {
		return nil, nil, err
	}
	sp, err := spec.ParseIn(data, project)
	if err != nil {
		return nil, nil, err
	}
	return data, sp, nil
}

// runCreate is app create and job create.
func runCreate(cmd *cobra.Command, g *globals, args []string, d *deployFlags) error {
	if err := d.spec.check(); err != nil {
		return err
	}
	id := ""
	if len(args) == 1 {
		var err error
		if id, err = g.app(args[0]); err != nil {
			return err
		}
	}
	project := g.project
	if id != "" {
		project, _ = appTarget(id)
	}
	data, _, err := createSpec(cmd, &d.spec, id, project)
	if err != nil {
		return err
	}
	client, conn, err := dialAdmin(g)
	if err != nil {
		return err
	}
	defer conn.Close()
	resp, err := client.Deploy(cmd.Context(), &armadav1.DeployRequest{Spec: data, Project: project, MustCreate: true})
	if err != nil {
		return RPCError(err)
	}
	if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Created %s (revision %s).\n", resp.App, resp.Revision); err != nil {
		return err
	}
	if d.spec.job || !d.wait.wait {
		return nil
	}
	return waitRollout(cmd.Context(), client, resp.App, resp.Revision, d.wait.timeout, cmd.OutOrStdout())
}

// runUpdate is app update and job update.
func runUpdate(cmd *cobra.Command, g *globals, args []string, d *deployFlags) error {
	f := &d.spec
	if err := f.check(); err != nil {
		return err
	}
	if f.file == "" && !f.specChanged() {
		return errors.New("nothing to change: give flags that change the spec, or --file")
	}
	id := ""
	if len(args) == 1 {
		var err error
		if id, err = g.app(args[0]); err != nil {
			return err
		}
	} else if f.file == "" {
		return fmt.Errorf("give the %s's name", kindWord(f.job))
	}
	project := g.project
	if id != "" {
		project, _ = appTarget(id)
	}
	client, conn, err := dialAdmin(g)
	if err != nil {
		return err
	}
	defer conn.Close()
	ctx := cmd.Context()

	var data, current []byte
	var base, prev string
	exists := true
	if f.file != "" {
		var sp *spec.App
		if data, sp, err = createSpec(cmd, f, id, project); err != nil {
			return err
		}
		id = spec.AppID(project, sp.Name)
		cur, err := client.GetAppSpec(ctx, &armadav1.GetAppSpecRequest{App: id})
		switch {
		case status.Code(err) == codes.NotFound:
			exists = false
		case err != nil:
			return RPCError(err)
		default:
			current, prev = cur.Spec, cur.Revision
			if err := checkCurrentKind(id, cur.Spec, f.job); err != nil {
				return err
			}
		}
		if d.diff {
			// Compare like with like: the file as the server would export it.
			if data, err = sp.Export(); err != nil {
				return err
			}
		}
	} else {
		cur, err := client.GetAppSpec(ctx, &armadav1.GetAppSpecRequest{App: id})
		var a *spec.App
		switch {
		case status.Code(err) == codes.NotFound:
			exists = false
			_, name := appTarget(id)
			a = &spec.App{Name: name}
			if f.job {
				a.Kind = spec.KindJob
			}
		case err != nil:
			return RPCError(err)
		default:
			current, base, prev = cur.Spec, cur.Revision, cur.Revision
			if a, err = spec.ParseIn(cur.Spec, project); err != nil {
				return fmt.Errorf("the spec of %s: %w", id, err)
			}
			if err := checkKind(a, f.job, "update"); err != nil {
				return err
			}
		}
		if !exists && d.createIfMissing && !f.fs.Changed("image") {
			return fmt.Errorf("%s does not exist; creating it needs --image", id)
		}
		if err := f.apply(a); err != nil {
			return err
		}
		if data, _, err = specData(a, project); err != nil {
			return err
		}
	}
	if !exists && !d.createIfMissing && !d.diff {
		return notExist(id, f.job)
	}

	out := cmd.OutOrStdout()
	if d.diff {
		return printDiff(out, current, data)
	}
	req := &armadav1.DeployRequest{Spec: data, Project: project, BaseRevision: base, MustCreate: !exists, MustExist: exists}
	resp, err := client.Deploy(ctx, req)
	if err != nil {
		if status.Code(err) == codes.NotFound && req.MustExist {
			return notExist(id, f.job)
		}
		return RPCError(err)
	}
	line := fmt.Sprintf("Updated %s (revision %s).", resp.App, resp.Revision)
	switch {
	case !exists:
		line = fmt.Sprintf("Created %s (revision %s).", resp.App, resp.Revision)
	case resp.Revision == prev:
		line = fmt.Sprintf("%s is unchanged (revision %s).", resp.App, resp.Revision)
	}
	if _, err := fmt.Fprintln(out, line); err != nil {
		return err
	}
	if f.job || !d.wait.wait {
		return nil
	}
	return waitRollout(ctx, client, resp.App, resp.Revision, d.wait.timeout, out)
}

func notExist(id string, job bool) error {
	return fmt.Errorf("%s does not exist: create it with armada %s create, or pass --create-if-missing", id, kindWord(job))
}

// checkCurrentKind refuses to replace a job with an app or the other way
// round.
func checkCurrentKind(id string, current []byte, job bool) error {
	p, _ := appTarget(id)
	sp, err := spec.ParseIn(current, p)
	if err != nil {
		return nil // the server decides
	}
	return checkKind(sp, job, "update")
}

// registerCreate and registerUpdate add the flags of create and update.
func (d *deployFlags) registerCreate(cmd *cobra.Command, job bool) {
	d.spec.register(cmd, job)
	if !job {
		d.wait.register(cmd)
	}
}

func (d *deployFlags) registerUpdate(cmd *cobra.Command, job bool) {
	d.registerCreate(cmd, job)
	cmd.Flags().BoolVar(&d.diff, "diff", false, "print what would change and change nothing")
	cmd.Flags().BoolVar(&d.createIfMissing, "create-if-missing", false, "create the "+kindWord(job)+" when it does not exist")
}
