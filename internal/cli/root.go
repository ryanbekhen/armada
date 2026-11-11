// Package cli wires the armada command tree: the client that talks to the
// control plane. Commands that run on a machine as root are in package daemon
// (the armadad binary).
package cli

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/ryanbekhen/armada/internal/clientconfig"
	"github.com/ryanbekhen/armada/internal/release"
	"github.com/ryanbekhen/armada/internal/spec"
	"github.com/ryanbekhen/armada/internal/version"
)

// globals holds persistent flags shared by subcommands.
type globals struct {
	configPath string
	// project is the project of the apps and jobs a command names (ADR
	// 0026): --project, else ARMADA_PROJECT, else the one `armada project
	// use` saved in the client config; empty means the default project.
	project string
	// allProjects is --all-projects: listings span every project.
	allProjects bool
}

// resolveProject fills project from the client config when neither
// --project nor ARMADA_PROJECT named one.
func (g *globals) resolveProject() error {
	if g.project == "" {
		if cc, err := clientconfig.Load(g.configPath); err == nil {
			g.project = cc.Project
		}
	}
	if g.project == spec.DefaultProject {
		g.project = ""
	}
	if g.project != "" && !spec.ValidProject(g.project) {
		return fmt.Errorf("invalid project %q", g.project)
	}
	return nil
}

// scope is the project a command works in.
func (g *globals) scope() string { return cmp.Or(g.project, spec.DefaultProject) }

// app returns the ID of app name in the project. name may already be an ID
// (web.staging) as long as --project does not name another project.
func (g *globals) app(name string) (string, error) {
	if strings.Contains(name, ".") {
		p, _, ok := spec.SplitAppID(name)
		if !ok {
			return "", fmt.Errorf("invalid name %q: want NAME, or NAME.PROJECT for one of another project", name)
		}
		if g.project != "" && g.project != p {
			return "", fmt.Errorf("%s belongs to project %s, not %s", name, p, g.project)
		}
		return name, nil
	}
	return spec.AppID(g.project, name), nil
}

// qualify replaces args[0], an app or job name, with its ID (see app).
func (g *globals) qualify(args []string) error {
	if len(args) == 0 {
		return nil
	}
	id, err := g.app(args[0])
	if err != nil {
		return err
	}
	args[0] = id
	return nil
}

// listed reports whether a listing shows the app with ID id: the
// project's, or every one with --all-projects.
func (g *globals) listed(id string) bool {
	if g.allProjects {
		return true
	}
	p, _, ok := spec.SplitAppID(id)
	return ok && p == g.scope()
}

// NewRootCommand builds the full command tree. Output goes to the writers
// configured on the returned command so tests can capture it.
func NewRootCommand() *cobra.Command {
	g := &globals{}
	cmd := &cobra.Command{
		Use:   version.Name,
		Short: "Manage apps on an Armada cluster",
		Long: version.Name + " manages apps, jobs, and the cluster they run on. Every command is\n" +
			"`armada <noun> <verb>`. It talks to the control plane with the credentials in\n" +
			"--config and needs no root. Machines run `armadad`.",
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(*cobra.Command, []string) error {
			return g.resolveProject()
		},
	}
	cmd.CompletionOptions.HiddenDefaultCmd = true

	cmd.PersistentFlags().StringVar(&g.configPath, "config", clientconfig.DefaultPath(), "client config file")
	cmd.PersistentFlags().StringVar(&g.project, "project", os.Getenv("ARMADA_PROJECT"), "project to work in")
	cmd.PersistentFlags().BoolVarP(&g.allProjects, "all-projects", "A", false, "every project")

	cmd.AddCommand(
		newAppCommand(g),
		newJobCommand(g),
		newSecretCommand(g),
		newDomainCommand(g),
		newVolumeCommand(g),
		newProjectCommand(g),
		newNodeCommand(g),
		newServerCommand(g),
		newClusterCommand(g),
		newRBACCommand(g),
		newMetricsCommand(g),
		NewVersionCommand(serverVersions(g)),
	)
	return cmd
}

// Execute runs the command tree with args and returns the process exit code.
// On a terminal it says, at most once a day, that a newer release exists.
func Execute(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	notice := startNotice(ctx, args, stderr)
	code := Run(ctx, NewRootCommand(), args, nil, stdout, stderr)
	if line := notice(time.Second); line != "" {
		_, _ = fmt.Fprintln(stderr, line)
	}
	return code
}

// startNotice looks for a newer release (release.StartNotice) only when a
// person reads stderr, and not for commands that need no cluster.
func startNotice(ctx context.Context, args []string, stderr io.Writer) func(time.Duration) string {
	none := func(time.Duration) string { return "" }
	f, ok := stderr.(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) {
		return none
	}
	if len(args) > 0 && slices.Contains([]string{"version", "help", "completion", "__complete"}, args[0]) {
		return none
	}
	dir, err := os.UserCacheDir()
	if err != nil {
		return none
	}
	return release.StartNotice(ctx, version.Get().Version, dir, time.Now())
}

// Run runs a command tree with args and returns the process exit code; a nil
// stdin means os.Stdin. armadad runs its own tree through it.
func Run(ctx context.Context, cmd *cobra.Command, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	cmd.SetArgs(args)
	if stdin != nil {
		cmd.SetIn(stdin)
	}
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)

	if err := cmd.ExecuteContext(ctx); err != nil {
		var code exitCodeError
		if errors.As(err, &code) {
			return int(code)
		}
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	return 0
}
