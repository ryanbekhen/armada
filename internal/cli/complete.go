package cli

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/spec"
)

// completeWait bounds the calls one Tab press makes to the cluster.
const completeWait = 5 * time.Second

// completer lists the names one kind of argument takes. args are the
// command's arguments so far (names, not IDs); it returns nothing when the
// cluster cannot be asked. Completion never offers a secret's value.
type completer func(ctx context.Context, c *completion, args []string) []string

// completion asks the cluster for names on behalf of one Tab press.
type completion struct {
	g      *globals
	client armadav1.AdminServiceClient
}

// completeFromCluster gives every command's arguments and the flags that
// name something Tab completion from the cluster (ADR 0052): apps,
// revisions, replicas, containers, jobs, runs, secrets, keys, volumes,
// spaces, nodes, users, services, roles, alerts, domains. The kind of an
// argument comes from its placeholder in the command's Use line.
func completeFromCluster(root *cobra.Command, g *globals) {
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		for _, sub := range c.Commands() {
			walk(sub)
		}
		if !c.Runnable() || c.HasSubCommands() {
			return
		}
		if c.ValidArgsFunction == nil {
			if kinds := argKinds(c); len(kinds) > 0 {
				c.ValidArgsFunction = g.completeArgs(kinds)
			}
		}
		for flag, kind := range flagKinds(c) {
			if c.Flags().Lookup(flag) != nil {
				_ = c.RegisterFlagCompletionFunc(flag, g.completeFlag(kind))
			}
		}
	}
	walk(root)
}

// argKinds is the completer of each positional argument in c's Use line;
// a nil entry completes nothing, and a variadic last one repeats.
func argKinds(c *cobra.Command) []completer {
	noun := ""
	if c.Parent() != nil {
		noun = c.Parent().Name()
	}
	var out []completer
	found := false
	for _, w := range argWords(c) {
		k := placeholderKind(noun, c.Name(), strings.Trim(w, "[]."))
		found = found || k != nil
		out = append(out, k)
	}
	if !found {
		return nil
	}
	return out
}

// placeholderKind is the completer of a placeholder such as APP or NAME.
func placeholderKind(noun, verb, word string) completer {
	switch word {
	case "APP":
		return completeApps
	case "JOB":
		return completeJobs
	case "RUN":
		return completeRuns
	case "SECRET":
		if verb == "create" {
			return nil
		}
		return completeSecrets
	case "KEY":
		return completeKeys
	case "REVISION":
		if noun == "revision" {
			return completeRevisionIDs
		}
		return completeRevisions
	case "REVISION=WEIGHT":
		return completeWeights
	case "NODE":
		return completeNodes
	case "SPACE":
		return completeSpaces
	case "ROLE":
		return completeRoles
	case "VOLUME":
		return completeVolumes
	case "DOMAIN":
		return completeDomains
	case "NAME":
		if verb == "create" {
			return nil // a new name
		}
		switch noun {
		case "user":
			return completePrincipals(kindUser)
		case "service":
			return completePrincipals(kindService)
		case "alert":
			return completeAlerts
		case "space":
			return completeSpaces
		case "metrics":
			return completeMetrics
		}
	}
	return nil
}

// flagKinds are the flags of c that name something, with their completers.
func flagKinds(c *cobra.Command) map[string]completer {
	m := map[string]completer{"space": completeSpaces, "node": completeNodes, "role": completeRoles,
		"user": completePrincipals(kindUser), "service": completePrincipals(kindService)}
	if p := c.Parent(); p != nil && p.Name() == "app" {
		m["replica"] = completeReplicas
		m["container"] = completeContainers
		m["to"] = completeRevisions
	}
	if p := c.Parent(); p != nil && p.Name() == "job" {
		m["run"] = completeRuns
	}
	return m
}

// completeArgs completes the next positional argument of a command.
func (g *globals) completeArgs(kinds []completer) cobra.CompletionFunc {
	return func(cmd *cobra.Command, args []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
		// (cobra completes with "--" appended, so ArgsLenAtDash cannot tell
		// a command after -- apart: past the placeholders nothing is offered.)
		i := len(args)
		if i >= len(kinds) {
			last := argWords(cmd)
			if len(last) == 0 || !strings.HasSuffix(strings.Trim(last[len(last)-1], "[]"), "...") {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			i = len(kinds) - 1
		}
		if kinds[i] == nil {
			return nil, cobra.ShellCompDirectiveDefault
		}
		return g.complete(cmd, kinds[i], args, toComplete)
	}
}

// completeFlag completes a flag's value.
func (g *globals) completeFlag(kind completer) cobra.CompletionFunc {
	return func(cmd *cobra.Command, args []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
		return g.complete(cmd, kind, args, toComplete)
	}
}

// complete asks the cluster for the names kind takes that start with
// toComplete.
func (g *globals) complete(cmd *cobra.Command, kind completer, args []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
	directive := cobra.ShellCompDirectiveNoFileComp
	if g.resolveSpace() != nil {
		return nil, directive
	}
	ctx, cancel := context.WithTimeout(cmd.Context(), completeWait)
	defer cancel()
	client, conn, err := dialAdmin(g)
	if err != nil {
		return nil, directive
	}
	defer conn.Close()
	var out []cobra.Completion
	for _, n := range kind(ctx, &completion{g: g, client: client}, args) {
		if strings.HasPrefix(n, toComplete) {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	out = slices.Compact(out)
	if len(out) > 0 && strings.HasSuffix(out[0], "=") {
		directive |= cobra.ShellCompDirectiveNoSpace
	}
	return out, directive
}

// id is the app or job ID of name in the space, or "" when it is not one.
func (c *completion) id(name string) string {
	id, err := c.g.app(name)
	if err != nil {
		return ""
	}
	return id
}

// name is how an app ID is typed in the space: its name there, else the ID.
func (c *completion) name(id string) string {
	space, name, ok := spec.SplitAppID(id)
	if ok && space == c.g.scope() {
		return name
	}
	return id
}

func completeApps(ctx context.Context, c *completion, _ []string) []string {
	var out []string
	token := ""
	for range 20 {
		resp, err := c.client.ListApps(ctx, &armadav1.ListAppsRequest{Space: c.g.scope(), PageToken: token})
		if err != nil {
			return out
		}
		for _, a := range resp.Apps {
			out = append(out, c.name(spec.AppID(a.Space, a.Name)))
		}
		if token = resp.NextPageToken; token == "" {
			break
		}
	}
	return out
}

func completeJobs(ctx context.Context, c *completion, _ []string) []string {
	resp, err := c.client.ListJobs(ctx, &armadav1.ListJobsRequest{})
	if err != nil {
		return nil
	}
	var out []string
	for _, j := range resp.Jobs {
		if c.g.listed(j.Name) {
			out = append(out, c.name(j.Name))
		}
	}
	return out
}

func completeRuns(ctx context.Context, c *completion, args []string) []string {
	if len(args) == 0 {
		return nil
	}
	resp, err := c.client.ListJobRuns(ctx, &armadav1.ListJobRunsRequest{Job: c.id(args[0])})
	if err != nil {
		return nil
	}
	var out []string
	for _, r := range resp.Runs {
		out = append(out, fmt.Sprint(r.Run))
	}
	return out
}

func completeSecrets(ctx context.Context, c *completion, _ []string) []string {
	resp, err := c.client.ListSpaceSecrets(ctx, &armadav1.ListSpaceSecretsRequest{Space: c.g.scope()})
	if err != nil {
		return nil
	}
	var out []string
	for _, s := range resp.Secrets {
		out = append(out, s.Name)
	}
	return out
}

// completeKeys lists the keys of the secret in args[0], never their values.
func completeKeys(ctx context.Context, c *completion, args []string) []string {
	if len(args) == 0 {
		return nil
	}
	secret, err := c.g.secretID(args[0])
	if err != nil {
		return nil
	}
	resp, err := c.client.ListSecrets(ctx, &armadav1.ListSecretsRequest{App: secret})
	if err != nil {
		return nil
	}
	var out []string
	for _, s := range resp.Secrets {
		out = append(out, s.Name)
	}
	return out
}

// revisions are the revisions of app ID id, as rN.
func (c *completion) revisions(ctx context.Context, id string) []string {
	if id == "" {
		return nil
	}
	resp, err := c.client.ListRevisions(ctx, &armadav1.ListRevisionsRequest{App: id})
	if err != nil {
		return nil
	}
	var out []string
	for _, r := range resp.Revisions {
		out = append(out, shortRevision(r.Name))
	}
	return out
}

// completeRevisions lists the revisions of the app in args[0], as rN.
func completeRevisions(ctx context.Context, c *completion, args []string) []string {
	if len(args) == 0 {
		return nil
	}
	return c.revisions(ctx, c.id(args[0]))
}

// completeRevisionIDs lists full revision names (api--r3) of every app.
func completeRevisionIDs(ctx context.Context, c *completion, _ []string) []string {
	var out []string
	for _, app := range completeApps(ctx, c, nil) {
		for _, r := range c.revisions(ctx, c.id(app)) {
			out = append(out, app+"--"+r)
		}
	}
	return out
}

// completeWeights offers rN= for each revision of the app in args[0].
func completeWeights(ctx context.Context, c *completion, args []string) []string {
	var out []string
	for _, r := range completeRevisions(ctx, c, args[:min(1, len(args))]) {
		out = append(out, r+"=")
	}
	return out
}

// replicas are the replicas of the app in args[0].
func (c *completion) replicas(ctx context.Context, args []string) []*armadav1.ReplicaStatus {
	if len(args) == 0 {
		return nil
	}
	id := c.id(args[0])
	if id == "" {
		return nil
	}
	resp, err := c.client.Status(ctx, &armadav1.StatusRequest{App: id})
	if err != nil || len(resp.Apps) != 1 {
		return nil
	}
	return resp.Apps[0].Replicas
}

// completeReplicas lists the short names of the app's replicas.
func completeReplicas(ctx context.Context, c *completion, args []string) []string {
	var out []string
	for _, r := range c.replicas(ctx, args) {
		out = append(out, shortReplica(r.Id))
	}
	return out
}

// completeContainers lists the containers of the app's replicas.
func completeContainers(ctx context.Context, c *completion, args []string) []string {
	var out []string
	for _, r := range c.replicas(ctx, args) {
		out = append(out, r.Containers...)
		out = append(out, r.InitContainers...)
	}
	return out
}

// completeVolumes lists the volumes of the app in args[0].
func completeVolumes(ctx context.Context, c *completion, args []string) []string {
	if len(args) == 0 {
		return nil
	}
	resp, err := c.client.ListVolumes(ctx, &armadav1.ListVolumesRequest{App: c.id(args[0])})
	if err != nil {
		return nil
	}
	var out []string
	for _, v := range resp.Volumes {
		out = append(out, v.Name)
	}
	return out
}

func completeNodes(ctx context.Context, c *completion, _ []string) []string {
	resp, err := c.client.Status(ctx, &armadav1.StatusRequest{NodesOnly: true})
	if err != nil {
		return nil
	}
	var out []string
	for _, n := range resp.Nodes {
		out = append(out, n.Id)
	}
	return out
}

func completeSpaces(ctx context.Context, c *completion, _ []string) []string {
	resp, err := c.client.ListSpaces(ctx, &armadav1.ListSpacesRequest{})
	if err != nil {
		return nil
	}
	var out []string
	for _, s := range resp.Spaces {
		out = append(out, s.Name)
	}
	return out
}

func completeRoles(ctx context.Context, c *completion, _ []string) []string {
	resp, err := c.client.ListRoles(ctx, &armadav1.ListRolesRequest{})
	if err != nil {
		return nil
	}
	var out []string
	for _, r := range resp.Roles {
		out = append(out, r.Name)
	}
	return out
}

func completePrincipals(kind string) completer {
	return func(ctx context.Context, c *completion, _ []string) []string {
		resp, err := c.client.ListPrincipals(ctx, &armadav1.ListPrincipalsRequest{Kind: kind})
		if err != nil {
			return nil
		}
		var out []string
		for _, p := range resp.Principals {
			if !p.Removed {
				out = append(out, p.Name)
			}
		}
		return out
	}
}

func completeAlerts(ctx context.Context, c *completion, _ []string) []string {
	resp, err := c.client.ListAlertChannels(ctx, &armadav1.ListAlertChannelsRequest{})
	if err != nil {
		return nil
	}
	var out []string
	for _, a := range resp.Channels {
		out = append(out, a.Name)
	}
	return out
}

func completeMetrics(ctx context.Context, c *completion, _ []string) []string {
	resp, err := c.client.ListMetricsCredentials(ctx, &armadav1.ListMetricsCredentialsRequest{})
	if err != nil {
		return nil
	}
	var out []string
	for _, m := range resp.Credentials {
		out = append(out, m.Name)
	}
	return out
}

func completeDomains(ctx context.Context, c *completion, _ []string) []string {
	resp, err := c.client.ListDomains(ctx, &armadav1.ListDomainsRequest{})
	if err != nil {
		return nil
	}
	var out []string
	for _, d := range resp.Domains {
		out = append(out, d.Name)
	}
	return out
}
