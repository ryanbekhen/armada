package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/release"
	"github.com/ryanbekhen/armada/internal/version"
)

const (
	outputText = "text"
	outputJSON = "json"
)

// NewVersionCommand prints build information; both binaries have it. As
// text it adds what each of more returns (the client: the servers'
// versions) and the latest release.
func NewVersionCommand(more ...func(context.Context) []string) *cobra.Command {
	var output string

	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print build information and the latest release",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			info := version.Get()
			out := cmd.OutOrStdout()

			switch output {
			case outputText:
				lines := []string{info.String()}
				for _, f := range more {
					lines = append(lines, f(cmd.Context())...)
				}
				lines = append(lines, LatestLine(cmd.Context(), info.Version)...)
				_, err := fmt.Fprintln(out, strings.Join(lines, "\n"))
				return err
			case outputJSON:
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(info)
			default:
				return fmt.Errorf("unsupported output format %q (want %q or %q)", output, outputText, outputJSON)
			}
		},
	}
	cmd.Flags().StringVarP(&output, "output", "o", outputText, "output format: text or json")
	return cmd
}

// LatestLine says how current compares with the latest release, or nothing
// when looking is turned off.
func LatestLine(ctx context.Context, current string) []string {
	if os.Getenv(release.DisableEnv) != "" {
		return nil
	}
	tag, err := release.Latest(ctx)
	switch {
	case err != nil:
		return []string{"latest: unknown (" + err.Error() + ")"}
	case release.Newer(tag, current):
		return []string{"latest: " + tag + ", " + release.URL(tag)}
	case release.IsRelease(current):
		return []string{"latest: " + tag + " (up to date)"}
	}
	return []string{"latest: " + tag}
}

// serverVersions lists the control plane's versions, when the client
// reaches it.
func serverVersions(g *globals) func(context.Context) []string {
	return func(ctx context.Context) []string {
		client, conn, err := dialAdmin(g)
		if err != nil {
			return nil
		}
		defer conn.Close()
		ctx, cancel := context.WithTimeout(ctx, release.CheckTimeout)
		defer cancel()
		resp, err := client.ListServers(ctx, &armadav1.ListServersRequest{})
		if err != nil {
			return []string{"server: unknown (" + RPCError(err).Error() + ")"}
		}
		byVersion := map[string][]string{}
		for _, s := range resp.GetServers() {
			v := s.GetVersion()
			if v == "" {
				v = "unknown"
			}
			byVersion[v] = append(byVersion[v], s.GetName())
		}
		var parts []string
		for _, v := range slices.Sorted(maps.Keys(byVersion)) {
			parts = append(parts, v+" ("+strings.Join(byVersion[v], ", ")+")")
		}
		return []string{"server: " + strings.Join(parts, ", ")}
	}
}
