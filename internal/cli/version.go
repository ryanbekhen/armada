package cli

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ryanbekhen/armada/internal/version"
)

const (
	outputText = "text"
	outputJSON = "json"
)

// NewVersionCommand prints build information; both binaries have it.
func NewVersionCommand() *cobra.Command {
	var output string

	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print build information",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			info := version.Get()
			out := cmd.OutOrStdout()

			switch output {
			case outputText:
				_, err := fmt.Fprintln(out, info.String())
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
