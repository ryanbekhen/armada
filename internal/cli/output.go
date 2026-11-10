package cli

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

const outputYAML = "yaml"

// outputFlag is -o of a command that prints data: text, json, and for the
// shows of apps and jobs yaml (the spec).
type outputFlag struct {
	format string
	yaml   bool
}

// addOutput registers -o on cmd.
func addOutput(cmd *cobra.Command, yaml bool) *outputFlag {
	o := &outputFlag{yaml: yaml}
	usage := "output format: text or json"
	if yaml {
		usage = "output format: text, json, or yaml (the spec, as a file holds it)"
	}
	cmd.Flags().StringVarP(&o.format, "output", "o", outputText, usage)
	return o
}

func (o *outputFlag) check() error {
	switch {
	case o.format == outputText, o.format == outputJSON, o.yaml && o.format == outputYAML:
		return nil
	case o.yaml:
		return fmt.Errorf("unsupported output format %q (want %q, %q, or %q)", o.format, outputText, outputJSON, outputYAML)
	}
	return checkOutput(o.format)
}

func (o *outputFlag) json() bool { return o.format == outputJSON }

func checkOutput(output string) error {
	if output != outputText && output != outputJSON {
		return fmt.Errorf("unsupported output format %q (want %q or %q)", output, outputText, outputJSON)
	}
	return nil
}

func printJSON(out io.Writer, m proto.Message) error {
	b, err := protojson.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(m)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, string(b))
	return err
}
