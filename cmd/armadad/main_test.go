package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

// Run as armada, armadad is the client; by any other name, the daemon.
func TestCommandByName(t *testing.T) {
	t.Setenv("ARMADA_NO_UPDATE_CHECK", "1")
	for argv0, wantClient := range map[string]bool{
		"armada":                     true,
		"/usr/local/bin/armada":      true,
		"armadad":                    false,
		"/usr/local/bin/armadad":     false,
		"/usr/local/bin/armada-old":  false,
		"/usr/local/bin/armadad.new": false,
	} {
		var out, errOut bytes.Buffer
		command(argv0)(context.Background(), []string{"--help"}, &out, &errOut)
		help := out.String() + errOut.String()
		client := strings.Contains(help, "app ") && !strings.Contains(help, "init ")
		if client != wantClient {
			t.Errorf("%s: client %v, want %v:\n%s", argv0, client, wantClient, help)
		}
	}
}
