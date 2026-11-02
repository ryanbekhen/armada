package cli

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
)

func TestMacOSRoles(t *testing.T) {
	t.Parallel()
	if err := linuxOnlyOn("darwin", "armada server"); err == nil || !strings.Contains(err.Error(), "armada join ADDR --ca-hash sha256:... --runtime NAME") {
		t.Errorf("server on macOS: %v", err)
	}
	if err := linuxOnlyOn("linux", "armada server"); err != nil {
		t.Errorf("server on Linux: %v", err)
	}
	for _, rt := range []string{"", runtimeEmbedded} {
		if err := needsDriverOn("darwin", rt); err == nil {
			t.Errorf("runtime %q accepted on macOS", rt)
		}
		if err := needsDriverOn("linux", rt); err != nil {
			t.Errorf("runtime %q refused on Linux: %v", rt, err)
		}
	}
	if err := needsDriverOn("darwin", "apple"); err != nil {
		t.Errorf("driver refused on macOS: %v", err)
	}
}

func TestLaunchAgentPlist(t *testing.T) {
	t.Parallel()
	b := launchAgentPlist("/opt/a&b/armada", "/Users/n/Library/Logs/Armada/agent.log")
	d := xml.NewDecoder(bytes.NewReader(b))
	var texts []string
	for {
		tok, err := d.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("not well-formed: %v\n%s", err, b)
		}
		if c, ok := tok.(xml.CharData); ok && strings.TrimSpace(string(c)) != "" {
			texts = append(texts, string(c))
		}
	}
	want := []string{"Label", "io.github.ryanbekhen.armada.agent", "ProgramArguments", "/opt/a&b/armada", "agent",
		"RunAtLoad", "KeepAlive", "StandardOutPath", "/Users/n/Library/Logs/Armada/agent.log", "StandardErrorPath", "/Users/n/Library/Logs/Armada/agent.log"}
	if !slices.Equal(texts, want) {
		t.Errorf("plist values = %q", texts)
	}
}
