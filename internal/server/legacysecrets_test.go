package server

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/secrets"
)

var updateLegacy = flag.Bool("update-legacy-secrets", false, "rewrite testdata/legacy-secrets.golden")

// TestLegacySecretsAssignmentUnchanged deploys an app that uses its own
// secrets in every way a spec could before secrets belonged to a space
// (envFrom: secrets, env, files, and the registry password) and compares
// what a node receives for its replica with what the release before
// ADR 0052 sent, byte for byte. A difference would restart every such
// replica on upgrade. The golden file was written by that release's code.
func TestLegacySecretsAssignmentUnchanged(t *testing.T) {
	t.Parallel()
	c := newClockServer(t)
	keys, err := secrets.NewKeyring(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	c.srv.keys = keys
	for name, value := range map[string]string{
		"database-url": "postgres://db", "jwt-secret": "jwt", "redis-url": "redis://r",
		"tls-key": "KEY", "registry-password": "ghp", "smtp-pass": "mail",
	} {
		if _, _, err := c.st.SetSecret(c.ctx, "api", name, func(v int) (secrets.Sealed, error) {
			return keys.Seal("api", name, v, secrets.NewValue([]byte(value)))
		}, false, "t"); err != nil {
			t.Fatal(err)
		}
	}
	send := make(chan *armadav1.ServerMessage, 64)
	c.srv.sessions["n1"] = &session{nodeID: "n1", send: send, done: make(chan struct{})}
	c.deploy(`name: api
image: ghcr.io/example/api:1
envFrom: secrets
env:
  - name: LOG_LEVEL
    value: info
  - name: MAIL_PASSWORD
    secretRef: smtp-pass
secretFiles:
  - secretRef: tls-key
    path: /run/tls/key.pem
registry:
  server: ghcr.io
  username: bot
  passwordSecretRef: registry-password
`)
	var spec *armadav1.ReplicaSpec
	for len(send) > 0 {
		if a := (<-send).GetAssignment(); a != nil {
			for _, r := range a.GetReplicas() {
				if r.GetApp() == "api" {
					spec = r
				}
			}
		}
	}
	if spec == nil {
		t.Fatal("no assignment for api")
	}
	spec = proto.Clone(spec).(*armadav1.ReplicaSpec)
	spec.Id = "" // random per replica
	for _, e := range spec.GetEnv() {
		if e.GetName() == "ARMADA_REPLICA" {
			e.Value = ""
		}
	}
	got, err := prototext.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	golden := filepath.Join("testdata", "legacy-secrets.golden")
	if *updateLegacy {
		if err := os.WriteFile(golden, got, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	// prototext adds random spaces between fields on purpose; compare the
	// messages, then the deterministic wire bytes.
	var w armadav1.ReplicaSpec
	if err := prototext.Unmarshal(want, &w); err != nil {
		t.Fatal(err)
	}
	gb, _ := proto.MarshalOptions{Deterministic: true}.Marshal(spec)
	wb, _ := proto.MarshalOptions{Deterministic: true}.Marshal(&w)
	if !bytes.Equal(gb, wb) {
		t.Errorf("the replica's spec changed:\n%s\nwant:\n%s", got, want)
	}
}
