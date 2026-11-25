package armadav1_test

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
)

var update = flag.Bool("update", false, "rewrite proto/tests/testdata")

// The messages armada-proto (proto/, ADR 0055) must read and write as Go
// does: proto/tests/protojson.rs decodes each .binpb, encodes it again to
// the same bytes, and writes the .json protojson writes (compared as JSON),
// and reads that JSON back to the same message.
func goldenMessages() map[string]proto.Message {
	return map[string]proto.Message{
		"replica_spec": &armadav1.ReplicaSpec{
			Id:       "web.shop-r3-a1b2c3",
			App:      "web.shop",
			Revision: "web.shop-r3",
			Image:    "registry.example.com/web@sha256:" + string(bytes.Repeat([]byte("ab"), 32)),
			Command:  []string{"/bin/web", "--listen", ":8080"},
			Env: []*armadav1.EnvVar{
				{Name: "PORT", Value: "8080"},
				{Name: "GREETING", Value: "héllo <world> & \"you\"\n"},
				{Name: "DATABASE_URL", Ref: "db/url@3"},
			},
			Port:        8080,
			MemoryBytes: 256 << 20,
			NanoCpus:    -1,
			PidsLimit:   1 << 40,
			Startup:     &armadav1.Probe{Path: "/healthz", Port: 8080, PeriodMs: 1000, FailureThreshold: 30},
			Liveness:    &armadav1.Probe{Command: []string{"pg_isready"}, TimeoutMs: 5000},
			SecretFiles: []*armadav1.SecretFile{
				{Path: "/run/secrets/key", Data: []byte{0, 1, 2, 0xfe, 0xff}, Ref: "key@1"},
			},
			Job:               &armadav1.JobAttempt{Job: "web.shop", Run: 9007199254740993},
			Volumes:           []*armadav1.VolumeSpec{{Name: "data", Path: "/data", Owner: "1000:1000"}},
			Hold:              true,
			FenceAfterSeconds: 30,
		},
		"agent_hello": &armadav1.AgentMessage{Msg: &armadav1.AgentMessage_Hello{Hello: &armadav1.Hello{
			CpuMillis:   4000,
			MemoryBytes: 8 << 30,
			Version:     "v0.1.0-alpha.41",
			PrivateIp:   "10.0.0.2",
			Os:          "linux",
			Arch:        "arm64",
			Jobs:        true,
			NetworkKey:  "zUiUUFo68E2u1IYbL+/4fuSeNfPVSTmKuhjVqJzBAzk=",
			RuntimeMove: true,
		}}},
		"join_token_request": &armadav1.CreateJoinTokenRequest{
			TtlSeconds: 600,
			Labels:     map[string]string{"zone": "b", "armada.site": "east", "Disk": "ssd", "gpu": "1"},
			Site:       "east",
		},
		// Go writes a map entry's empty value; prost leaves it out
		// (proto/tests/protojson.rs keeps the difference known).
		"map_empty_value": &armadav1.LabelNodeRequest{
			Node: "n1",
			Set:  map[string]string{"empty": "", "full": "yes"},
		},
		"metrics_certificate": &armadav1.IssueMetricsCertificateResponse{
			Cert:      []byte("-----BEGIN CERTIFICATE-----\n"),
			CaCert:    []byte{},
			ExpiresAt: &timestamppb.Timestamp{Seconds: 1795000000, Nanos: 500000000},
		},
		"log_entry": &armadav1.LogEntry{
			Replica: "web-r1-x",
			Stream:  armadav1.Stream_STREAM_STDERR,
			Data:    []byte("line\n"),
			Time:    &timestamppb.Timestamp{Seconds: -62135596800, Nanos: 1},
		},
		"volume_request": &armadav1.VolumeRequest{
			RequestId: "r-1",
			Op:        armadav1.VolumeRequest_OP_RESTORE_SNAPSHOT,
			App:       "db",
			Volume:    "data",
			Snapshot:  "latest",
		},
		"empty": &armadav1.StatusRequest{},
	}
}

func TestProtojsonGolden(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "proto", "tests", "testdata")
	for name, m := range goldenMessages() {
		bin, err := proto.MarshalOptions{Deterministic: true}.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		js, err := protojson.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		js = append(js, '\n')
		for file, want := range map[string][]byte{name + ".binpb": bin, name + ".json": js} {
			path := filepath.Join(dir, file)
			if *update {
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, want, 0o644); err != nil {
					t.Fatal(err)
				}
				continue
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%v (go test ./api/armada/v1 -update writes it)", err)
			}
			// protojson's spacing changes between builds on purpose; only
			// what the JSON says is compared.
			if same(got, want, file == name+".json") {
				continue
			}
			t.Errorf("%s differs from what Go writes now (go test ./api/armada/v1 -update)", path)
		}
	}
}

func same(got, want []byte, isJSON bool) bool {
	if !isJSON {
		return bytes.Equal(got, want)
	}
	var a, b any
	if json.Unmarshal(got, &a) != nil || json.Unmarshal(want, &b) != nil {
		return false
	}
	return reflect.DeepEqual(a, b)
}
