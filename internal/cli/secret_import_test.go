package cli

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"google.golang.org/grpc"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
)

func TestParseSecretFile(t *testing.T) {
	t.Parallel()
	got, err := parseSecretFile(strings.NewReader("# a comment\n\nDATABASE_URL=postgres://u:p@h/db?a=b\r\nEMPTY=\n  # indented comment\nQUOTED=\"kept\"\nFCM_KEY=-----BEGIN\\nx\\n=\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := []struct{ key, name, value string }{
		{"DATABASE_URL", "database-url", "postgres://u:p@h/db?a=b"},
		{"EMPTY", "empty", ""},
		{"QUOTED", "quoted", `"kept"`},
		{"FCM_KEY", "fcm-key", `-----BEGIN\nx\n=`},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d entries, want %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i].key != w.key || got[i].name != w.name || string(got[i].value) != w.value {
			t.Errorf("entry %d = %s %s, want %s %s", i, got[i].key, got[i].name, w.key, w.name)
		}
	}
}

// A malformed line may be a secret that lost its key: an error names the line
// by number and never repeats it.
func TestParseSecretFileRefusesWithoutQuoting(t *testing.T) {
	t.Parallel()
	const secret = "hunter2-very-secret"
	for name, in := range map[string]string{
		"no equals":      "A=1\n" + secret + "\n",
		"bad key":        "A=1\n" + secret + " x=1\n",
		"lower dup":      "A_B=1\na-b=" + secret + "\n",
		"same name":      "A_B=" + secret + "\na_b=2\n",
		"bad secret key": "_A=" + secret + "\n",
	} {
		_, err := parseSecretFile(strings.NewReader(in))
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if strings.Contains(err.Error(), secret) {
			t.Errorf("%s: error quotes the value: %v", name, err)
		}
		if !strings.Contains(err.Error(), "line ") {
			t.Errorf("%s: error names no line: %v", name, err)
		}
	}
	if _, err := parseSecretFile(strings.NewReader("A=" + strings.Repeat("x", 70<<20))); err == nil {
		t.Error("an oversized line was accepted")
	}
}

type fakeSecrets struct {
	armadav1.AdminServiceClient
	reqs   []*armadav1.SetSecretRequest
	failAt int
}

func (f *fakeSecrets) SetSecret(_ context.Context, r *armadav1.SetSecretRequest, _ ...grpc.CallOption) (*armadav1.SetSecretResponse, error) {
	if f.failAt > 0 && len(f.reqs) == f.failAt {
		return nil, errors.New("refused")
	}
	f.reqs = append(f.reqs, r)
	return &armadav1.SetSecretResponse{Version: 1}, nil
}

func TestImportSecrets(t *testing.T) {
	t.Parallel()
	entries := []secretEntry{{key: "A", name: "a", value: []byte("value-one")}, {key: "B_C", name: "b-c", value: []byte("value-two")}}
	var out strings.Builder
	f := &fakeSecrets{}
	if err := importSecrets(context.Background(), f, "api", entries, &out); err != nil {
		t.Fatal(err)
	}
	if len(f.reqs) != 2 || f.reqs[1].GetApp() != "api" || f.reqs[1].GetName() != "b-c" || string(f.reqs[1].GetValue()) != "value-two" {
		t.Errorf("requests = %v", len(f.reqs))
	}
	for _, r := range f.reqs {
		if r.GetRollout() {
			t.Errorf("%s rolled out", r.GetName())
		}
	}
	if strings.Contains(out.String(), "value-") {
		t.Errorf("output shows a value: %s", out.String())
	}
	err := importSecrets(context.Background(), &fakeSecrets{failAt: 1}, "api", entries, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "b-c (1 of 2") || strings.Contains(err.Error(), "value-") {
		t.Errorf("err = %v", err)
	}
}
