package haproxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"testing"

	"github.com/ryanbekhen/armada/internal/proxy"
)

func TestParseLoad(t *testing.T) {
	t.Parallel()
	out := "# pxname,svname,qcur,qmax,scur,smax,slim,stot\n" +
		"fe_http,FRONTEND,,,40,90,,100\n" +
		"be_web,s1,0,0,7,9,,50\n" +
		"be_web,s2,3,3,10,10,,60\n" +
		"be_web,s3,0,0,0,0,,0\n" +
		"be_web,BACKEND,3,3,17,19,,110\n" +
		"be_api,s1,0,0,2,2,,4\n" +
		"be_api,s9,0,0,5,5,,5\n" + // slot past the layout
		"wk_web,wake,0,0,1,1,,1\n" +
		"be_armada_notfound,BACKEND,0,0,0,0,,0\n" +
		"stats,FRONTEND,,,1,1,,1\n" +
		"be_web,s1,short\n"
	layout := Layout{"be_web": {"web-a", "web-b", ""}, "be_api": {"api-a"}}
	got, err := parseLoad(out, layout)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]proxy.ServerLoad{"web-a": {InFlight: 7, Total: 50}, "web-b": {InFlight: 13, Total: 60}, "api-a": {InFlight: 2, Total: 4}}
	if !maps.Equal(got, want) {
		t.Errorf("load = %v, want %v", got, want)
	}
	if _, err := parseLoad("", layout); err == nil {
		t.Error("empty output accepted")
	}
	if _, err := parseLoad("# pxname,svname,scur,qcur\nbe_web,s1,1,0\n", layout); err == nil {
		t.Error("output without stot accepted")
	}
}

// statAPI answers "show info" and "show stat" with what the test sets.
type statAPI struct {
	pid   string
	total int
	err   error
}

func (a *statAPI) Command(_ context.Context, cmd string) (string, error) {
	if a.err != nil {
		return "", a.err
	}
	if cmd == "show info" {
		return "Name: HAProxy\nPid: " + a.pid + "\nUptime_sec: 1\n", nil
	}
	return fmt.Sprintf("# pxname,svname,scur,qcur,stot\nbe_web,s1,0,0,%d\n", a.total), nil
}

func (a *statAPI) Payload(context.Context, string, string) (string, error) { return "", nil }

func TestLoadTotalsSurviveReloads(t *testing.T) {
	t.Parallel()
	api := &statAPI{pid: "10", total: 100}
	d := &Driver{cfg: Config{API: api}, log: slog.New(slog.DiscardHandler), layout: Layout{"be_web": {"web-1"}}}
	ctx := context.Background()
	total := func(want int64) {
		t.Helper()
		l, err := d.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if got := l["web-1"].Total; got != want {
			t.Errorf("total %d, want %d", got, want)
		}
	}
	total(100)

	// The outgoing process's last read, and it still answers after the
	// signal: nothing is counted twice.
	api.total = 150
	total(150)
	api.total = 155
	total(155)

	// The new process starts from zero.
	api.pid, api.total = "11", 3
	total(158)
	api.total = 10
	total(165)

	// A second reload carries the running total, not only the last process.
	api.pid, api.total = "12", 0
	total(165)
	api.total = 1
	total(166)

	// A failed read changes nothing.
	api.err = errors.New("socket gone")
	if _, err := d.Load(ctx); err == nil {
		t.Error("no error from a failed read")
	}
	api.err = nil
	api.total = 2
	total(167)
}

func TestLoadCarriesOnlyCurrentReplicas(t *testing.T) {
	t.Parallel()
	api := &statAPI{pid: "10", total: 100}
	d := &Driver{cfg: Config{API: api}, log: slog.New(slog.DiscardHandler), layout: Layout{"be_web": {"web-1"}}}
	ctx := context.Background()
	if _, err := d.Load(ctx); err != nil {
		t.Fatal(err)
	}
	// The slot now serves another replica; the first one's total is not kept
	// past the next process.
	d.layout = Layout{"be_web": {"web-2"}}
	if _, err := d.Load(ctx); err != nil {
		t.Fatal(err)
	}
	api.pid, api.total = "11", 0
	if _, err := d.Load(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := d.carried["web-1"]; ok {
		t.Errorf("carried %v", d.carried)
	}
}
