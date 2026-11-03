package haproxy

import (
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
	layout := Layout{"web": {"web-a", "web-b", ""}, "api": {"api-a"}}
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
