package haproxy

import (
	"maps"
	"testing"
)

func TestParseLoad(t *testing.T) {
	t.Parallel()
	out := "# pxname,svname,qcur,qmax,scur,smax,slim\n" +
		"fe_http,FRONTEND,,,40,90,\n" +
		"be_web,s1,0,0,7,9,\n" +
		"be_web,s2,3,3,10,10,\n" +
		"be_web,s3,0,0,0,0,\n" +
		"be_web,BACKEND,3,3,17,19,\n" +
		"be_api,s1,0,0,2,2,\n" +
		"be_api,s9,0,0,5,5,\n" + // slot past the layout
		"be_armada_notfound,BACKEND,0,0,0,0,\n" +
		"stats,FRONTEND,,,1,1,\n" +
		"be_web,s1,short\n"
	layout := Layout{"web": {"web-a", "web-b", ""}, "api": {"api-a"}}
	got, err := parseLoad(out, layout)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int64{"web-a": 7, "web-b": 13, "api-a": 2}
	if !maps.Equal(got, want) {
		t.Errorf("load = %v, want %v", got, want)
	}
	if _, err := parseLoad("", layout); err == nil {
		t.Error("empty output accepted")
	}
	if _, err := parseLoad("# pxname,svname\nbe_web,s1\n", layout); err == nil {
		t.Error("output without scur accepted")
	}
}
