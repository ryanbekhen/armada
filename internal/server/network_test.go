package server

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestValidNetworkKey(t *testing.T) {
	t.Parallel()
	good := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32)))
	if !validNetworkKey(good) {
		t.Errorf("%s refused", good)
	}
	for _, bad := range []string{
		"",
		"not a key",
		base64.StdEncoding.EncodeToString(make([]byte, 32)),                   // zero
		base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 31))),    // short
		base64.URLEncoding.EncodeToString([]byte(strings.Repeat("\xff", 32))), // other alphabet
		good[:43] + "\n",
	} {
		if validNetworkKey(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}
