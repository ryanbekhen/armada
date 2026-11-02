package runtime

import (
	"strings"
	"testing"
)

func TestCheckExecCommand(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("a", MaxExecArgLen)
	for _, ok := range [][]string{{"sh"}, {"sh", "-c", "echo hi"}, {"x", long}, make([]string, MaxExecArgs)} {
		if len(ok) == MaxExecArgs {
			for i := range ok {
				ok[i] = "a"
			}
		}
		if err := CheckExecCommand(ok); err != nil {
			t.Errorf("%.40q: %v", ok, err)
		}
	}
	for _, bad := range [][]string{nil, {}, {""}, {"sh", long + "a"}, {"sh", "secret\x00value"}, make([]string, MaxExecArgs+1)} {
		err := CheckExecCommand(bad)
		if err == nil {
			t.Errorf("%.40q accepted", bad)
		} else if strings.Contains(err.Error(), "secret") {
			t.Errorf("error repeats an argument: %v", err)
		}
	}
}
