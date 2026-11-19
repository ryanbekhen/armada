package clientconfig

import (
	"strconv"
	"strings"
	"testing"
)

func TestGroupAdvice(t *testing.T) {
	const gid = 4242
	oldS, oldA := sessionGroups, accountGroups
	t.Cleanup(func() { sessionGroups, accountGroups = oldS, oldA })
	for _, tc := range []struct {
		session []int
		account []string
		want    string
	}{
		{nil, nil, "not in the armada group"},
		{nil, []string{strconv.Itoa(gid)}, "log in again"},
		{[]int{gid}, []string{strconv.Itoa(gid)}, "not shared"},
	} {
		sessionGroups = func() ([]int, error) { return tc.session, nil }
		accountGroups = func() ([]string, error) { return tc.account, nil }
		if got := adviceFor(gid); !strings.Contains(got, tc.want) {
			t.Errorf("session %v, account %v: %q, want %q", tc.session, tc.account, got, tc.want)
		}
	}
}
