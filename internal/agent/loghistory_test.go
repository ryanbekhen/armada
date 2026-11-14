package agent

import (
	"testing"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
)

// A node runs at most maxSearches history searches at once and answers the
// next with a notice, before touching its logs.
func TestSearchesAreBounded(t *testing.T) {
	t.Parallel()
	a, _ := newAgent(t)
	for range maxSearches {
		a.searches <- struct{}{}
	}
	var got string
	a.serveSearch(t.Context(), &armadav1.LogRequest{Query: &armadav1.LogQuery{App: "web"}}, nil, func(msg string) { got = msg })
	if got == "" || len(a.searches) != maxSearches {
		t.Errorf("notice %q, %d slots taken", got, len(a.searches))
	}
}
