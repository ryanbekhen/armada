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

// A node serves at most maxLiveLogs live log streams at once and answers
// the next with a notice, before touching its containers.
func TestLiveLogsAreBounded(t *testing.T) {
	t.Parallel()
	a, _ := newAgent(t)
	for range maxLiveLogs {
		a.liveLogs <- struct{}{}
	}
	var got string
	a.serveLive(t.Context(), &armadav1.LogRequest{ReplicaId: "web-1", Follow: true}, nil, func(msg string) { got = msg })
	if got != "busy with other log streams; try again shortly" || len(a.liveLogs) != maxLiveLogs {
		t.Errorf("notice %q, %d slots taken", got, len(a.liveLogs))
	}
	// A free slot is taken for the stream and given back after it.
	<-a.liveLogs
	got = ""
	a.serveLive(t.Context(), &armadav1.LogRequest{ReplicaId: "web-1"}, nil, func(msg string) { got = msg })
	if got == "busy with other log streams; try again shortly" || len(a.liveLogs) != maxLiveLogs-1 {
		t.Errorf("with a free slot: notice %q, %d slots taken", got, len(a.liveLogs))
	}
}
