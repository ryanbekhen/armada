package server

import (
	"testing"

	"google.golang.org/protobuf/proto"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
)

// A removed node's last, empty assignment is queued even when its queue
// is full, so its agent stops what it ran.
func TestSessionEndWithFullQueue(t *testing.T) {
	s := &session{nodeID: "n1", send: make(chan *armadav1.ServerMessage, 2), done: make(chan struct{})}
	for range 2 {
		s.send <- &armadav1.ServerMessage{Msg: &armadav1.ServerMessage_Assignment{Assignment: &armadav1.Assignment{Replicas: []*armadav1.ReplicaSpec{{Id: "web-1"}}}}}
	}
	s.endWith(&armadav1.Assignment{})
	var last *armadav1.ServerMessage
	for len(s.send) > 0 {
		last = <-s.send
	}
	if !proto.Equal(last.GetAssignment(), &armadav1.Assignment{}) {
		t.Fatalf("last message %v", last)
	}
}
