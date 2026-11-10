package cli

import "time"

// SetPollIntervals sets how often commands that wait poll the control plane
// (app create and update --wait, job run --wait, node delete) and returns a function that
// restores them. armadad's tests drive these commands against a server they
// run in process.
func SetPollIntervals(wait, node time.Duration) (restore func()) {
	origWait, origNode := waitPoll, pollInterval
	waitPoll, pollInterval = wait, node
	return func() { waitPoll, pollInterval = origWait, origNode }
}
