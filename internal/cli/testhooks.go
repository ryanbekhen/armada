package cli

import "time"

// SetPollIntervals sets how often commands that wait poll the control plane
// (deploy --wait and job run --wait, node remove) and returns a function that
// restores them. armadad's tests drive these commands against a server they
// run in process.
func SetPollIntervals(wait, node time.Duration) (restore func()) {
	origWait, origNode := waitPoll, pollInterval
	waitPoll, pollInterval = wait, node
	return func() { waitPoll, pollInterval = origWait, origNode }
}
