package runtime

import (
	"context"
	"io"
	"sync"
	"time"
)

// OutputActivity tells when a command's output last moved. Runtimes wrap
// the writers they copy a command's output to with Wrap and, once the
// command exited, keep copying while output moves (WaitQuiet): a child the
// command left in the background can hold the output open for as long as
// it lives, but output still on its way to a slow reader is never cut.
// The zero value is ready to use.
type OutputActivity struct {
	mu      sync.Mutex
	writing int       // writes in progress
	last    time.Time // when the last write ended
}

// Wrap returns a writer that writes to w and counts as activity; nil stays
// nil.
func (a *OutputActivity) Wrap(w io.Writer) io.Writer {
	if w == nil {
		return nil
	}
	return &activityWriter{a: a, w: w}
}

type activityWriter struct {
	a *OutputActivity
	w io.Writer
}

func (aw *activityWriter) Write(p []byte) (int, error) {
	a := aw.a
	a.mu.Lock()
	a.writing++
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		a.writing--
		a.last = time.Now()
		a.mu.Unlock()
	}()
	return aw.w.Write(p)
}

// quietFor is how long no output has moved: 0 while a write is in
// progress (a slow reader is still taking output), else the time since the
// last write ended, or since start when nothing was written after it.
func (a *OutputActivity) quietFor(start time.Time) time.Duration {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.writing > 0 {
		return 0
	}
	last := a.last
	if last.Before(start) {
		last = start
	}
	return time.Since(last)
}

// WaitQuiet waits until done is closed, or until no output has moved for
// grace, counted from the call at the earliest. It returns ctx.Err() when
// ctx ends first, since output may then have been cut.
func (a *OutputActivity) WaitQuiet(ctx context.Context, done <-chan struct{}, grace time.Duration) error {
	start := time.Now()
	t := time.NewTimer(grace)
	defer t.Stop()
	for {
		select {
		case <-done:
			return nil
		case <-ctx.Done():
			select {
			case <-done:
				return nil
			default:
			}
			return ctx.Err()
		case <-t.C:
		}
		quiet := a.quietFor(start)
		if quiet >= grace {
			return nil
		}
		// Output moved within the grace: wait until it has been quiet for
		// the whole grace, checking at least every grace/4 while a write
		// is in progress.
		t.Reset(max(grace-quiet, grace/4))
	}
}
