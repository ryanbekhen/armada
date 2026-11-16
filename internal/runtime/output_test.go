package runtime

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

func TestOutputActivityWaitQuiet(t *testing.T) {
	t.Parallel()
	const grace = 100 * time.Millisecond

	t.Run("done", func(t *testing.T) {
		t.Parallel()
		var a OutputActivity
		done := make(chan struct{})
		close(done)
		if err := a.WaitQuiet(context.Background(), done, time.Hour); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("quiet", func(t *testing.T) {
		t.Parallel()
		var a OutputActivity
		start := time.Now()
		if err := a.WaitQuiet(context.Background(), nil, grace); err != nil {
			t.Fatal(err)
		}
		if took := time.Since(start); took < grace || took > 10*grace {
			t.Errorf("took %s", took)
		}
	})
	t.Run("moving output extends it", func(t *testing.T) {
		t.Parallel()
		var a OutputActivity
		w := a.Wrap(io.Discard)
		stop := make(chan struct{})
		go func() {
			for range 20 {
				_, _ = w.Write([]byte("x"))
				time.Sleep(grace / 4)
			}
			close(stop)
		}()
		start := time.Now()
		if err := a.WaitQuiet(context.Background(), nil, grace); err != nil {
			t.Fatal(err)
		}
		select {
		case <-stop:
		default:
			t.Fatalf("returned after %s while output still moved", time.Since(start))
		}
	})
	t.Run("a write in progress counts", func(t *testing.T) {
		t.Parallel()
		var a OutputActivity
		w := a.Wrap(writerFunc(func(p []byte) (int, error) {
			time.Sleep(5 * grace)
			return len(p), nil
		}))
		wrote := make(chan struct{})
		go func() {
			_, _ = w.Write([]byte("x"))
			close(wrote)
		}()
		time.Sleep(grace / 4)
		if err := a.WaitQuiet(context.Background(), nil, grace); err != nil {
			t.Fatal(err)
		}
		select {
		case <-wrote:
		default:
			t.Fatal("returned while a write was in progress")
		}
	})
	t.Run("ctx", func(t *testing.T) {
		t.Parallel()
		var a OutputActivity
		w := a.Wrap(io.Discard)
		ctx, cancel := context.WithTimeout(context.Background(), 2*grace)
		defer cancel()
		go func() {
			for ctx.Err() == nil {
				_, _ = w.Write([]byte("x"))
				time.Sleep(grace / 10)
			}
		}()
		if err := a.WaitQuiet(ctx, nil, grace); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("nil writer", func(t *testing.T) {
		t.Parallel()
		var a OutputActivity
		if a.Wrap(nil) != nil {
			t.Fatal("Wrap(nil) is not nil")
		}
	})
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }
