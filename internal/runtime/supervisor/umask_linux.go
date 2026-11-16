package supervisor

import (
	"fmt"
	"runtime"

	"golang.org/x/sys/unix"
)

// imageUmask is the umask image layers and root filesystems are made with.
// The agent's service runs with 0077, which would make every directory a
// layer creates without stating its mode, and the root of every
// container's filesystem, 0700: closed to a container's non-root users.
// Container content takes the modes an image runtime gives it.
const imageUmask = 0o022

// withImageUmask runs fn on an OS thread of its own whose umask is
// imageUmask. The thread stops sharing filesystem attributes (umask, root,
// working directory) with the rest of the process first, so every other
// thread keeps the service's umask; it ends with fn.
func withImageUmask(fn func() error) error {
	done := make(chan error, 1)
	go func() {
		// Never unlocked: the thread exits with this goroutine instead of
		// going back to the scheduler with its own umask.
		runtime.LockOSThread()
		if err := unix.Unshare(unix.CLONE_FS); err != nil {
			done <- fmt.Errorf("unshare filesystem attributes: %w", err)
			return
		}
		unix.Umask(imageUmask)
		done <- fn()
	}()
	return <-done
}
