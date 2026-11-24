package agent

import (
	"context"
	"testing"
	"time"
)

// Only a backslash and three octal digits is an escape in mountinfo;
// anything shorter, larger, or cut off stays as written.
func TestUnescapeMount(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		`plain`:        `plain`,
		`a\040b\134c`:  `a b\c`,
		`a\04x`:        `a\04x`,
		`a\04`:         `a\04`,
		`a\7`:          `a\7`,
		`a\`:           `a\`,
		`a\777b`:       `a\777b`,
		`a\08b`:        `a\08b`,
		`\\040`:        `\ `,
		`/mnt/fi\154e`: `/mnt/file`,
	} {
		if got := unescapeMount(in); got != want {
			t.Errorf("unescapeMount(%q) = %q, want %q", in, got, want)
		}
	}
}

// A statfs that never ends (a hard NFS mount whose server is gone) holds
// the caller only for the limit.
func TestMountedReadOnlyBounded(t *testing.T) {
	t.Parallel()
	ro, err := within(context.Background(), time.Second, "/m", func() bool { return true })
	if !ro || err != nil {
		t.Errorf("quick: %v %v", ro, err)
	}
	hang := make(chan struct{})
	defer close(hang)
	start := time.Now()
	_, err = within(context.Background(), 50*time.Millisecond, "/var/lib/armada/nfs/web/files", func() bool { <-hang; return false })
	if err == nil || err.Error() != "the NFS mount on /var/lib/armada/nfs/web/files does not answer" || time.Since(start) > 5*time.Second {
		t.Errorf("hung: %v after %v", err, time.Since(start))
	}
}
