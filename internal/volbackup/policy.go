package volbackup

import (
	"slices"
	"time"

	"github.com/ryanbekhen/armada/internal/spec"
)

// selectKept says which of the snapshots taken at times keep holds: the
// latest Last, and the newest of each of the latest Hourly hours, Daily
// days, Weekly ISO weeks, and Monthly months, counted in loc.
func selectKept(times []time.Time, keep spec.BackupKeep, loc *time.Location) []bool {
	order := make([]int, len(times))
	for i := range order {
		order[i] = i
	}
	// Newest first.
	slices.SortStableFunc(order, func(a, b int) int { return times[b].Compare(times[a]) })
	kept := make([]bool, len(times))
	for n, i := range order {
		if n < keep.Last {
			kept[i] = true
		}
	}
	bucket := func(count int, key func(time.Time) [3]int) {
		seen := map[[3]int]bool{}
		for _, i := range order {
			if len(seen) == count {
				return
			}
			k := key(times[i].In(loc))
			if !seen[k] {
				seen[k] = true
				kept[i] = true
			}
		}
	}
	bucket(keep.Hourly, func(t time.Time) [3]int { return [3]int{t.Year(), t.YearDay(), t.Hour()} })
	bucket(keep.Daily, func(t time.Time) [3]int { return [3]int{t.Year(), t.YearDay(), 0} })
	bucket(keep.Weekly, func(t time.Time) [3]int { y, w := t.ISOWeek(); return [3]int{y, w, 0} })
	bucket(keep.Monthly, func(t time.Time) [3]int { return [3]int{t.Year(), int(t.Month()), 0} })
	return kept
}
