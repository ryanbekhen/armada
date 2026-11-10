package cli

import (
	"fmt"
	"io"
	"strings"
)

// maxDiffCells bounds the work of lineDiff; larger inputs show every old
// line removed and every new line added.
const maxDiffCells = 4 << 20

// printDiff prints what changes from before to after, line by line: "-" for a
// line removed, "+" for one added, and the lines around them.
func printDiff(out io.Writer, before, after []byte) error {
	ops := lineDiff(splitLines(string(before)), splitLines(string(after)))
	changed := false
	for _, op := range ops {
		if op.kind != ' ' {
			changed = true
			break
		}
	}
	if !changed {
		_, err := fmt.Fprintln(out, "No changes.")
		return err
	}
	const around = 3
	shown := -1
	for i, op := range ops {
		near := false
		for j := max(0, i-around); j <= min(len(ops)-1, i+around); j++ {
			if ops[j].kind != ' ' {
				near = true
				break
			}
		}
		if !near {
			continue
		}
		if shown >= 0 && i > shown+1 {
			if _, err := fmt.Fprintln(out, "@@"); err != nil {
				return err
			}
		}
		shown = i
		if _, err := fmt.Fprintf(out, "%c %s\n", op.kind, op.line); err != nil {
			return err
		}
	}
	return nil
}

func splitLines(s string) []string {
	s = strings.TrimSuffix(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

type diffOp struct {
	kind byte // ' ', '-', or '+'
	line string
}

// lineDiff returns the edit script from a to b along their longest common
// subsequence.
func lineDiff(a, b []string) []diffOp {
	var ops []diffOp
	if len(a)*len(b) > maxDiffCells {
		for _, l := range a {
			ops = append(ops, diffOp{'-', l})
		}
		for _, l := range b {
			ops = append(ops, diffOp{'+', l})
		}
		return ops
	}
	// lcs[i][j] is the length of the longest common subsequence of a[i:]
	// and b[j:].
	lcs := make([][]int, len(a)+1)
	for i := range lcs {
		lcs[i] = make([]int, len(b)+1)
	}
	for i := len(a) - 1; i >= 0; i-- {
		for j := len(b) - 1; j >= 0; j-- {
			if a[i] == b[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		switch {
		case a[i] == b[j]:
			ops = append(ops, diffOp{' ', a[i]})
			i++
			j++
		case lcs[i+1][j] >= lcs[i][j+1]:
			ops = append(ops, diffOp{'-', a[i]})
			i++
		default:
			ops = append(ops, diffOp{'+', b[j]})
			j++
		}
	}
	for ; i < len(a); i++ {
		ops = append(ops, diffOp{'-', a[i]})
	}
	for ; j < len(b); j++ {
		ops = append(ops, diffOp{'+', b[j]})
	}
	return ops
}
