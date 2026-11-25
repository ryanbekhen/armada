// Command gentables writes spec/src/gotables.rs: Go's tables of runes the
// spec crate (ADR 0055) needs to quote and sort as Go does.
package main

import (
	"fmt"
	"strconv"
	"unicode"
)

func ranges(name string, f func(rune) bool) {
	fmt.Printf("pub(crate) const %s: &[(u32, u32)] = &[\n", name)
	in := false
	var start rune
	for r := rune(0); r <= unicode.MaxRune+1; r++ {
		ok := r <= unicode.MaxRune && f(r)
		if ok && !in {
			start, in = r, true
		} else if !ok && in {
			fmt.Printf("    (0x%x, 0x%x),\n", start, r-1)
			in = false
		}
	}
	fmt.Println("];")
}

func main() {
	fmt.Println("//! Generated from Go's strconv and unicode packages by")
	fmt.Println("//! `go run ./internal/spec/testdata/gentables > spec/src/gotables.rs`; do")
	fmt.Println("//! not edit. Each table lists the inclusive ranges of runes for which the")
	fmt.Println("//! Go function in its name is true.")
	fmt.Println()
	ranges("IS_PRINT", strconv.IsPrint)
	ranges("IS_SPACE", unicode.IsSpace)
	ranges("IS_LETTER", unicode.IsLetter)
	ranges("IS_DIGIT", unicode.IsDigit)
}
