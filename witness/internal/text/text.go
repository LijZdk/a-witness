// Package text prints document-supplied strings safely.
package text

import (
	"fmt"
	"strings"
)

// Esc makes a string taken from a document safe to print inside a message:
// plain printable text is kept as it is, and these become \uXXXX (lower case
// hex), so that nothing in a document can start a new line, forge a result
// line or reorder what a reader sees:
//
//   - control characters: C0, DEL and C1 (U+0000 to U+001F, U+007F to U+009F)
//   - the line and paragraph separators U+2028 and U+2029
//   - the bidirectional controls U+200E, U+200F, U+202A to U+202E and
//     U+2066 to U+2069
//
// scripts/validate.py has the same function (esc) and escapes the same
// characters, plus the lone surrogates U+D800 to U+DFFF, which Go strings
// cannot hold. The two print the same bytes for every other input.
func Esc(s string) string {
	var b strings.Builder
	for _, r := range s {
		if mustEscape(r) {
			fmt.Fprintf(&b, "\\u%04x", r)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func mustEscape(r rune) bool {
	switch {
	case r < 0x20, r >= 0x7f && r <= 0x9f:
		return true
	case r == 0x200e, r == 0x200f, r >= 0x202a && r <= 0x202e, r == 0x2028, r == 0x2029, r >= 0x2066 && r <= 0x2069:
		return true
	}
	return false
}
