package text

import (
	"fmt"
	"strings"
	"testing"
)

func TestEsc(t *testing.T) {
	r := func(cs ...rune) string { return string(cs) }
	// lit spells runes the way Esc must: a backslash, u and four hex digits.
	lit := func(cs ...rune) string {
		var b strings.Builder
		for _, c := range cs {
			fmt.Fprintf(&b, "%cu%04x", 92, c)
		}
		return b.String()
	}
	for _, c := range []struct{ in, want string }{
		{"plain é 日本 'quoted' \\ back", "plain é 日本 'quoted' \\ back"},
		{"a\tb\x00c\x7fd\n", "a" + lit(9) + "b" + lit(0) + "c" + lit(0x7f) + "d" + lit(10)},
		{r(0x85, 0x9f, 0xa0), lit(0x85, 0x9f) + r(0xa0)},
		{r(0x2028, 0x2029), lit(0x2028, 0x2029)},
		{r(0x200e, 0x200f, 0x202a, 0x202e, 0x2066, 0x2069), lit(0x200e, 0x200f, 0x202a, 0x202e, 0x2066, 0x2069)},
		{r(0x200d, 0x202f, 0x2065, 0x206a), r(0x200d, 0x202f, 0x2065, 0x206a)},
	} {
		if got := Esc(c.in); got != c.want {
			t.Errorf("Esc(%q) = %q, want %q", c.in, got, c.want)
		}
		if again := Esc(Esc(c.in)); again != Esc(c.in) {
			t.Errorf("Esc is not idempotent on %q", c.in)
		}
	}
}
