package canon

import (
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The vectors are generated outside Go (see testdata/vectors/README.md), so
// these tests compare this package against independent implementations.
func loadVectors[T any](t *testing.T, name string) []T {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors", name))
	if err != nil {
		t.Fatal(err)
	}
	var file struct{ Vectors []T }
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if len(file.Vectors) == 0 {
		t.Fatalf("%s: no vectors", name)
	}
	return file.Vectors
}

func TestCanonVectors(t *testing.T) {
	type vector struct {
		Name     string
		Input    *string
		InputHex string `json:"input_hex"`
		Output   *string
		Error    bool
	}
	for _, v := range loadVectors[vector](t, "canon.json") {
		t.Run(v.Name, func(t *testing.T) {
			var in []byte
			switch {
			case v.Input != nil:
				in = []byte(*v.Input)
			default:
				var err error
				if in, err = hex.DecodeString(v.InputHex); err != nil {
					t.Fatal(err)
				}
			}
			got, err := Transform(in)
			if v.Error {
				if err == nil {
					t.Fatalf("accepted invalid input %q, producing %s", in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("rejected valid input: %v", err)
			}
			if string(got) != *v.Output {
				t.Fatalf("got  %s\nwant %s", got, *v.Output)
			}
			// Canonical output is a fixed point.
			again, err := Transform(got)
			if err != nil || string(again) != string(got) {
				t.Fatalf("canonical form is not stable: %s -> %s (%v)", got, again, err)
			}
		})
	}
}

func TestNumberVectors(t *testing.T) {
	type vector struct{ Bits, Output string }
	for _, v := range loadVectors[vector](t, "numbers.json") {
		bits, err := strconv.ParseUint(v.Bits, 16, 64)
		if err != nil {
			t.Fatal(err)
		}
		f := math.Float64frombits(bits)
		got, err := FormatNumber(f)
		if err != nil {
			t.Errorf("%s: %v", v.Bits, err)
			continue
		}
		if got != v.Output {
			t.Errorf("%s (%g): got %s, want %s", v.Bits, f, got, v.Output)
		}
		// Reading the output back must give the same double.
		back, err := Parse([]byte(v.Output))
		if err != nil || math.Float64bits(back.(float64)) != bits && f != 0 {
			t.Errorf("%s: %s does not read back as the same double (%v)", v.Bits, v.Output, err)
		}
	}
}

func TestFormatNumberRejectsNonFinite(t *testing.T) {
	for _, f := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		if s, err := FormatNumber(f); err == nil {
			t.Errorf("FormatNumber(%v) = %q, want an error", f, s)
		}
	}
}

func TestSerializeGoValues(t *testing.T) {
	got, err := Serialize(map[string]any{"b": int64(2), "a": []any{1, true, nil, "x"}})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"a":[1,true,null,"x"],"b":2}`; string(got) != want {
		t.Fatalf("got %s, want %s", got, want)
	}
	for _, bad := range []any{
		int64(1 << 53),          // not exactly representable as a double
		"\xff",                  // invalid UTF-8
		map[string]any{"k": 1i}, // not a JSON type
	} {
		if out, err := Serialize(bad); err == nil {
			t.Errorf("Serialize(%#v) = %s, want an error", bad, out)
		}
	}
}

func nested(open, close string, n int) []byte {
	return []byte(strings.Repeat(open, n) + strings.Repeat(close, n))
}

func TestMaxDepth(t *testing.T) {
	t.Run("1,000 levels of arrays are accepted", func(t *testing.T) {
		in := nested("[", "]", MaxDepth)
		got, err := Transform(in)
		if err != nil || string(got) != string(in) {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("1,001 levels of arrays are rejected", func(t *testing.T) {
		_, err := Parse(nested("[", "]", MaxDepth+1))
		if err == nil || !strings.Contains(err.Error(), "nesting deeper than 1000 levels") {
			t.Fatalf("err %v", err)
		}
	})
	objects := func(n int) []byte {
		return []byte(strings.Repeat(`{"a":`, n) + "1" + strings.Repeat("}", n))
	}
	t.Run("objects count", func(t *testing.T) {
		if _, err := Parse(objects(MaxDepth)); err != nil {
			t.Fatal(err)
		}
		if _, err := Parse(objects(MaxDepth + 1)); err == nil {
			t.Fatal("accepted 1,001 levels of objects")
		}
	})
	t.Run("arrays and objects share one count", func(t *testing.T) {
		in := strings.Repeat(`[{"a":`, MaxDepth/2) + "1" + strings.Repeat("}]", MaxDepth/2)
		if _, err := Parse([]byte(in)); err != nil {
			t.Fatal(err)
		}
		if _, err := Parse([]byte("[" + in + "]")); err == nil {
			t.Fatal("accepted 1,001 mixed levels")
		}
	})
	t.Run("a scalar is depth 0", func(t *testing.T) {
		if _, err := Parse([]byte("1")); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("5,000,000 levels are rejected quickly, without a stack overflow", func(t *testing.T) {
		in := []byte(strings.Repeat("[", 5_000_000))
		start := time.Now()
		if _, err := Parse(in); err == nil {
			t.Fatal("accepted")
		}
		if d := time.Since(start); d > 2*time.Second {
			t.Fatalf("took %v", d)
		}
	})
}
