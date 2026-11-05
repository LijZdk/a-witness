// Package canon implements the JSON Canonicalization Scheme (JCS), RFC 8785.
//
// Canonical JSON gives every JSON value exactly one byte representation, so
// that two parties hashing or signing the same value get the same result.
// a-witness hashes mandates and events in this form; see SPEC.md, "Hashing".
//
// Parsing is strict, as RFC 8785 requires of its input (I-JSON, RFC 7493).
// Leniency here would be a weakness: if two different inputs were accepted
// as the same value, they would share a hash, and an edit could go unnoticed.
package canon

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// MaxDepth is the deepest nesting Parse accepts. Arrays and objects each count
// one level; a top-level scalar is depth 0 and "[]" is depth 1. No real
// document comes close, and unbounded depth can crash a parser: when this
// limit was added (Go 1.25), encoding/json imposed no depth limit of its own, and
// a few million "[" overflow the goroutine stack, a fatal error that cannot be recovered.
const MaxDepth = 1000

var errTooDeep = fmt.Errorf("canon: nesting deeper than %d levels", MaxDepth)

// Transform returns the canonical form of a JSON text.
func Transform(in []byte) ([]byte, error) {
	v, err := Parse(in)
	if err != nil {
		return nil, err
	}
	return Serialize(v)
}

// Parse decodes a JSON text, rejecting anything RFC 8785 does not accept:
// invalid UTF-8, unpaired surrogate escapes (such as "\ud800"), duplicate
// object keys, numbers outside the range of an IEEE 754 double, and anything
// other than exactly one top-level value. Nesting deeper than MaxDepth is
// rejected as it is met, before the recursion can grow.
//
// The result is built from nil, bool, float64, string, []any and
// map[string]any, the same types Serialize accepts.
func Parse(in []byte) (any, error) {
	if !utf8.Valid(in) {
		return nil, errors.New("canon: input is not valid UTF-8")
	}
	if err := checkSurrogates(in); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(in))
	dec.UseNumber()
	v, err := parseValue(dec, 0)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("canon: unexpected data after the top-level value")
	}
	return v, nil
}

// parseValue reads one value; depth is how many arrays and objects enclose it.
func parseValue(dec *json.Decoder, depth int) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("canon: %w", err)
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{', '[':
			if depth >= MaxDepth {
				return nil, errTooDeep
			}
			if t == '{' {
				return parseObject(dec, depth+1)
			}
			return parseArray(dec, depth+1)
		}
		return nil, fmt.Errorf("canon: unexpected %q", t)
	case json.Number:
		f, err := strconv.ParseFloat(string(t), 64)
		if err != nil {
			return nil, fmt.Errorf("canon: number %s does not fit an IEEE 754 double", t)
		}
		return f, nil
	case string, bool, nil:
		return t, nil
	}
	return nil, fmt.Errorf("canon: unexpected token %v", tok)
}

func parseObject(dec *json.Decoder, depth int) (any, error) {
	obj := map[string]any{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("canon: %w", err)
		}
		key, ok := tok.(string)
		if !ok {
			return nil, fmt.Errorf("canon: object key %v is not a string", tok)
		}
		if _, dup := obj[key]; dup {
			return nil, fmt.Errorf("canon: duplicate object key %q", key)
		}
		val, err := parseValue(dec, depth)
		if err != nil {
			return nil, err
		}
		obj[key] = val
	}
	if _, err := dec.Token(); err != nil { // the closing '}'
		return nil, fmt.Errorf("canon: %w", err)
	}
	return obj, nil
}

func parseArray(dec *json.Decoder, depth int) (any, error) {
	arr := []any{}
	for dec.More() {
		val, err := parseValue(dec, depth)
		if err != nil {
			return nil, err
		}
		arr = append(arr, val)
	}
	if _, err := dec.Token(); err != nil { // the closing ']'
		return nil, fmt.Errorf("canon: %w", err)
	}
	return arr, nil
}

// checkSurrogates rejects \u escapes that encode half of a UTF-16 surrogate
// pair without the other half. encoding/json would silently turn them into
// U+FFFD, making "\ud800" and "�" hash the same.
func checkSurrogates(in []byte) error {
	inString := false
	for i := 0; i < len(in); i++ {
		c := in[i]
		if !inString {
			inString = c == '"'
			continue
		}
		switch c {
		case '"':
			inString = false
		case '\\':
			u, ok := escapeAt(in, i)
			switch {
			case !ok: // not a \u escape: skip the escaped character
				i++
			case u >= 0xD800 && u <= 0xDBFF:
				low, ok := escapeAt(in, i+6)
				if !ok || low < 0xDC00 || low > 0xDFFF {
					return fmt.Errorf("canon: unpaired surrogate escape \\u%04x", u)
				}
				i += 11 // past both escapes
			case u >= 0xDC00 && u <= 0xDFFF:
				return fmt.Errorf("canon: unpaired surrogate escape \\u%04x", u)
			default:
				i += 5
			}
		}
	}
	return nil
}

// escapeAt reads a \uXXXX escape starting at in[i], if there is one.
func escapeAt(in []byte, i int) (rune, bool) {
	if i+6 > len(in) || in[i] != '\\' || in[i+1] != 'u' {
		return 0, false
	}
	n, err := strconv.ParseUint(string(in[i+2:i+6]), 16, 16)
	if err != nil {
		return 0, false
	}
	return rune(n), true
}

// Serialize writes a value in canonical form. It accepts the types Parse
// returns, plus int and int64 for convenience when building values in Go.
func Serialize(v any) ([]byte, error) {
	var b bytes.Buffer
	if err := write(&b, v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// maxSafeInteger is the largest integer an IEEE 754 double holds exactly.
const maxSafeInteger = 1<<53 - 1

func write(b *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(t))
	case float64:
		s, err := FormatNumber(t)
		if err != nil {
			return err
		}
		b.WriteString(s)
	case int:
		return write(b, int64(t))
	case int64:
		if t > maxSafeInteger || t < -maxSafeInteger {
			return fmt.Errorf("canon: integer %d cannot be represented exactly as a JSON number", t)
		}
		return write(b, float64(t))
	case string:
		return writeString(b, t)
	case []any:
		b.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := write(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		slices.SortFunc(keys, compareUTF16)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeString(b, k); err != nil {
				return err
			}
			b.WriteByte(':')
			if err := write(b, t[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("canon: cannot serialise a value of type %T", v)
	}
	return nil
}

// compareUTF16 orders object keys by their UTF-16 code units, as RFC 8785
// section 3.2.3 requires. This differs from byte or code point order only
// for keys containing characters outside the Basic Multilingual Plane.
func compareUTF16(a, b string) int {
	return slices.Compare(utf16.Encode([]rune(a)), utf16.Encode([]rune(b)))
}

// writeString escapes only what JSON requires (RFC 8785 section 3.2.2.2):
// the quote, the backslash and control characters. Everything else,
// including non-ASCII, is written as literal UTF-8.
func writeString(b *bytes.Buffer, s string) error {
	if !utf8.ValidString(s) {
		return errors.New("canon: string is not valid UTF-8")
	}
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return nil
}

// FormatNumber writes a number the way ECMAScript's Number.prototype.toString
// does, which is what RFC 8785 section 3.2.2.3 requires: the shortest digits
// that round-trip, in plain notation from 1e-7 up to 1e21 and in exponent
// notation outside that range.
func FormatNumber(f float64) (string, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "", errors.New("canon: NaN and infinity cannot be represented in JSON")
	}
	if f == 0 {
		return "0", nil // also for negative zero
	}
	if f < 0 {
		s, err := FormatNumber(-f)
		return "-" + s, err
	}

	// strconv gives the shortest round-trip digits, as "d.ddde±XX".
	mantissa, exponent, _ := strings.Cut(strconv.FormatFloat(f, 'e', -1, 64), "e")
	digits := strings.Replace(mantissa, ".", "", 1)
	e, err := strconv.Atoi(exponent)
	if err != nil {
		return "", fmt.Errorf("canon: formatting %v: %w", f, err)
	}

	// In ECMAScript's terms the value is digits × 10^(n-k).
	k, n := len(digits), e+1
	switch {
	case k <= n && n <= 21:
		return digits + strings.Repeat("0", n-k), nil
	case 0 < n && n <= 21:
		return digits[:n] + "." + digits[n:], nil
	case -6 < n && n <= 0:
		return "0." + strings.Repeat("0", -n) + digits, nil
	}
	sign := "+"
	if n-1 < 0 {
		sign = "-"
	}
	exp := strconv.Itoa(abs(n - 1))
	if k == 1 {
		return digits + "e" + sign + exp, nil
	}
	return digits[:1] + "." + digits[1:] + "e" + sign + exp, nil
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}
