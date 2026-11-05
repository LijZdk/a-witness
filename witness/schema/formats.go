package schema

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// The two formats the schemas use. They are registered with the compiler,
// replacing the library's built-in versions, under one rule: no looser than
// the verifier (witness.Verify parses times with time.RFC3339), and no looser
// than scripts/validate.py.
var (
	dateTimeFormat = &jsonschema.Format{Name: "date-time", Validate: validateDateTime}
	uriFormat      = &jsonschema.Format{Name: "uri", Validate: validateURI}
)

var dateTimeShape = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$`)

// validateDateTime accepts an RFC 3339 timestamp in its upper-case form with
// a zone, as time.RFC3339 reads it. The shape check comes first because
// time.Parse is more lenient than the specification in places (it accepts a
// comma before the fraction, for one). It rejects second 60, "+0100", a day
// that does not exist (February 30) and year 0000.
//
// Known gap: Python's jsonschema format checker (scripts/validate.py) accepts
// a lower-case "t" or "z"; this check does not. Being stricter is the safe
// direction, and a test pins it.
func validateDateTime(v any) error {
	s, ok := v.(string)
	if !ok {
		return nil
	}
	if !dateTimeShape.MatchString(s) {
		return errors.New("not an RFC 3339 date-time such as 2026-01-02T15:04:05Z")
	}
	if s[:4] == "0000" {
		return errors.New("year 0000 is not allowed")
	}
	if _, err := time.Parse(time.RFC3339, s); err != nil {
		return errors.New("not a real date and time")
	}
	return nil
}

// validateURI accepts an absolute URI made only of RFC 3986 unreserved and
// reserved characters and well-formed %HH escapes. That rejects spaces and
// non-ASCII text, which url.Parse alone lets through.
//
// A scheme such as "javascript:x" is a valid URI and passes, as it does in
// Python. Nothing may treat a URI that passed this check as safe to fetch or
// to render as a link.
func validateURI(v any) error {
	s, ok := v.(string)
	if !ok {
		return nil
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '%':
			if i+2 >= len(s) || !isHex(s[i+1]) || !isHex(s[i+2]) {
				return errors.New("bad % escape")
			}
			i += 2
		case isURIChar(c):
		default:
			return fmt.Errorf("character %q is not allowed in a URI", rune(c))
		}
	}
	u, err := url.Parse(s)
	if err != nil {
		return errors.New("cannot be parsed as a URI")
	}
	if !u.IsAbs() {
		return errors.New("not an absolute URI (no scheme)")
	}
	return nil
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// isURIChar reports whether c is unreserved or reserved in RFC 3986.
func isURIChar(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	switch c {
	case '-', '.', '_', '~', ':', '/', '?', '#', '[', ']', '@',
		'!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=':
		return true
	}
	return false
}
