package schema

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// The two formats the schemas use. They are registered with the compiler,
// replacing the library's built-in versions, under one rule: no looser than
// the verifier (witness.Verify parses times with time.RFC3339), and, for the
// cases tested, no looser than scripts/validate.py (Python's jsonschema format
// checker). The one known difference runs the safe way: see validateDateTime.
var (
	dateTimeFormat = &jsonschema.Format{Name: "date-time", Validate: validateDateTime}
	uriFormat      = &jsonschema.Format{Name: "uri", Validate: validateURI}
)

var dateTimeShape = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$`)

// validateDateTime accepts an RFC 3339 timestamp in its upper-case form with
// a zone, as time.RFC3339 reads it. The shape check comes first because
// time.Parse is more lenient than the specification in places (it accepts a
// comma before the fraction, or a zone offset of +24:00 or +00:60, for
// example; the shape allows only hours 00-23 and minutes 00-59). It rejects second 60, "+0100", a day
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

// validateURI accepts an absolute URI under these rules, which follow RFC 3986
// and what Python's validator (rfc3986) accepts:
//   - only unreserved and reserved characters and well-formed %HH escapes, so
//     no spaces and no non-ASCII text;
//   - at most one '#';
//   - '[' and ']' only as the delimiters of an IP-literal host;
//   - a scheme, so the URI is absolute;
//   - if there is an authority ("scheme://..."), it is parsed here, not by
//     url.Parse, which is loose and differs between Go versions: at most one
//     '@' (userinfo before it); a port, if any, of numerals only; a host that
//     is either a reg-name
//     (unreserved, sub-delims and %HH, so no ':'), or in brackets an IPv6
//     address without a zone, or IPvFuture ("v" 1*HEXDIG "." 1*(unreserved /
//     sub-delims / ":")).
//
// Known differences from Python, where Go is stricter (found by running about
// 229,000 generated strings through both): a trailing newline, which Python
// accepts; and a leading zero in an IPv4 address embedded in an IPv6 literal,
// such as "[::01.2.3.4]", which netip refuses. IPvFuture needs a lower-case
// "v" in both. For date-time, Python also accepts a lower-case "t" or "z" and
// a trailing newline. In no case found does Go accept what Python rejects.
//
// A scheme such as "javascript:x" is a valid URI and passes, as it does in
// Python. Nothing may treat a URI that passed this check as safe to fetch or
// to render as a link.
func validateURI(v any) error {
	s, ok := v.(string)
	if !ok {
		return nil
	}
	if strings.Count(s, "#") > 1 {
		return errors.New("more than one '#'")
	}
	open, closing, auth, hasAuth := authority(s)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '[' && i != open, c == ']' && i != closing:
			return fmt.Errorf("%q is only allowed around an IP-literal host", rune(c))
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
	if hasAuth {
		if err := validateAuthority(auth); err != nil {
			return err
		}
	}
	return validateScheme(s)
}

// validateScheme checks that s starts with scheme ":" where scheme is
// ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ). url.Parse is deliberately not
// used: its host checks differ between Go versions.
func validateScheme(s string) error {
	scheme, _, found := strings.Cut(s, ":")
	if !found || scheme == "" || strings.ContainsAny(scheme, "/?#") {
		return errors.New("not an absolute URI (no scheme)")
	}
	for i := 0; i < len(scheme); i++ {
		c := scheme[i]
		alpha := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
		if !(alpha || i > 0 && (c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.')) {
			return errors.New("not a valid scheme")
		}
	}
	return nil
}

// authority finds the authority of "scheme://authority/..." in s. It returns
// the positions of the '[' and ']' that delimit an IP-literal host (-1, -1 if
// there is none) and the authority text.
func authority(s string) (open, closing int, auth string, ok bool) {
	// The scheme ends at the first ':'; there is an authority only if "//"
	// follows it directly. Anything else after the scheme is a path.
	scheme, afterScheme, found := strings.Cut(s, ":")
	rest, hasSlashes := strings.CutPrefix(afterScheme, "//")
	if !found || !hasSlashes || strings.ContainsAny(scheme, "/?#") {
		return -1, -1, "", false
	}
	start := len(scheme) + len(":") + len("//")
	auth = rest
	if i := strings.IndexAny(auth, "/?#"); i >= 0 {
		auth = auth[:i]
	}
	open, closing = -1, -1
	hostStart := start
	if i := strings.LastIndexByte(auth, '@'); i >= 0 {
		hostStart += i + 1
	}
	if hostStart < len(s) && s[hostStart] == '[' {
		open = hostStart
		if end := strings.IndexByte(s[open:], ']'); end >= 0 && open+end < start+len(auth) {
			closing = open + end
		}
	}
	return open, closing, auth, true
}

func validateAuthority(auth string) error {
	if strings.Count(auth, "@") > 1 {
		return errors.New("more than one '@' in the authority")
	}
	if _, hostport, found := strings.Cut(auth, "@"); found {
		auth = hostport
	}
	var port string
	if strings.HasPrefix(auth, "[") {
		end := strings.IndexByte(auth, ']')
		if end < 0 {
			return errors.New("unclosed '[' in the host")
		}
		port = auth[end+1:]
		if port != "" {
			if port[0] != ':' {
				return errors.New("junk after the IP-literal host")
			}
			port = port[1:]
		}
		if err := validateIPLiteral(auth[1:end]); err != nil {
			return err
		}
	} else {
		_, port, _ = strings.Cut(auth, ":")
	}
	for i := 0; i < len(port); i++ {
		if port[i] < '0' || port[i] > '9' {
			return errors.New("port is not all digits")
		}
	}
	return nil
}

// validateIPLiteral checks what sits between '[' and ']': an IPv6 address
// without a zone, or IPvFuture.
func validateIPLiteral(h string) error {
	if rest, ok := strings.CutPrefix(h, "v"); ok {
		hex, tail, found := strings.Cut(rest, ".")
		if !found || hex == "" || tail == "" {
			return errors.New("bad IPvFuture host")
		}
		for i := 0; i < len(hex); i++ {
			if !isHex(hex[i]) {
				return errors.New("bad IPvFuture host")
			}
		}
		for i := 0; i < len(tail); i++ {
			if c := tail[i]; !(isUnreserved(c) || isSubDelim(c) || c == ':') {
				return errors.New("bad IPvFuture host")
			}
		}
		return nil
	}
	a, err := netip.ParseAddr(h)
	if err != nil || !a.Is6() || a.Zone() != "" || strings.Contains(h, "%") {
		return errors.New("not an IPv6 address")
	}
	return nil
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func isUnreserved(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	return c == '-' || c == '.' || c == '_' || c == '~'
}

func isSubDelim(c byte) bool {
	switch c {
	case '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=':
		return true
	}
	return false
}

// isURIChar reports whether c is unreserved or reserved in RFC 3986. The
// brackets are checked separately, by the caller.
func isURIChar(c byte) bool {
	return isUnreserved(c) || isSubDelim(c) || strings.IndexByte(":/?#@[]", c) >= 0
}
