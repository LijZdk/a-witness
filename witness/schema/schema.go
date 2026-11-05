// Package schema checks mandates and traces against the JSON Schemas in
// schemas/, the same files scripts/validate.py reads.
//
// The documents it checks are the values canon.Parse produces, so what is
// validated is exactly what witness.Verify hashes and signs; no other JSON
// parser is involved. canon.Parse rejects duplicate keys, invalid UTF-8,
// unpaired surrogates and numbers outside the range of a double, which the
// schemas cannot express.
//
// The schemas are compiled once, from the embedded copies, with a loader that
// refuses to fetch anything: a document cannot make this package read a file
// or call a server.
package schema

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/LijZdk/a-witness/schemas"
	"github.com/LijZdk/a-witness/witness/canon"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/santhosh-tekuri/jsonschema/v6/kind"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

// maxMessage is the longest message, in bytes, before it is cut. A format
// error quotes the offending value, which can be huge.
const maxMessage = 200

// A Violation is one way a document fails its schema.
type Violation struct {
	// Path locates the value in the document: the object keys and array
	// indexes joined with "/", or "<root>" for the document itself.
	Path    string
	Message string
}

// String returns "path: message".
func (v Violation) String() string { return v.Path + ": " + v.Message }

// ValidateMandate checks a mandate against mandate.schema.json. doc must be a
// value returned by canon.Parse; anything else is not meaningful. No
// violations means the mandate conforms.
func ValidateMandate(doc any) []Violation { return validate(compiled().mandate, doc) }

// ValidateTrace checks a trace against trace.schema.json. doc must be a value
// returned by canon.Parse. No violations means the trace conforms.
func ValidateTrace(doc any) []Violation { return validate(compiled().trace, doc) }

// ValidateMandateJSON parses b with canon.Parse and then calls
// ValidateMandate. A non-nil error means b is not strict JSON and could not
// be checked at all.
func ValidateMandateJSON(b []byte) ([]Violation, error) {
	doc, err := canon.Parse(b)
	if err != nil {
		return nil, err
	}
	return ValidateMandate(doc), nil
}

// ValidateTraceJSON is ValidateMandateJSON for traces.
func ValidateTraceJSON(b []byte) ([]Violation, error) {
	doc, err := canon.Parse(b)
	if err != nil {
		return nil, err
	}
	return ValidateTrace(doc), nil
}

// bundle is the compiled schemas and, per schema location, the message for
// each anyOf keyword whose branches only say "required".
type bundle struct {
	mandate, trace *jsonschema.Schema
	anyRequired    map[string]string
}

var compiled = sync.OnceValue(func() *bundle {
	b, err := compile()
	if err != nil {
		panic("witness/schema: embedded schemas do not compile: " + err.Error())
	}
	return b
})

// denyLoader refuses every load, so a $ref that is not one of the two
// embedded schemas fails to compile instead of fetching anything.
type denyLoader struct{}

func (denyLoader) Load(u string) (any, error) {
	return nil, fmt.Errorf("loading %s is not allowed", u)
}

// newCompiler returns a compiler with both schemas added, our formats
// registered and format assertion on, plus the parsed schema documents. The
// tests use it too, so they exercise the same setup.
func newCompiler() (*jsonschema.Compiler, map[string]any, error) {
	c := jsonschema.NewCompiler()
	c.UseLoader(denyLoader{})
	c.AssertFormat()
	c.RegisterFormat(dateTimeFormat)
	c.RegisterFormat(uriFormat)
	docs := map[string]any{}
	raw := map[string][]byte{schemas.MandateID: schemas.MandateJSON(), schemas.TraceID: schemas.TraceJSON()}
	for id, b := range raw {
		doc, err := canon.Parse(b)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", id, err)
		}
		if err := c.AddResource(id, doc); err != nil {
			return nil, nil, err
		}
		docs[id] = doc
	}
	return c, docs, nil
}

func compile() (*bundle, error) {
	c, docs, err := newCompiler()
	if err != nil {
		return nil, err
	}
	b := &bundle{anyRequired: map[string]string{}}
	if b.mandate, err = c.Compile(schemas.MandateID); err != nil {
		return nil, err
	}
	if b.trace, err = c.Compile(schemas.TraceID); err != nil {
		return nil, err
	}
	for id, doc := range docs {
		findAnyRequired(doc, id, nil, b.anyRequired)
	}
	return b, nil
}

// findAnyRequired records every schema object whose anyOf branches each hold
// only "required", keyed by schema location. For those, the useful message is
// the list of fields, not "'anyOf' failed" and the causes underneath. This
// reads the schema, as scripts/validate.py's describe() does.
func findAnyRequired(node any, id string, path []string, out map[string]string) {
	switch n := node.(type) {
	case map[string]any:
		if branches, ok := n["anyOf"].([]any); ok && len(branches) > 0 {
			var fields []string
			only := true
			for _, br := range branches {
				m, isMap := br.(map[string]any)
				req, hasReq := m["required"].([]any)
				if !isMap || len(m) != 1 || !hasReq {
					only = false
					break
				}
				for _, f := range req {
					s, _ := f.(string)
					fields = append(fields, s)
				}
			}
			if only {
				out[locationKey(id, path)] = "needs at least one of: " + strings.Join(fields, ", ")
			}
		}
		for k, v := range n {
			findAnyRequired(v, id, append(path[:len(path):len(path)], k), out)
		}
	case []any:
		for i, v := range n {
			findAnyRequired(v, id, append(path[:len(path):len(path)], fmt.Sprint(i)), out)
		}
	}
}

func locationKey(id string, tokens []string) string {
	return id + "#/" + strings.Join(tokens, "/")
}

// normalizeLocation turns the library's SchemaURL (a percent-encoded JSON
// pointer fragment) into the form locationKey produces.
func normalizeLocation(u string) string {
	base, frag, _ := strings.Cut(u, "#")
	var toks []string
	for _, t := range strings.Split(strings.TrimPrefix(frag, "/"), "/") {
		if d, err := url.PathUnescape(t); err == nil {
			t = d
		}
		t = strings.ReplaceAll(strings.ReplaceAll(t, "~1", "/"), "~0", "~")
		toks = append(toks, t)
	}
	return locationKey(base, toks)
}

type found struct {
	path    []string
	message string
}

func validate(sch *jsonschema.Schema, doc any) []Violation {
	err := sch.Validate(doc)
	if err == nil {
		return nil
	}
	var verr *jsonschema.ValidationError
	if !errors.As(err, &verr) {
		// Not a schema failure: a value of a type canon.Parse never produces.
		return []Violation{{Path: "<root>", Message: truncate(err.Error())}}
	}
	p := message.NewPrinter(language.English)
	var out []found
	collect(verr, compiled().anyRequired, p, &out)
	slices.SortStableFunc(out, func(a, b found) int {
		if c := slices.Compare(a.path, b.path); c != 0 {
			return c
		}
		return strings.Compare(a.message, b.message)
	})
	vs := make([]Violation, len(out))
	for i, f := range out {
		path := strings.Join(f.path, "/")
		if path == "" {
			path = "<root>"
		}
		vs[i] = Violation{Path: path, Message: f.message}
	}
	return vs
}

// collect walks the error tree, emitting one entry per leaf. It does not use
// the library's flattened output, so the anyOf case can stop the descent.
func collect(e *jsonschema.ValidationError, anyRequired map[string]string, p *message.Printer, out *[]found) {
	if _, ok := e.ErrorKind.(*kind.AnyOf); ok {
		if msg, ok := anyRequired[normalizeLocation(e.SchemaURL)]; ok {
			*out = append(*out, found{e.InstanceLocation, msg})
			return
		}
	}
	if len(e.Causes) == 0 {
		k := e.ErrorKind
		if ap, ok := k.(*kind.AdditionalProperties); ok {
			// The library lists these in map order; sort so the message is
			// the same on every run.
			k = &kind.AdditionalProperties{Properties: slices.Sorted(slices.Values(ap.Properties))}
		}
		*out = append(*out, found{e.InstanceLocation, truncate(k.LocalizedString(p))})
		return
	}
	for _, c := range e.Causes {
		collect(c, anyRequired, p, out)
	}
}

// truncate cuts s to at most maxMessage bytes on a rune boundary, adding "…".
func truncate(s string) string {
	if len(s) <= maxMessage {
		return s
	}
	n := maxMessage
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}
