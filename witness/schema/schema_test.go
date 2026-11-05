package schema

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/LijZdk/a-witness/schemas"
	"github.com/LijZdk/a-witness/witness/canon"
)

var exampleNames = []string{
	"home-insurance-switch",
	"home-insurance-no-confirmation",
	"fixed-rate-savings-switch",
}

func readExample(t *testing.T, name, kind string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "examples", name+"."+kind+".json"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// parseExample returns a fresh canon.Parse tree of an example, to edit.
func parseExample(t *testing.T, name, kind string) map[string]any {
	t.Helper()
	v, err := canon.Parse(readExample(t, name, kind))
	if err != nil {
		t.Fatal(err)
	}
	return v.(map[string]any)
}

func strs(vs []Violation) []string {
	var out []string
	for _, v := range vs {
		out = append(out, v.String())
	}
	return out
}

func TestSchemasCompile(t *testing.T) {
	// compiled() panics if the embedded schemas do not compile.
	b := compiled()
	if b.mandate == nil || b.trace == nil {
		t.Fatal("schemas not compiled")
	}
	if len(b.anyRequired) == 0 {
		t.Fatal("found no anyOf-of-required locations; the walk is broken")
	}
	// The one we know of: a quote needs a price or a rate.
	want := schemas.TraceID + "#/$defs/p_quote"
	if got := b.anyRequired[want]; got != "needs at least one of: price, aer" {
		t.Errorf("anyRequired[%s] = %q", want, got)
	}
}

func TestExamplesConform(t *testing.T) {
	for _, name := range exampleNames {
		t.Run(name, func(t *testing.T) {
			if vs, err := ValidateMandateJSON(readExample(t, name, "mandate")); err != nil || len(vs) != 0 {
				t.Errorf("mandate: %v, %v", strs(vs), err)
			}
			if vs, err := ValidateTraceJSON(readExample(t, name, "trace")); err != nil || len(vs) != 0 {
				t.Errorf("trace: %v, %v", strs(vs), err)
			}
		})
	}
}

func TestTraceMissingMandateRef(t *testing.T) {
	tr := parseExample(t, "home-insurance-switch", "trace")
	delete(tr, "mandate_ref")
	vs := ValidateTrace(tr)
	if len(vs) != 1 || vs[0].Path != "<root>" || !strings.Contains(vs[0].Message, "mandate_ref") {
		t.Fatalf("got %v", strs(vs))
	}
}

func TestQuoteWithNeitherPriceNorRate(t *testing.T) {
	tr := parseExample(t, "fixed-rate-savings-switch", "trace")
	payload := tr["events"].([]any)[2].(map[string]any)["payload"].(map[string]any)
	if _, ok := payload["aer"]; !ok {
		t.Fatal("test premise: the example's quote has an aer")
	}
	delete(payload, "aer")
	vs := ValidateTrace(tr)
	if len(vs) != 1 || vs[0].String() != "events/2/payload: needs at least one of: price, aer" {
		t.Fatalf("got %q", strs(vs))
	}
}

func TestSchemaValidEditsStayValid(t *testing.T) {
	// The edited variants in scripts/check.sh that only the chain or the
	// signatures can catch must still pass the schema.
	t.Run("changed price", func(t *testing.T) {
		tr := parseExample(t, "home-insurance-switch", "trace")
		price := tr["events"].([]any)[2].(map[string]any)["payload"].(map[string]any)["price"].(map[string]any)
		price["amount"] = "198.00"
		if vs := ValidateTrace(tr); len(vs) != 0 {
			t.Errorf("%v", strs(vs))
		}
	})
	t.Run("quote id changed to q_nowhere", func(t *testing.T) {
		tr := parseExample(t, "home-insurance-switch", "trace")
		tr["events"].([]any)[8].(map[string]any)["payload"].(map[string]any)["quote_id"] = "q_nowhere"
		if vs := ValidateTrace(tr); len(vs) != 0 {
			t.Errorf("%v", strs(vs))
		}
	})
}

func TestNotJSONIsAnError(t *testing.T) {
	if _, err := ValidateMandateJSON([]byte("not json\n")); err == nil {
		t.Error("mandate: no error")
	}
	if _, err := ValidateTraceJSON([]byte("not json\n")); err == nil {
		t.Error("trace: no error")
	}
}

// The trace schema reaches the mandate schema's enum through a relative $ref
// to a file that is not on disk or the network; only AddResource supplies it.
func TestTraceRefResolvesIntoMandateSchema(t *testing.T) {
	tr := parseExample(t, "home-insurance-switch", "trace")
	tr["journey"].(map[string]any)["product_class"] = "not_a_class"
	vs := ValidateTrace(tr)
	if len(vs) == 0 {
		t.Fatal("an invalid product_class was accepted")
	}
	if vs[0].Path != "journey/product_class" {
		t.Errorf("got %v", strs(vs))
	}
}

func TestEveryFormatInTheSchemasIsOneWeCheck(t *testing.T) {
	known := map[string]bool{"date-time": true, "uri": true}
	seen := map[string]int{}
	var walk func(v any)
	walk = func(v any) {
		switch n := v.(type) {
		case map[string]any:
			for k, c := range n {
				if s, ok := c.(string); ok && k == "format" {
					seen[s]++
					if !known[s] {
						t.Errorf("schema uses format %q, which this package does not check", s)
					}
				}
				walk(c)
			}
		case []any:
			for _, c := range n {
				walk(c)
			}
		}
	}
	_, docs, err := newCompiler()
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range docs {
		walk(d)
	}
	if seen["date-time"] == 0 || seen["uri"] == 0 {
		t.Errorf("walk found %v; expected both formats", seen)
	}
}

func TestDateTimeFormat(t *testing.T) {
	cases := []struct {
		value string
		ok    bool
	}{
		{"2026-10-01T09:00:00Z", true},
		{"2026-10-01T09:00:00.123456Z", true},
		{"2026-10-01T09:00:00+01:00", true},
		{"2026-10-01T09:00:00-05:30", true},
		{"2026-12-31T23:59:60Z", false}, // leap second: time.RFC3339 refuses it
		{"2026-10-01t09:00:00Z", false}, // known gap: Python accepts lower case
		{"2026-10-01T09:00:00z", false}, // known gap: Python accepts lower case
		{"2026-10-01T09:00:00,5Z", false},
		{"0000-10-01T09:00:00Z", false},
		{"2026-02-30T09:00:00Z", false},
		{"2026-10-01T09:00:00+0100", false},
		{"2026-10-01T09:00:00", false},
		{"2026-10-01 09:00:00Z", false},
		{"", false},
	}
	// Each case is used at three kinds of location: a plain one (mandate
	// consent), an if/then one (a quote's valid_until) and the trace's own.
	for _, tc := range cases {
		t.Run(tc.value, func(t *testing.T) {
			m := parseExample(t, "home-insurance-switch", "mandate")
			m["consent"].(map[string]any)["granted_at"] = tc.value
			checkAccept(t, "consent/granted_at", ValidateMandate(m), tc.ok)

			tr := parseExample(t, "fixed-rate-savings-switch", "trace")
			tr["events"].([]any)[2].(map[string]any)["payload"].(map[string]any)["valid_until"] = tc.value
			checkAccept(t, "events/2/payload/valid_until", ValidateTrace(tr), tc.ok)

			tr = parseExample(t, "fixed-rate-savings-switch", "trace")
			tr["journey"].(map[string]any)["started_at"] = tc.value
			checkAccept(t, "journey/started_at", ValidateTrace(tr), tc.ok)
		})
	}
}

func TestURIFormat(t *testing.T) {
	cases := []struct {
		value string
		ok    bool
	}{
		{"https://wallet.example/mandates/m1/status", true},
		{"https://wallet.example/a%20b?x=1&y=2#frag", true},
		{"urn:isbn:0451450523", true},
		{"javascript:x", true}, // a valid URI; see validateURI
		{"/mandates/m1/status", false},
		{"wallet.example/status", false},
		{"https://wallet.example/a b", false},
		{"https://wallet.example/é", false},
		{"https://wallet.example/%zz", false},
		{"https://wallet.example/%2", false},
		{"https://wallet.example/\x00", false},
		{"", false},
	}
	for _, tc := range cases {
		t.Run(tc.value, func(t *testing.T) {
			m := parseExample(t, "home-insurance-switch", "mandate")
			m["validity"].(map[string]any)["revocation_url"] = tc.value
			checkAccept(t, "validity/revocation_url", ValidateMandate(m), tc.ok)
		})
	}
}

func checkAccept(t *testing.T, path string, vs []Violation, ok bool) {
	t.Helper()
	if ok {
		if len(vs) != 0 {
			t.Errorf("rejected, want accepted: %v", strs(vs))
		}
		return
	}
	if len(vs) != 1 || vs[0].Path != path {
		t.Errorf("want one violation at %s, got %v", path, strs(vs))
	}
}

func TestHostileInputs(t *testing.T) {
	t.Run("duplicate key", func(t *testing.T) {
		b := readExample(t, "home-insurance-switch", "mandate")
		dup := strings.Replace(string(b), `"mandate_id"`, `"mandate_id": "mdt_other", "mandate_id"`, 1)
		if dup == string(b) {
			t.Fatal("test premise")
		}
		if _, err := ValidateMandateJSON([]byte(dup)); err == nil {
			t.Error("duplicate mandate_id was accepted")
		}
	})
	t.Run("lone surrogate", func(t *testing.T) {
		b := readExample(t, "home-insurance-switch", "mandate")
		bad := strings.Replace(string(b), `"mdt_7Hq2Lk9Xw3Pz"`, `"mdt_\ud800"`, 1)
		if bad == string(b) {
			t.Fatal("test premise")
		}
		if _, err := ValidateMandateJSON([]byte(bad)); err == nil {
			t.Error("lone surrogate was accepted")
		}
	})
	t.Run("external refs do not compile", func(t *testing.T) {
		for _, ref := range []string{"https://example.com/other.schema.json", "file:///etc/hosts", "other.schema.json"} {
			c, _, err := newCompiler()
			if err != nil {
				t.Fatal(err)
			}
			doc, err := canon.Parse([]byte(fmt.Sprintf(`{"$schema":"https://json-schema.org/draft/2020-12/schema","$ref":%q}`, ref)))
			if err != nil {
				t.Fatal(err)
			}
			if err := c.AddResource("https://a-witness.dev/schemas/0.1/throwaway.json", doc); err != nil {
				t.Fatal(err)
			}
			_, err = c.Compile("https://a-witness.dev/schemas/0.1/throwaway.json")
			if err == nil {
				t.Errorf("$ref %s compiled", ref)
			} else if !strings.Contains(err.Error(), "not allowed") {
				t.Errorf("$ref %s failed for another reason: %v", ref, err)
			}
		}
	})
	t.Run("deeply nested value", func(t *testing.T) {
		const depth = 100000
		deep := strings.Repeat("[", depth) + strings.Repeat("]", depth)
		m := string(readExample(t, "home-insurance-switch", "mandate"))
		// As the value of a field the schema types as a string, and as an
		// unknown extra field.
		for name, doc := range map[string]string{
			"known field":   strings.Replace(m, `"mdt_7Hq2Lk9Xw3Pz"`, deep, 1),
			"unknown field": strings.Replace(m, `"spec_version"`, `"extra": `+deep+`, "spec_version"`, 1),
		} {
			start := time.Now()
			vs, err := ValidateMandateJSON([]byte(doc))
			if time.Since(start) > 2*time.Second {
				t.Errorf("%s: took %v", name, time.Since(start))
			}
			if err == nil && len(vs) == 0 {
				t.Errorf("%s: accepted", name)
			}
			if err == nil {
				t.Errorf("%s: canon.Parse accepted %d levels of nesting", name, depth)
			}
		}
	})
	t.Run("deep value that bypasses the parser", func(t *testing.T) {
		// canon.Parse caps nesting, so documents from it cannot be this deep.
		// The validator must still cope if a caller hands it one.
		var deep any = "x"
		for i := 0; i < 100000; i++ {
			deep = []any{deep}
		}
		for name, key := range map[string]string{"known field": "mandate_id", "unknown field": "extra"} {
			m := parseExample(t, "home-insurance-switch", "mandate")
			m[key] = deep
			start := time.Now()
			vs := ValidateMandate(m)
			if time.Since(start) > 2*time.Second {
				t.Errorf("%s: took %v", name, time.Since(start))
			}
			if len(vs) == 0 {
				t.Errorf("%s: accepted", name)
			}
			for _, v := range vs {
				if len(v.Message) > maxMessage+len("…") {
					t.Errorf("%s: message of %d bytes", name, len(v.Message))
				}
			}
		}
	})
	t.Run("huge value in a format field", func(t *testing.T) {
		huge := strings.Repeat("é", 1<<19) // 1 MiB of two-byte runes
		m := parseExample(t, "home-insurance-switch", "mandate")
		m["consent"].(map[string]any)["granted_at"] = huge
		m["validity"].(map[string]any)["revocation_url"] = huge
		m["spec_version"] = huge
		vs := ValidateMandate(m)
		if len(vs) < 3 {
			t.Fatalf("got %d violations", len(vs))
		}
		for _, v := range vs {
			if len(v.Message) > maxMessage+len("…") || !utf8.ValidString(v.Message) {
				t.Errorf("%s: message is %d bytes, valid=%v", v.Path, len(v.Message), utf8.ValidString(v.Message))
			}
		}
	})
}

func TestTruncate(t *testing.T) {
	if got := truncate("short"); got != "short" {
		t.Errorf("%q", got)
	}
	exact := strings.Repeat("a", maxMessage)
	if truncate(exact) != exact {
		t.Error("a message of exactly the limit was cut")
	}
	// A multi-byte rune straddling the limit must not be split.
	s := strings.Repeat("a", maxMessage-1) + "éééé"
	got := truncate(s)
	if !utf8.ValidString(got) || !strings.HasSuffix(got, "…") || len(got) > maxMessage+len("…") {
		t.Errorf("bad truncation: %d bytes valid=%v", len(got), utf8.ValidString(got))
	}
	if got != strings.Repeat("a", maxMessage-1)+"…" {
		t.Errorf("split on the wrong boundary: %q", got[len(got)-8:])
	}
}

func TestViolationsAreSorted(t *testing.T) {
	tr := parseExample(t, "home-insurance-switch", "trace")
	tr["journey"].(map[string]any)["started_at"] = "nope"
	tr["journey"].(map[string]any)["product_class"] = "not_a_class"
	delete(tr, "seal")
	vs := ValidateTrace(tr)
	if len(vs) < 3 {
		t.Fatalf("got %v", strs(vs))
	}
	var paths []string
	for _, v := range vs {
		paths = append(paths, v.Path)
	}
	want := []string{"<root>", "journey/product_class", "journey/started_at"}
	if strings.Join(paths, ",") != strings.Join(want, ",") {
		t.Errorf("paths %v, want %v", paths, want)
	}
}

func TestConcurrentValidation(t *testing.T) {
	good := parseExample(t, "home-insurance-switch", "trace")
	bad := parseExample(t, "fixed-rate-savings-switch", "trace")
	delete(bad["events"].([]any)[2].(map[string]any)["payload"].(map[string]any), "aer")
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				if vs := ValidateTrace(good); len(vs) != 0 {
					t.Errorf("good trace: %v", strs(vs))
					return
				}
				vs := ValidateTrace(bad)
				if len(vs) != 1 || vs[0].String() != "events/2/payload: needs at least one of: price, aer" {
					t.Errorf("bad trace: %v", strs(vs))
					return
				}
			}
		}()
	}
	wg.Wait()
}
