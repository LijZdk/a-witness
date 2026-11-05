package witness

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/LijZdk/a-witness/witness/canon"
	"github.com/LijZdk/a-witness/witness/sign"
)

var examples = []string{"home-insurance-switch", "home-insurance-no-confirmation", "fixed-rate-savings-switch"}

func readFile(t *testing.T, parts ...string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(append([]string{".."}, parts...)...))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func parse(t *testing.T, b []byte) map[string]any {
	t.Helper()
	v, err := canon.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	return v.(map[string]any)
}

// The hash vectors were computed by the Python implementation.
func TestHashVectors(t *testing.T) {
	var file struct {
		Vectors []struct {
			Name, Kind, Hash string
			Input            json.RawMessage
		}
	}
	if err := json.Unmarshal(readFile(t, "testdata", "vectors", "hashes.json"), &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Vectors) == 0 {
		t.Fatal("no hash vectors")
	}
	for _, v := range file.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			var got string
			var err error
			switch v.Kind {
			case "text":
				var s string
				if err := json.Unmarshal(v.Input, &s); err != nil {
					t.Fatal(err)
				}
				got = HashText(s)
			case "mandate":
				got, err = MandateHash(parse(t, v.Input))
			case "event":
				got, err = HashEvent(parse(t, v.Input))
			default:
				t.Fatalf("unknown kind %q", v.Kind)
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != v.Hash {
				t.Fatalf("got  %s\nwant %s", got, v.Hash)
			}
		})
	}
}

// exampleTrust trusts the examples' public keys, one file per role.
func exampleTrust(t *testing.T) *Trust {
	t.Helper()
	return loadTrust(t, func(name string) []byte { return readFile(t, "examples", name) })
}

func loadTrust(tb testing.TB, read func(name string) []byte) *Trust {
	tb.Helper()
	set := func(role string) sign.KeySet {
		keys, err := sign.ParseJWKS(read("keys." + role + ".jwks.json"))
		if err != nil {
			tb.Fatal(err)
		}
		return keys
	}
	return &Trust{Principal: set("principal"), Provider: set("provider"), Agent: set("agent")}
}

// The examples were written and signed by Python, so passing them shows the
// two implementations agree on real documents, not just on the vectors.
func TestExamplesVerify(t *testing.T) {
	keys := exampleTrust(t)
	for _, name := range examples {
		t.Run(name, func(t *testing.T) {
			mandate := readFile(t, "examples", name+".mandate.json")
			trace := readFile(t, "examples", name+".trace.json")
			problems, err := Verify(context.Background(), mandate, trace, keys)
			if err != nil {
				t.Fatal(err)
			}
			// home-insurance-no-confirmation passes too: its record is genuine.
			// It breaks rule 9, a mandate rule, which Verify does not check yet.
			if len(problems) > 0 {
				t.Fatalf("unexpected problems: %v", problems)
			}
			got, err := MandateHash(parse(t, mandate))
			if err != nil {
				t.Fatal(err)
			}
			ref := parse(t, trace)["mandate_ref"].(map[string]any)["mandate_hash"]
			if got != ref {
				t.Fatalf("Go mandate hash %s, Python wrote %s", got, ref)
			}
		})
	}
}

// edit changes a copy of an example trace. If rechain is true, every hash is
// recomputed afterwards, as a forger would, so only the rule under test can object.
func edit(t *testing.T, name string, rechain bool, change func(trace map[string]any, events []any)) []byte {
	t.Helper()
	trace := parse(t, readFile(t, "examples", name+".trace.json"))
	events := trace["events"].([]any)
	change(trace, events)
	events = trace["events"].([]any)
	if rechain {
		prev := trace["mandate_ref"].(map[string]any)["mandate_hash"]
		for _, e := range events {
			ev := e.(map[string]any)
			ev["prev_hash"] = prev
			h, err := HashEvent(ev)
			if err != nil {
				t.Fatal(err)
			}
			ev["hash"] = h
			prev = h
		}
		trace["seal"].(map[string]any)["final_event_hash"] = prev
	}
	b, err := canon.Serialize(trace)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func payload(events []any, seq int) map[string]any {
	return events[seq].(map[string]any)["payload"].(map[string]any)
}

// These cases test rules 1 to 8, so signatures are skipped: every edit
// would also break the seal signatures, which TestSignatures covers.
func TestVerifyFindsProblems(t *testing.T) {
	home := "home-insurance-switch"
	homeMandate := readFile(t, "examples", home+".mandate.json")
	savingsMandate := readFile(t, "examples", "fixed-rate-savings-switch.mandate.json")

	cases := []struct {
		name    string
		mandate []byte
		trace   []byte
		want    []Problem // Rule and Seq are compared; Message only if set
	}{
		{
			name:    "an edited price breaks the hashes of the events that carry it",
			mandate: homeMandate,
			trace: edit(t, home, false, func(_ map[string]any, e []any) {
				payload(e, 2)["price"].(map[string]any)["amount"] = "198.00"
			}),
			want: []Problem{{Rule: 4, Seq: 2, Message: "event 2: hash does not match its content (tampered?)"}},
		},
		{
			name:    "an edited extension field is caught too, because hashes cover every field",
			mandate: homeMandate,
			trace: edit(t, home, false, func(_ map[string]any, e []any) {
				payload(e, 0)["channel"] = "voice"
			}),
			want: []Problem{{Rule: 4, Seq: 0}},
		},
		{
			name:    "a removed event breaks numbering and chaining",
			mandate: homeMandate,
			trace: edit(t, home, false, func(tr map[string]any, e []any) {
				tr["events"] = slices.Delete(slices.Clone(e), 5, 6)
			}),
			want: []Problem{
				{Rule: 2, Seq: 5}, {Rule: 3, Seq: 5}, {Rule: 2, Seq: 6}, {Rule: 2, Seq: 7}, {Rule: 2, Seq: 8}, {Rule: 2, Seq: 9}, {Rule: 2, Seq: 10},
				// The trace is now one event shorter, so its outcome_evidence cites a missing event 11.
				{Rule: 7, Seq: -1, Message: "outcome_evidence.consumer_support cites event 11, but the trace has only 11 events"},
			},
		},
		{
			name:    "the wrong mandate is caught at the link and at the start of the chain",
			mandate: savingsMandate,
			trace:   readFile(t, "examples", home+".trace.json"),
			want:    []Problem{{Rule: 1, Seq: -1}, {Rule: 1, Seq: -1}, {Rule: 3, Seq: 0}},
		},
		{
			name:    "a rewritten, re-hashed history is still caught if time runs backwards",
			mandate: homeMandate,
			trace: edit(t, home, true, func(_ map[string]any, e []any) {
				e[3].(map[string]any)["at"] = "2026-10-02T07:00:00Z"
			}),
			want: []Problem{{Rule: 5, Seq: 3, Message: "event 3: timestamp is earlier than event 2"}},
		},
		{
			name:    "a seal dated before the last event",
			mandate: homeMandate,
			trace: edit(t, home, true, func(tr map[string]any, _ []any) {
				tr["seal"].(map[string]any)["sealed_at"] = "2026-10-02T08:00:00Z"
			}),
			want: []Problem{{Rule: 5, Seq: -1, Message: "seal is dated before the final event"}},
		},
		{
			name:    "a seal over the wrong event",
			mandate: homeMandate,
			trace: edit(t, home, false, func(tr map[string]any, e []any) {
				tr["seal"].(map[string]any)["final_event_hash"] = e[5].(map[string]any)["hash"]
			}),
			want: []Problem{{Rule: 6, Seq: -1}},
		},
		{
			name:    "outcome evidence citing an event that does not exist",
			mandate: homeMandate,
			trace: edit(t, home, false, func(tr map[string]any, _ []any) {
				tr["outcome_evidence"].(map[string]any)["consumer_support"].(map[string]any)["event_seqs"] = []any{11, 40}
			}),
			want: []Problem{{Rule: 7, Seq: -1, Message: "outcome_evidence.consumer_support cites event 40, but the trace has only 12 events"}},
		},
		{
			name:    "selecting a quote nobody offered",
			mandate: homeMandate,
			trace: edit(t, home, true, func(_ map[string]any, e []any) {
				payload(e, 8)["quote_id"] = "q_nowhere"
			}),
			want: []Problem{{Rule: 8, Seq: 8, Message: "event 8 (selection_made): refers to quote 'q_nowhere', but no earlier quote_received offered it"}},
		},
		{
			name:    "two quotes sharing an id",
			mandate: homeMandate,
			trace: edit(t, home, true, func(_ map[string]any, e []any) {
				payload(e, 3)["quote_id"] = "q_newco"
			}),
			want: []Problem{
				{Rule: 8, Seq: 3, Message: "event 3 (quote_received): quote_id 'q_newco' was already used by event 2"},
				{Rule: 8, Seq: 5}, {Rule: 8, Seq: 6},
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Verify(context.Background(), c.mandate, c.trace, SkipSignatures)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) < len(c.want) {
				t.Fatalf("got %d problems, want at least %d: %v", len(got), len(c.want), got)
			}
			for i, w := range c.want {
				g := got[i]
				if g.Rule != w.Rule || g.Seq != w.Seq || (w.Message != "" && g.Message != w.Message) {
					t.Errorf("problem %d: got rule %d, event %d, %q; want rule %d, event %d, %q", i, g.Rule, g.Seq, g.Message, w.Rule, w.Seq, w.Message)
				}
			}
			if len(got) != len(c.want) {
				t.Errorf("got %d problems, want %d: %v", len(got), len(c.want), got)
			}
		})
	}
}

func TestVerifyAcceptsExtensionFields(t *testing.T) {
	trace := edit(t, "home-insurance-switch", true, func(_ map[string]any, e []any) {
		payload(e, 0)["channel"] = "voice"
	})
	problems, err := Verify(context.Background(), readFile(t, "examples", "home-insurance-switch.mandate.json"), trace, SkipSignatures)
	if err != nil || len(problems) > 0 {
		t.Fatalf("a correctly hashed extension field was rejected: %v %v", err, problems)
	}
}

func TestVerifyRejectsUnreadableDocuments(t *testing.T) {
	mandate := readFile(t, "examples", "home-insurance-switch.mandate.json")
	for name, trace := range map[string]string{
		"not JSON":             "not json",
		"duplicate key":        `{"events": [], "events": []}`,
		"not an object":        `[]`,
		"no events":            `{"mandate_ref": {"mandate_id": "m", "mandate_hash": "h"}, "events": [], "seal": {}}`,
		"missing mandate_ref":  `{"events": [{}]}`,
		"event missing a hash": `{"mandate_ref": {"mandate_id": "m", "mandate_hash": "h"}, "events": [{"seq": 0, "at": "", "type": "error", "prev_hash": "", "payload": {"code": "x"}}], "seal": {"final_event_hash": "", "sealed_at": ""}}`,
		"fractional seq":       `{"mandate_ref": {"mandate_id": "m", "mandate_hash": "h"}, "events": [{"seq": 0.5}], "seal": {}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if problems, err := Verify(context.Background(), mandate, []byte(trace), SkipSignatures); err == nil {
				t.Fatalf("accepted an unreadable trace, reporting %v", problems)
			}
		})
	}
}
