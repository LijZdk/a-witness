package rules

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
)

const noon = "2026-10-02T12:00:00Z"

func strs(s ...string) []any {
	out := make([]any, len(s))
	for i, v := range s {
		out[i] = v
	}
	return out
}

func newMandate(confirmation string) map[string]any {
	return map[string]any{
		"human_confirmation": confirmation,
		"scope": map[string]any{
			"product_classes": strs("home_insurance"),
			"allowed_actions": strs("quote", "compare", "switch"),
		},
		"validity": map[string]any{
			"not_before": "2026-10-01T09:00:00Z",
			"expires_at": "2027-01-31T23:59:59Z",
		},
	}
}

func newTrace(events ...map[string]any) map[string]any {
	list := make([]any, len(events))
	for i, e := range events {
		list[i] = e
	}
	return map[string]any{
		"journey": map[string]any{"product_class": "home_insurance", "action": "switch"},
		"events":  list,
	}
}

func ev(typ, actor, at string, payload map[string]any) map[string]any {
	return map[string]any{"type": typ, "actor": actor, "at": at, "payload": payload}
}

func sel(q string) map[string]any {
	return ev("selection_made", "agent", noon, map[string]any{"quote_id": q})
}

func confirm(actor, decision string) map[string]any {
	return ev("human_confirmation", actor, noon, map[string]any{"method": "passkey", "decision": decision})
}

func act(q string) map[string]any {
	return ev("action_executed", "provider", noon, map[string]any{
		"quote_id":         q,
		"amount_committed": map[string]any{"amount": "298.00", "currency": "GBP"},
	})
}

func at(t string) map[string]any { return ev("intent_captured", "agent", t, map[string]any{}) }

type want struct{ rule, seq int }

func findings(fs []Finding) []want {
	var out []want
	for _, f := range fs {
		out = append(out, want{f.Rule, f.Seq})
	}
	return out
}

func TestConfirmationRule9(t *testing.T) {
	cases := []struct {
		name   string
		events []map[string]any
		want   []want
		msg    string // a fragment the first finding's message must contain
	}{
		{"principal approves the selection, then the action", []map[string]any{sel("q1"), confirm("principal", "approved"), act("q1")}, nil, ""},
		{"approval for a re-selected quote, then the action", []map[string]any{sel("q1"), sel("q2"), confirm("principal", "approved"), act("q2")}, nil, ""},
		{"two purchases each with their own yes", []map[string]any{
			sel("q1"), confirm("principal", "approved"), act("q1"),
			sel("q2"), confirm("principal", "approved"), act("q2"),
		}, nil, ""},
		{"a declined, then an approved, then the action", []map[string]any{
			sel("q1"), confirm("principal", "declined"), confirm("principal", "approved"), act("q1"),
		}, nil, ""},
		{"no confirmation at all", []map[string]any{sel("q1"), act("q1")}, []want{{9, 1}},
			"event 1 (action_executed): the agent committed 298.00 GBP without an approved human_confirmation from the principal, but the mandate requires one every time"},
		{"a yes from the agent instead of the principal", []map[string]any{sel("q1"), confirm("agent", "approved"), act("q1")}, []want{{9, 2}}, "without an approved human_confirmation"},
		{"a yes from the provider", []map[string]any{sel("q1"), confirm("provider", "approved"), act("q1")}, []want{{9, 2}}, "without an approved human_confirmation"},
		{"the principal declined", []map[string]any{sel("q1"), confirm("principal", "declined"), act("q1")}, []want{{9, 2}}, "without an approved human_confirmation"},
		{"the principal modified", []map[string]any{sel("q1"), confirm("principal", "modified"), act("q1")}, []want{{9, 2}}, "without an approved human_confirmation"},
		{"a re-selection after approval cancels the yes", []map[string]any{
			sel("q1"), confirm("principal", "approved"), sel("q2"), act("q2"),
		}, []want{{9, 3}}, "without an approved human_confirmation"},
		{"one yes for two purchases", []map[string]any{
			sel("q1"), confirm("principal", "approved"), act("q1"), act("q1"),
		}, []want{{9, 3}}, "without an approved human_confirmation"},
		{"declined after approval cancels the yes", []map[string]any{
			sel("q1"), confirm("principal", "approved"), confirm("principal", "declined"), act("q1"),
		}, []want{{9, 3}}, "without an approved human_confirmation"},
		{"modified after approval cancels the yes", []map[string]any{
			sel("q1"), confirm("principal", "approved"), confirm("principal", "modified"), act("q1"),
		}, []want{{9, 3}}, "without an approved human_confirmation"},
		{"an agent's yes after the principal's does not undo it", []map[string]any{
			sel("q1"), confirm("principal", "approved"), confirm("agent", "approved"), act("q1"),
		}, nil, ""},
		{"action on a different quote than the approved selection", []map[string]any{
			sel("q1"), confirm("principal", "approved"), act("q2"),
		}, []want{{9, 2}}, "on quote 'q2', but the principal approved quote 'q1'"},
		{"approval with no selection before it is not counted", []map[string]any{
			confirm("principal", "approved"), sel("q1"), act("q1"),
		}, []want{{9, 2}}, "without an approved human_confirmation"},
		{"approval with no selection at all", []map[string]any{confirm("principal", "approved"), act("q1")}, []want{{9, 1}}, "without an approved human_confirmation"},
		{"a yes is used up by a wrong-quote action and cannot be reused", []map[string]any{
			sel("q1"), confirm("principal", "approved"), act("q2"), act("q1"),
		}, []want{{9, 2}, {9, 3}}, "on quote 'q2'"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, err := Check(newMandate("always"), newTrace(c.events...), true)
			if err != nil {
				t.Fatal(err)
			}
			var got []Finding
			for _, f := range res.Findings {
				if f.Rule == 9 {
					got = append(got, f)
				}
			}
			if !slices.Equal(findings(got), c.want) {
				t.Fatalf("got %v, want %v", got, c.want)
			}
			if c.msg != "" && !strings.Contains(got[0].Message, c.msg) {
				t.Fatalf("message %q lacks %q", got[0].Message, c.msg)
			}
		})
	}
}

func TestConfirmationOtherSettings(t *testing.T) {
	unconfirmed := newTrace(sel("q1"), act("q1"))

	res, err := Check(newMandate("never"), unconfirmed, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf(`"never" must warn, not fail: %v`, res.Findings)
	}
	if len(res.Warnings) != 1 || res.Warnings[0].Rule != 14 {
		t.Fatalf(`"never" must give one rule 14 warning: %v`, res.Warnings)
	}

	res, err = Check(newMandate("always"), newTrace(sel("q1"), confirm("principal", "approved"), act("q1")), true)
	if err != nil || len(res.Warnings) != 0 {
		t.Fatalf(`"always" must not warn: %v %v`, res.Warnings, err)
	}

	res, err = Check(newMandate("above_limits"), unconfirmed, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 || len(res.Warnings) != 0 {
		t.Fatalf("above_limits is not checked yet, so it must not report: %v %v", res.Findings, res.Warnings)
	}
	if !hasNote(res, 9, "above_limits") {
		t.Fatalf("above_limits must be listed as not checked: %v", res.NotChecked)
	}

	if _, err = Check(newMandate("sometimes"), unconfirmed, true); err == nil {
		t.Fatal(`human_confirmation "sometimes" must be an error, not a skip`)
	}
}

func hasNote(res Result, rule int, fragment string) bool {
	return slices.ContainsFunc(res.NotChecked, func(n NotChecked) bool {
		return n.Rule == rule && strings.Contains(n.Reason, fragment)
	})
}

func TestPrincipalApprovalIsTheAgentsClaimUnlessSigned(t *testing.T) {
	tr := newTrace(sel("q1"), confirm("principal", "approved"), act("q1"))
	signed, err := Check(newMandate("always"), tr, true)
	if err != nil {
		t.Fatal(err)
	}
	if hasNote(signed, 9, "did not sign the seal") {
		t.Fatal("a principal-signed seal still reports the approvals as unsigned")
	}
	unsigned, err := Check(newMandate("always"), tr, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(unsigned.Findings) != 0 || !hasNote(unsigned, 9, "did not sign the seal") {
		t.Fatalf("an unsigned approval must be noted, not failed: %v %v", unsigned.Findings, unsigned.NotChecked)
	}
	// With a rule 9 finding there is nothing to qualify: the rule already failed.
	broken, err := Check(newMandate("always"), newTrace(sel("q1"), act("q1")), false)
	if err != nil {
		t.Fatal(err)
	}
	if hasNote(broken, 9, "did not sign the seal") {
		t.Fatal("a rule 9 failure should not also carry the unsigned-approval note")
	}
}

func TestScopeRule10(t *testing.T) {
	with := func(mutate func(m map[string]any)) map[string]any {
		m := newMandate("never")
		mutate(m["scope"].(map[string]any))
		return m
	}
	journey := func(class, action string, events ...map[string]any) map[string]any {
		tr := newTrace(events...)
		tr["journey"] = map[string]any{"product_class": class, "action": action}
		return tr
	}
	cases := []struct {
		name    string
		mandate map[string]any
		trace   map[string]any
		want    []want
	}{
		{"within scope", newMandate("never"), journey("home_insurance", "switch"), nil},
		{"wrong product", newMandate("never"), journey("pet_insurance", "switch"), []want{{10, -1}}},
		{"wrong action", newMandate("never"), journey("home_insurance", "purchase"), []want{{10, -1}}},
		{"wrong product and action", newMandate("never"), journey("pet_insurance", "cancel"), []want{{10, -1}, {10, -1}}},
		{"non-binding scope with no action carried out", with(func(s map[string]any) { s["allowed_actions"] = strs("quote", "compare") }),
			journey("home_insurance", "compare", sel("q1")), nil},
		{"non-binding scope with an action_executed", with(func(s map[string]any) { s["allowed_actions"] = strs("research", "quote", "compare") }),
			journey("home_insurance", "compare", sel("q1"), act("q1")), []want{{10, 1}}},
		{"binding scope with an action_executed", newMandate("never"), journey("home_insurance", "switch", sel("q1"), act("q1")), nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, err := Check(c.mandate, c.trace, true)
			if err != nil {
				t.Fatal(err)
			}
			var got []Finding
			for _, f := range res.Findings {
				if f.Rule == 10 {
					got = append(got, f)
				}
			}
			if !slices.Equal(findings(got), c.want) {
				t.Fatalf("got %v, want %v", got, c.want)
			}
		})
	}

	t.Run("provider lists are noted as not covered", func(t *testing.T) {
		for _, key := range []string{"provider_allowlist", "provider_blocklist"} {
			res, err := Check(with(func(s map[string]any) { s[key] = strs("prov_oldco") }), newTrace(), true)
			if err != nil {
				t.Fatal(err)
			}
			if !hasNote(res, 0, "provider allow and block lists") {
				t.Fatalf("%s: not noted: %v", key, res.NotChecked)
			}
		}
		res, err := Check(newMandate("never"), newTrace(), true)
		if err != nil || hasNote(res, 0, "provider") {
			t.Fatalf("no provider list, yet a note: %v %v", res.NotChecked, err)
		}
	})

	t.Run("a scope that is not lists is an error", func(t *testing.T) {
		if _, err := Check(with(func(s map[string]any) { s["allowed_actions"] = "switch" }), newTrace(), true); err == nil {
			t.Fatal("allowed_actions as a string must be an error")
		}
		if _, err := Check(with(func(s map[string]any) { delete(s, "product_classes") }), newTrace(), true); err == nil {
			t.Fatal("missing product_classes must be an error")
		}
	})
}

func TestWindowRule11(t *testing.T) {
	cases := []struct {
		name string
		at   string
		want []want
	}{
		{"inside", "2026-10-02T08:00:00Z", nil},
		{"exactly on not_before", "2026-10-01T09:00:00Z", nil},
		{"exactly on expires_at", "2027-01-31T23:59:59Z", nil},
		{"one second before not_before", "2026-10-01T08:59:59Z", []want{{11, 1}}},
		{"one second after expires_at", "2027-02-01T00:00:00Z", []want{{11, 1}}},
		{"+01:00 offset inside the window as an instant", "2026-10-01T10:00:00+01:00", nil},
		{"+01:00 offset that is before not_before as an instant", "2026-10-01T09:30:00+01:00", []want{{11, 1}}},
		{"+01:00 offset on expires_at as an instant", "2027-02-01T00:59:59+01:00", nil},
		{"+01:00 offset one second after expires_at", "2027-02-01T01:00:00+01:00", []want{{11, 1}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, err := Check(newMandate("never"), newTrace(at("2026-10-02T08:00:00Z"), at(c.at)), true)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(findings(res.Findings), c.want) {
				t.Fatalf("got %v, want %v", res.Findings, c.want)
			}
		})
	}

	t.Run("only event times count", func(t *testing.T) {
		tr := newTrace(at("2026-10-02T08:00:00Z"))
		tr["journey"].(map[string]any)["started_at"] = "2020-01-01T00:00:00Z"
		tr["seal"] = map[string]any{"sealed_at": "2030-01-01T00:00:00Z"}
		res, err := Check(newMandate("never"), tr, true)
		if err != nil || len(res.Findings) != 0 {
			t.Fatalf("journey and seal times must not be checked: %v %v", res.Findings, err)
		}
	})

	t.Run("revocation is noted as not checked", func(t *testing.T) {
		res, err := Check(newMandate("never"), newTrace(at(noon)), true)
		if err != nil || !hasNote(res, 11, "revocation") {
			t.Fatalf("%v %v", res.NotChecked, err)
		}
	})

	t.Run("unreadable or missing bounds are errors", func(t *testing.T) {
		for name, mutate := range map[string]func(v map[string]any){
			"unparsable not_before": func(v map[string]any) { v["not_before"] = "yesterday" },
			"unparsable expires_at": func(v map[string]any) { v["expires_at"] = "2027-01-31" },
			"missing not_before":    func(v map[string]any) { delete(v, "not_before") },
			"missing expires_at":    func(v map[string]any) { delete(v, "expires_at") },
			"not a string":          func(v map[string]any) { v["expires_at"] = 5.0 },
		} {
			m := newMandate("never")
			mutate(m["validity"].(map[string]any))
			if _, err := Check(m, newTrace(at(noon)), true); err == nil {
				t.Errorf("%s: no error", name)
			}
		}
	})

	t.Run("an unparsable event time is an error", func(t *testing.T) {
		if _, err := Check(newMandate("never"), newTrace(at("noon")), true); err == nil {
			t.Fatal("no error")
		}
	})
}

func TestUnreadableRecordIsAnErrorNotASkip(t *testing.T) {
	good := func() map[string]any { return newTrace(sel("q1"), confirm("principal", "approved"), act("q1")) }
	if _, err := Check(newMandate("always"), good(), true); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(tr map[string]any){
		"decision outside the enum": func(tr map[string]any) {
			tr["events"].([]any)[1].(map[string]any)["payload"].(map[string]any)["decision"] = "maybe"
		},
		"missing decision": func(tr map[string]any) {
			delete(tr["events"].([]any)[1].(map[string]any)["payload"].(map[string]any), "decision")
		},
		"missing action quote_id": func(tr map[string]any) {
			delete(tr["events"].([]any)[2].(map[string]any)["payload"].(map[string]any), "quote_id")
		},
		"missing amount_committed": func(tr map[string]any) {
			delete(tr["events"].([]any)[2].(map[string]any)["payload"].(map[string]any), "amount_committed")
		},
		"missing actor":       func(tr map[string]any) { delete(tr["events"].([]any)[1].(map[string]any), "actor") },
		"missing journey":     func(tr map[string]any) { delete(tr, "journey") },
		"event not an object": func(tr map[string]any) { tr["events"].([]any)[0] = "selection" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			tr := good()
			mutate(tr)
			if res, err := Check(newMandate("always"), tr, true); err == nil {
				t.Fatalf("no error, and reported %v", res.Findings)
			}
		})
	}
	// The enum is checked whatever the mandate asks for.
	tr := good()
	tr["events"].([]any)[1].(map[string]any)["payload"].(map[string]any)["decision"] = "maybe"
	if _, err := Check(newMandate("never"), tr, true); err == nil {
		t.Fatal(`decision "maybe" went unnoticed under human_confirmation "never"`)
	}
}

func TestRules12And13AreNotChecked(t *testing.T) {
	res, err := Check(newMandate("never"), newTrace(at(noon)), true)
	if err != nil {
		t.Fatal(err)
	}
	if !hasNote(res, 12, "not implemented") || !hasNote(res, 13, "not implemented") {
		t.Fatalf("rules 12 and 13 must be listed as not checked: %v", res.NotChecked)
	}
}

func FuzzCheck(f *testing.F) {
	f.Add("always", "principal", "approved", "q1", "q1", "2026-10-02T08:00:00Z")
	f.Add("never", "agent", "declined", "q1", "q2", "nonsense")
	f.Fuzz(func(t *testing.T, conf, actor, decision, sq, aq, when string) {
		tr := newTrace(
			sel(sq),
			ev("human_confirmation", actor, when, map[string]any{"decision": decision}),
			act(aq),
		)
		_, _ = Check(newMandate(conf), tr, true) // must not panic
	})
}

func TestUnknownEventTypeOrActorIsAnError(t *testing.T) {
	// A purchase renamed so that rule 9 does not see it must not pass.
	renamed := act("q1")
	renamed["type"] = "action_executed_v2"
	if res, err := Check(newMandate("always"), newTrace(sel("q1"), renamed), true); err == nil {
		t.Fatalf("no error, findings %v", res.Findings)
	}
	odd := sel("q1")
	odd["actor"] = "guardian"
	if _, err := Check(newMandate("always"), newTrace(odd), true); err == nil {
		t.Fatal("an unknown actor was accepted")
	}
}

// The lists in rules.go are a copy of the trace schema's enums; this keeps them honest.
func TestEventTypesAndActorsMatchTheSchema(t *testing.T) {
	b, err := os.ReadFile("../../../schemas/trace.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Defs map[string]struct {
			Properties map[string]struct {
				Enum []string `json:"enum"`
			} `json:"properties"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(b, &schema); err != nil {
		t.Fatal(err)
	}
	event, ok := schema.Defs["event"]
	if !ok {
		t.Fatal("the schema has no $defs.event")
	}
	for name, ours := range map[string][]string{"type": eventTypes, "actor": actors} {
		theirs := event.Properties[name].Enum
		if len(theirs) == 0 {
			t.Fatalf("no enum for event.%s in the schema", name)
		}
		a, b := slices.Sorted(slices.Values(ours)), slices.Sorted(slices.Values(theirs))
		if !slices.Equal(a, b) {
			t.Errorf("event.%s: rules.go has %v, the schema has %v", name, a, b)
		}
	}
}
