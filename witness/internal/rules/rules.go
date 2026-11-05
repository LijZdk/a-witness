// Package rules checks the mandate rules of SPEC.md, "Rules across
// documents": 9 (human confirmation), 10 (scope), 11 (validity window) and
// 14 (human_confirmation "never"). Rules 12 and 13 are not implemented and
// are reported as not checked.
//
// The checks are pure functions of a parsed mandate and a parsed trace (see
// canon.Parse). They assume the record has already been shown to be intact:
// run them on a tampered record and what they say proves nothing. Package
// witness enforces that order in witness.Check.
//
// Anything a rule needs that is missing, of the wrong type, or outside the
// schema's enum is an error, never a silent skip: a rule that quietly did not
// run would look like a rule that was met.
package rules

import (
	"fmt"
	"slices"
	"time"
)

// Finding is one way the journey breaks, or deserves a note about, a rule.
type Finding struct {
	Rule    int    // the rule's number in SPEC.md
	Seq     int    // the event concerned (its position in the trace), or -1
	Message string // plain language, for a person reading a report
}

// NotChecked says that part of the rules was not checked, so that a pass
// is never mistaken for a wider pass than it is.
type NotChecked struct {
	Rule   int // the rule's number in SPEC.md; 0 if no rule covers it
	Reason string
}

// Result is what the rules found.
type Result struct {
	Findings   []Finding // the agent broke its mandate
	Warnings   []Finding // worth flagging, but not a breach (rule 14)
	NotChecked []NotChecked
}

// ParseTime reads an RFC 3339 timestamp. It is the one place timestamps are
// parsed, so that rule 5 (in package witness) and rule 11 agree on what a
// timestamp is.
func ParseTime(s string) (time.Time, error) {
	return time.Parse(time.RFC3339, s)
}

// The event types and actors of schemas/trace.schema.json. Rule 9 looks at
// events by type, so an event of a type it does not know (a purchase renamed
// "action_executed_v2", say) would slip past it; Check refuses such a record
// instead. A test keeps these lists equal to the schema's enums.
var (
	eventTypes = []string{
		"intent_captured", "quote_requested", "quote_received", "disclosure_presented",
		"alternatives_considered", "requirement_check", "selection_made", "human_confirmation",
		"action_executed", "post_sale_notice", "escalation", "error",
	}
	actors = []string{"agent", "provider", "principal", "system"}
)

var binding = []string{"purchase", "renew", "switch", "cancel", "amend"}

// Check applies the mandate rules to a mandate and a trace.
//
// principalSigned says whether a valid seal signature from the principal was
// checked. Without one, the principal's approvals are only the agent's word.
func Check(mandate, trace map[string]any, principalSigned bool) (Result, error) {
	var res Result
	confirmation, err := get[string](mandate, "human_confirmation", "mandate")
	if err != nil {
		return res, err
	}
	if !slices.Contains([]string{"always", "above_limits", "never"}, confirmation) {
		return res, fmt.Errorf("witness: mandate.human_confirmation: %q is not always, above_limits or never", confirmation)
	}
	events, err := readEvents(trace)
	if err != nil {
		return res, err
	}

	scope, err := get[map[string]any](mandate, "scope", "mandate")
	if err != nil {
		return res, err
	}
	scopeFindings, scopeNotes, err := checkScope(scope, trace, events)
	if err != nil {
		return res, err
	}
	res.Findings = append(res.Findings, scopeFindings...)
	res.NotChecked = append(res.NotChecked, scopeNotes...)

	confFindings, confNotes, err := checkConfirmation(confirmation, events, principalSigned)
	if err != nil {
		return res, err
	}
	res.Findings = append(res.Findings, confFindings...)
	res.NotChecked = append(res.NotChecked, confNotes...)
	if confirmation == "never" {
		res.Warnings = append(res.Warnings, Finding{Rule: 14, Seq: -1,
			Message: `the mandate sets human_confirmation to "never", which removes the principal from every decision`})
	}

	validity, err := get[map[string]any](mandate, "validity", "mandate")
	if err != nil {
		return res, err
	}
	windowFindings, err := checkWindow(validity, events)
	if err != nil {
		return res, err
	}
	res.Findings = append(res.Findings, windowFindings...)
	res.NotChecked = append(res.NotChecked, NotChecked{11, "revocation was not checked"})

	res.NotChecked = append(res.NotChecked,
		NotChecked{12, "limits (max_commitment, max_term_months, max_transactions, max_price_increase_pct, min_aer) were not checked; rule 12 is not implemented yet"},
		NotChecked{13, "requirement checks were not checked against the chosen quote; rule 13 is not implemented yet"})
	return res, nil
}

type event struct {
	seq      int // position in the trace
	typ      string
	actor    string
	decision string // human_confirmation events only
	at       time.Time
	payload  map[string]any
}

func readEvents(trace map[string]any) ([]event, error) {
	raw, err := get[[]any](trace, "events", "trace")
	if err != nil {
		return nil, err
	}
	out := make([]event, 0, len(raw))
	for i, v := range raw {
		where := fmt.Sprintf("trace.events[%d]", i)
		obj, ok := v.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("witness: %s: expected an object", where)
		}
		ev := event{seq: i}
		if ev.typ, err = get[string](obj, "type", where); err != nil {
			return nil, err
		}
		if !slices.Contains(eventTypes, ev.typ) {
			return nil, fmt.Errorf("witness: %s.type: %q is not an event type in the trace schema", where, ev.typ)
		}
		if ev.actor, err = get[string](obj, "actor", where); err != nil {
			return nil, err
		}
		if !slices.Contains(actors, ev.actor) {
			return nil, fmt.Errorf("witness: %s.actor: %q is not an actor in the trace schema", where, ev.actor)
		}
		at, err := get[string](obj, "at", where)
		if err != nil {
			return nil, err
		}
		if ev.at, err = ParseTime(at); err != nil {
			return nil, fmt.Errorf("witness: %s.at: not an RFC 3339 timestamp: %q", where, at)
		}
		if ev.payload, err = get[map[string]any](obj, "payload", where); err != nil {
			return nil, err
		}
		if ev.typ == "human_confirmation" {
			if ev.decision, err = get[string](ev.payload, "decision", where+".payload"); err != nil {
				return nil, err
			}
			if !slices.Contains([]string{"approved", "declined", "modified"}, ev.decision) {
				return nil, fmt.Errorf("witness: %s.payload.decision: %q is not approved, declined or modified", where, ev.decision)
			}
		}
		out = append(out, ev)
	}
	return out, nil
}

// Rule 9. Only for human_confirmation "always": every action_executed needs
// its own approval, from the principal, given after the latest selection and
// for the quote that was selected.
func checkConfirmation(setting string, events []event, principalSigned bool) ([]Finding, []NotChecked, error) {
	switch setting {
	case "above_limits":
		return nil, []NotChecked{{9, "above_limits needs limit checks (rule 12), not implemented yet"}}, nil
	case "always":
	default:
		return nil, nil, nil
	}

	var findings []Finding
	var selected string // quote_id of the latest selection_made
	hasSelection := false
	pending := false // an approval is waiting to be used by an action
	approvedQuote := ""
	for _, ev := range events {
		where := fmt.Sprintf("trace.events[%d].payload", ev.seq)
		switch ev.typ {
		case "selection_made":
			id, err := get[string](ev.payload, "quote_id", where)
			if err != nil {
				return nil, nil, err
			}
			selected, hasSelection = id, true
			pending = false // a yes to one choice is not a yes to another
		case "human_confirmation":
			switch ev.decision {
			case "approved":
				// The agent's yes is not the principal's, and a yes before
				// any choice was made is not a yes to a choice.
				if ev.actor == "principal" && hasSelection {
					pending, approvedQuote = true, selected
				}
			case "declined", "modified":
				pending = false
			}
		case "action_executed":
			quote, err := get[string](ev.payload, "quote_id", where)
			if err != nil {
				return nil, nil, err
			}
			amount, err := get[map[string]any](ev.payload, "amount_committed", where)
			if err != nil {
				return nil, nil, err
			}
			value, err := get[string](amount, "amount", where+".amount_committed")
			if err != nil {
				return nil, nil, err
			}
			currency, err := get[string](amount, "currency", where+".amount_committed")
			if err != nil {
				return nil, nil, err
			}
			switch {
			case !pending:
				findings = append(findings, Finding{9, ev.seq, fmt.Sprintf(
					"event %d (action_executed): the agent committed %s %s without an approved human_confirmation from the principal, but the mandate requires one every time",
					ev.seq, value, currency)})
			case quote != approvedQuote:
				findings = append(findings, Finding{9, ev.seq, fmt.Sprintf(
					"event %d (action_executed): the agent committed %s %s on quote '%s', but the principal approved quote '%s'",
					ev.seq, value, currency, quote, approvedQuote)})
			}
			pending = false // each approval is used up by one action
		}
	}

	var notes []NotChecked
	if len(findings) == 0 && !principalSigned {
		notes = append(notes, NotChecked{9, "the principal's approvals are recorded by the agent; the principal did not sign the seal"})
	}
	return findings, notes, nil
}

// Rule 10. The journey is within the mandate's scope. Extension: a mandate
// whose allowed_actions has no binding action allows no action_executed.
func checkScope(scope, trace map[string]any, events []event) ([]Finding, []NotChecked, error) {
	classes, err := stringList(scope, "product_classes", "mandate.scope")
	if err != nil {
		return nil, nil, err
	}
	actions, err := stringList(scope, "allowed_actions", "mandate.scope")
	if err != nil {
		return nil, nil, err
	}
	journey, err := get[map[string]any](trace, "journey", "trace")
	if err != nil {
		return nil, nil, err
	}
	class, err := get[string](journey, "product_class", "trace.journey")
	if err != nil {
		return nil, nil, err
	}
	action, err := get[string](journey, "action", "trace.journey")
	if err != nil {
		return nil, nil, err
	}

	var findings []Finding
	if !slices.Contains(classes, class) {
		findings = append(findings, Finding{10, -1, fmt.Sprintf("journey.product_class '%s' is not in the mandate's scope.product_classes", class)})
	}
	if !slices.Contains(actions, action) {
		findings = append(findings, Finding{10, -1, fmt.Sprintf("journey.action '%s' is not in the mandate's scope.allowed_actions", action)})
	}
	if !slices.ContainsFunc(actions, func(a string) bool { return slices.Contains(binding, a) }) {
		for _, ev := range events {
			if ev.typ == "action_executed" {
				findings = append(findings, Finding{10, ev.seq, fmt.Sprintf(
					"event %d (action_executed): the mandate's scope.allowed_actions has no binding action, but the agent carried one out", ev.seq)})
			}
		}
	}

	var notes []NotChecked
	for _, key := range []string{"provider_allowlist", "provider_blocklist"} {
		if _, ok := scope[key]; ok {
			notes = append(notes, NotChecked{0, "provider allow and block lists are not covered by any rule yet"})
			break
		}
	}
	return findings, notes, nil
}

// Rule 11. Every event falls inside the validity window, bounds included.
// Only events[].at are checked, as SPEC.md says "every event": the seal's,
// the consent's and the journey's timestamps are not.
func checkWindow(validity map[string]any, events []event) ([]Finding, error) {
	bound := func(key string) (time.Time, string, error) {
		s, err := get[string](validity, key, "mandate.validity")
		if err != nil {
			return time.Time{}, "", err
		}
		t, err := ParseTime(s)
		if err != nil {
			return time.Time{}, "", fmt.Errorf("witness: mandate.validity.%s: not an RFC 3339 timestamp: %q", key, s)
		}
		return t, s, nil
	}
	from, fromText, err := bound("not_before")
	if err != nil {
		return nil, err
	}
	to, toText, err := bound("expires_at")
	if err != nil {
		return nil, err
	}
	var findings []Finding
	for _, ev := range events {
		switch {
		case ev.at.Before(from):
			findings = append(findings, Finding{11, ev.seq, fmt.Sprintf("event %d: happened before the mandate's not_before (%s)", ev.seq, fromText)})
		case ev.at.After(to):
			findings = append(findings, Finding{11, ev.seq, fmt.Sprintf("event %d: happened after the mandate's expires_at (%s)", ev.seq, toText)})
		}
	}
	return findings, nil
}

func stringList(obj map[string]any, key, where string) ([]string, error) {
	list, err := get[[]any](obj, key, where)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(list))
	for i, v := range list {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("witness: %s.%s[%d]: expected a string", where, key, i)
		}
		out = append(out, s)
	}
	return out, nil
}

// get reads obj[key] as a T, or explains why it cannot.
func get[T any](obj map[string]any, key, where string) (T, error) {
	var zero T
	v, ok := obj[key]
	if !ok {
		return zero, fmt.Errorf("witness: %s: missing field %q", where, key)
	}
	t, ok := v.(T)
	if !ok {
		return zero, fmt.Errorf("witness: %s.%s: unexpected type %T", where, key, v)
	}
	return t, nil
}
