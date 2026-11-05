package witness

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/LijZdk/a-witness/witness/canon"
	"github.com/LijZdk/a-witness/witness/internal/rules"
)

// Problem is one way a trace breaks a rule in SPEC.md, "Rules across documents".
type Problem struct {
	Rule    int    // the rule's number in SPEC.md
	Seq     int    // the event concerned, or -1 if the problem is not about one event
	Message string // plain language, for a person reading a report
}

func (p Problem) String() string { return p.Message }

// Verify checks that a trace is a genuine record made under the given
// mandate: SPEC.md rules 1 to 8 and 15. No problems means the record holds
// together and is signed as it should be; it says nothing yet about whether
// the agent obeyed the mandate.
//
// t says which keys are trusted for which party (see Trust): the principal's
// and the provider's, from key sources the verifier pinned, and the agent's,
// which only the key the mandate names can use. By default rule 15 needs the
// mandate signature from a principal key and valid seal signatures from the
// agent and from a provider; Trust.RequirePrincipalSeal adds the principal.
// Pass SkipSignatures to check rules 1 to 8 only. A nil t, or a Trust missing
// a role, is an error.
//
// Not checked here yet:
//   - JSON Schema conformance: witness/schema exists, but Verify does not call it yet
//   - mandate rules: Check runs rules 9, 10, 11 and 14 (12 and 13 are reported as not checked), on a record Verify finds intact
//
// An error means a document could not be read at all: it is not strict
// JSON (see canon.Parse), or lacks a field these checks need.
func Verify(ctx context.Context, mandateJSON, traceJSON []byte, t *Trust) ([]Problem, error) {
	if err := t.check(); err != nil {
		return nil, err
	}
	mandate, err := parseObject(mandateJSON, "mandate")
	if err != nil {
		return nil, err
	}
	traceDoc, err := parseObject(traceJSON, "trace")
	if err != nil {
		return nil, err
	}
	problems, _, err := verify(ctx, mandate, traceDoc, t)
	return problems, err
}

// verify is Verify on parsed documents, so that Check can run the mandate
// rules on exactly the maps that were verified. principalSigned is true when
// rule 15 was checked and the seal carries a valid signature from the
// principal who signed the mandate.
func verify(ctx context.Context, mandate, traceDoc map[string]any, trust *Trust) (problems []Problem, principalSigned bool, err error) {
	mandateID, err := field[string](mandate, "mandate_id", "mandate")
	if err != nil {
		return nil, false, err
	}
	mandateHash, err := MandateHash(mandate)
	if err != nil {
		return nil, false, err
	}
	t, err := readTrace(traceDoc)
	if err != nil {
		return nil, false, err
	}

	add := func(rule, seq int, format string, args ...any) {
		problems = append(problems, Problem{Rule: rule, Seq: seq, Message: fmt.Sprintf(format, args...)})
	}

	// Rule 1: the trace names this mandate.
	if t.mandateID != mandateID {
		add(1, -1, "trace mandate_ref.mandate_id does not match the mandate")
	}
	if t.mandateHash != mandateHash {
		add(1, -1, "trace mandate_ref.mandate_hash does not match the mandate")
	}

	// Rules 2 to 4: numbering, chaining and each event's own hash.
	prev := mandateHash
	for i, ev := range t.events {
		if ev.seq != i {
			add(2, i, "event %d: seq is %d, expected %d", i, ev.seq, i)
		}
		if ev.prevHash != prev {
			add(3, i, "event %d: prev_hash breaks the chain", i)
		}
		h, err := HashEvent(ev.raw)
		if err != nil {
			return nil, false, fmt.Errorf("witness: hashing event %d: %w", i, err)
		}
		if ev.hash != h {
			add(4, i, "event %d: hash does not match its content (tampered?)", i)
		}
		prev = ev.hash
	}

	// Rule 5: time only moves forward.
	var last time.Time
	for i, ev := range t.events {
		at, err := rules.ParseTime(ev.at)
		if err != nil {
			add(5, i, "event %d: unreadable timestamp %q", i, ev.at)
			continue
		}
		if i > 0 && at.Before(last) {
			add(5, i, "event %d: timestamp is earlier than event %d", i, i-1)
		}
		last = at
	}
	if sealedAt, err := rules.ParseTime(t.sealedAt); err != nil {
		add(5, -1, "seal: unreadable timestamp %q", t.sealedAt)
	} else if sealedAt.Before(last) {
		add(5, -1, "seal is dated before the final event")
	}

	// Rule 6: the seal covers the last event.
	if t.finalEventHash != prev {
		add(6, -1, "seal does not cover the final event")
	}

	// Rule 7: outcome evidence cites events that exist.
	for _, outcome := range t.evidenceOrder {
		for _, seq := range t.evidence[outcome] {
			if seq >= len(t.events) {
				add(7, -1, "outcome_evidence.%s cites event %d, but the trace has only %d events", esc(outcome), seq, len(t.events))
			}
		}
	}

	// Rule 8: quote ids are unique, and references point back to a received quote.
	received := map[string]int{}
	for i, ev := range t.events {
		if ev.typ == "quote_received" {
			id := ev.quoteIDs[0]
			if first, dup := received[id]; dup {
				add(8, i, "event %d (quote_received): quote_id '%s' was already used by event %d", i, esc(id), first)
			} else {
				received[id] = i
			}
			continue
		}
		for _, id := range ev.quoteIDs {
			if _, ok := received[id]; !ok {
				add(8, i, "event %d (%s): refers to quote '%s', but no earlier quote_received offered it", i, esc(ev.typ), esc(id))
			}
		}
	}

	// Rule 15: the mandate and the seal are validly signed, by the right keys.
	if trust != SkipSignatures {
		var sigProblems []Problem
		sigProblems, principalSigned, err = signatureProblems(ctx, mandate, traceDoc, trust)
		if err != nil {
			return nil, false, err
		}
		problems = append(problems, sigProblems...)
	}

	return problems, principalSigned, nil
}

type event struct {
	raw      map[string]any // the whole event, as hashed
	seq      int
	at       string
	typ      string
	prevHash string
	hash     string
	quoteIDs []string // the quote it defines (quote_received) or refers to
}

type trace struct {
	mandateID, mandateHash string
	events                 []event
	finalEventHash         string
	sealedAt               string
	evidence               map[string][]int
	evidenceOrder          []string // the four outcomes, in SPEC.md order
}

var outcomes = []string{"products_and_services", "price_and_value", "consumer_understanding", "consumer_support"}

func readTrace(doc map[string]any) (*trace, error) {
	t := &trace{evidence: map[string][]int{}}
	ref, err := field[map[string]any](doc, "mandate_ref", "trace")
	if err != nil {
		return nil, err
	}
	if t.mandateID, err = field[string](ref, "mandate_id", "trace.mandate_ref"); err != nil {
		return nil, err
	}
	if t.mandateHash, err = field[string](ref, "mandate_hash", "trace.mandate_ref"); err != nil {
		return nil, err
	}

	rawEvents, err := field[[]any](doc, "events", "trace")
	if err != nil {
		return nil, err
	}
	if len(rawEvents) == 0 {
		return nil, fmt.Errorf("witness: trace.events: a trace needs at least one event")
	}
	for i, re := range rawEvents {
		ev, err := readEvent(re, fmt.Sprintf("trace.events[%d]", i))
		if err != nil {
			return nil, err
		}
		t.events = append(t.events, ev)
	}

	seal, err := field[map[string]any](doc, "seal", "trace")
	if err != nil {
		return nil, err
	}
	if t.finalEventHash, err = field[string](seal, "final_event_hash", "trace.seal"); err != nil {
		return nil, err
	}
	if t.sealedAt, err = field[string](seal, "sealed_at", "trace.seal"); err != nil {
		return nil, err
	}

	if _, ok := doc["outcome_evidence"]; ok {
		evidence, err := field[map[string]any](doc, "outcome_evidence", "trace")
		if err != nil {
			return nil, err
		}
		for _, outcome := range outcomes {
			if _, ok := evidence[outcome]; !ok {
				continue
			}
			where := "trace.outcome_evidence." + outcome
			ref, err := field[map[string]any](evidence, outcome, "trace.outcome_evidence")
			if err != nil {
				return nil, err
			}
			seqs, err := field[[]any](ref, "event_seqs", where)
			if err != nil {
				return nil, err
			}
			for j, s := range seqs {
				n, err := wholeNumber(s, fmt.Sprintf("%s.event_seqs[%d]", where, j))
				if err != nil {
					return nil, err
				}
				t.evidence[outcome] = append(t.evidence[outcome], n)
			}
			t.evidenceOrder = append(t.evidenceOrder, outcome)
		}
	}
	return t, nil
}

func readEvent(v any, where string) (event, error) {
	raw, ok := v.(map[string]any)
	if !ok {
		return event{}, fmt.Errorf("witness: %s: expected an object", where)
	}
	ev := event{raw: raw}
	seq, err := field[float64](raw, "seq", where)
	if err != nil {
		return ev, err
	}
	if ev.seq, err = wholeNumber(seq, where+".seq"); err != nil {
		return ev, err
	}
	for _, f := range []struct {
		key string
		dst *string
	}{{"at", &ev.at}, {"type", &ev.typ}, {"prev_hash", &ev.prevHash}, {"hash", &ev.hash}} {
		if *f.dst, err = field[string](raw, f.key, where); err != nil {
			return ev, err
		}
	}
	payload, err := field[map[string]any](raw, "payload", where)
	if err != nil {
		return ev, err
	}
	ev.quoteIDs, err = quoteIDs(ev.typ, payload, where+".payload")
	return ev, err
}

// quoteIDs returns the quote an event defines or refers to, by event type.
func quoteIDs(typ string, payload map[string]any, where string) ([]string, error) {
	switch typ {
	case "quote_received", "requirement_check", "selection_made", "action_executed":
		id, err := field[string](payload, "quote_id", where)
		return []string{id}, err
	case "alternatives_considered":
		options, err := field[[]any](payload, "options", where)
		if err != nil {
			return nil, err
		}
		var ids []string
		for j, o := range options {
			option, ok := o.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("witness: %s.options[%d]: expected an object", where, j)
			}
			id, err := field[string](option, "quote_id", fmt.Sprintf("%s.options[%d]", where, j))
			if err != nil {
				return nil, err
			}
			ids = append(ids, id)
		}
		return ids, nil
	case "escalation", "error":
		if _, ok := payload["related_quote_id"]; !ok {
			return nil, nil
		}
		id, err := field[string](payload, "related_quote_id", where)
		return []string{id}, err
	}
	return nil, nil
}

func parseObject(b []byte, what string) (map[string]any, error) {
	v, err := canon.Parse(b)
	if err != nil {
		return nil, fmt.Errorf("witness: reading the %s: %w", what, err)
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("witness: the %s is not a JSON object", what)
	}
	return obj, nil
}

// field reads obj[key] as a T, or explains why it cannot.
func field[T any](obj map[string]any, key, where string) (T, error) {
	var zero T
	v, ok := obj[key]
	if !ok {
		return zero, fmt.Errorf("witness: %s: missing field %q", where, key)
	}
	t, ok := v.(T)
	if !ok {
		return zero, fmt.Errorf("witness: %s.%s: expected %s", where, key, kindOf(zero))
	}
	return t, nil
}

func kindOf(v any) string {
	switch v.(type) {
	case string:
		return "a string"
	case float64:
		return "a number"
	case map[string]any:
		return "an object"
	case []any:
		return "an array"
	}
	return fmt.Sprintf("%T", v)
}

func wholeNumber(v any, where string) (int, error) {
	f, ok := v.(float64)
	if !ok || f < 0 || f != math.Trunc(f) || f > 1<<31 {
		return 0, fmt.Errorf("witness: %s: expected a whole number of 0 or more", where)
	}
	return int(f), nil
}
