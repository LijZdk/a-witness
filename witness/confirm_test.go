package witness

// AW-36: the principal signs each human_confirmation. The cases build variants
// of the home-insurance-switch example (whose event 9 is Sam's signed yes) in
// which only the check under test can object: each is re-chained and the seal
// re-signed by the agent and the provider. scripts/check.sh runs the same cases
// through validate.py against the same golden files.

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/LijZdk/a-witness/witness/canon"
	"github.com/LijZdk/a-witness/witness/sign"
)

const confSeq = 9 // the human_confirmation in home-insurance-switch

func sam() Signer { return exampleSigner("sam", "principal") }

func deepCopy(t *testing.T, m map[string]any) map[string]any {
	t.Helper()
	b, err := canon.Serialize(m)
	if err != nil {
		t.Fatal(err)
	}
	return parse(t, b)
}

// signAt (re)signs the human_confirmation at events[idx] as s, over the trace as
// it stands: its trace_id, mandate_ref and the events before idx.
func signAt(t *testing.T, tr map[string]any, idx int, s Signer) {
	t.Helper()
	events := tr["events"].([]any)
	pl := payload(events, idx)
	delete(pl, "principal_signature")
	before := map[string]any{"trace_id": tr["trace_id"], "mandate_ref": tr["mandate_ref"], "events": events[:idx]}
	b, err := ConfirmationPayload(before, pl)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := SignConfirmation(b, s)
	if err != nil {
		t.Fatal(err)
	}
	pl["principal_signature"] = sig
}

// resignConfirmation signs the example's yes again as Sam, after the trace's
// mandate_ref or earlier events changed.
func resignConfirmation(t *testing.T, tr map[string]any) { signAt(t, tr, confSeq, sam()) }

func renumber(tr map[string]any) {
	for i, e := range tr["events"].([]any) {
		e.(map[string]any)["seq"] = float64(i)
	}
}

// insertAfter puts ev after events[idx] and renumbers the trace.
func insertAfter(tr map[string]any, idx int, ev map[string]any) {
	events := tr["events"].([]any)
	tr["events"] = slices.Insert(slices.Clone(events), idx+1, any(ev))
	renumber(tr)
}

// confVariant is the home trace after change, with the hash chain recomputed and
// the seal re-signed by the agent and the provider, so that only the
// confirmation can object.
func confVariant(t *testing.T, change func(tr map[string]any, events []any)) []byte {
	t.Helper()
	trace := edit(t, home, true, change)
	return reseal(t, trace, exampleSigner("home-helper", "agent"), exampleSigner("newco", "provider"))
}

func confTrust(t *testing.T, require bool) *Trust {
	t.Helper()
	trust := exampleTrust(t)
	trust.RequireSignedConfirmations = require
	return trust
}

// refused checks that Check refuses the trace for exactly these rule 15
// messages, with or without the policy, and runs no mandate rules.
func refused(t *testing.T, trace []byte, want ...string) {
	t.Helper()
	mandate, _ := exampleMandateAndTrace(t)
	for _, require := range []bool{false, true} {
		r, err := Check(context.Background(), mandate, trace, confTrust(t, require))
		if err != nil {
			t.Fatal(err)
		}
		if got := rule15(r.Integrity); !slices.Equal(got, want) || len(r.Integrity) != len(want) {
			t.Fatalf("require=%v: got %q (all: %v), want %q", require, got, r.Integrity, want)
		}
		if r.Pass() || r.RulesRan || r.Signatures == SignaturesValid || len(r.SignedConfirmations) != 0 {
			t.Fatalf("require=%v: a refused record must not pass, run the rules or list signed confirmations: %+v", require, r)
		}
	}
}

func rule9Messages(r Report) []string {
	var out []string
	for _, p := range r.Rules {
		if p.Rule == 9 {
			out = append(out, p.Message)
		}
	}
	return out
}

const confKeyPrefix = "event 9 (human_confirmation): "

func TestConfirmation_SignedExamplePasses(t *testing.T) {
	for _, require := range []bool{false, true} {
		r := checkExample(t, home, confTrust(t, require))
		if !r.Pass() || len(r.Rules) != 0 || len(r.Integrity) != 0 {
			t.Fatalf("require=%v: not a pass: %+v", require, r)
		}
		if len(r.SignedConfirmations) != 1 || r.SignedConfirmations[0].Seq != confSeq {
			t.Fatalf("require=%v: signed confirmations: %+v", require, r.SignedConfirmations)
		}
		// scripts/check.sh asserts that validate.py prints this same line after "signed: ".
		if got, want := r.SignedConfirmations[0].String(), golden(t, "confirmation.signed.txt"); got != want {
			t.Fatalf("got  %s\nwant %s", got, want)
		}
		if hasNotChecked(r, 9, "did not sign the seal") {
			t.Fatalf("a signed yes is still noted as the agent's claim: %+v", r.NotChecked)
		}
	}
	// The ref is the hash of the bytes Sam signed, computed here from scratch.
	tr := parse(t, readFile(t, "examples", home+".trace.json"))
	pl := payload(tr["events"].([]any), confSeq)
	want, err := canon.Serialize(map[string]any{
		"mandate_hash": tr["mandate_ref"].(map[string]any)["mandate_hash"], "trace_id": tr["trace_id"], "previous_ref": "",
		"payload": without(pl, "principal_signature"),
	})
	if err != nil {
		t.Fatal(err)
	}
	r := checkExample(t, home, confTrust(t, true))
	if r.SignedConfirmations[0].Ref != ConfirmationRef(want) {
		t.Fatalf("ref %s, want %s", r.SignedConfirmations[0].Ref, ConfirmationRef(want))
	}
}

func TestConfirmation_PolicyUnsignedRefused(t *testing.T) {
	r := checkExample(t, "fixed-rate-savings-switch", confTrust(t, true))
	if r.Pass() || !r.RulesRan || r.Signatures != SignaturesValid || len(r.Integrity) != 0 {
		t.Fatalf("want an intact record that breaks rule 9: %+v", r)
	}
	want := golden(t, "rule9.unsigned-under-policy.txt")
	if len(r.Rules) != 1 || r.Rules[0].Rule != 9 || r.Rules[0].Seq != 11 || r.Rules[0].Message != want {
		t.Fatalf("got %+v, want rule 9 at event 11: %s", r.Rules, want)
	}
	if len(r.SignedConfirmations) != 0 {
		t.Fatalf("nothing in the savings example is signed: %+v", r.SignedConfirmations)
	}
}

func TestConfirmation_PolicyOffUnsignedIsAgentsClaim(t *testing.T) {
	r := checkExample(t, "fixed-rate-savings-switch", confTrust(t, false))
	if !r.Pass() {
		t.Fatalf("an unsigned yes is still a valid record without the policy: %+v", r)
	}
	want := golden(t, "rule9.agents-claim.txt")
	if !hasNotChecked(r, 9, want) {
		t.Fatalf("want the note %q, got %+v", want, r.NotChecked)
	}
}

// A yes signed with a key the verifier does not trust for the principal's role
// that signed the mandate: the agent's, the provider's, another principal's.
func TestConfirmation_ForgedKeys(t *testing.T) {
	sam := exampleKeyIDs["sam"]
	for _, c := range []struct{ name, holder string }{
		{"AgentKey", "home-helper"}, {"ProviderKey", "newco"}, {"OtherPrincipalKey", "jo"},
	} {
		t.Run(c.name, func(t *testing.T) {
			forger := exampleSigner(c.holder, "principal")
			trace := confVariant(t, func(tr map[string]any, _ []any) { signAt(t, tr, confSeq, forger) })
			want := confKeyPrefix + "principal_signature uses key '" + exampleKeyIDs[c.holder] + "', but the mandate was signed with '" + sam + "'"
			refused(t, trace, want)
			if c.holder == "home-helper" && golden(t, "rule15.confirm-key.txt") != want {
				t.Fatal("the golden file scripts/check.sh reads differs from the message")
			}
		})
	}
}

func TestConfirmation_RelabelledKid(t *testing.T) {
	// The agent's key, with Sam's key id on the signature object and in the JWS header.
	forger := Signer{Role: "principal", Alg: sign.EdDSA, KeyID: exampleKeyIDs["sam"], Key: exampleKey("home-helper")}
	trace := confVariant(t, func(tr map[string]any, _ []any) { signAt(t, tr, confSeq, forger) })
	refused(t, trace, confKeyPrefix+"principal_signature does not verify: the signature does not match the document and key")
}

func TestConfirmation_SealTypReused(t *testing.T) {
	// Sam signed the right bytes, but as a seal signature: the typ keeps it from being a confirmation.
	trace := confVariant(t, func(tr map[string]any, events []any) {
		pl := payload(events, confSeq)
		delete(pl, "principal_signature")
		b, err := ConfirmationPayload(map[string]any{"trace_id": tr["trace_id"], "mandate_ref": tr["mandate_ref"], "events": events[:confSeq]}, pl)
		if err != nil {
			t.Fatal(err)
		}
		s := sam()
		jws, err := sign.Sign(s.Key, s.Alg, s.KeyID, SealTyp, b)
		if err != nil {
			t.Fatal(err)
		}
		pl["principal_signature"] = map[string]any{"alg": s.Alg, "key_id": s.KeyID, "value": jws}
	})
	mandate, _ := exampleMandateAndTrace(t)
	problems, err := Verify(context.Background(), mandate, trace, exampleTrust(t))
	if err != nil {
		t.Fatal(err)
	}
	got := rule15(problems)
	if len(got) != 1 || !strings.HasPrefix(got[0], confKeyPrefix+"principal_signature does not verify: the JWS header has typ") {
		t.Fatalf("got %q", got)
	}
}

// What Sam signed is what the verifier sees: change any of it afterwards and the signature fails.
func TestConfirmation_Tampered(t *testing.T) {
	bad := confKeyPrefix + "principal_signature does not verify: the signature does not match the document and key"
	for name, tamper := range map[string]func(pl map[string]any){
		"Summary":  func(pl map[string]any) { pl["shown_summary_hash"] = HashText("Switch to NewCo, for 198 GBP. Approve?") },
		"Quote":    func(pl map[string]any) { pl["quote_id"] = "q_incumbent" },
		"Amount":   func(pl map[string]any) { pl["amount"].(map[string]any)["amount"] = "198.00" },
		"Currency": func(pl map[string]any) { pl["amount"].(map[string]any)["currency"] = "EUR" },
		"Decision": func(pl map[string]any) { pl["decision"] = "modified" },
		"Method":   func(pl map[string]any) { pl["method"] = "voice" },
		"AddedAER": func(pl map[string]any) { pl["aer"] = "4.35" },
	} {
		t.Run(name, func(t *testing.T) {
			trace := confVariant(t, func(_ map[string]any, e []any) { tamper(payload(e, confSeq)) })
			refused(t, trace, bad)
			if name == "Summary" && golden(t, "rule15.confirm-bad-sig.txt") != bad {
				t.Fatal("the golden file scripts/check.sh reads differs from the message")
			}
		})
	}
}

// A real signed yes cannot be moved into another journey or under another mandate.
func TestConfirmation_OtherTraceID(t *testing.T) {
	trace := confVariant(t, func(tr map[string]any, _ []any) {
		real := tr["trace_id"]
		tr["trace_id"] = "trc_SomewhereElse1"
		resignConfirmation(t, tr) // Sam signed it for another journey
		tr["trace_id"] = real
	})
	refused(t, trace, confKeyPrefix+"principal_signature does not verify: the signature does not match the document and key")
}

func TestConfirmation_OtherMandateSamePrincipal(t *testing.T) {
	other := parse(t, readFile(t, "examples", "home-insurance-no-confirmation.trace.json"))["mandate_ref"].(map[string]any)["mandate_hash"]
	trace := confVariant(t, func(tr map[string]any, _ []any) {
		ref := tr["mandate_ref"].(map[string]any)
		real := ref["mandate_hash"]
		ref["mandate_hash"] = other // Sam's other mandate
		resignConfirmation(t, tr)
		ref["mandate_hash"] = real
	})
	refused(t, trace, confKeyPrefix+"principal_signature does not verify: the signature does not match the document and key")
}

// The same signed yes twice in one trace: the copy sits after a signed confirmation, so its
// previous_ref is wrong.
func TestConfirmation_DuplicateWithinTrace(t *testing.T) {
	trace := confVariant(t, func(tr map[string]any, events []any) {
		insertAfter(tr, confSeq, deepCopy(t, events[confSeq].(map[string]any)))
	})
	refused(t, trace, "event 10 (human_confirmation): principal_signature does not verify: the signature does not match the document and key")
}

// A signed decline followed by a signed yes becomes a yes then a decline when swapped, but each
// signature names the one before it, so neither verifies where it now sits.
func TestConfirmation_SwapYesAndSignedDecline(t *testing.T) {
	trace := confVariant(t, func(tr map[string]any, events []any) {
		decline := deepCopy(t, events[confSeq].(map[string]any))
		payload([]any{decline}, 0)["decision"] = "declined"
		insertAfter(tr, confSeq, decline)
		signAt(t, tr, confSeq+1, sam()) // the decline names the yes before it
		e := tr["events"].([]any)
		e[confSeq], e[confSeq+1] = e[confSeq+1], e[confSeq]
		renumber(tr)
	})
	refused(t, trace,
		"event 9 (human_confirmation): principal_signature does not verify: the signature does not match the document and key",
		"event 10 (human_confirmation): principal_signature does not verify: the signature does not match the document and key")

	// Unswapped, the same two signed events are genuine, and the later decline cancels the yes.
	genuine := confVariant(t, func(tr map[string]any, events []any) {
		decline := deepCopy(t, events[confSeq].(map[string]any))
		payload([]any{decline}, 0)["decision"] = "declined"
		insertAfter(tr, confSeq, decline)
		signAt(t, tr, confSeq+1, sam())
	})
	mandate, _ := exampleMandateAndTrace(t)
	r, err := Check(context.Background(), mandate, genuine, confTrust(t, true))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Integrity) != 0 || len(r.SignedConfirmations) != 2 || r.Pass() {
		t.Fatalf("want two signed confirmations and a purchase with no live yes: %+v", r)
	}
	if got := rule9Messages(r); len(got) != 1 || !strings.HasPrefix(got[0], "event 11 (action_executed): the agent committed 298.00 GBP without an approved human_confirmation") {
		t.Fatalf("got %q", got)
	}
}

// Only an unsigned decline is added: it still cancels the signed yes, because withdrawing a yes
// needs no proof.
func TestConfirmation_UnsignedDeclineStillCancels(t *testing.T) {
	trace := confVariant(t, func(tr map[string]any, events []any) {
		decline := deepCopy(t, events[confSeq].(map[string]any))
		pl := payload([]any{decline}, 0)
		pl["decision"] = "declined"
		delete(pl, "principal_signature")
		insertAfter(tr, confSeq, decline)
	})
	mandate, _ := exampleMandateAndTrace(t)
	for _, require := range []bool{false, true} {
		r, err := Check(context.Background(), mandate, trace, confTrust(t, require))
		if err != nil {
			t.Fatal(err)
		}
		got := rule9Messages(r)
		if len(r.Integrity) != 0 || len(got) != 1 || !strings.HasPrefix(got[0], "event 11 (action_executed): the agent committed 298.00 GBP without an approved human_confirmation") {
			t.Fatalf("require=%v: got %q, %+v", require, got, r.Integrity)
		}
	}
}

func TestConfirmation_MissingField(t *testing.T) {
	for _, name := range confirmationRequired {
		t.Run(name, func(t *testing.T) {
			trace := confVariant(t, func(_ map[string]any, e []any) { delete(payload(e, confSeq), name) })
			want := confKeyPrefix + "a signed confirmation needs " + name
			refused(t, trace, want)
			if name == "shown_summary_hash" && golden(t, "rule15.confirm-needs-summary.txt") != want {
				t.Fatal("the golden file scripts/check.sh reads differs from the message")
			}
		})
	}
	t.Run("all three, in order", func(t *testing.T) {
		trace := confVariant(t, func(_ map[string]any, e []any) {
			for _, name := range confirmationRequired {
				delete(payload(e, confSeq), name)
			}
		})
		refused(t, trace, confKeyPrefix+"a signed confirmation needs shown_summary_hash",
			confKeyPrefix+"a signed confirmation needs quote_id", confKeyPrefix+"a signed confirmation needs amount")
	})
}

func TestConfirmation_ActorNotPrincipal(t *testing.T) {
	trace := confVariant(t, func(_ map[string]any, e []any) { e[confSeq].(map[string]any)["actor"] = "agent" })
	want := confKeyPrefix + "carries the principal's signature, but its actor is 'agent'"
	refused(t, trace, want)
	if golden(t, "rule15.confirm-actor.txt") != want {
		t.Fatal("the golden file scripts/check.sh reads differs from the message")
	}
	// A document string is escaped, so an actor cannot start a line of the report.
	trace = confVariant(t, func(_ map[string]any, e []any) { e[confSeq].(map[string]any)["actor"] = "a\nPASS  forged" })
	refused(t, trace, confKeyPrefix+`carries the principal's signature, but its actor is 'a\u000aPASS  forged'`)
	// And R1 stops R3 and R4: a wrong key on top of a wrong actor adds nothing.
	trace = confVariant(t, func(tr map[string]any, e []any) {
		signAt(t, tr, confSeq, exampleSigner("home-helper", "principal"))
		e[confSeq].(map[string]any)["actor"] = "agent"
	})
	refused(t, trace, want)
}

func TestConfirmation_AmountMismatch(t *testing.T) {
	// The yes was for 298.00 GBP; the purchase went through for another amount.
	for name, change := range map[string]func(amount map[string]any){
		"Amount":   func(a map[string]any) { a["amount"] = "198.00" },
		"Currency": func(a map[string]any) { a["currency"] = "EUR" },
	} {
		t.Run(name, func(t *testing.T) {
			trace := confVariant(t, func(_ map[string]any, e []any) { change(payload(e, 10)["amount_committed"].(map[string]any)) })
			mandate, _ := exampleMandateAndTrace(t)
			r, err := Check(context.Background(), mandate, trace, confTrust(t, false))
			if err != nil {
				t.Fatal(err)
			}
			got := rule9Messages(r)
			if len(r.Integrity) != 0 || len(got) != 1 || r.Pass() || r.Rules[0].Seq != 10 {
				t.Fatalf("got %q %+v", got, r)
			}
			if name == "Amount" && got[0] != golden(t, "rule9.amount-mismatch.txt") {
				t.Fatalf("got %q, want the golden line", got[0])
			}
			if name == "Currency" && got[0] != "event 10 (action_executed): the agent committed 298.00 EUR, but the principal approved 298.00 GBP" {
				t.Fatalf("got %q", got[0])
			}
		})
	}
}

func TestConfirmation_QuoteMismatch(t *testing.T) {
	// Sam signed a yes to the incumbent's quote; the agent bought NewCo's.
	trace := confVariant(t, func(tr map[string]any, e []any) {
		payload(e, confSeq)["quote_id"] = "q_incumbent"
		resignConfirmation(t, tr)
	})
	mandate, _ := exampleMandateAndTrace(t)
	r, err := Check(context.Background(), mandate, trace, confTrust(t, true))
	if err != nil {
		t.Fatal(err)
	}
	want := "event 10 (action_executed): the agent committed 298.00 GBP on quote 'q_newco', but the principal approved quote 'q_incumbent'"
	if got := rule9Messages(r); len(r.Integrity) != 0 || !slices.Equal(got, []string{want}) {
		t.Fatalf("got %q %+v", got, r.Integrity)
	}
}

// A genuine signed yes covers only the quote the agent selected last, with the existing quote message.
func TestConfirmation_SignedYesNeedsTheSelectedQuote(t *testing.T) {
	mandate, _ := exampleMandateAndTrace(t)
	cases := map[string]struct {
		change func(tr map[string]any, e []any)
		want   string
	}{
		"YesAfterOtherSelection": {func(tr map[string]any, e []any) {
			other := deepCopy(t, e[8].(map[string]any))
			payload([]any{other}, 0)["quote_id"] = "q_incumbent"
			insertAfter(tr, 8, other) // selects q_incumbent after q_newco, before Sam's yes
		}, "event 11 (action_executed): the principal signed approval for quote 'q_newco', but the agent selected quote 'q_incumbent'"},
		"YesForUnselectedQuote": {func(tr map[string]any, e []any) {
			payload(e, confSeq)["quote_id"] = "q_incumbent"
			resignConfirmation(t, tr)
			payload(e, 10)["quote_id"] = "q_incumbent"
		}, "event 10 (action_executed): the principal signed approval for quote 'q_incumbent', but the agent selected quote 'q_newco'"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			trace := confVariant(t, c.change)
			for _, require := range []bool{false, true} {
				r, err := Check(context.Background(), mandate, trace, confTrust(t, require))
				if err != nil {
					t.Fatal(err)
				}
				if name == "YesAfterOtherSelection" && c.want != "event 11 (action_executed): the principal signed approval for quote 'q_newco', but the agent selected quote 'q_incumbent'" {
					t.Fatal("unexpected message")
				}
				if name == "YesAfterOtherSelection" && golden(t, "rule9.signed-other-quote.txt") != c.want {
					t.Fatal("the golden file scripts/check.sh reads differs from the message")
				}
				if got := rule9Messages(r); len(r.Integrity) != 0 || !slices.Equal(got, []string{c.want}) || r.Pass() {
					t.Fatalf("require=%v: got %q %+v", require, got, r.Integrity)
				}
			}
		})
	}
}

func TestConfirmation_AERMismatch(t *testing.T) {
	// The home quote offers a price, not a rate: a signed yes to an AER is a yes to something it did not offer.
	trace := confVariant(t, func(tr map[string]any, e []any) {
		payload(e, confSeq)["aer"] = "4.35"
		resignConfirmation(t, tr)
	})
	mandate, _ := exampleMandateAndTrace(t)
	r, err := Check(context.Background(), mandate, trace, confTrust(t, true))
	if err != nil {
		t.Fatal(err)
	}
	if got := rule9Messages(r); len(r.Integrity) != 0 || !slices.Equal(got, []string{golden(t, "rule9.aer-mismatch.txt")}) || r.Rules[0].Seq != confSeq {
		t.Fatalf("got %q %+v", got, r.Integrity)
	}
}

func TestConfirmation_QuoteNotReceived(t *testing.T) {
	// A signed yes to a quote no quote_received offered: rule 8 counts the confirmation's quote_id.
	trace := confVariant(t, func(tr map[string]any, e []any) {
		payload(e, confSeq)["quote_id"] = "q_nowhere"
		resignConfirmation(t, tr)
	})
	mandate, _ := exampleMandateAndTrace(t)
	problems, err := Verify(context.Background(), mandate, trace, exampleTrust(t))
	if err != nil {
		t.Fatal(err)
	}
	want := []Problem{{Rule: 8, Seq: confSeq, Message: "event 9 (human_confirmation): refers to quote 'q_nowhere', but no earlier quote_received offered it"}}
	if !slices.Equal(problems, want) {
		t.Fatalf("got %v, want %v", problems, want)
	}
}

func TestConfirmation_PolicyAboveLimitsAndNever(t *testing.T) {
	signers := []Signer{exampleSigner("home-helper", "agent"), exampleSigner("newco", "provider")}
	for _, setting := range []string{"never", "above_limits"} {
		mandate, trace := rebuild(t, func(m map[string]any) { m["human_confirmation"] = setting }, "sam", signers...)
		want := "the policy that only principal-signed approvals count was not applied, because human_confirmation is '" + setting + "'"
		if setting == "never" && golden(t, "rule9.policy-not-applied.txt") != want {
			t.Fatal("the golden file scripts/check.sh reads differs from the message")
		}
		on, err := Check(context.Background(), mandate, trace, confTrust(t, true))
		if err != nil {
			t.Fatal(err)
		}
		if !on.Pass() || !hasNotChecked(on, 9, want) {
			t.Errorf("%s: want a pass that says the policy was not applied: %+v", setting, on)
		}
		off, err := Check(context.Background(), mandate, trace, confTrust(t, false))
		if err != nil {
			t.Fatal(err)
		}
		if hasNotChecked(off, 9, "the policy that only principal-signed approvals count") {
			t.Errorf("%s: the policy is off, yet it is reported: %+v", setting, off.NotChecked)
		}
	}
}

func TestConfirmation_NoConfirmationGoldenUnderPolicy(t *testing.T) {
	want := golden(t, "no-confirmation.rule9.txt")
	for _, require := range []bool{false, true} {
		r := checkExample(t, "home-insurance-no-confirmation", confTrust(t, require))
		if len(r.Rules) != 1 || r.Rules[0].Message != want || r.Rules[0].Seq != 11 || r.Pass() {
			t.Fatalf("require=%v: got %+v, want the unchanged golden line: %s", require, r.Rules, want)
		}
	}
}

func TestConfirmation_SkipSignatures(t *testing.T) {
	mandate, trace := exampleMandateAndTrace(t)
	r, err := Check(context.Background(), mandate, trace, SkipSignatures)
	if err != nil {
		t.Fatal(err)
	}
	if r.Pass() || len(r.Integrity) != 0 || !r.RulesRan || len(r.SignedConfirmations) != 0 {
		t.Fatalf("skipping signatures must not pass or list signed confirmations: %+v", r)
	}
	// Nothing is verified, so a signed yes is still only the agent's claim.
	if !hasNotChecked(r, 9, golden(t, "rule9.agents-claim.txt")) {
		t.Fatalf("want the agent's-claim note: %+v", r.NotChecked)
	}
	// And a signature that would not verify is not looked at: no R1 to R4.
	tampered := confVariant(t, func(_ map[string]any, e []any) { payload(e, confSeq)["quote_id"] = "q_incumbent" })
	problems, err := Verify(context.Background(), mandate, tampered, SkipSignatures)
	if err != nil || len(problems) != 0 {
		t.Fatalf("skipped signatures reported %v (%v)", problems, err)
	}
}

// Changing the shared SkipSignatures to demand signatures would be a policy that did not run.
func TestSkipSignaturesMutatedErrors(t *testing.T) {
	mandate, trace := exampleMandateAndTrace(t)
	for name, set := range map[string]func(bool){
		"RequirePrincipalSeal":       func(b bool) { SkipSignatures.RequirePrincipalSeal = b },
		"RequireSignedConfirmations": func(b bool) { SkipSignatures.RequireSignedConfirmations = b },
	} {
		set(true)
		_, verr := Verify(context.Background(), mandate, trace, SkipSignatures)
		_, cerr := Check(context.Background(), mandate, trace, SkipSignatures)
		set(false)
		if !errors.Is(verr, errSkipWithRequire) || !errors.Is(cerr, errSkipWithRequire) {
			t.Errorf("%s: Verify %v, Check %v", name, verr, cerr)
		}
	}
	if _, err := Check(context.Background(), mandate, trace, SkipSignatures); err != nil {
		t.Fatalf("SkipSignatures was left changed: %v", err)
	}
}

// The residual risk, written down: the agent chooses trace_id and writes every event, so it can fork a
// byte-identical prefix under one trace_id and a single trace cannot reveal it. Both forks verify, and
// the confirmation_ref is the same, which is what a relying party that sees many traces can notice.
func TestConfirmation_ForkSameTraceIDPasses(t *testing.T) {
	mandate, _ := exampleMandateAndTrace(t)
	a := confVariant(t, func(map[string]any, []any) {})
	b := confVariant(t, func(_ map[string]any, e []any) { payload(e, 10)["provider_reference"] = "NC-HP-OTHER" })
	if string(a) == string(b) {
		t.Fatal("the forks are the same trace")
	}
	var refs []string
	for _, trace := range [][]byte{a, b} {
		r, err := Check(context.Background(), mandate, trace, confTrust(t, true))
		if err != nil || !r.Pass() || len(r.SignedConfirmations) != 1 {
			t.Fatalf("a fork does not pass: %v %+v", err, r)
		}
		refs = append(refs, r.SignedConfirmations[0].Ref)
	}
	if refs[0] != refs[1] {
		t.Fatalf("the forks have different refs: %v", refs)
	}
}

// parties are the keys of a record built from nothing: the principal's alg is a parameter.
type parties struct {
	principal, agent, provider Signer
	keys                       *Trust
}

func newParties(t *testing.T, alg string) parties {
	t.Helper()
	var pkey crypto.Signer
	if alg == sign.ES256 {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		pkey = k
	} else {
		_, k, _ := ed25519.GenerateKey(rand.Reader)
		pkey = k
	}
	_, akey, _ := ed25519.GenerateKey(rand.Reader)
	_, vkey, _ := ed25519.GenerateKey(rand.Reader)
	p := parties{
		principal: Signer{Role: "principal", Alg: alg, KeyID: "https://wallet.test/jwks.json#p", Key: pkey},
		agent:     Signer{Role: "agent", Alg: sign.EdDSA, KeyID: "https://agent.test/jwks.json#a", Key: akey},
		provider:  Signer{Role: "provider", Alg: sign.EdDSA, KeyID: "https://provider.test/jwks.json#s", Key: vkey},
	}
	p.keys = &Trust{
		Principal:                  sign.KeySet{p.principal.KeyID: pkey.Public()},
		Provider:                   sign.KeySet{p.provider.KeyID: vkey.Public()},
		Agent:                      sign.KeySet{p.agent.KeyID: akey.Public()},
		RequireSignedConfirmations: true,
	}
	return p
}

// build makes a signed record with the producer API. The yes is made by
// ConfirmationPayload, SignConfirmation and AppendSignedConfirmation.
func (p parties) build(t *testing.T) (mandate []byte, trace map[string]any) {
	t.Helper()
	m := map[string]any{
		"spec_version":       "0.1",
		"mandate_id":         "mdt_builtByGoTest03",
		"agent":              map[string]any{"agent_id": "agt_test", "operator": "Test Ltd", "public_key_ref": p.agent.KeyID},
		"human_confirmation": "always",
		"scope":              map[string]any{"product_classes": []any{"pet_insurance"}, "allowed_actions": []any{"quote", "purchase"}},
		"validity":           map[string]any{"not_before": "2026-11-01T00:00:00Z", "expires_at": "2026-12-01T00:00:00Z"},
	}
	if err := SignMandate(m, p.principal); err != nil {
		t.Fatal(err)
	}
	mHash, err := MandateHash(m)
	if err != nil {
		t.Fatal(err)
	}
	trace = map[string]any{
		"spec_version": "0.1",
		"trace_id":     "trc_builtByGoTest03",
		"mandate_ref":  map[string]any{"mandate_id": "mdt_builtByGoTest03", "mandate_hash": mHash},
		"journey":      map[string]any{"action": "purchase", "product_class": "pet_insurance", "started_at": "2026-11-03T10:00:00Z"},
	}
	add := func(at, typ, actor string, pl map[string]any) {
		t.Helper()
		if err := AppendEvent(trace, map[string]any{"at": at, "type": typ, "actor": actor, "payload": pl}); err != nil {
			t.Fatal(err)
		}
	}
	add("2026-11-03T10:00:00Z", "intent_captured", "agent", map[string]any{"summary": "Buy pet cover."})
	add("2026-11-03T10:00:04Z", "quote_received", "provider", map[string]any{"quote_id": "q1", "provider_id": "p", "product_id": "pet", "term_months": float64(12), "aer": "4.35"})
	add("2026-11-03T10:00:09Z", "selection_made", "agent", map[string]any{"quote_id": "q1", "rationale": "Only quote."})
	yes := map[string]any{
		"at": "2026-11-03T10:00:30Z", "type": "human_confirmation", "actor": "principal",
		"payload": map[string]any{
			"method": "passkey", "decision": "approved", "shown_summary_hash": HashText("Buy pet cover for 12.00 GBP. Approve?"),
			"quote_id": "q1", "amount": map[string]any{"amount": "12.00", "currency": "GBP"}, "aer": "4.35",
		},
	}
	signable, err := ConfirmationPayload(trace, yes["payload"].(map[string]any))
	if err != nil {
		t.Fatal(err)
	}
	sig, err := SignConfirmation(signable, p.principal)
	if err != nil {
		t.Fatal(err)
	}
	if err := AppendSignedConfirmation(trace, yes, sig); err != nil {
		t.Fatal(err)
	}
	add("2026-11-03T10:00:40Z", "action_executed", "provider", map[string]any{"quote_id": "q1", "provider_reference": "R1", "amount_committed": map[string]any{"amount": "12.00", "currency": "GBP"}})
	mb, err := canon.Serialize(m)
	if err != nil {
		t.Fatal(err)
	}
	return mb, trace
}

// sealed seals and signs a copy of the trace as the agent and the provider.
func (p parties) sealed(t *testing.T, tr map[string]any) []byte {
	t.Helper()
	tr = deepCopy(t, tr)
	delete(tr, "seal")
	if err := Seal(tr, time.Date(2026, 11, 3, 10, 1, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	for _, s := range []Signer{p.agent, p.provider} {
		if err := SignSeal(tr, s); err != nil {
			t.Fatal(err)
		}
	}
	b, err := canon.Serialize(tr)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestAppendSignedConfirmation(t *testing.T) {
	ctx := context.Background()
	p := newParties(t, sign.EdDSA)

	t.Run("a round trip passes under the policy", func(t *testing.T) {
		mandate, tr := p.build(t)
		r, err := Check(ctx, mandate, p.sealed(t, tr), p.keys)
		if err != nil || !r.Pass() || len(r.SignedConfirmations) != 1 || r.SignedConfirmations[0].Seq != 3 {
			t.Fatalf("%v %+v", err, r)
		}
		if hasNotChecked(r, 9, "did not sign the seal") {
			t.Fatalf("a signed yes is noted as the agent's claim: %+v", r.NotChecked)
		}
	})

	good := func() map[string]any {
		return map[string]any{"at": "2026-11-03T10:00:30Z", "type": "human_confirmation", "actor": "principal", "payload": map[string]any{
			"method": "passkey", "decision": "approved", "shown_summary_hash": HashText("s"), "quote_id": "q1",
			"amount": map[string]any{"amount": "12.00", "currency": "GBP"},
		}}
	}
	_, base := p.build(t)
	base["events"] = base["events"].([]any)[:3]
	delete(base, "seal")
	someSig := map[string]any{"alg": "EdDSA", "key_id": p.principal.KeyID, "value": "a..b"}

	t.Run("refusals", func(t *testing.T) {
		wrongActor := good()
		wrongActor["actor"] = "agent"
		wrongType := good()
		wrongType["type"] = "selection_made"
		noQuote := good()
		delete(noQuote["payload"].(map[string]any), "quote_id")
		noAmount := good()
		delete(noAmount["payload"].(map[string]any), "amount")
		noSummary := good()
		delete(noSummary["payload"].(map[string]any), "shown_summary_hash")
		for name, ev := range map[string]map[string]any{
			"actor not the principal": wrongActor, "not a human_confirmation": wrongType,
			"no quote_id": noQuote, "no amount": noAmount, "no shown_summary_hash": noSummary,
		} {
			if err := AppendSignedConfirmation(deepCopy(t, base), ev, someSig); err == nil {
				t.Errorf("%s: appended", name)
			}
		}
		if err := AppendSignedConfirmation(deepCopy(t, base), good(), map[string]any{"alg": "EdDSA"}); err == nil {
			t.Error("a signature with no key_id or value was appended")
		}
		noID := deepCopy(t, base)
		delete(noID, "trace_id")
		if _, err := ConfirmationPayload(noID, good()["payload"].(map[string]any)); err == nil {
			t.Error("a payload was made for a trace with no trace_id")
		}
		noHash := deepCopy(t, base)
		delete(noHash["mandate_ref"].(map[string]any), "mandate_hash")
		if _, err := ConfirmationPayload(noHash, good()["payload"].(map[string]any)); err == nil {
			t.Error("a payload was made for a trace with no mandate_hash")
		}
		sealed := deepCopy(t, base)
		sealed["seal"] = map[string]any{}
		if err := AppendSignedConfirmation(sealed, good(), someSig); err == nil {
			t.Error("appended to a sealed trace")
		}
	})

	t.Run("a refusal leaves the caller's event as it was", func(t *testing.T) {
		sealed := deepCopy(t, base)
		sealed["seal"] = map[string]any{}
		ev := good()
		before, err := canon.Serialize(ev)
		if err != nil {
			t.Fatal(err)
		}
		if err := AppendSignedConfirmation(sealed, ev, someSig); err == nil {
			t.Fatal("appended to a sealed trace")
		}
		after, _ := canon.Serialize(ev)
		if string(before) != string(after) {
			t.Fatalf("the event was changed by a refused append:\n%s\n%s", before, after)
		}
		// And a successful append leaves the trace holding the caller's own event.
		ok := good()
		tr := deepCopy(t, base)
		if err := AppendSignedConfirmation(tr, ok, someSig); err != nil {
			t.Fatal(err)
		}
		events := tr["events"].([]any)
		last := events[len(events)-1].(map[string]any)
		if _, signed := ok["payload"].(map[string]any)["principal_signature"]; !signed || ok["hash"] == nil || last["hash"] != ok["hash"] {
			t.Fatalf("the appended event is not the caller's: %v", ok)
		}
	})

	t.Run("only the principal signs", func(t *testing.T) {
		b, err := ConfirmationPayload(base, good()["payload"].(map[string]any))
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range []Signer{p.agent, p.provider} {
			if _, err := SignConfirmation(b, s); err == nil {
				t.Errorf("a %s signed a confirmation", s.Role)
			}
		}
	})
}

func TestConfirmation_ES256Malleated(t *testing.T) {
	ctx := context.Background()
	p := newParties(t, sign.ES256)
	mandate, tr := p.build(t)
	original := p.sealed(t, tr)

	// (r, n-s) is a second valid ES256 signature over the same bytes. The ref hashes the signed
	// bytes, not the signature, so it does not move; the event hash does, because it covers the signature.
	mal := deepCopy(t, tr)
	yes := mal["events"].([]any)[3].(map[string]any)
	sig := yes["payload"].(map[string]any)["principal_signature"].(map[string]any)
	parts := strings.Split(sig["value"].(string), ".")
	raw, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(raw) != 64 {
		t.Fatalf("%v %d", err, len(raw))
	}
	n := elliptic.P256().Params().N
	s := new(big.Int).Sub(n, new(big.Int).SetBytes(raw[32:]))
	s.FillBytes(raw[32:])
	sig["value"] = parts[0] + ".." + base64.RawURLEncoding.EncodeToString(raw)
	events := mal["events"].([]any)
	prev := mal["mandate_ref"].(map[string]any)["mandate_hash"]
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
	malleated := p.sealed(t, mal)

	var refs, hashes []string
	for _, trace := range [][]byte{original, malleated} {
		r, err := Check(ctx, mandate, trace, p.keys)
		if err != nil || !r.Pass() || len(r.SignedConfirmations) != 1 {
			t.Fatalf("both signatures should verify: %v %+v", err, r)
		}
		refs = append(refs, r.SignedConfirmations[0].Ref)
		hashes = append(hashes, parse(t, trace)["events"].([]any)[3].(map[string]any)["hash"].(string))
	}
	if refs[0] != refs[1] {
		t.Errorf("malleating the signature moved the ref: %v", refs)
	}
	if hashes[0] == hashes[1] {
		t.Error("the event hash did not change")
	}
}
