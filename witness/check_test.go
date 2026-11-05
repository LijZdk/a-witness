package witness

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/LijZdk/a-witness/witness/canon"
	"github.com/LijZdk/a-witness/witness/sign"
)

func hasNotChecked(r Report, rule int, fragment string) bool {
	return slices.ContainsFunc(r.NotChecked, func(n NotChecked) bool {
		return n.Rule == rule && strings.Contains(n.Reason, fragment)
	})
}

func checkExample(t *testing.T, name string, keys sign.Resolver) Report {
	t.Helper()
	r, err := Check(context.Background(), readFile(t, "examples", name+".mandate.json"), readFile(t, "examples", name+".trace.json"), keys)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestCheckExamples(t *testing.T) {
	keys := exampleKeys(t)

	for _, name := range []string{"home-insurance-switch", "fixed-rate-savings-switch"} {
		t.Run(name+" passes", func(t *testing.T) {
			r := checkExample(t, name, keys)
			if !r.Pass() {
				t.Fatalf("not a pass: %+v", r)
			}
			if len(r.Integrity) != 0 || len(r.Rules) != 0 || len(r.Warnings) != 0 || !r.RulesRan || r.Signatures != SignaturesValid {
				t.Fatalf("unexpected report: %+v", r)
			}
			// The examples are not signed by the principal, so the yes is the agent's claim.
			if !hasNotChecked(r, 9, "the principal did not sign the seal") {
				t.Errorf("the unsigned approval is not noted: %+v", r.NotChecked)
			}
			for _, rule := range []int{11, 12, 13} {
				if !hasNotChecked(r, rule, "") {
					t.Errorf("rule %d is not listed as unchecked: %+v", rule, r.NotChecked)
				}
			}
		})
	}

	t.Run("home-insurance-no-confirmation fails rule 9 with validate.py's finding", func(t *testing.T) {
		r := checkExample(t, "home-insurance-no-confirmation", keys)
		if r.Pass() {
			t.Fatal("passed")
		}
		if len(r.Integrity) != 0 || !r.RulesRan || r.Signatures != SignaturesValid {
			t.Fatalf("the record is intact and should say so: %+v", r)
		}
		// scripts/check.sh asserts that validate.py prints this same line.
		golden := strings.TrimSpace(string(readFile(t, "testdata", "golden", "no-confirmation.rule9.txt")))
		if len(r.Rules) != 1 || r.Rules[0].Rule != 9 || r.Rules[0].Seq != 11 || r.Rules[0].Message != golden {
			t.Fatalf("got %+v, want rule 9 at event 11: %s", r.Rules, golden)
		}
	})
}

func TestCheckPassNeedsEverything(t *testing.T) {
	if (Report{}).Pass() {
		t.Fatal("the zero Report passes")
	}
	valid := Report{RulesRan: true, Signatures: SignaturesValid}
	if !valid.Pass() {
		t.Fatal("a clean, signed, checked report does not pass")
	}
	withNotes := valid
	withNotes.Warnings = []Problem{{Rule: 14}}
	withNotes.NotChecked = []NotChecked{{Rule: 12}}
	if !withNotes.Pass() {
		t.Fatal("warnings and NotChecked must not stop a pass")
	}
	for name, mutate := range map[string]func(*Report){
		"rules did not run":  func(r *Report) { r.RulesRan = false },
		"integrity problem":  func(r *Report) { r.Integrity = []Problem{{Rule: 4}} },
		"rules finding":      func(r *Report) { r.Rules = []Problem{{Rule: 9}} },
		"signatures skipped": func(r *Report) { r.Signatures = SignaturesNotChecked },
	} {
		r := valid
		mutate(&r)
		if r.Pass() {
			t.Errorf("%s: passes", name)
		}
	}
}

func TestCheckWithoutSignaturesIsNeverAPass(t *testing.T) {
	// home-insurance-switch obeys its mandate, so only the skipped signatures stop the pass.
	r := checkExample(t, "home-insurance-switch", SkipSignatures)
	if r.Pass() {
		t.Fatal("an unsigned check passed")
	}
	if len(r.Integrity) != 0 || len(r.Rules) != 0 || !r.RulesRan {
		t.Fatalf("the rules should have run and found nothing: %+v", r)
	}
	if r.Signatures != SignaturesNotChecked || !hasNotChecked(r, 15, "signatures were not checked") {
		t.Fatalf("skipped signatures must be recorded: %+v", r)
	}
	if hasNotChecked(r, 9, "did not sign the seal") == false {
		t.Fatalf("without signatures the principal's yes is certainly unsigned: %+v", r.NotChecked)
	}
}

func TestCheckNilResolverIsAnError(t *testing.T) {
	if _, err := Check(context.Background(), readFile(t, "examples", "home-insurance-switch.mandate.json"), readFile(t, "examples", "home-insurance-switch.trace.json"), nil); err == nil {
		t.Fatal("Check ran without a key resolver")
	}
}

// A mandate rule is only meaningful on an intact record, so an integrity
// problem must stop the rules, even for a trace that would break rule 9.
func TestCheckRunsNoRulesOnARecordThatIsNotIntact(t *testing.T) {
	ctx := context.Background()
	name := "home-insurance-no-confirmation" // breaks rule 9 when intact
	mandate := readFile(t, "examples", name+".mandate.json")

	t.Run("an edited, not re-hashed trace", func(t *testing.T) {
		trace := edit(t, name, false, func(_ map[string]any, e []any) {
			e[11].(map[string]any)["at"] = "2026-10-02T11:45:21Z"
		})
		r, err := Check(ctx, mandate, trace, SkipSignatures)
		if err != nil {
			t.Fatal(err)
		}
		if len(r.Integrity) == 0 || r.Integrity[0].Rule != 4 {
			t.Fatalf("want a rule 4 integrity problem: %+v", r)
		}
		assertNoRules(t, r)
	})

	t.Run("a valid chain with a bad signature", func(t *testing.T) {
		trace := edit(t, name, true, func(_ map[string]any, e []any) {
			e[11].(map[string]any)["at"] = "2026-10-02T11:45:21Z"
		})
		// With signatures skipped the re-hashed chain is intact, and the rule 9 breach shows.
		skipped, err := Check(ctx, mandate, trace, SkipSignatures)
		if err != nil {
			t.Fatal(err)
		}
		if len(skipped.Integrity) != 0 || len(skipped.Rules) != 1 {
			t.Fatalf("the re-hashed chain should be intact and show rule 9: %+v", skipped)
		}
		// With the example keys the edit is caught by the seal signatures.
		r, err := Check(ctx, mandate, trace, exampleKeys(t))
		if err != nil {
			t.Fatal(err)
		}
		if len(rule15(r.Integrity)) == 0 || len(r.Integrity) != len(rule15(r.Integrity)) {
			t.Fatalf("want only rule 15 integrity problems: %+v", r.Integrity)
		}
		assertNoRules(t, r)
		if r.Signatures == SignaturesValid {
			t.Fatal("signatures reported valid")
		}
	})
}

func assertNoRules(t *testing.T, r Report) {
	t.Helper()
	if r.Rules != nil || r.RulesRan || r.Pass() {
		t.Fatalf("rules must not run on a record that is not intact: %+v", r)
	}
	if !hasNotChecked(r, 0, "record not intact; mandate rules not checked") {
		t.Fatalf("missing the not-intact note: %+v", r.NotChecked)
	}
}

// buildSigned makes a signed record from nothing with the producer API.
// principalSeal says who adds a seal signature with signer "principal": nobody (""),
// the principal's own mandate key ("mandate key"), or the agent's key posing as the
// principal ("agent key").
// Each tweak may change the events before they are chained and sealed.
func buildSigned(t *testing.T, confirmation, principalSeal string, tweaks ...func(events *[]map[string]any)) (mandate, trace []byte, keys sign.KeySet) {
	t.Helper()
	_, principalKey, _ := ed25519.GenerateKey(rand.Reader)
	_, agentKey, _ := ed25519.GenerateKey(rand.Reader)
	principal := Signer{Role: "principal", Alg: sign.EdDSA, KeyID: "https://wallet.test/jwks.json#p", Key: principalKey}
	agent := Signer{Role: "agent", Alg: sign.EdDSA, KeyID: "https://agent.test/jwks.json#a", Key: agentKey}
	keys = sign.KeySet{principal.KeyID: principalKey.Public(), agent.KeyID: agentKey.Public()}

	m := map[string]any{
		"spec_version":       "0.1",
		"mandate_id":         "mdt_builtByGoTest02",
		"agent":              map[string]any{"agent_id": "agt_test", "operator": "Test Ltd", "public_key_ref": agent.KeyID},
		"human_confirmation": confirmation,
		"scope": map[string]any{
			"product_classes": []any{"pet_insurance"},
			"allowed_actions": []any{"quote", "purchase"},
		},
		"validity": map[string]any{"not_before": "2026-11-01T00:00:00Z", "expires_at": "2026-12-01T00:00:00Z"},
	}
	if err := SignMandate(m, principal); err != nil {
		t.Fatal(err)
	}
	mHash, err := MandateHash(m)
	if err != nil {
		t.Fatal(err)
	}
	tr := map[string]any{
		"spec_version": "0.1",
		"trace_id":     "trc_builtByGoTest02",
		"mandate_ref":  map[string]any{"mandate_id": "mdt_builtByGoTest02", "mandate_hash": mHash},
		"journey":      map[string]any{"action": "purchase", "product_class": "pet_insurance", "started_at": "2026-11-03T10:00:00Z"},
	}
	events := []map[string]any{
		{"at": "2026-11-03T10:00:00Z", "type": "intent_captured", "actor": "agent", "payload": map[string]any{"summary": "Buy pet cover."}},
		{"at": "2026-11-03T10:00:04Z", "type": "quote_received", "actor": "provider", "payload": map[string]any{"quote_id": "q1", "provider_id": "p", "product_id": "pet", "term_months": 12}},
		{"at": "2026-11-03T10:00:09Z", "type": "selection_made", "actor": "agent", "payload": map[string]any{"quote_id": "q1", "rationale": "Only quote."}},
		{"at": "2026-11-03T10:00:30Z", "type": "human_confirmation", "actor": "principal", "payload": map[string]any{"method": "passkey", "decision": "approved"}},
		{"at": "2026-11-03T10:00:40Z", "type": "action_executed", "actor": "provider", "payload": map[string]any{"quote_id": "q1", "provider_reference": "R1", "amount_committed": map[string]any{"amount": "12.00", "currency": "GBP"}}},
	}
	for _, tweak := range tweaks {
		tweak(&events)
	}
	for i, ev := range events {
		if err := AppendEvent(tr, ev); err != nil {
			t.Fatalf("event %d: %v", i, err)
		}
	}
	if err := Seal(tr, time.Date(2026, 11, 3, 10, 1, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	signers := []Signer{agent}
	switch principalSeal {
	case "mandate key":
		signers = append(signers, principal)
	case "agent key":
		signers = append(signers, Signer{Role: "principal", Alg: agent.Alg, KeyID: agent.KeyID, Key: agentKey})
	}
	for _, s := range signers {
		if err := SignSeal(tr, s); err != nil {
			t.Fatal(err)
		}
	}
	mb, err := canon.Serialize(m)
	if err != nil {
		t.Fatal(err)
	}
	tb, err := canon.Serialize(tr)
	if err != nil {
		t.Fatal(err)
	}
	return mb, tb, keys
}

func TestCheckPrincipalSignatureAndWarnings(t *testing.T) {
	ctx := context.Background()

	t.Run("a seal the principal signed vouches for the yes", func(t *testing.T) {
		m, tr, keys := buildSigned(t, "always", "mandate key")
		r, err := Check(ctx, m, tr, keys)
		if err != nil {
			t.Fatal(err)
		}
		if !r.Pass() || hasNotChecked(r, 9, "did not sign the seal") {
			t.Fatalf("want a pass with no unsigned-yes note: %+v", r)
		}
	})

	t.Run("a seal the principal did not sign leaves the yes as the agent's claim", func(t *testing.T) {
		m, tr, keys := buildSigned(t, "always", "")
		r, err := Check(ctx, m, tr, keys)
		if err != nil {
			t.Fatal(err)
		}
		if !r.Pass() || !hasNotChecked(r, 9, "did not sign the seal") {
			t.Fatalf("want a pass that notes the unsigned yes: %+v", r)
		}
	})

	t.Run("the agent's key posing as the principal does not vouch for the yes", func(t *testing.T) {
		m, tr, keys := buildSigned(t, "always", "agent key")
		r, err := Check(ctx, m, tr, keys)
		if err != nil {
			t.Fatal(err)
		}
		if len(r.Integrity) != 0 || !r.RulesRan {
			t.Fatalf("the record is genuine, so the rules should run: %+v", r)
		}
		if !hasNotChecked(r, 9, "did not sign the seal") {
			t.Fatalf("a principal-labelled signature made with the agent's key hid the unsigned-yes note: %+v", r.NotChecked)
		}
	})

	t.Run("a purchase renamed to an unknown event type is an error, not a pass", func(t *testing.T) {
		// No approval, and the purchase is no longer called action_executed, so
		// rule 9 would never see it. The record is otherwise genuine and signed.
		m, tr, keys := buildSigned(t, "always", "mandate key", func(evs *[]map[string]any) {
			list := *evs
			list[4]["type"] = "action_executed_v2"
			*evs = append(list[:3], list[4:]...)
		})
		r, err := Check(ctx, m, tr, keys)
		if err == nil {
			t.Fatalf("no error; Pass() = %v, report %+v", r.Pass(), r)
		}
		if r.Pass() {
			t.Fatal("a partial report on error passes")
		}
	})

	t.Run("an unknown actor is an error", func(t *testing.T) {
		m, tr, keys := buildSigned(t, "always", "mandate key", func(evs *[]map[string]any) {
			(*evs)[3]["actor"] = "guardian"
		})
		if r, err := Check(ctx, m, tr, keys); err == nil {
			t.Fatalf("no error: %+v", r)
		}
	})

	t.Run("every Report says the JSON Schemas were not checked", func(t *testing.T) {
		m, tr, keys := buildSigned(t, "always", "mandate key")
		r, err := Check(ctx, m, tr, keys)
		if err != nil || !hasNotChecked(r, 0, "JSON Schema conformance was not checked") {
			t.Fatalf("%v %+v", err, r)
		}
		r, err = Check(ctx, readFile(t, "examples", "home-insurance-switch.mandate.json"), edit(t, "home-insurance-switch", false, func(map[string]any, []any) {}), SkipSignatures)
		if err != nil || !hasNotChecked(r, 0, "JSON Schema conformance was not checked") {
			t.Fatalf("%v %+v", err, r)
		}
	})

	t.Run(`"never" is a warning and does not fail`, func(t *testing.T) {
		m, tr, keys := buildSigned(t, "never", "mandate key")
		r, err := Check(ctx, m, tr, keys)
		if err != nil {
			t.Fatal(err)
		}
		if !r.Pass() || len(r.Warnings) != 1 || r.Warnings[0].Rule != 14 || len(r.Rules) != 0 {
			t.Fatalf("want a pass with one rule 14 warning: %+v", r)
		}
	})

	t.Run(`"sometimes" is an error`, func(t *testing.T) {
		// The mandate is signed, but its human_confirmation is not a value the schema
		// allows. Skip signatures so that only the unreadable value can object.
		m, tr, _ := buildSigned(t, "sometimes", "mandate key")
		if r, err := Check(ctx, m, tr, SkipSignatures); err == nil {
			t.Fatalf("no error: %+v", r)
		}
	})
}

// Check must never panic, whatever it is given.
func FuzzCheck(f *testing.F) {
	for _, name := range examples {
		f.Add(readFileF(f, "examples", name+".mandate.json"), readFileF(f, "examples", name+".trace.json"))
	}
	f.Add([]byte(`{}`), []byte(`{}`))
	f.Add([]byte(`[]`), []byte(`null`))
	keys, err := sign.ParseJWKS(readFileF(f, "examples", "keys.jwks.json"))
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, mandate, trace []byte) {
		_, _ = Check(context.Background(), mandate, trace, SkipSignatures)
		_, _ = Check(context.Background(), mandate, trace, keys)
	})
}

func readFileF(f *testing.F, parts ...string) []byte {
	f.Helper()
	b, err := os.ReadFile(filepath.Join(append([]string{".."}, parts...)...))
	if err != nil {
		f.Fatal(err)
	}
	return b
}
