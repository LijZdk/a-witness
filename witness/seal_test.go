package witness

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/LijZdk/a-witness/witness/canon"
	"github.com/LijZdk/a-witness/witness/sign"
)

func rule15(problems []Problem) []string {
	var out []string
	for _, p := range problems {
		if p.Rule == 15 {
			out = append(out, p.Message)
		}
	}
	return out
}

func TestSignatures(t *testing.T) {
	ctx := context.Background()
	keys := exampleTrust(t)
	home := "home-insurance-switch"
	mandate := readFile(t, "examples", home+".mandate.json")

	t.Run("a changed journey status is caught: the seal covers the whole trace", func(t *testing.T) {
		trace := edit(t, home, false, func(tr map[string]any, _ []any) {
			tr["journey"].(map[string]any)["status"] = "failed"
		})
		problems, err := Verify(ctx, mandate, trace, keys)
		if err != nil {
			t.Fatal(err)
		}
		if len(problems) != len(rule15(problems)) {
			t.Fatalf("only signatures should object, got %v", problems)
		}
		got := strings.Join(rule15(problems), "\n")
		for _, want := range []string{"seal signature 0 (agent) does not verify", "seal signature 1 (provider) does not verify", "no valid signature from the agent"} {
			if !strings.Contains(got, want) {
				t.Errorf("missing %q in:\n%s", want, got)
			}
		}
	})

	t.Run("a fully re-hashed rewrite is caught by the signatures", func(t *testing.T) {
		trace := edit(t, home, true, func(_ map[string]any, e []any) {
			payload(e, 2)["price"].(map[string]any)["amount"] = "198.00"
		})
		problems, err := Verify(ctx, mandate, trace, keys)
		if err != nil {
			t.Fatal(err)
		}
		if len(problems) == 0 || len(problems) != len(rule15(problems)) {
			t.Fatalf("want only signature problems, got %v", problems)
		}
	})

	t.Run("an edited mandate breaks its signature and its link to the trace", func(t *testing.T) {
		m := parse(t, mandate)
		m["limits"].(map[string]any)["max_transactions"] = float64(5)
		b, _ := canon.Serialize(m)
		problems, err := Verify(ctx, b, readFile(t, "examples", home+".trace.json"), keys)
		if err != nil {
			t.Fatal(err)
		}
		// Changed by AW-32: a bad mandate signature now also stops the seal
		// signatures from being checked, and says so (M4).
		if got := rule15(problems); len(got) != 2 || !strings.Contains(got[0], "mandate signature does not verify") || !strings.HasPrefix(got[1], "seal signatures were not checked") {
			t.Fatalf("got %v", problems)
		}
	})

	t.Run("unknown keys are reported, not trusted", func(t *testing.T) {
		empty := &Trust{Principal: sign.KeySet{}, Provider: sign.KeySet{}, Agent: sign.KeySet{}}
		problems, err := Verify(ctx, mandate, readFile(t, "examples", home+".trace.json"), empty)
		if err != nil {
			t.Fatal(err)
		}
		// Changed by AW-32: the unknown principal key is one problem, then M4.
		if got := rule15(problems); len(got) != 2 || !strings.Contains(got[0], "is not trusted for the principal") {
			t.Fatalf("got %v", got)
		}
		// With the principal known, the unknown agent and provider keys are reported too.
		partial := &Trust{Principal: keys.Principal, Provider: sign.KeySet{}, Agent: sign.KeySet{}}
		problems, err = Verify(ctx, mandate, readFile(t, "examples", home+".trace.json"), partial)
		if err != nil {
			t.Fatal(err)
		}
		got := strings.Join(rule15(problems), "\n")
		for _, want := range []string{"could not be found", "is not trusted for the provider", "no valid signature from a provider"} {
			if !strings.Contains(got, want) {
				t.Errorf("missing %q in:\n%s", want, got)
			}
		}
	})

	t.Run("a seal signed by the provider's key posing as the agent", func(t *testing.T) {
		trace := parse(t, readFile(t, "examples", home+".trace.json"))
		sigs := trace["seal"].(map[string]any)["signatures"].([]any)
		provider := sigs[1].(map[string]any)
		sigs[0] = map[string]any{"signer": "agent", "alg": provider["alg"], "key_id": provider["key_id"], "value": provider["value"]}
		b, _ := canon.Serialize(trace)
		problems, err := Verify(ctx, mandate, b, keys)
		if err != nil {
			t.Fatal(err)
		}
		got := strings.Join(rule15(problems), "\n")
		if !strings.Contains(got, "but the mandate names the agent's key") || !strings.Contains(got, "no valid signature from the agent") {
			t.Fatalf("got %v", problems)
		}
	})

	t.Run("no key resolver is an error, not a silent skip", func(t *testing.T) {
		if _, err := Verify(ctx, mandate, readFile(t, "examples", home+".trace.json"), nil); err == nil {
			t.Fatal("Verify ran without keys")
		}
	})
}

// TestBuildAndVerify makes a trace from nothing with the producer API, using
// one key of each algorithm, and checks it verifies.
func TestBuildAndVerify(t *testing.T) {
	ctx := context.Background()
	_, principalKey, _ := ed25519.GenerateKey(rand.Reader)
	agentKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, providerKey, _ := ed25519.GenerateKey(rand.Reader)
	principal := Signer{Alg: sign.EdDSA, KeyID: "https://wallet.test/jwks.json#p", Key: principalKey}
	agent := Signer{Role: "agent", Alg: sign.ES256, KeyID: "https://agent.test/jwks.json#a", Key: agentKey}
	provider := Signer{Role: "provider", Alg: sign.EdDSA, KeyID: "https://provider.test/jwks.json#s", Key: providerKey}
	keys := &Trust{
		Principal: sign.KeySet{principal.KeyID: principalKey.Public()},
		Provider:  sign.KeySet{provider.KeyID: providerKey.Public()},
		Agent:     sign.KeySet{agent.KeyID: agentKey.Public()},
	}

	mandate := map[string]any{
		"spec_version": "0.1",
		"mandate_id":   "mdt_builtByGoTest01",
		"agent":        map[string]any{"agent_id": "agt_test", "operator": "Test Ltd", "public_key_ref": agent.KeyID},
	}
	if err := SignMandate(mandate, principal); err != nil {
		t.Fatal(err)
	}
	mHash, err := MandateHash(mandate)
	if err != nil {
		t.Fatal(err)
	}
	trace := map[string]any{
		"spec_version": "0.1",
		"trace_id":     "trc_builtByGoTest01",
		"mandate_ref":  map[string]any{"mandate_id": "mdt_builtByGoTest01", "mandate_hash": mHash},
		"journey":      map[string]any{"action": "quote", "product_class": "pet_insurance", "started_at": "2026-11-03T10:00:00Z"},
	}
	for i, ev := range []map[string]any{
		{"at": "2026-11-03T10:00:00Z", "type": "intent_captured", "actor": "agent", "payload": map[string]any{"summary": "Quote for pet cover."}},
		{"at": "2026-11-03T10:00:04Z", "type": "quote_received", "actor": "provider", "payload": map[string]any{"quote_id": "q1", "provider_id": "p", "product_id": "pet", "price": map[string]any{"amount": "12.00", "currency": "GBP"}, "term_months": 12}},
		{"at": "2026-11-03T10:00:09Z", "type": "selection_made", "actor": "agent", "payload": map[string]any{"quote_id": "q1", "rationale": "Only quote."}},
	} {
		if err := AppendEvent(trace, ev); err != nil {
			t.Fatalf("event %d: %v", i, err)
		}
	}
	if err := Seal(trace, time.Date(2026, 11, 3, 10, 0, 10, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	for _, s := range []Signer{agent, provider} {
		if err := SignSeal(trace, s); err != nil {
			t.Fatal(err)
		}
	}
	if err := AppendEvent(trace, map[string]any{}); err == nil {
		t.Fatal("AppendEvent accepted an event after sealing")
	}

	mb, _ := canon.Serialize(mandate)
	tb, _ := canon.Serialize(trace)
	problems, err := Verify(ctx, mb, tb, keys)
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) > 0 {
		t.Fatalf("a freshly built trace has problems: %v", problems)
	}
}
