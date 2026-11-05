package witness

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/LijZdk/a-witness/witness/canon"
	"github.com/LijZdk/a-witness/witness/sign"
)

// The example keys are derived from public strings (scripts/jws.py,
// example_key), and the ids are those of scripts/make_examples.py, KEY_IDS.
var exampleKeyIDs = map[string]string{
	"sam":         "https://wallet.example/.well-known/jwks.json#prn_a91f0c3e",
	"jo":          "https://wallet.example/.well-known/jwks.json#prn_5d2e7b14",
	"home-helper": "https://agent.example/.well-known/jwks.json#home-helper",
	"save-wise":   "https://agent.example/.well-known/jwks.json#save-wise",
	"newco":       "https://newco.example/.well-known/jwks.json#seal-2026",
	"steadybank":  "https://steadybank.example/.well-known/jwks.json#seal-2026",
}

func exampleKey(holder string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("a-witness example key: " + holder))
	return ed25519.NewKeyFromSeed(seed[:])
}

// exampleSigner signs as holder, with the given seal role.
func exampleSigner(holder, role string) Signer {
	return Signer{Role: role, Alg: sign.EdDSA, KeyID: exampleKeyIDs[holder], Key: exampleKey(holder)}
}

const home = "home-insurance-switch"

// reseal replaces the seal's signatures with the given ones, as a forger who
// holds only those keys would.
func reseal(t *testing.T, trace []byte, signers ...Signer) []byte {
	t.Helper()
	doc := parse(t, trace)
	doc["seal"].(map[string]any)["signatures"] = []any{}
	for _, s := range signers {
		if err := SignSeal(doc, s); err != nil {
			t.Fatal(err)
		}
	}
	b, err := canon.Serialize(doc)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// resignMandate signs a copy of the mandate with holder's key. The signature
// is outside the mandate hash, so the trace still names the mandate.
func resignMandate(t *testing.T, mandate []byte, holder string) []byte {
	t.Helper()
	m := parse(t, mandate)
	if err := SignMandate(m, exampleSigner(holder, "")); err != nil {
		t.Fatal(err)
	}
	b, err := canon.Serialize(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// rebuild changes the mandate, signs it as signer, chains the home trace to the
// new mandate and seals it with the given signers.
func rebuild(t *testing.T, change func(m map[string]any), signer string, sealers ...Signer) (mandate, trace []byte) {
	t.Helper()
	m := parse(t, readFile(t, "examples", home+".mandate.json"))
	change(m)
	if err := SignMandate(m, exampleSigner(signer, "")); err != nil {
		t.Fatal(err)
	}
	h, err := MandateHash(m)
	if err != nil {
		t.Fatal(err)
	}
	trace = edit(t, home, true, func(tr map[string]any, _ []any) {
		tr["mandate_ref"].(map[string]any)["mandate_hash"] = h
	})
	if mandate, err = canon.Serialize(m); err != nil {
		t.Fatal(err)
	}
	return mandate, reseal(t, trace, sealers...)
}

func exampleMandateAndTrace(t *testing.T) (mandate, trace []byte) {
	t.Helper()
	return readFile(t, "examples", home+".mandate.json"), readFile(t, "examples", home+".trace.json")
}

// sigProblems runs Verify and returns the rule 15 messages, requiring that
// nothing else objects.
func sigProblems(t *testing.T, mandate, trace []byte, trust *Trust) []string {
	t.Helper()
	problems, err := Verify(context.Background(), mandate, trace, trust)
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) != len(rule15(problems)) {
		t.Fatalf("only signatures should object, got %v", problems)
	}
	return rule15(problems)
}

func mustHave(t *testing.T, got []string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !slices.Contains(got, w) {
			t.Errorf("missing %q in:\n  %s", w, strings.Join(got, "\n  "))
		}
	}
}

func golden(t *testing.T, name string) string {
	t.Helper()
	return strings.TrimSpace(string(readFile(t, "testdata", "golden", name)))
}

const (
	msgNoProvider  = "the seal has no valid signature from a provider"
	msgNoAgent     = "the seal has no valid signature from the agent the mandate names"
	msgNoPrincipal = "the seal has no valid signature from the principal who signed the mandate"
	msgM4          = "seal signatures were not checked, because the mandate signature is not valid"
)

func m1(keyID string) string {
	return "mandate signature: key '" + keyID + "' is not trusted for the principal"
}

// The attack AW-32 closes: rewrite event 10 (the amount committed), re-hash
// the chain, and seal with the agent's key alone. Rule 15 used to accept one
// valid agent signature.
func TestAgentOnlyRewriteRefused(t *testing.T) {
	mandate, _ := exampleMandateAndTrace(t)
	trace := edit(t, home, true, func(_ map[string]any, e []any) {
		payload(e, 10)["amount_committed"].(map[string]any)["amount"] = "198.00"
	})
	trace = reseal(t, trace, exampleSigner("home-helper", "agent"))
	trust := exampleTrust(t)

	got := sigProblems(t, mandate, trace, trust)
	if want := []string{msgNoProvider}; !slices.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
	if golden(t, "rule15.no-provider.txt") != msgNoProvider {
		t.Fatal("the golden file scripts/check.sh reads differs from the message")
	}
	r, err := Check(context.Background(), mandate, trace, trust)
	if err != nil || r.Pass() || r.Signatures == SignaturesValid || len(r.Integrity) != 1 {
		t.Fatalf("Check passed or missed it: %v %+v", err, r)
	}
}

func TestMandateResignedByAgentOrProviderRefused(t *testing.T) {
	mandate, trace := exampleMandateAndTrace(t)
	trust := exampleTrust(t)
	for _, holder := range []string{"home-helper", "newco"} {
		got := sigProblems(t, resignMandate(t, mandate, holder), trace, trust)
		if want := []string{m1(exampleKeyIDs[holder]), msgM4}; !slices.Equal(got, want) {
			t.Errorf("%s: got %q, want %q", holder, got, want)
		}
	}
	// The principal's own re-signature is the same bytes and passes.
	if got := sigProblems(t, resignMandate(t, mandate, "sam"), trace, trust); len(got) != 0 {
		t.Errorf("sam re-signing his own mandate: %q", got)
	}
	if golden(t, "rule15.mandate-agent-key.txt") != m1(exampleKeyIDs["home-helper"]) {
		t.Fatal("the golden file scripts/check.sh reads differs from the message")
	}
}

func TestAgentOrPrincipalKeyAsProviderRefused(t *testing.T) {
	mandate, trace := exampleMandateAndTrace(t)
	trust := exampleTrust(t)
	for _, holder := range []string{"home-helper", "sam"} {
		forged := reseal(t, trace, exampleSigner("home-helper", "agent"), exampleSigner(holder, "provider"))
		got := sigProblems(t, mandate, forged, trust)
		want := []string{"seal signature 1 (provider): key '" + exampleKeyIDs[holder] + "' is not trusted for the provider", msgNoProvider}
		if !slices.Equal(got, want) {
			t.Errorf("%s: got %q, want %q", holder, got, want)
		}
	}
}

func TestMissingProviderSignatureRefused(t *testing.T) {
	mandate, trace := exampleMandateAndTrace(t)
	got := sigProblems(t, mandate, reseal(t, trace, exampleSigner("home-helper", "agent")), exampleTrust(t))
	if want := []string{msgNoProvider}; !slices.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
	// And a missing agent signature is refused as before.
	got = sigProblems(t, mandate, reseal(t, trace, exampleSigner("newco", "provider")), exampleTrust(t))
	if want := []string{msgNoAgent}; !slices.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func merge(sets ...sign.KeySet) sign.KeySet {
	out := sign.KeySet{}
	for _, s := range sets {
		for k, v := range s {
			out[k] = v
		}
	}
	return out
}

func TestKeyInTwoRoleSets(t *testing.T) {
	mandate, trace := exampleMandateAndTrace(t)
	trust := exampleTrust(t)
	helper := exampleKeyIDs["home-helper"]

	t.Run("the agent's key also trusted for the provider (M7)", func(t *testing.T) {
		both := &Trust{Principal: trust.Principal, Agent: trust.Agent,
			Provider: merge(trust.Provider.(sign.KeySet), sign.KeySet{helper: exampleKey("home-helper").Public()})}
		mustHave(t, sigProblems(t, mandate, trace, both),
			"the agent's key '"+helper+"' is also trusted for the provider",
			msgNoAgent)
	})
	t.Run("the agent's key also trusted for the principal (M7)", func(t *testing.T) {
		both := &Trust{Provider: trust.Provider, Agent: trust.Agent,
			Principal: merge(trust.Principal.(sign.KeySet), sign.KeySet{helper: exampleKey("home-helper").Public()})}
		mustHave(t, sigProblems(t, mandate, trace, both),
			"the agent's key '"+helper+"' is also trusted for the principal")
	})
	t.Run("one combined set in every slot fails closed (M2)", func(t *testing.T) {
		all := merge(trust.Principal.(sign.KeySet), trust.Provider.(sign.KeySet), trust.Agent.(sign.KeySet))
		got := sigProblems(t, mandate, trace, &Trust{Principal: all, Provider: all, Agent: all})
		mustHave(t, got, "mandate signature: key '"+exampleKeyIDs["sam"]+"' is also trusted for the provider", msgM4)
	})
	t.Run("a provider key also trusted for the principal (S2)", func(t *testing.T) {
		both := &Trust{Provider: trust.Provider, Agent: trust.Agent,
			Principal: merge(trust.Principal.(sign.KeySet), sign.KeySet{exampleKeyIDs["newco"]: exampleKey("newco").Public()})}
		mustHave(t, sigProblems(t, mandate, trace, both),
			"seal signature 1 (provider): key '"+exampleKeyIDs["newco"]+"' is also trusted for the principal",
			msgNoProvider)
	})
}

// A key trusted under two ids is one key. Decided on the key bytes, not the id.
func TestSameKeyBytesTwoKids(t *testing.T) {
	mandate, trace := exampleMandateAndTrace(t)
	trust := exampleTrust(t)
	const alias = "https://alias.example/jwks.json#alias"

	for _, c := range []struct{ holder, wantSame string }{
		{"home-helper", "agent"},
		{"sam", "mandate signature"},
	} {
		provider := merge(trust.Provider.(sign.KeySet), sign.KeySet{alias: exampleKey(c.holder).Public()})
		forger := Signer{Role: "provider", Alg: sign.EdDSA, KeyID: alias, Key: exampleKey(c.holder)}
		forged := reseal(t, trace, exampleSigner("home-helper", "agent"), forger)
		got := sigProblems(t, mandate, forged, &Trust{Principal: trust.Principal, Provider: provider, Agent: trust.Agent})
		mustHave(t, got, "seal signature 1 (provider) uses the same key as the "+c.wantSame, msgNoProvider)
	}
}

func TestAgentRefIsMandateKey(t *testing.T) {
	const alias = "https://agent.example/.well-known/jwks.json#alias"
	mandate, trace := rebuild(t, func(m map[string]any) {
		m["agent"].(map[string]any)["public_key_ref"] = alias
	}, "sam", exampleSigner("home-helper", "agent"), exampleSigner("newco", "provider"))
	trust := exampleTrust(t)
	// The agent's resolver knows the alias, but it is the principal's key.
	trust = &Trust{Principal: trust.Principal, Provider: trust.Provider, Agent: sign.KeySet{alias: exampleKey("sam").Public()}}
	mustHave(t, sigProblems(t, mandate, trace, trust),
		"the agent's key '"+alias+"' is the key that signed the mandate", msgNoAgent)
}

func TestNoPublicKeyRef(t *testing.T) {
	mandate, trace := rebuild(t, func(m map[string]any) {
		delete(m["agent"].(map[string]any), "public_key_ref")
	}, "sam", exampleSigner("home-helper", "agent"), exampleSigner("newco", "provider"))
	got := sigProblems(t, mandate, trace, exampleTrust(t))
	if want := []string{"the mandate names no agent key (agent.public_key_ref)", msgNoAgent}; !slices.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestUnknownAgentKey(t *testing.T) {
	mandate, trace := exampleMandateAndTrace(t)
	trust := exampleTrust(t)
	got := sigProblems(t, mandate, trace, &Trust{Principal: trust.Principal, Provider: trust.Provider, Agent: sign.KeySet{}})
	want := []string{"the agent's key '" + exampleKeyIDs["home-helper"] + "' could not be found", msgNoAgent}
	if !slices.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestPrincipalSeal(t *testing.T) {
	ctx := context.Background()
	mandate, trace := exampleMandateAndTrace(t)
	trust := exampleTrust(t)
	required := &Trust{Principal: trust.Principal, Provider: trust.Provider, Agent: trust.Agent, RequirePrincipalSeal: true}
	signers := func(extra ...Signer) []Signer {
		return append([]Signer{exampleSigner("home-helper", "agent"), exampleSigner("newco", "provider")}, extra...)
	}

	t.Run("required, and absent (R3)", func(t *testing.T) {
		got := sigProblems(t, mandate, trace, required)
		if want := []string{msgNoPrincipal}; !slices.Equal(got, want) {
			t.Fatalf("got %q, want %q", got, want)
		}
		if got := sigProblems(t, mandate, trace, trust); len(got) != 0 {
			t.Fatalf("not required, but refused: %q", got)
		}
	})
	t.Run("signed by the principal who signed the mandate", func(t *testing.T) {
		cosigned := reseal(t, trace, signers(exampleSigner("sam", "principal"))...)
		if got := sigProblems(t, mandate, cosigned, required); len(got) != 0 {
			t.Fatalf("got %q", got)
		}
		r, err := Check(ctx, mandate, cosigned, required)
		if err != nil || !r.Pass() || hasNotChecked(r, 9, "did not sign the seal") {
			t.Fatalf("want a pass that does not note the yes as the agent's: %v %+v", err, r)
		}
	})
	t.Run("signed by another principal (S4)", func(t *testing.T) {
		forged := reseal(t, trace, signers(exampleSigner("jo", "principal"))...)
		got := sigProblems(t, mandate, forged, required)
		want := []string{"seal signature 2 (principal) uses key '" + exampleKeyIDs["jo"] + "', but the mandate was signed with '" + exampleKeyIDs["sam"] + "'", msgNoPrincipal}
		if !slices.Equal(got, want) {
			t.Fatalf("got %q, want %q", got, want)
		}
	})
	t.Run("a principal signature that does not verify", func(t *testing.T) {
		cosigned := parse(t, reseal(t, trace, signers(exampleSigner("sam", "principal"))...))
		sigs := cosigned["seal"].(map[string]any)["signatures"].([]any)
		sigs[2].(map[string]any)["value"] = sigs[0].(map[string]any)["value"] // the agent's signature
		b, _ := canon.Serialize(cosigned)
		got := sigProblems(t, mandate, b, required)
		mustHave(t, got, msgNoPrincipal)
		if len(got) != 2 || !strings.HasPrefix(got[0], "seal signature 2 (principal) does not verify") {
			t.Fatalf("got %q", got)
		}
	})
}

func TestWitnessServiceRefused(t *testing.T) {
	mandate, trace := exampleMandateAndTrace(t)
	extra := reseal(t, trace, exampleSigner("home-helper", "agent"), exampleSigner("newco", "provider"), exampleSigner("newco", "witness_service"))
	got := sigProblems(t, mandate, extra, exampleTrust(t))
	if want := []string{"seal signature 2 (witness_service): this verifier trusts no keys for that signer"}; !slices.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// countingResolver counts lookups.
type countingResolver struct {
	sign.Resolver
	calls int
}

func (c *countingResolver) PublicKey(ctx context.Context, id string) (crypto.PublicKey, error) {
	c.calls++
	return c.Resolver.PublicKey(ctx, id)
}

func TestNoAgentLookupWhenMandateInvalid(t *testing.T) {
	mandate, trace := exampleMandateAndTrace(t)
	trust := exampleTrust(t)
	agent := &countingResolver{Resolver: trust.Agent}
	counted := &Trust{Principal: trust.Principal, Provider: trust.Provider, Agent: agent}

	got := sigProblems(t, resignMandate(t, mandate, "home-helper"), trace, counted)
	mustHave(t, got, msgM4)
	if agent.calls != 0 {
		t.Fatalf("the Agent resolver was asked %d times about a mandate the principal did not sign", agent.calls)
	}
	if got := sigProblems(t, mandate, trace, counted); len(got) != 0 || agent.calls == 0 {
		t.Fatalf("a genuine record: %q, %d agent lookups", got, agent.calls)
	}
}

func TestIncompleteTrustIsError(t *testing.T) {
	ctx := context.Background()
	mandate, trace := exampleMandateAndTrace(t)
	full := exampleTrust(t)
	for name, trust := range map[string]*Trust{
		"nil":           nil,
		"empty":         {},
		"no principal":  {Provider: full.Provider, Agent: full.Agent},
		"no provider":   {Principal: full.Principal, Agent: full.Agent},
		"no agent":      {Principal: full.Principal, Provider: full.Provider},
		"only the flag": {RequirePrincipalSeal: true},
	} {
		if _, err := Verify(ctx, mandate, trace, trust); err == nil {
			t.Errorf("%s: Verify ran", name)
		}
		if r, err := Check(ctx, mandate, trace, trust); err == nil || r.Pass() {
			t.Errorf("%s: Check ran (%v)", name, err)
		}
	}
	if _, err := Verify(ctx, mandate, trace, nil); !errors.Is(err, errNoResolver) {
		t.Errorf("nil: %v", err)
	}
	if _, err := Verify(ctx, mandate, trace, &Trust{}); !errors.Is(err, errIncompleteTrust) {
		t.Errorf("empty: %v", err)
	}
	// SkipSignatures is the one Trust that needs no keys, and a copy of it is no different.
	copied := *SkipSignatures
	if _, err := Verify(ctx, mandate, trace, &copied); err != nil {
		t.Errorf("a copy of SkipSignatures: %v", err)
	}
}
