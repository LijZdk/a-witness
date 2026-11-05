package witness

import (
	"context"
	"crypto"
	"errors"
	"fmt"

	"github.com/LijZdk/a-witness/witness/sign"
)

type lookupResult int

const (
	keyFound   lookupResult = iota
	keyUnknown              // the resolver trusts no such key
	keyFailed               // the lookup itself failed; reported, and the key is not trusted
)

// signatureProblems checks rule 15 (SPEC.md, "Rules across documents"), in
// this order:
//
//  1. The mandate signature's key is trusted for the principal, and not also
//     for the provider, and the signature verifies.
//  2. If anything in step 1 failed, stop. The seal signatures are not checked,
//     and the Agent resolver is not asked, because the principal's signature
//     is what vouches for the agent's key.
//  3. The mandate names an agent key (agent.public_key_ref) that the Agent
//     resolver knows, that neither the principal nor the provider keys
//     trust, and that is not the key that signed the mandate.
//  4. Each seal signature is checked for its role: the agent's uses exactly
//     the mandate's key; the provider's uses a key trusted for the provider
//     (and for no other role); the principal's uses the key that signed the
//     mandate; any other signer is refused.
//  5. The signers a seal cannot do without are present and valid: the agent,
//     a provider, and the principal when Trust.RequirePrincipalSeal is set.
//
// principalSigned reports whether the seal carries a valid signature from the
// principal.
func signatureProblems(ctx context.Context, mandate, traceDoc map[string]any, t *Trust) (problems []Problem, principalSigned bool, err error) {
	add := func(format string, args ...any) {
		problems = append(problems, Problem{Rule: 15, Seq: -1, Message: fmt.Sprintf(format, args...)})
	}
	look := func(r sign.Resolver, keyID, role, where string) (crypto.PublicKey, lookupResult) {
		key, err := r.PublicKey(ctx, keyID)
		switch {
		case err == nil && key != nil:
			return key, keyFound
		case err == nil || errors.Is(err, sign.ErrUnknownKey):
			return nil, keyUnknown
		}
		add("%s: key '%s' could not be looked up for the %s", where, keyID, role)
		return nil, keyFailed
	}
	// verifies reports whether sig verifies under key, adding a problem if not.
	verifies := func(sig signature, where, typ string, payload []byte, key crypto.PublicKey) bool {
		if err := sign.Verify(sig.value, payload, key, sig.alg, sig.keyID, typ); err != nil {
			add("%s does not verify: %v", where, err)
			return false
		}
		return true
	}

	// Step 1: the mandate signature.
	msig, err := field[map[string]any](mandate, "signature", "mandate")
	if err != nil {
		return nil, false, err
	}
	mandateSig, err := readSignature(msig, "mandate signature")
	if err != nil {
		return nil, false, err
	}
	payload, err := MandatePayload(mandate)
	if err != nil {
		return nil, false, err
	}
	p := mandateSig.keyID
	principalKey, found := look(t.Principal, p, "principal", "mandate signature")
	switch found {
	case keyUnknown:
		add("mandate signature: key '%s' is not trusted for the principal", p)
	case keyFound:
		if _, also := look(t.Provider, p, "provider", "mandate signature"); also == keyFound {
			add("mandate signature: key '%s' is also trusted for the provider", p)
		}
		verifies(mandateSig, "mandate signature", MandateTyp, payload, principalKey)
	}

	// Step 2.
	if len(problems) > 0 {
		add("seal signatures were not checked, because the mandate signature is not valid")
		return problems, false, nil
	}

	// Step 3: the agent's key.
	var agentRef string
	if agent, ok := mandate["agent"].(map[string]any); ok {
		agentRef, _ = agent["public_key_ref"].(string)
	}
	var agentKey crypto.PublicKey
	agentUsable := false
	if agentRef == "" {
		add("the mandate names no agent key (agent.public_key_ref)")
	} else {
		agentUsable = true
		for _, role := range []struct {
			name string
			r    sign.Resolver
		}{{"principal", t.Principal}, {"provider", t.Provider}} {
			if _, also := look(role.r, agentRef, role.name, "the agent's key"); also == keyFound {
				add("the agent's key '%s' is also trusted for the %s", agentRef, role.name)
				agentUsable = false
			}
		}
		key, st := look(t.Agent, agentRef, "agent", "the agent's key")
		switch st {
		case keyUnknown:
			add("the agent's key '%s' could not be found", agentRef)
			agentUsable = false
		case keyFailed:
			agentUsable = false
		case keyFound:
			agentKey = key
			if sameKey(key, principalKey) {
				add("the agent's key '%s' is the key that signed the mandate", agentRef)
				agentUsable = false
			}
		}
	}

	// Step 4: each seal signature, in order.
	payload, err = SealPayload(traceDoc)
	if err != nil {
		return nil, false, err
	}
	sigs, err := field[[]any](traceDoc["seal"].(map[string]any), "signatures", "trace.seal")
	if err != nil {
		return nil, false, err
	}
	var agentSigned, providerSigned bool
	for i, s := range sigs {
		where := fmt.Sprintf("trace.seal.signatures[%d]", i)
		raw, ok := s.(map[string]any)
		if !ok {
			return nil, false, fmt.Errorf("witness: %s: expected an object", where)
		}
		signer, err := field[string](raw, "signer", where)
		if err != nil {
			return nil, false, err
		}
		sig, err := readSignature(raw, where)
		if err != nil {
			return nil, false, err
		}
		label := fmt.Sprintf("seal signature %d (%s)", i, signer)
		switch signer {
		case "agent":
			if agentRef != "" && sig.keyID != agentRef {
				add("seal signature %d (agent) uses key '%s', but the mandate names the agent's key as '%s'", i, sig.keyID, agentRef)
				continue
			}
			if agentUsable && verifies(sig, label, SealTyp, payload, agentKey) {
				agentSigned = true
			}
		case "provider":
			key, st := look(t.Provider, sig.keyID, "provider", label)
			if st == keyUnknown {
				add("seal signature %d (provider): key '%s' is not trusted for the provider", i, sig.keyID)
			}
			if st != keyFound {
				continue
			}
			if _, also := look(t.Principal, sig.keyID, "principal", label); also == keyFound {
				add("seal signature %d (provider): key '%s' is also trusted for the principal", i, sig.keyID)
				continue
			}
			if agentKey != nil && sameKey(key, agentKey) {
				add("seal signature %d (provider) uses the same key as the agent", i)
				continue
			}
			if sameKey(key, principalKey) {
				add("seal signature %d (provider) uses the same key as the mandate signature", i)
				continue
			}
			if verifies(sig, label, SealTyp, payload, key) {
				providerSigned = true
			}
		case "principal":
			if sig.keyID != p {
				add("seal signature %d (principal) uses key '%s', but the mandate was signed with '%s'", i, sig.keyID, p)
				continue
			}
			if verifies(sig, label, SealTyp, payload, principalKey) {
				principalSigned = true
			}
		default:
			add("seal signature %d (%s): this verifier trusts no keys for that signer", i, signer)
		}
	}

	// Step 5: the signers a seal cannot do without.
	if !agentSigned {
		add("the seal has no valid signature from the agent the mandate names")
	}
	if !providerSigned {
		add("the seal has no valid signature from a provider")
	}
	if t.RequirePrincipalSeal && !principalSigned {
		add("the seal has no valid signature from the principal who signed the mandate")
	}
	return problems, principalSigned, nil
}

// signature is a signature object's three fields, as read from a document.
type signature struct{ alg, keyID, value string }

func readSignature(obj map[string]any, where string) (signature, error) {
	var s signature
	var err error
	if s.alg, err = field[string](obj, "alg", where); err != nil {
		return s, err
	}
	if s.keyID, err = field[string](obj, "key_id", where); err != nil {
		return s, err
	}
	s.value, err = field[string](obj, "value", where)
	return s, err
}

// sameKey reports whether two public keys are the same key, whatever their key ids.
func sameKey(a, b crypto.PublicKey) bool {
	e, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && b != nil && e.Equal(b)
}
