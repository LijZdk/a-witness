package witness

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"strings"

	"github.com/LijZdk/a-witness/witness/internal/text"
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
//     (not also trusted for the principal, and not the agent's or the mandate
//     signer's key material); the principal's uses the key that signed the
//     mandate; any other signer is refused.
//  5. The signers a seal cannot do without are present and valid: the agent,
//     a provider, and the principal when Trust.RequirePrincipalSeal is set.
//  6. Each human_confirmation that carries a principal_signature, in event
//     order: its actor is the principal; it holds the fields a signed
//     confirmation needs; the signature uses the key that signed the mandate;
//     and it verifies over the confirmation payload (see ConfirmationPayload).
//     This step runs whenever step 2 did not stop.
//
// principalSigned reports whether the seal carries a valid signature from the
// principal. signed maps the seq of each human_confirmation whose signature
// verified to its confirmation_ref.
func signatureProblems(ctx context.Context, mandate, traceDoc map[string]any, t *Trust) (problems []Problem, principalSigned bool, signed map[int]string, err error) {
	addAt := func(seq int, format string, args ...any) {
		problems = append(problems, Problem{Rule: 15, Seq: seq, Message: fmt.Sprintf(format, args...)})
	}
	add := func(format string, args ...any) { addAt(-1, format, args...) }
	look := func(r sign.Resolver, keyID, role, where string) (crypto.PublicKey, lookupResult) {
		key, err := r.PublicKey(ctx, keyID)
		switch {
		case err == nil && key != nil:
			return key, keyFound
		case err == nil || errors.Is(err, sign.ErrUnknownKey):
			return nil, keyUnknown
		}
		add("%s: key '%s' could not be looked up for the %s (%v)", where, esc(keyID), role, esc(err.Error()))
		return nil, keyFailed
	}
	// verifiesAt reports whether sig verifies under key, adding a problem (at
	// event seq, or -1) if not. The "sign: " prefix of the error is left off, so
	// that a bad signature reads the same as scripts/validate.py's.
	verifiesAt := func(seq int, sig signature, where, typ string, payload []byte, key crypto.PublicKey) bool {
		if err := sign.Verify(sig.value, payload, key, sig.alg, sig.keyID, typ); err != nil {
			addAt(seq, "%s does not verify: %s", where, esc(strings.TrimPrefix(err.Error(), "sign: ")))
			return false
		}
		return true
	}
	verifies := func(sig signature, where, typ string, payload []byte, key crypto.PublicKey) bool {
		return verifiesAt(-1, sig, where, typ, payload, key)
	}

	// Step 1: the mandate signature.
	msig, err := field[map[string]any](mandate, "signature", "mandate")
	if err != nil {
		return nil, false, nil, err
	}
	mandateSig, err := readSignature(msig, "mandate signature")
	if err != nil {
		return nil, false, nil, err
	}
	payload, err := MandatePayload(mandate)
	if err != nil {
		return nil, false, nil, err
	}
	p := mandateSig.keyID
	principalKey, found := look(t.Principal, p, "principal", "mandate signature")
	switch found {
	case keyUnknown:
		add("mandate signature: key '%s' is not trusted for the principal", esc(p))
	case keyFound:
		if _, also := look(t.Provider, p, "provider", "mandate signature"); also == keyFound {
			add("mandate signature: key '%s' is also trusted for the provider", esc(p))
		}
		verifies(mandateSig, "mandate signature", MandateTyp, payload, principalKey)
	}

	// Step 2.
	if len(problems) > 0 {
		add("seal signatures were not checked, because the mandate signature is not valid")
		return problems, false, nil, nil
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
				add("the agent's key '%s' is also trusted for the %s", esc(agentRef), role.name)
				agentUsable = false
			}
		}
		key, st := look(t.Agent, agentRef, "agent", "the agent's key")
		switch st {
		case keyUnknown:
			add("the agent's key '%s' could not be found", esc(agentRef))
			agentUsable = false
		case keyFailed:
			agentUsable = false
		case keyFound:
			agentKey = key
			if sameKey(key, principalKey) {
				add("the agent's key '%s' is the key that signed the mandate", esc(agentRef))
				agentUsable = false
			}
		}
	}

	// Step 4: each seal signature, in order.
	payload, err = SealPayload(traceDoc)
	if err != nil {
		return nil, false, nil, err
	}
	sigs, err := field[[]any](traceDoc["seal"].(map[string]any), "signatures", "trace.seal")
	if err != nil {
		return nil, false, nil, err
	}
	var agentSigned, providerSigned bool
	for i, s := range sigs {
		where := fmt.Sprintf("trace.seal.signatures[%d]", i)
		raw, ok := s.(map[string]any)
		if !ok {
			return nil, false, nil, fmt.Errorf("witness: %s: expected an object", where)
		}
		signer, err := field[string](raw, "signer", where)
		if err != nil {
			return nil, false, nil, err
		}
		sig, err := readSignature(raw, where)
		if err != nil {
			return nil, false, nil, err
		}
		label := fmt.Sprintf("seal signature %d (%s)", i, esc(signer))
		switch signer {
		case "agent":
			if agentRef != "" && sig.keyID != agentRef {
				add("seal signature %d (agent) uses key '%s', but the mandate names the agent's key as '%s'", i, esc(sig.keyID), esc(agentRef))
				continue
			}
			if agentUsable && verifies(sig, label, SealTyp, payload, agentKey) {
				agentSigned = true
			}
		case "provider":
			key, st := look(t.Provider, sig.keyID, "provider", label)
			if st == keyUnknown {
				add("seal signature %d (provider): key '%s' is not trusted for the provider", i, esc(sig.keyID))
			}
			if st != keyFound {
				continue
			}
			if _, also := look(t.Principal, sig.keyID, "principal", label); also == keyFound {
				add("seal signature %d (provider): key '%s' is also trusted for the principal", i, esc(sig.keyID))
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
				add("seal signature %d (principal) uses key '%s', but the mandate was signed with '%s'", i, esc(sig.keyID), esc(p))
				continue
			}
			if verifies(sig, label, SealTyp, payload, principalKey) {
				principalSigned = true
			}
		default:
			add("seal signature %d (%s): this verifier trusts no keys for that signer", i, esc(signer))
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

	// Step 6: each signed human_confirmation, in event order.
	signed = map[int]string{}
	events, _ := traceDoc["events"].([]any)
	ref, _ := traceDoc["mandate_ref"].(map[string]any)
	mandateHash, _ := ref["mandate_hash"].(string)
	traceID := func() (string, error) { return field[string](traceDoc, "trace_id", "trace") }
	_, err = walkSignedConfirmations(events, mandateHash, traceID, func(i int, ev, pl map[string]any, cp []byte, confirmationRef string) error {
		where := fmt.Sprintf("trace.events[%d].payload.principal_signature", i)
		sigObj, ok := pl["principal_signature"].(map[string]any)
		if !ok {
			return fmt.Errorf("witness: %s: expected an object", where)
		}
		csig, err := readSignature(sigObj, where)
		if err != nil {
			return err
		}
		label := fmt.Sprintf("event %d (human_confirmation)", i)
		refused := false
		if actor, _ := ev["actor"].(string); actor != "principal" {
			addAt(i, "%s: carries the principal's signature, but its actor is '%s'", label, esc(actor))
			refused = true
		}
		for _, name := range confirmationRequired {
			if _, ok := pl[name]; !ok {
				addAt(i, "%s: a signed confirmation needs %s", label, name)
				refused = true
			}
		}
		if refused {
			return nil
		}
		if csig.keyID != p {
			addAt(i, "%s: principal_signature uses key '%s', but the mandate was signed with '%s'", label, esc(csig.keyID), esc(p))
			return nil
		}
		if verifiesAt(i, csig, label+": principal_signature", ConfirmationTyp, cp, principalKey) {
			signed[i] = confirmationRef
		}
		return nil
	})
	if err != nil {
		return nil, false, nil, err
	}
	return problems, principalSigned, signed, nil
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

// esc prints a string from a document safely; see text.Esc.
var esc = text.Esc
