package witness

import (
	"crypto"
	"errors"
	"fmt"
	"maps"
	"time"

	"github.com/LijZdk/a-witness/witness/canon"
	"github.com/LijZdk/a-witness/witness/sign"
)

// The JWS "typ" for each kind of signature, so that a mandate signature can
// never pass as a seal signature or the other way round.
const (
	MandateTyp = "a-witness-mandate"
	SealTyp    = "a-witness-seal"
)

// Signer is a party able to sign: who they are, and their key.
type Signer struct {
	Role  string        // for seals: "agent", "provider", "principal" or "witness_service"
	Alg   string        // sign.ES256 or sign.EdDSA
	KeyID string        // where verifiers find the public key, ideally "https://host/jwks.json#kid"
	Key   crypto.Signer // the private key, or a handle to one held elsewhere
}

// MandatePayload is what a mandate signature covers: the mandate's
// canonical JSON without its "signature" field. These are the same bytes
// the mandate hash covers.
func MandatePayload(mandate map[string]any) ([]byte, error) {
	return canon.Serialize(without(mandate, "signature"))
}

// SealPayload is what every seal signature covers: the whole trace, in
// canonical JSON, except the seal's "signatures". Each signer signs the
// same bytes, so signatures can be added independently and in any order.
func SealPayload(trace map[string]any) ([]byte, error) {
	seal, ok := trace["seal"].(map[string]any)
	if !ok {
		return nil, errors.New("witness: the trace has no seal")
	}
	t := without(trace, "seal")
	t["seal"] = without(seal, "signatures")
	return canon.Serialize(t)
}

// SignMandate signs a mandate as its principal, setting its "signature".
func SignMandate(mandate map[string]any, s Signer) error {
	payload, err := MandatePayload(mandate)
	if err != nil {
		return err
	}
	jws, err := sign.Sign(s.Key, s.Alg, s.KeyID, MandateTyp, payload)
	if err != nil {
		return err
	}
	mandate["signature"] = map[string]any{"alg": s.Alg, "key_id": s.KeyID, "value": jws}
	return nil
}

// AppendEvent adds an event to an unsealed trace, setting its seq,
// prev_hash and hash. The caller fills in at, type, actor and payload.
// The first event is chained to trace.mandate_ref.mandate_hash.
func AppendEvent(trace, event map[string]any) error {
	if _, sealed := trace["seal"]; sealed {
		return errors.New("witness: the trace is sealed; no more events can be added")
	}
	events, _ := trace["events"].([]any)
	var prev any
	if n := len(events); n > 0 {
		last, ok := events[n-1].(map[string]any)
		if !ok {
			return fmt.Errorf("witness: event %d is not an object", n-1)
		}
		prev = last["hash"]
	} else if ref, ok := trace["mandate_ref"].(map[string]any); ok {
		prev = ref["mandate_hash"]
	}
	if p, ok := prev.(string); !ok || p == "" {
		return errors.New("witness: nothing to chain to: set trace.mandate_ref.mandate_hash before the first event")
	}
	delete(event, "hash")
	event["seq"] = float64(len(events))
	event["prev_hash"] = prev
	h, err := HashEvent(event)
	if err != nil {
		return err
	}
	event["hash"] = h
	trace["events"] = append(events, event)
	return nil
}

// Seal closes a trace: it records the last event's hash and the time, with
// no signatures yet. After sealing, add signatures with SignSeal; change
// nothing else, or every signature breaks.
func Seal(trace map[string]any, sealedAt time.Time) error {
	if _, sealed := trace["seal"]; sealed {
		return errors.New("witness: the trace is already sealed")
	}
	events, _ := trace["events"].([]any)
	if len(events) == 0 {
		return errors.New("witness: a trace needs at least one event before it can be sealed")
	}
	last, _ := events[len(events)-1].(map[string]any)
	trace["seal"] = map[string]any{
		"final_event_hash": last["hash"],
		"sealed_at":        sealedAt.UTC().Format(time.RFC3339),
		"signatures":       []any{},
	}
	return nil
}

// SignSeal adds one party's signature to a sealed trace.
func SignSeal(trace map[string]any, s Signer) error {
	switch s.Role {
	case "agent", "provider", "principal", "witness_service":
	default:
		return fmt.Errorf("witness: unknown signer role %q", s.Role)
	}
	payload, err := SealPayload(trace)
	if err != nil {
		return err
	}
	jws, err := sign.Sign(s.Key, s.Alg, s.KeyID, SealTyp, payload)
	if err != nil {
		return err
	}
	seal := trace["seal"].(map[string]any)
	sigs, _ := seal["signatures"].([]any)
	seal["signatures"] = append(sigs, map[string]any{"signer": s.Role, "alg": s.Alg, "key_id": s.KeyID, "value": jws})
	return nil
}

// ConfirmationTyp is the JWS "typ" of the principal's signature on a
// human_confirmation (SPEC.md, "Signed confirmations"), so that it can never
// pass as a mandate signature or a seal signature, or the other way round.
const ConfirmationTyp = "a-witness-confirmation"

// confirmationRequired are the payload fields, besides method and decision,
// that a signed human_confirmation cannot do without.
var confirmationRequired = []string{"shown_summary_hash", "quote_id", "amount"}

// confirmationBytes is the RFC 8785 canonical JSON that the principal signs:
// the mandate hash and trace id that tie the yes to one journey, the ref of the
// signed confirmation before it (previousRef, "" if none) that fixes its place,
// and the event payload without principal_signature.
func confirmationBytes(mandateHash, traceID, previousRef string, payload map[string]any) ([]byte, error) {
	return canon.Serialize(map[string]any{
		"mandate_hash": mandateHash,
		"trace_id":     traceID,
		"previous_ref": previousRef,
		"payload":      without(payload, "principal_signature"),
	})
}

// ConfirmationRef names a signed confirmation: the SHA-256 of the bytes the
// principal signed (see ConfirmationPayload), not of the signature.
func ConfirmationRef(payload []byte) string { return HashBytes(payload) }

// traceIdentity reads the two fields of a trace that a confirmation signature
// ties the yes to.
func traceIdentity(trace map[string]any) (mandateHash, traceID string, err error) {
	ref, _ := trace["mandate_ref"].(map[string]any)
	if mandateHash, _ = ref["mandate_hash"].(string); mandateHash == "" {
		return "", "", errors.New("witness: the trace has no mandate_ref.mandate_hash to sign a confirmation against")
	}
	if traceID, _ = trace["trace_id"].(string); traceID == "" {
		return "", "", errors.New("witness: the trace has no trace_id to sign a confirmation against")
	}
	return mandateHash, traceID, nil
}

// walkSignedConfirmations visits, in event order, each human_confirmation whose
// payload has a principal_signature, with the bytes that were (or would be)
// signed for it and its confirmation_ref, and returns the ref of the last one
// ("" if none). previous_ref is worked out here from the events, never read
// from them, and advances for every signed event whether or not its signature
// verifies. traceID is asked for only when there is a signed event. visit may
// be nil.
func walkSignedConfirmations(events []any, mandateHash string, traceID func() (string, error),
	visit func(i int, ev, payload map[string]any, body []byte, ref string) error) (string, error) {
	previous, id := "", ""
	for i, e := range events {
		ev, _ := e.(map[string]any)
		pl, _ := ev["payload"].(map[string]any)
		if ev["type"] != "human_confirmation" || pl == nil {
			continue
		}
		if _, signed := pl["principal_signature"]; !signed {
			continue
		}
		if id == "" {
			var err error
			if id, err = traceID(); err != nil {
				return "", err
			}
		}
		body, err := confirmationBytes(mandateHash, id, previous, pl)
		if err != nil {
			return "", err
		}
		previous = ConfirmationRef(body)
		if visit != nil {
			if err := visit(i, ev, pl, body, previous); err != nil {
				return "", err
			}
		}
	}
	return previous, nil
}

// ConfirmationPayload is what the principal signs to confirm: the canonical
// JSON of the trace's mandate_hash and trace_id, the confirmation_ref of the
// latest signed human_confirmation already in the trace's events (or "" if
// there is none), and the event payload without its principal_signature. The
// payload must hold method, decision, shown_summary_hash, quote_id and amount.
// seq, prev_hash and at are not signed.
func ConfirmationPayload(trace map[string]any, payload map[string]any) ([]byte, error) {
	mandateHash, traceID, err := traceIdentity(trace)
	if err != nil {
		return nil, err
	}
	for _, name := range append([]string{"method", "decision"}, confirmationRequired...) {
		if _, ok := payload[name]; !ok {
			return nil, fmt.Errorf("witness: a signed confirmation needs %s", name)
		}
	}
	events, _ := trace["events"].([]any)
	previous, err := walkSignedConfirmations(events, mandateHash, func() (string, error) { return traceID, nil }, nil)
	if err != nil {
		return nil, err
	}
	return confirmationBytes(mandateHash, traceID, previous, payload)
}

// SignConfirmation signs the bytes from ConfirmationPayload as the principal.
// The signer's role must be "principal"; its key must be the one that signed
// the mandate, or a verifier refuses the confirmation. It returns the
// signature object to set as the payload's principal_signature.
func SignConfirmation(payload []byte, s Signer) (map[string]any, error) {
	if s.Role != "principal" {
		return nil, fmt.Errorf("witness: only the principal signs a confirmation, not role %q", s.Role)
	}
	jws, err := sign.Sign(s.Key, s.Alg, s.KeyID, ConfirmationTyp, payload)
	if err != nil {
		return nil, err
	}
	return map[string]any{"alg": s.Alg, "key_id": s.KeyID, "value": jws}, nil
}

// AppendSignedConfirmation adds a signed human_confirmation to an unsealed
// trace. event must be of type human_confirmation, with actor principal and
// the payload that was signed; sig is what SignConfirmation returned for
// ConfirmationPayload(trace, event["payload"]) on this trace as it stands. The
// payload is recomputed here, so a missing field or trace id is refused, then
// principal_signature is set and the event is appended as by AppendEvent. The
// signature itself is checked by the verifier, which holds the keys.
func AppendSignedConfirmation(trace, event, sig map[string]any) error {
	if event["type"] != "human_confirmation" {
		return fmt.Errorf("witness: a signed confirmation is a human_confirmation event, not %v", event["type"])
	}
	if event["actor"] != "principal" {
		return fmt.Errorf("witness: a signed confirmation has actor principal, not %v", event["actor"])
	}
	payload, ok := event["payload"].(map[string]any)
	if !ok {
		return errors.New("witness: the event has no payload")
	}
	for _, f := range []string{"alg", "key_id", "value"} {
		if s, _ := sig[f].(string); s == "" {
			return fmt.Errorf("witness: the signature has no %s", f)
		}
	}
	if _, err := ConfirmationPayload(trace, payload); err != nil {
		return err
	}
	// Work on copies, so that a refusal by AppendEvent leaves the caller's event as it was.
	staged := maps.Clone(event)
	stagedPayload := maps.Clone(payload)
	stagedPayload["principal_signature"] = sig
	staged["payload"] = stagedPayload
	if err := AppendEvent(trace, staged); err != nil {
		return err
	}
	maps.Copy(event, staged)
	events := trace["events"].([]any)
	events[len(events)-1] = event
	return nil
}
