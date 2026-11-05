package witness

import (
	"crypto"
	"errors"
	"fmt"
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
