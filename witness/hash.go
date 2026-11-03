// Package witness is the reference implementation of a-witness: hashing,
// and checking that a trace is a genuine record made under its mandate.
//
// SPEC.md is the definition; this package implements it. Mandates, traces
// and events are handled as parsed JSON (see canon.Parse), not Go structs,
// because hashes cover every field, including extension fields in event
// payloads that a struct would silently drop.
package witness

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/LijZdk/a-witness/witness/canon"
)

// HashPrefix starts every a-witness hash.
const HashPrefix = "sha256:"

// HashBytes returns the a-witness form of the SHA-256 of b.
func HashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return HashPrefix + hex.EncodeToString(sum[:])
}

// HashText hashes text exactly as given: its UTF-8 bytes, with no Unicode
// normalisation. Used for terms_hash, utterance_hash, document_hash and
// shown_summary_hash, so wording can be proved without being stored.
func HashText(s string) string {
	return HashBytes([]byte(s))
}

// HashValue hashes the RFC 8785 canonical form of a parsed JSON value.
func HashValue(v any) (string, error) {
	b, err := canon.Serialize(v)
	if err != nil {
		return "", err
	}
	return HashBytes(b), nil
}

// MandateHash hashes a mandate without its "signature" field, so signing
// a mandate does not change its hash. The trace's mandate_ref.mandate_hash
// and the first event's prev_hash both hold this value.
func MandateHash(mandate map[string]any) (string, error) {
	return HashValue(without(mandate, "signature"))
}

// HashEvent hashes an event without its own "hash" field. The result is
// the event's hash, and the next event's prev_hash.
func HashEvent(event map[string]any) (string, error) {
	return HashValue(without(event, "hash"))
}

func without(m map[string]any, key string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		if k != key {
			out[k] = v
		}
	}
	return out
}
