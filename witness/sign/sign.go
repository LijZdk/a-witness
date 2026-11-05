// Package sign makes and checks the signatures a-witness uses: detached JWS
// (RFC 7515, appendix F) with ES256 or EdDSA (Ed25519), and finds public
// keys by key id, from a local key set or a JWKS URL (RFC 7517).
//
// It uses only the Go standard library. SPEC.md, "Signatures", is the
// definition this implements.
package sign

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/LijZdk/a-witness/witness/canon"
)

// Algorithms a-witness accepts.
const (
	ES256 = "ES256" // ECDSA on P-256 with SHA-256
	EdDSA = "EdDSA" // Ed25519
)

var b64 = base64.RawURLEncoding.Strict()

// Sign returns a detached JWS over payload: "header..signature", with the
// payload left out because the verifier rebuilds it from the document.
//
// The header holds exactly alg, kid and typ, in RFC 8785 canonical form, so
// that Ed25519 signatures are byte-for-byte reproducible across languages.
// The signer may be any crypto.Signer, such as a key held in a hardware
// module, as long as its public key fits alg.
func Sign(signer crypto.Signer, alg, kid, typ string, payload []byte) (string, error) {
	if err := keyFits(signer.Public(), alg); err != nil {
		return "", err
	}
	header, err := canon.Serialize(map[string]any{"alg": alg, "kid": kid, "typ": typ})
	if err != nil {
		return "", err
	}
	protected := b64.EncodeToString(header)
	input := []byte(protected + "." + b64.EncodeToString(payload))

	var sig []byte
	switch alg {
	case EdDSA:
		if sig, err = signer.Sign(rand.Reader, input, crypto.Hash(0)); err != nil {
			return "", fmt.Errorf("sign: %w", err)
		}
	case ES256:
		digest := sha256.Sum256(input)
		der, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
		if err != nil {
			return "", fmt.Errorf("sign: %w", err)
		}
		// crypto.Signer gives ASN.1 DER; JWS wants R and S as 32 bytes each.
		var rs struct{ R, S *big.Int }
		if rest, err := asn1.Unmarshal(der, &rs); err != nil || len(rest) > 0 {
			return "", errors.New("sign: the signer returned a malformed ECDSA signature")
		}
		sig = make([]byte, 64)
		rs.R.FillBytes(sig[:32])
		rs.S.FillBytes(sig[32:])
	}
	return protected + ".." + b64.EncodeToString(sig), nil
}

// Verify checks a detached JWS made by Sign against the payload it should
// cover and the key it should verify with. The header must hold exactly
// alg, kid and typ, matching the expected values: anything else, such as a
// "crit" or "jku" header, is refused rather than interpreted.
func Verify(jws string, payload []byte, key crypto.PublicKey, alg, kid, typ string) error {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 || parts[1] != "" {
		return errors.New("sign: not a detached JWS (expected header..signature)")
	}
	headerJSON, err := b64.DecodeString(parts[0])
	if err != nil {
		return errors.New("sign: the JWS header is not valid base64url")
	}
	h, err := canon.Parse(headerJSON)
	if err != nil {
		return fmt.Errorf("sign: the JWS header is not valid JSON: %w", err)
	}
	header, ok := h.(map[string]any)
	if !ok || len(header) != 3 {
		return errors.New("sign: the JWS header must hold exactly alg, kid and typ")
	}
	for _, f := range [][2]string{{"alg", alg}, {"kid", kid}, {"typ", typ}} {
		if got, ok := header[f[0]].(string); !ok || got != f[1] {
			return fmt.Errorf("sign: the JWS header has %s %v, expected %q", f[0], header[f[0]], f[1])
		}
	}
	if err := keyFits(key, alg); err != nil {
		return err
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return errors.New("sign: the JWS signature is not valid base64url")
	}
	input := []byte(parts[0] + "." + b64.EncodeToString(payload))

	switch alg {
	case EdDSA:
		if len(sig) != ed25519.SignatureSize || !ed25519.Verify(key.(ed25519.PublicKey), input, sig) {
			return ErrBadSignature
		}
	case ES256:
		digest := sha256.Sum256(input)
		if len(sig) != 64 {
			return ErrBadSignature
		}
		r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
		if !ecdsa.Verify(key.(*ecdsa.PublicKey), digest[:], r, s) {
			return ErrBadSignature
		}
	}
	return nil
}

// ErrBadSignature means the signature does not match the payload and key:
// the document was changed after signing, or signed with a different key.
var ErrBadSignature = errors.New("sign: the signature does not match the document and key")

// keyFits checks that a public key is the kind alg needs.
func keyFits(key crypto.PublicKey, alg string) error {
	switch alg {
	case EdDSA:
		if k, ok := key.(ed25519.PublicKey); ok && len(k) == ed25519.PublicKeySize {
			return nil
		}
		return errors.New("sign: EdDSA needs an Ed25519 key")
	case ES256:
		if k, ok := key.(*ecdsa.PublicKey); ok && k.Curve == elliptic.P256() {
			return nil
		}
		return errors.New("sign: ES256 needs a P-256 ECDSA key")
	}
	return fmt.Errorf("sign: unsupported algorithm %q (use ES256 or EdDSA)", alg)
}
