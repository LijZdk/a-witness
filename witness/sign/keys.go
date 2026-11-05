package sign

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Resolver finds the public key a key id names. Which keys a resolver
// returns is a trust decision: a signature only means something if the
// key behind it really belongs to the party it claims to be.
type Resolver interface {
	PublicKey(ctx context.Context, keyID string) (crypto.PublicKey, error)
}

// ErrUnknownKey means a resolver has no key with that id.
var ErrUnknownKey = errors.New("sign: no key with that id")

// KeySet is a fixed set of public keys, by full key id.
type KeySet map[string]crypto.PublicKey

// PublicKey implements Resolver.
func (s KeySet) PublicKey(_ context.Context, keyID string) (crypto.PublicKey, error) {
	if k, ok := s[keyID]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("%w: %q", ErrUnknownKey, keyID)
}

// ParseJWKS reads a JSON Web Key Set (RFC 7517) holding public keys: EC keys
// on P-256 and OKP keys on Ed25519. Each key needs a "kid", and the set is
// keyed by it. Private key members ("d") are refused, so a private key
// published by mistake is caught rather than silently used.
func ParseJWKS(b []byte) (KeySet, error) {
	var doc struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("sign: reading JWKS: %w", err)
	}
	set := KeySet{}
	for i, jwk := range doc.Keys {
		kid, _ := jwk["kid"].(string)
		if kid == "" {
			return nil, fmt.Errorf("sign: JWKS key %d has no kid", i)
		}
		if _, dup := set[kid]; dup {
			return nil, fmt.Errorf("sign: JWKS has two keys with kid %q", kid)
		}
		if _, private := jwk["d"]; private {
			return nil, fmt.Errorf("sign: JWKS key %q includes private key material; publish only public keys", kid)
		}
		key, err := parseJWK(jwk)
		if err != nil {
			return nil, fmt.Errorf("sign: JWKS key %q: %w", kid, err)
		}
		set[kid] = key
	}
	return set, nil
}

func parseJWK(jwk map[string]any) (crypto.PublicKey, error) {
	member := func(name string, size int) ([]byte, error) {
		s, _ := jwk[name].(string)
		b, err := b64.DecodeString(s)
		if err != nil || len(b) != size {
			return nil, fmt.Errorf("%q must be %d bytes of base64url", name, size)
		}
		return b, nil
	}
	switch kty, crv := jwk["kty"], jwk["crv"]; {
	case kty == "OKP" && crv == "Ed25519":
		x, err := member("x", ed25519.PublicKeySize)
		if err != nil {
			return nil, err
		}
		return ed25519.PublicKey(x), nil
	case kty == "EC" && crv == "P-256":
		x, err := member("x", 32)
		if err != nil {
			return nil, err
		}
		y, err := member("y", 32)
		if err != nil {
			return nil, err
		}
		// This rejects points that are not on the curve.
		key, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
		if err != nil {
			return nil, errors.New("the point is not on the P-256 curve")
		}
		return key, nil
	default:
		return nil, fmt.Errorf("unsupported key type %v/%v (use EC P-256 or OKP Ed25519)", kty, crv)
	}
}

// JWKSFetcher resolves key ids of the form "https://host/path#kid": it
// fetches the JWKS at the URL and returns the key whose "kid" is the part
// after "#". Only HTTPS is used. Each URL is fetched once and a successful
// result is cached. Concurrent lookups of one URL share a single fetch, and a
// slow URL never delays lookups of other URLs. A failed fetch is not cached,
// so a later lookup tries again.
type JWKSFetcher struct {
	Client *http.Client // nil means a client with a 10 second timeout

	mu      sync.Mutex // guards entries only; never held during network I/O
	entries map[string]*jwksEntry
}

// jwksEntry is one URL's fetch, in flight or finished. set and err are
// written before done is closed and read only after it.
type jwksEntry struct {
	done     chan struct{}
	set      KeySet
	err      error
	ctxEnded bool // err happened after the fetching caller's own ctx ended
}

// maxJWKSBytes caps how much a fetch will read, so a hostile URL cannot
// exhaust memory.
const maxJWKSBytes = 1 << 20

// PublicKey implements Resolver.
func (f *JWKSFetcher) PublicKey(ctx context.Context, keyID string) (crypto.PublicKey, error) {
	address, kid, ok := strings.Cut(keyID, "#")
	u, err := url.Parse(address)
	if !ok || kid == "" || err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("sign: key id %q is not of the form https://host/path#kid", keyID)
	}
	set, err := f.fetch(ctx, address)
	if err != nil {
		return nil, err
	}
	if k, ok := set[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("%w: %q at %s", ErrUnknownKey, kid, address)
}

func (f *JWKSFetcher) fetch(ctx context.Context, address string) (KeySet, error) {
	for {
		f.mu.Lock()
		e, ok := f.entries[address]
		if !ok {
			e = &jwksEntry{done: make(chan struct{})}
			if f.entries == nil {
				f.entries = map[string]*jwksEntry{}
			}
			f.entries[address] = e
		}
		f.mu.Unlock()

		if !ok {
			return f.lead(ctx, address, e)
		}

		// A finished entry is used without consulting ctx.
		select {
		case <-e.done:
		default:
			select {
			case <-e.done:
			case <-ctx.Done():
				return nil, fmt.Errorf("sign: fetching %s: %w", address, ctx.Err())
			}
		}
		if e.err != nil && e.ctxEnded {
			// The fetcher's own context ended (or its fetch never
			// finished), which says nothing about this caller. Give up
			// only if this caller's ctx ended too; otherwise look the
			// entry up again and fetch with our own.
			if err := ctx.Err(); err != nil {
				return nil, fmt.Errorf("sign: fetching %s: %w", address, err)
			}
			continue
		}
		return e.set, e.err
	}
}

// lead runs the fetch for an entry this caller created. Whatever way it
// exits, including a panic or runtime.Goexit, the entry is finished: removed
// unless the fetch succeeded, given an error if it has none, and done is
// closed, so no later caller waits on it forever. A panic keeps propagating.
func (f *JWKSFetcher) lead(ctx context.Context, address string, e *jwksEntry) (KeySet, error) {
	completed := false
	defer func() {
		if !completed {
			e.set = nil
			e.err = fmt.Errorf("sign: fetching %s: the fetch did not complete", address)
		}
		if e.err != nil {
			e.ctxEnded = !completed || ctx.Err() != nil
			f.mu.Lock()
			delete(f.entries, address)
			f.mu.Unlock()
		}
		close(e.done)
	}()
	e.set, e.err = f.get(ctx, address)
	completed = true
	return e.set, e.err
}

// get does the network fetch for one URL.
func (f *JWKSFetcher) get(ctx context.Context, address string) (KeySet, error) {
	client := f.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, fmt.Errorf("sign: fetching %s: %w", address, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sign: fetching %s: %w", address, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sign: fetching %s: %s", address, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes+1))
	if err != nil {
		return nil, fmt.Errorf("sign: fetching %s: %w", address, err)
	}
	if len(body) > maxJWKSBytes {
		return nil, fmt.Errorf("sign: %s is larger than %d bytes", address, maxJWKSBytes)
	}
	return ParseJWKS(body)
}

// PublicJWK returns the JWK (RFC 7517) for a public key, with the given kid.
func PublicJWK(key crypto.PublicKey, kid string) (map[string]any, error) {
	switch k := key.(type) {
	case ed25519.PublicKey:
		return map[string]any{"kty": "OKP", "crv": "Ed25519", "kid": kid, "x": b64.EncodeToString(k)}, nil
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			break
		}
		point, err := k.Bytes() // 0x04, then X and Y as 32 bytes each
		if err != nil {
			return nil, fmt.Errorf("sign: %w", err)
		}
		return map[string]any{"kty": "EC", "crv": "P-256", "kid": kid, "x": b64.EncodeToString(point[1:33]), "y": b64.EncodeToString(point[33:])}, nil
	}
	return nil, fmt.Errorf("sign: unsupported public key type %T", key)
}
