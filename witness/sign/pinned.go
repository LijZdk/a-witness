package sign

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
)

// Pinned is a Resolver whose key source the verifier chose. A verifier needs
// one for each party whose keys it must trust on its own authority (the
// principal and the provider): their keys must never come from a place that a
// key id inside the document being verified can point to.
//
// Pinned is sealed. Only KeySet (a fixed set of keys) and *PinnedJWKS (a
// JWKSFetcher limited to URLs the verifier listed) implement it. A bare
// *JWKSFetcher does not, because it fetches whatever URL a key id names,
// so passing one where a Pinned is required does not compile. The seal guards
// against accidental misuse only: a type that embeds a KeySet and overrides
// PublicKey still satisfies Pinned, and deliberately so can any resolver.
type Pinned interface {
	Resolver
	pinned()
}

func (KeySet) pinned() {}

// PinnedJWKS resolves "https://host/path#kid" key ids through a JWKSFetcher,
// but only when the part before "#" is exactly one of the URLs it was made
// with. Any other address is refused as an unknown key, and no request is
// made.
//
// The fetcher follows HTTP redirects unless its Client says otherwise. A
// redirect can move the fetch to a host the verifier did not list, so give the
// fetcher a Client whose CheckRedirect refuses redirects if that matters.
type PinnedJWKS struct {
	f    *JWKSFetcher
	urls []string
}

func (*PinnedJWKS) pinned() {}

// NewPinnedJWKS pins f to the given URLs. It fails when f is nil, when there
// are no URLs, or when a URL is not a plain, canonical https URL: it needs a
// host and no userinfo, query, fragment or dot segments, and must be written
// exactly as net/url writes it back, so that it can be compared byte for byte.
func NewPinnedJWKS(f *JWKSFetcher, urls ...string) (*PinnedJWKS, error) {
	if f == nil {
		return nil, errors.New("sign: NewPinnedJWKS needs a JWKSFetcher")
	}
	if len(urls) == 0 {
		return nil, errors.New("sign: NewPinnedJWKS needs at least one URL")
	}
	for _, s := range urls {
		if err := checkPinnedURL(s); err != nil {
			return nil, err
		}
	}
	return &PinnedJWKS{f: f, urls: slices.Clone(urls)}, nil
}

func checkPinnedURL(s string) error {
	bad := func(why string) error { return fmt.Errorf("sign: pinned URL %q: %s", s, why) }
	u, err := url.Parse(s)
	switch {
	case err != nil:
		return bad("not a URL")
	case u.Scheme != "https":
		return bad("must be https")
	case u.Host == "" || u.Hostname() == "":
		return bad("has no host")
	case u.User != nil:
		return bad("must not hold userinfo")
	case u.RawQuery != "" || u.ForceQuery:
		return bad("must not hold a query")
	case u.Fragment != "" || u.RawFragment != "" || strings.Contains(s, "#"):
		return bad("must not hold a fragment")
	case u.Opaque != "":
		return bad("is opaque")
	}
	for seg := range strings.SplitSeq(u.Path, "/") {
		if seg == "." || seg == ".." {
			return bad("must not hold . or .. segments")
		}
	}
	if u.String() != s {
		return bad("is not in canonical form (want " + u.String() + ")")
	}
	return nil
}

// PublicKey implements Resolver. The address before "#" must equal a pinned
// URL byte for byte; otherwise the key is unknown and nothing is fetched.
func (p *PinnedJWKS) PublicKey(ctx context.Context, keyID string) (crypto.PublicKey, error) {
	address, kid, ok := strings.Cut(keyID, "#")
	if p == nil || !ok || kid == "" || !slices.Contains(p.urls, address) {
		return nil, fmt.Errorf("%w: %q is not at a pinned address", ErrUnknownKey, keyID)
	}
	return p.f.PublicKey(ctx, keyID)
}
