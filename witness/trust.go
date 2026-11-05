package witness

import (
	"errors"

	"github.com/LijZdk/a-witness/witness/sign"
)

// Trust says which keys a verifier trusts, role by role (SPEC.md, "Keys").
// Rule 15 checks the mandate signer's key id, the mandate's agent.public_key_ref
// and each provider signature's key id against the Principal and Provider sets
// (SPEC.md, rule 15), and compares key material between the mandate signer, the
// agent's key and each provider signature. It does not look at the other keys in
// the sets: a key id in the Agent set is not checked against the Provider set,
// and the same key or key id listed in two role sets is not detected, so the
// verifier must keep the role sets disjoint.
type Trust struct {
	// Principal holds the keys trusted for the principal: the mandate
	// signature, and the seal signature labelled "principal". Required.
	Principal sign.Pinned
	// Provider holds the keys trusted for providers: the seal signature
	// labelled "provider". Required. Trust only the parties to the journey
	// being verified: the seal does not say which provider it should be.
	Provider sign.Pinned
	// Agent resolves the one key the mandate names in agent.public_key_ref.
	// It is asked only after the principal's signature on the mandate has
	// verified, so it may be a sign.JWKSFetcher: the principal vouches for
	// the key id it fetches. Required.
	Agent sign.Resolver
	// RequirePrincipalSeal also requires a valid seal signature from the
	// principal, made with the key that signed the mandate.
	RequirePrincipalSeal bool
}

// Principal and Provider are sign.Pinned so that their key source is fixed by
// the verifier (a sign.KeySet, or a sign.PinnedJWKS) and cannot be steered by
// a key id inside the documents being verified. An unpinned fetcher does not
// compile there.

// SkipSignatures, passed to Verify or Check as the Trust, leaves out the
// signature checks (rule 15). Skipping has to be asked for by name, so that
// nobody believes signatures were checked when they were not. Only this very
// pointer skips: a copy of it is an empty Trust, which is an error, and a copy
// given keys is checked in full.
var SkipSignatures = &Trust{}

var (
	errNoResolver      = errors.New("witness: no keys to trust; pass a *witness.Trust, or witness.SkipSignatures to check without signatures")
	errIncompleteTrust = errors.New("witness: Trust needs Principal, Provider and Agent keys; one is missing")
)

// check reports why t cannot be used to verify signatures, if it cannot.
func (t *Trust) check() error {
	if t == nil {
		return errNoResolver
	}
	if t == SkipSignatures {
		return nil
	}
	if f, ok := t.Agent.(*sign.JWKSFetcher); ok && f == nil {
		return errIncompleteTrust
	}
	if t.Principal == nil || t.Provider == nil || t.Agent == nil {
		return errIncompleteTrust
	}
	return nil
}
