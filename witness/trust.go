package witness

import (
	"errors"

	"github.com/LijZdk/a-witness/witness/sign"
)

// Trust says which keys a verifier trusts, role by role (SPEC.md, "Keys").
// A key id trusted for one role is refused for another, and the keys of the
// mandate signer, the agent and a provider signature are compared with each
// other. The same public key listed under different key ids in two role sets
// is not detected, so keep the role sets disjoint.
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
