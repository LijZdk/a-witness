# a-witness roadmap

Built phase by phase. Each phase ends with something a stranger could run. Time estimates assume one focused build session a week (roughly 3 to 4 hours).

Think of it like building a car from the frame up: frame (schemas), locks (signing), dashboard (verifier), then the engine bay connections (middleware), and only then a test drive with other people.

---

## Phase 0: Setup (1 session) - DONE 2026-10-31

**Goal:** a clean home for the work.

- [x] Confirm the name (a-witness) is free on GitHub, npm and PyPI (checked 2026-10-31: no npm package, PyPI project, or GitHub user/org of that name)
- [x] Create a personal GitHub repo (`LijZdk/a-witness`; private at first, public since 2026-11-01), Apache 2.0 licence, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`

**Done when:** repo exists (private until Phase 1 ends).

---

## Phase 1: Schemas v0.1 (1 to 2 sessions) - DONE 2026-11-01

**Goal:** the two formats exist, have a worked example, and are machine-checked.

- [x] `mandate.schema.json`
- [x] `trace.schema.json` with typed payloads for the key event types
- [x] Worked example: home insurance renewal switch, with a real hash chain
- [x] `validate.py`: schema, chain, mandate link and seal checks
- [x] Second example that should **fail**: agent buys without `human_confirmation` when the mandate says `always` (`home-insurance-no-confirmation`; `validate.py` gained this one rule early so CI can prove it fails)
- [x] Third example from a different product: fixed rate savings switch (`fixed-rate-savings-switch`; quotes gained `aer` and `previous_aer`, mandates gained `min_aer`)
- [x] GitHub Action running validation on every push (`scripts/check.sh`, which also proves tampered and malformed inputs fail)
- [x] Short `SPEC.md` explaining each field in plain English, plus cross-document rules (marked checked or not in v0.1) and exact v0.1 hashing

**Done when:** three examples, CI green, repo made public.

---

## Phase 2: Go core, real signatures and canonicalisation (2 to 3 sessions)

**Goal:** the chain is cryptographically real, not just hashed, in a Go reference library.

- [ ] Go module `github.com/LijZdk/a-witness` (Go 1.23+), layout below
- [ ] Switch to RFC 8785 (JSON Canonicalization Scheme)
- [ ] Sign mandates and seals with ES256 / EdDSA as detached JWS (prefer standard library crypto; one small JWS dependency at most)
- [ ] Key discovery via JWKS URLs in `public_key_ref`
- [ ] Core API: `HashEvent`, `AppendEvent`, `Seal`, `Verify`
- [ ] Test vectors in `testdata/vectors/`: known inputs with known hashes and signatures, so other languages can implement and check themselves
- [ ] CI: `go test ./...`, `go vet`, `staticcheck`, plus the Python schema check until Phase 3 replaces it

Package layout:

```
cmd/a-witness/        CLI entry point, builds the `a-witness` binary (Phase 3)
witness/              public API: Mandate, Trace, Event types; AppendEvent, Seal, Verify
witness/canon/        RFC 8785 canonical JSON
witness/sign/         JWS sign and verify, JWKS key lookup
witness/schema/       embedded JSON Schemas and validation (go:embed ../../schemas)
witness/rules/        mandate rule checks (Phase 3)
witness/report/       text, JSON and HTML reports (Phase 3)
testdata/vectors/     cross-language test vectors
schemas/              source of truth JSON Schemas (unchanged)
ts/                   TypeScript middleware (Phase 4)
```

The spec and test vectors are the source of truth. The Go code is the reference implementation, not the definition.

**Done when:** a third party could reimplement verification from the spec and test vectors alone.

---

## Phase 3: Go verifier CLI with Consumer Duty checks (2 to 3 sessions)

**Goal:** point it at a trace, get a plain-English report a complaints handler can read. Ships as a single binary.

- [ ] `a-witness verify <mandate> <trace>`: integrity (schema, chain, signatures, mandate validity window, revocation)
- [ ] Rule checks against the mandate:
  - binding action without required human confirmation (port from `validate.py`, which already checks it for `always`; add `above_limits` once the price rules exist, and flag `never`)
  - amount committed above `max_commitment`, or renewal price rise above `max_price_increase_pct`; for savings, AER below `min_aer`
  - selected quote failed a requirement check
  - product class or action outside scope
  - binding action after mandate expiry
- [ ] Outcome report grouped by the four Consumer Duty outcomes, with gaps flagged ("no disclosure shown before confirmation")
- [ ] Output as terminal text, JSON and a single-page HTML report
- [ ] Release binaries for macOS, Linux and Windows via GoReleaser on tagged versions
- [ ] Retire `scripts/validate.py` once the Go verifier covers everything it checks

**Done when:** the failing example from Phase 1 produces a clear, human-readable red flag.

---

## Phase 4: TypeScript MCP middleware and demo (3 sessions)

**Goal:** adding a-witness to an existing agent setup takes minutes.

- [ ] npm package `@a-witness/mcp` in `ts/`, built on the official MCP TypeScript SDK
- [ ] Must pass the Phase 2 test vectors, so its hashes match the Go core byte for byte
- [ ] Middleware that wraps an MCP server's tools and writes trace events automatically for quote, disclose, bind calls
- [ ] Mock insurer MCP server (3 fictional providers, clearly fake brands)
- [ ] Mock agent that runs Sam's story end to end
- [ ] `docker compose up` demo producing a sealed trace and a verifier report
- [ ] 2 minute screen recording for the README

**Done when:** someone new can run the full demo in under 5 minutes.

---

## Phase 5: Protocol mappings and outreach (2 sessions, then ongoing)

**Goal:** get real people to look at it.

- [ ] `docs/mappings/ap2.md`: how a Witness mandate relates to an AP2 intent/cart mandate, and how `payment_mandate_ref` links them
- [ ] `docs/mappings/ucp.md` and `docs/mappings/mcp.md`
- [ ] Read the Veridom IETF OMP FCA draft properly; decide whether to align with it, contribute to it, or explain the difference
- [ ] Open a discussion (not a PR) on the AP2 and UCP repos asking whether an evidence extension is wanted
- [ ] Write one blog post telling Sam's story
- [ ] Share with 10 people: insurance distribution, Consumer Duty / compliance, payments engineers, agent builders

**Done when:** at least one of: a maintainer engages, an outside engineer tries it, or a compliance or legal person gives substantive feedback.

---

## Phase 6: v0.2 from feedback (open-ended)

Only start after Phase 5 signals. Likely candidates:

- Selective disclosure (show a complaints handler some events but not others)
- Revocation and amendment of mandates mid-journey
- Multi-agent journeys (a comparison agent hands off to a buying agent)
- Storage guidance: where traces live, retention periods, who holds copies

---

## Open questions

1. ~~**Reference language.**~~ Decided: Go for the core library and verifier CLI (single binary, standard library crypto); TypeScript for the MCP middleware (where MCP servers live). Python adapter only if asked for.
2. ~~**Name.**~~ Decided: a-witness. Go packages cannot contain hyphens, so the import path is `github.com/LijZdk/a-witness` with package `witness`; the CLI binary is `a-witness`; npm scope `@a-witness`.
3. **Should the principal sign the seal too?** Strong evidence, but adds friction.
4. **Free text in traces.** `plain_summary` and `rationale` help humans but could carry personal data. Hash them, cap them, or both?
5. **Who stores traces?** Agent, provider, person's wallet, or all three. The spec should not care, but the docs should advise.

## Kill or pause criteria

Pause the project if, after Phase 5 outreach, nobody outside gives substantive feedback within 8 weeks, or if one of the major protocols ships an equivalent evidence layer. In that case, contribute the useful parts upstream instead.
