# a-witness

**A flight recorder for AI agents buying financial products.**

> a-witness, short for agent witness. Draft spec v0.1. Not production ready.

## The problem in one story

Sam's home insurance renewal arrives 25% higher. Sam tells their AI agent: "sort it". The agent shops around, finds a cheaper policy, and switches.

Six months later Sam's kitchen floods and the claim is refused. Sam says: "I never agreed to that excess." The insurer says: "your agent bought it." The agent maker says: "the insurer showed us those terms."

Nobody can prove what actually happened.

Planes have the same problem when something goes wrong, which is why they carry a black box. It does not fly the plane. It just records, faithfully and tamper-proof, so that afterwards everyone can see the truth.

a-witness is that black box for agent-led financial journeys.

## What it is

Two small, open JSON formats plus tooling:

| Piece | Plain-English job |
|---|---|
| **Mandate** | The permission slip. What the person allowed their agent to do: which products, which actions, price limits, must-haves, when to ask first, when it expires. Signed by the person. |
| **Trace** | The flight recording. Every step of the journey: quotes received, documents shown, alternatives ruled out and why, the human "yes", the purchase. Each event is hash-chained to the one before, the chain starts from the mandate, and the agent and provider sign the whole record when it closes, so nothing can be edited, removed or reordered without detection. See [How the chain works](#how-the-chain-works). |

Every field is explained in plain English in [SPEC.md](SPEC.md), along with the hashing rules and what a verifier checks.

Later phases add a verifier CLI, drop-in middleware for MCP servers, and mappings to AP2 and UCP.

## What it is not

- **Not a new commerce protocol.** MCP, A2A, AP2, UCP and ACP already move the messages and money. a-witness rides on top of them.
- **Not a marketplace or a broker.** It never chooses, recommends or sells anything.
- **Not a compliance certificate.** It produces evidence. Whether that evidence shows good outcomes is for firms, ombudsmen and regulators to judge.
- **Not a store of personal data.** Mandates are pseudonymous. Documents and instructions are referenced by hash, not copied.

## Why the UK first

The FCA has said it will not write new AI-specific rules. Instead it relies on the Consumer Duty and the Senior Managers regime, and firms stay responsible for customer outcomes even when the customer is an agent. That creates an evidence gap: how does an insurer show a good outcome when a robot did the buying?

Traces map events to the four Consumer Duty outcomes:

| Outcome | Example evidence in a trace |
|---|---|
| Products and services | `requirement_check` events showing the product met the person's stated must-haves |
| Price and value | `quote_received` with `previous_price`, plus `alternatives_considered` |
| Consumer understanding | `disclosure_presented` with a plain summary, before `human_confirmation` |
| Consumer support | `post_sale_notice` for cooling-off rights and support contacts |

The formats are jurisdiction-neutral; the Consumer Duty mapping is a profile on top.

They are also product-neutral. Insurance is about what you pay and savings about what you earn, so a quote carries a `price`, an `aer` (annual equivalent rate), or both. The `fixed-rate-savings-switch` example shows the same record shape working for a maturing savings bond, where `previous_aer` makes a poor rollover rate visible the way `previous_price` makes a renewal rise visible.

## Quick start

```bash
pip install -r requirements.txt
go test ./...            # the Go reference implementation
python scripts/validate.py \
  examples/home-insurance-switch.mandate.json \
  examples/home-insurance-switch.trace.json \
  --keys examples/keys.jwks.json
```

Expected output:

```
PASS  home-insurance-switch.trace.json: schema ok, 12 events chained to mandate, seal covers final event, signatures valid, confirmation rule met
```

Try changing any price in the trace file and run it again. The validator will name the event that was tampered with, and report that the signatures no longer verify.

Now run the version of Sam's story where things go wrong. The agent asks Sam to approve the switch, hears nothing, and buys anyway before the quote expires:

```bash
python scripts/validate.py \
  examples/home-insurance-no-confirmation.mandate.json \
  examples/home-insurance-no-confirmation.trace.json \
  --keys examples/keys.jwks.json
```

```
FAIL  home-insurance-no-confirmation.trace.json: the record is intact, but the agent broke its mandate
  - event 11 (action_executed): the agent committed 298.00 GBP without an approved human_confirmation from the principal, but the mandate requires one every time
```

The record itself is genuine; the agent even logged that it gave up waiting. That is the point: a faithful record of a bad decision is exactly what settles the argument afterwards. The validator keeps the two questions apart, "is this record genuine?" and "did the agent do what it was allowed to?", and says which one failed.

To run everything CI runs (example regeneration, the passing example, and the inputs that must fail): `scripts/check.sh`.

## Repository layout

```
schemas/
  mandate.schema.json   permission slip (JSON Schema 2020-12)
  trace.schema.json     flight recording (JSON Schema 2020-12); reuses the mandate's
                        product and action lists
examples/
  home-insurance-switch.*.json            Sam's story, end to end (passes)
  home-insurance-no-confirmation.*.json   the agent buys without Sam's yes (fails)
  fixed-rate-savings-switch.*.json        Jo's maturing savings bond moved to a better,
                                          FSCS protected rate (passes)
  keys.jwks.json                          public keys the examples are signed with
                                          (all generated by make_examples.py, do not hand-edit)
witness/                Go reference implementation: hashing, AppendEvent, Seal, SignSeal,
                        and Verify (rules 1-8 and 15)
  canon/                RFC 8785 canonical JSON
  sign/                 detached JWS (ES256, EdDSA) and JWKS key lookup
testdata/vectors/       cross-language test vectors (canonical JSON, numbers, hashes, signatures)
scripts/
  chain.py              canonical JSON (RFC 8785) and hashing, shared by the scripts below
  jws.py                signatures, the Python counterpart of witness/sign
  make_vectors.py       builds the canonical JSON, hash and signature vectors
  make_number_vectors.mjs  builds the number vectors, using JavaScript itself
  make_examples.py      builds and signs the examples
  validate.py           schema, chain, timestamp, evidence, quote reference, seal
                        and signature checks, plus the human confirmation rule
  check.sh              everything CI runs
SPEC.md                 every field, the cross-document rules, and exact hashing
ROADMAP.md              phase by phase plan
CONTRIBUTING.md         how to help
```

## How the chain works

```
mandate ──hash──▶ event 0 ──hash──▶ event 1 ──hash──▶ ... ──hash──▶ event N ──▶ seal (signed)
```

- Each event stores `prev_hash` (the hash of the event before it). Event 0 points at the mandate hash.
- Each event's own `hash` is sha256 over its canonical JSON ([RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)) without the `hash` field.
- The principal signs the mandate. The agent signs the `seal`, with the key the mandate names, and the provider signs it too, so both sides hold the same record. Each seal signature covers the **whole trace**, not just the chain.

**What the hashes and the signatures each prove.** The hash chain catches a careless edit: change one event and its hash no longer matches. But anyone can edit an event and recompute every hash after it. The signatures stop that: any change anywhere in the trace, including its `journey` summary and `outcome_evidence`, breaks every seal signature, and nobody can re-sign without the signers' private keys. A signature proves only that the holder of a key signed, so a verifier must trust which keys belong to whom; see [SPEC.md, Keys](SPEC.md#keys).

Canonical JSON is RFC 8785 and signatures are detached JWS with ES256 or EdDSA. Both are implemented in Go ([`witness/canon`](witness/canon), [`witness/sign`](witness/sign)) and in Python, and the two are held together by the shared [test vectors](testdata/vectors/). The examples are signed with throwaway keys anyone can derive, so they show the mechanism, not who signed.

## Design principles

1. **Ride, don't replace.** Work alongside existing agent protocols.
2. **Record, don't decide.** Never sit in the decision path.
3. **Hash, don't hoard.** Keep personal data and documents out; keep fingerprints in.
4. **Readable by a human.** A complaints handler should understand a trace without a developer.
5. **Small enough to adopt in an afternoon.**

## Status and contributing

This is an early personal open source project, shared to get feedback. Issues and critiques of the schemas are the most useful contribution right now, especially from people working on insurance distribution, Consumer Duty, payments or agent protocols. See [CONTRIBUTING.md](CONTRIBUTING.md) and the [code of conduct](CODE_OF_CONDUCT.md).

## Licence

Apache 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

## Disclaimer

Nothing here is legal or regulatory advice. Using these formats does not make a firm compliant with any regulation.
