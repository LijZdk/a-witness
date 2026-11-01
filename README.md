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
| **Trace** | The flight recording. Every step of the journey: quotes received, documents shown, alternatives ruled out and why, the human "yes", the purchase. Each event is hash-chained to the one before, the chain starts from the mandate, and the agent and provider sign the end of it, so nothing can be edited, removed or reordered without detection. (Signing arrives in Phase 2; see [How the chain works](#how-the-chain-works).) |

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
python scripts/validate.py \
  examples/home-insurance-switch.mandate.json \
  examples/home-insurance-switch.trace.json
```

Expected output:

```
PASS  home-insurance-switch.trace.json: schema ok, 12 events chained to mandate, seal covers final event, confirmation rule met
```

Try changing any price in the trace file and run it again. The validator will name the event that was tampered with.

Now run the version of Sam's story where things go wrong. The agent asks Sam to approve the switch, hears nothing, and buys anyway before the quote expires:

```bash
python scripts/validate.py \
  examples/home-insurance-no-confirmation.mandate.json \
  examples/home-insurance-no-confirmation.trace.json
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
                                          (all generated by make_examples.py, do not hand-edit)
scripts/
  chain.py              canonical JSON and hashing, shared by the scripts below
  make_examples.py      builds the examples with a real hash chain
  validate.py           schema, chain, timestamp, evidence and seal checks,
                        plus the human confirmation rule
  check.sh              everything CI runs
ROADMAP.md              phase by phase plan
CONTRIBUTING.md         how to help
```

## How the chain works

```
mandate ──hash──▶ event 0 ──hash──▶ event 1 ──hash──▶ ... ──hash──▶ event N ──▶ seal (signed)
```

- Each event stores `prev_hash` (the hash of the event before it). Event 0 points at the mandate hash.
- Each event's own `hash` is sha256 over its canonical JSON without the `hash` field.
- The `seal` signs the final hash. Agent and provider can both sign, so both sides hold the same record.

**What v0.1 does and does not prove.** The hash chain alone is *tamper-evident against naive edits*: change one event and its hash no longer matches. It does not stop a determined rewrite, because anyone can edit an event and recompute every hash after it. What stops that is the signed seal: a rewritten chain ends in a different final hash, which the original signers never signed. v0.1 signatures are placeholders (`UNSIGNED-EXAMPLE`), so **until Phase 2 a v0.1 trace is not tamper-proof**.

v0.1 also uses sorted-key compact JSON as a stand-in for RFC 8785 canonicalisation. Real signatures and RFC 8785 both arrive in Phase 2.

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
