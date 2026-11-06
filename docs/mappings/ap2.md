# Mapping a-witness to AP2

Status: draft, written 2026-11-05 against AP2 v0.2. Not affiliated with or endorsed by the AP2 maintainers. Back to [README](../../README.md) and [SPEC](../../SPEC.md). Related: [UCP](ucp.md), [MCP](mcp.md).

## What AP2 is

The Agent Payments Protocol (AP2) is a protocol for securing payments that an AI agent makes for a person. Its core idea is the *mandate*: a signed record that the person authorised the agent to do something, which merchants, payment providers and networks can verify. In v0.2 there are two mandate types, a Checkout Mandate (what is bought) and a Payment Mandate (how it is paid), each with a signed receipt ([AP2 specification](https://ap2-protocol.org/ap2/specification/)).

AP2 does not define catalogs, checkout APIs or messaging between the parties. It says it works as a security feature inside a commerce protocol and is designed to be compatible with UCP ([AP2 specification](https://ap2-protocol.org/ap2/specification/)).

## Where a-witness sits

AP2 authorises. a-witness records. An AP2 mandate lets a verifier decide, at the moment of payment, whether the agent may pay. An a-witness trace lets a reviewer decide, months later, whether the whole journey was reasonable. a-witness does not replace, wrap or alter AP2 messages. It keeps a reference to them and a hash of what they said.

The two overlap in one place. AP2 says the Checkout and Payment Mandates and Receipts can be brought together as evidence in a dispute ([AP2 specification, Dispute Evidence](https://ap2-protocol.org/ap2/specification/)). That covers the purchase step. It does not cover the quotes compared, the documents shown or the reasons for the choice. a-witness is a draft format for recording those steps. The entries are the recorder's own account, signed with the agent's key. They are not independent proof of what happened.

## Terminology warning

AP2 v0.1 (September 2025) had Intent, Cart and Payment mandates, and much writing online still uses those names. **AP2 v0.2 (April 2026) has only Checkout and Payment mandates, each either "open" or "closed".** The v0.1.0 specification names the Cart Mandate, the Intent Mandate and the Payment Mandate ([AP2 v0.1.0 docs/specification.md](https://github.com/google-agentic-commerce/AP2/blob/v0.1.0/docs/specification.md)). I found no Intent Mandate or Cart Mandate in v0.2 ([AP2 specification](https://ap2-protocol.org/ap2/specification/); release dates from the [AP2 changelog](https://github.com/google-agentic-commerce/AP2/blob/main/CHANGELOG.md)). This document uses v0.2 terms. Roughly:

| Older name | v0.2 equivalent | Basis |
|---|---|---|
| Intent Mandate | Open Checkout Mandate and open Payment Mandate: user-signed, carry constraints and the agent's key (`cnf`), not yet tied to a transaction | [Agent Authorization, Mandate Structure](https://ap2-protocol.org/ap2/agent_authorization/) |
| Cart Mandate | Closed Checkout Mandate: tied to one merchant-signed checkout by `checkout_hash` | [Checkout Mandate](https://ap2-protocol.org/ap2/checkout_mandate/) |

This table is my reading, not a statement in the AP2 spec. I only searched the v0.1.0 specification for the mandate names. I did not read it through.

## AP2 in one paragraph

A Shopping Agent builds a checkout with a Merchant. A Trusted Surface (a UI that must not be agentic) shows it to the user. In **human-present** mode the user signs *closed* Checkout and Payment Mandates directly. In **human-not-present** mode the user signs *open* mandates holding constraints (allowed payees, amount range, allowed line items, budget, recurrence, execution dates), and the agent later signs the closed mandates with the key named in the open one. The verifier gets the chain. The Merchant checks the Checkout Mandate. The Credential Provider, Network and Merchant Payment Processor check the Payment Mandate. The Merchant returns a Checkout Receipt. AP2 does not name who issues the Payment Receipt. It says that once the Merchant Payment Processor has accepted or rejected the Payment Mandate, a signed Payment Receipt must be returned to the Shopping Agent, the Credential Provider and possibly the Networks (my reading: the Merchant Payment Processor issues it). If the Credential Provider's or Network's own verification of the Payment Mandate fails, they must return a Payment Receipt carrying the error. More generally, a verifier must return a signed receipt on acceptance or rejection of a mandate. A receipt's `reference` is a hash of the closed mandate it answers ([AP2 specification, Modes](https://ap2-protocol.org/ap2/specification/); [Payment Mandate](https://ap2-protocol.org/ap2/payment_mandate/); [Agent Authorization, Action Authorization](https://ap2-protocol.org/ap2/agent_authorization/)).

## How `payment_mandate_ref` links to an AP2 payment mandate

Today the schema says only: "Link to an AP2 payment mandate or similar, if payment was taken" ([`schemas/trace.schema.json`](../../schemas/trace.schema.json), [SPEC.md](../../SPEC.md#action_executed)). It is a free string. The example uses `ap2:pm_example_123`.

**What AP2 gives you to point at.** A closed Payment Mandate has no id field of its own. Its fields are `vct`, `transaction_id`, `payee`, `payment_amount`, `payment_instrument`, and optionally `pisp`, `execution_date`, `risk_data`, `iat`, `exp` ([payment_mandate.json schema](https://github.com/google-agentic-commerce/AP2/blob/main/code/sdk/schemas/ap2/payment_mandate.json)). Three things identify it:

| Candidate | What it is | Source |
|---|---|---|
| `transaction_id` | Base64url hash of the merchant-signed `checkout_jwt`. It names the *checkout*, so it is shared by the Checkout and Payment Mandates for that purchase. | [payment_mandate.json schema](https://github.com/google-agentic-commerce/AP2/blob/main/code/sdk/schemas/ap2/payment_mandate.json) |
| Payment Receipt `reference` | Hash of the closed Payment Mandate the receipt answers, "calculated in the same manner as the `sd_hash`". This is the value AP2 itself uses to say "this receipt is about that mandate". | [AP2 specification, Dispute](https://ap2-protocol.org/ap2/specification/); [payment_receipt.json schema](https://github.com/google-agentic-commerce/AP2/blob/main/code/sdk/schemas/ap2/payment_receipt.json) |
| Payment Receipt `payment_id`, `psp_confirmation_id`, `network_confirmation_id` | Identifiers of the payment and its confirmations. The last two appear only on success. | [payment_receipt.json schema](https://github.com/google-agentic-commerce/AP2/blob/main/code/sdk/schemas/ap2/payment_receipt.json) |

**Proposal (not yet in SPEC.md).** Set `payment_mandate_ref` to the Payment Receipt `reference`, written `ap2:` followed by the base64url value. The `ap2:` prefix is an a-witness convention, not defined by AP2. Reasons: it is a content hash, so it cannot be quietly re-pointed at a different mandate; it is the value AP2 receipts use to identify the mandate; and a-witness already prefers hashes to copies of documents. `transaction_id` is the better key for finding the Checkout Mandate, because AP2 notes that retrieval of the Checkout Mandate would use the Payment Mandate `transaction_id` as the key ([AP2 specification, Dispute Evidence](https://ap2-protocol.org/ap2/specification/)). Carry `transaction_id`, `payment_id` and the confirmation ids as extra payload fields on the same `action_executed` event. Payloads are open, so this needs no schema change (SPEC.md, Conventions).

What this does **not** do: the a-witness trace holds only a hash, not the mandate. To check the link, a reviewer needs the closed Payment Mandate (and the Checkout Mandate) from a party that holds them. AP2 says the Shopping Agent, Credential Provider, Network and Merchant Payment Processor may each be able to provide the Payment Mandate and Receipt, and the Shopping Agent or Merchant the Checkout Mandate ([AP2 specification, Dispute Evidence](https://ap2-protocol.org/ap2/specification/)). It leaves retention and retrieval requirements out of scope, so a-witness cannot assume the mandate will still be obtainable.

## Concept table

"No counterpart" means I found nothing in the AP2 pages listed under Sources that does this job.

| a-witness | AP2 v0.2 | Notes |
|---|---|---|
| Mandate (whole) | Open Checkout and Payment Mandates (autonomous mode) | Both are pre-authorisation signed by the user. Not equivalent; see mismatches. In human-present mode there is no open mandate, only closed ones. [Specification, Modes](https://ap2-protocol.org/ap2/specification/) |
| `principal` (`principal_ref`, `type`, `jurisdiction`, `support_needs_declared`) | The user, identified through a User Credential or a Trusted Agent Provider. [Agent Authorization](https://ap2-protocol.org/ap2/agent_authorization/) | No pseudonymous reference field in the mandate schemas I read. `support_needs_declared`: no counterpart. |
| `agent` (`agent_id`, `operator`, `software`) | Shopping Agent role. [Specification, Roles](https://ap2-protocol.org/ap2/specification/) | AP2 identifies the agent by a key (`cnf`). `agent_id`, `operator`, `software`: no counterpart. |
| `agent.public_key_ref` | `cnf` claim: the agent's public key, required in open mandates. [Specification, Autonomous](https://ap2-protocol.org/ap2/specification/); [Agent Authorization](https://ap2-protocol.org/ap2/agent_authorization/) | AP2 embeds the JWK. a-witness points to a JWKS URL and `kid`. |
| `scope.product_classes` | No counterpart. The line-items constraint lists acceptable item ids. [Checkout Mandate](https://ap2-protocol.org/ap2/checkout_mandate/) | AP2 constrains specific items, not categories. |
| `scope.allowed_actions` | No counterpart. | AP2 mandates authorise a checkout and a payment. They do not name actions such as `switch` or `cancel`. |
| `scope.provider_allowlist` | `checkout.allowed_merchants` and `payment.allowed_payees` constraints. [Checkout Mandate](https://ap2-protocol.org/ap2/checkout_mandate/); [Payment Mandate](https://ap2-protocol.org/ap2/payment_mandate/) | Close match. |
| `scope.provider_blocklist` | No counterpart. | AP2 constraints list allowed values only. |
| `limits.max_commitment` | `payment.amount_range` (`min`, `max`, `currency`) and `payment.budget`. [Payment Mandate](https://ap2-protocol.org/ap2/payment_mandate/) | Close match. `budget` is meant for use with `agent_recurrence`. |
| `limits.max_transactions` | `payment.agent_recurrence` (`max_occurrences`, `frequency`). Also, an agent must not present another open mandate until it has a rejection receipt for the previous one. [Payment Mandate](https://ap2-protocol.org/ap2/payment_mandate/); [Specification, Autonomous](https://ap2-protocol.org/ap2/specification/) | Partial. |
| `limits.max_price_increase_pct`, `min_aer`, `max_term_months`, `requirements` | No counterpart. | AP2 has an extension point for new constraint types, and a verifier must treat an unknown constraint as failing. [Agent Authorization, Verification](https://ap2-protocol.org/ap2/agent_authorization/); [Specification, Extension Points](https://ap2-protocol.org/ap2/specification/) |
| `human_confirmation` (`always`, `above_limits`, `never`) | The mode: human present (user signs the closed mandates) or human not present (agent signs under an open mandate). [Specification, Modes](https://ap2-protocol.org/ap2/specification/) | `always` is roughly human present. `never` is roughly human not present. `above_limits`: no counterpart, because AP2 mode is not defined as depending on limits. |
| `consent` (`granted_at`, `method`, `terms_hash`) | The Trusted Surface obtaining informed user consent before a user-signed mandate is created. [Specification, Roles](https://ap2-protocol.org/ap2/specification/) | Mandates carry `iat`, but I found no field for consent method or a hash of the wording shown. Treat as no counterpart. |
| `validity` (`not_before`, `expires_at`) | `iat` and `exp` claims. `payment.execution_date` has `not_before` and `not_after`. [Payment Mandate](https://ap2-protocol.org/ap2/payment_mandate/) | AP2 recommends `exp` be the smallest value that lets the agent finish. |
| `validity.revocation_url` | No counterpart. | I did not find a revocation mechanism in the pages read. |
| `signature` on the mandate (detached JWS, ES256 or EdDSA) | The user's signature on a closed or open mandate, as an SD-JWT with key binding. [Specification, Verifiable Digital Credential Formats](https://ap2-protocol.org/ap2/specification/) | Different format. See mismatches. |
| Events `quote_requested`, `quote_received` | Outside AP2, which leaves catalog and checkout APIs to the commerce protocol. The merchant-signed `checkout_jwt` is the nearest thing to a quote. [Checkout Mandate](https://ap2-protocol.org/ap2/checkout_mandate/) | A `quote_received` could carry the hash of the `checkout_jwt` as an extra field. |
| Events `intent_captured`, `requirement_check`, `alternatives_considered`, `selection_made` | No counterpart. | Agent reasoning is outside AP2. |
| Event `disclosure_presented` | No counterpart. | AP2 records what was bought and paid, not which documents were shown. |
| Event `human_confirmation` | The user's signature on a closed mandate through a Trusted Surface (human present). | In human-not-present mode the signing happened at mandate time, not at purchase time. See mismatches. A signed `human_confirmation` (`principal_signature`) is not an AP2 Checkout Mandate and does not reference one; linking the two is undefined. |
| Event `action_executed` | Checkout Receipt and Payment Receipt. [Checkout Mandate](https://ap2-protocol.org/ap2/checkout_mandate/); [Payment Mandate](https://ap2-protocol.org/ap2/payment_mandate/) | See the section above. `provider_reference`: no exact counterpart (the receipt has `payment_id` and confirmation ids). |
| Events `post_sale_notice`, `escalation` | No counterpart. | |
| Event `error` | Receipts carry `error` and `error_description`. [payment_receipt.json schema](https://github.com/google-agentic-commerce/AP2/blob/main/code/sdk/schemas/ap2/payment_receipt.json) | AP2 defines the codes `invalid_credential`, `unresolved_constraint`, `invalid_mandate` and `mandates_not_supported`; they could be recorded in an a-witness `error` event. [Agent Authorization, Errors](https://ap2-protocol.org/ap2/agent_authorization/) |
| Hash chain (`prev_hash`, `hash`) | No counterpart. | AP2 hashes single artifacts (`checkout_hash`, receipt `reference`, `sd_hash`). It does not chain a journey. |
| Seal and `seal.signatures` | No counterpart. | Receipts are signed by the verifier, one artifact each. Nothing signs a whole journey. |
| Key ids and JWKS (`key_id` as `https://…#kid`) | Keys are named by `kid` in JWS headers. How a verifier finds them depends on the trust model (User Credential issuer, or Trusted Agent Provider). [Agent Authorization](https://ap2-protocol.org/ap2/agent_authorization/) | I found no JWKS convention in AP2 itself. The UCP AP2 extension uses a `keys` array in the UCP profile; see [ucp.md](ucp.md). |

## Mismatches and open questions

1. **No format for `payment_mandate_ref` is defined.** The proposal above is mine. The existing example value (`ap2:pm_example_123`) does not correspond to anything in AP2. Needs a decision, and the example should change with it.
2. **Naming drift.** ROADMAP.md Phase 5 speaks of an "AP2 intent/cart mandate". AP2 v0.2 has no intent or cart mandate. The roadmap wording should change.
3. **Open mandates are not a-witness mandates.** An AP2 open mandate constrains one purchase's payee, amount and items and is bound to an agent key. An a-witness mandate covers a whole journey, with product classes, actions, must-haves and confirmation rules. One journey could involve several AP2 open mandates, or none (human-present mode). Whether an a-witness journey should list the hashes of the AP2 mandates it relied on is undecided. The mandate schema is closed, so a trace event payload is the only place for them today.
4. **Who creates the mandate.** In AP2 the Shopping Agent assembles mandate content and a Trusted Surface gets the user's signature. a-witness says the principal's wallet or app signs the mandate. These may or may not be the same component. Not checked.
5. **Constraint gaps.** AP2 has no standard constraint for product class, renewal price rise, minimum rate, term or must-haves. A verifier must fail on unknown constraints, so a-witness limits cannot be pushed into an AP2 open mandate as custom constraints unless every verifier on the path supports them.
6. **Signature formats differ.** AP2 uses SD-JWT with key binding and selective disclosure. a-witness uses detached JWS over RFC 8785 canonical JSON, with `typ` values `a-witness-mandate`, `a-witness-seal` and `a-witness-confirmation`. An a-witness signature does not verify as an AP2 mandate, and the reverse. The principal's signature on a `human_confirmation` is an a-witness JWS made with the mandate key; it is not an AP2 Checkout Mandate (which the user signs on a Trusted Surface) and does not reference one. How the two would be linked is not defined.
7. **Algorithm rule.** The AP2 specification text requires the Checkout JWT to use a non-deterministic signature such as ECDSA, not Ed25519. a-witness permits EdDSA. This only matters if one key serves both. The UCP AP2 extension says AP2 v0.2 is internally inconsistent on this and that [AP2 issue 268](https://github.com/google-agentic-commerce/AP2/issues/268) tracks it. Follow AP2 for the checkout JWT. ([AP2 specification, Payment Mandate](https://ap2-protocol.org/ap2/specification/); [UCP AP2 extension, note on algorithm](https://ucp.dev/2026-08-25/specification/payment/extensions/ap2-mandates/))
8. **Money, time and hashes are encoded differently.** AP2 amounts are integers in minor units; a-witness uses decimal strings. AP2 `iat` and `exp` are Unix epoch integers, while `execution_date` and the `payment.execution_date` constraint use ISO 8601 / RFC 3339 strings; a-witness uses RFC 3339 throughout. AP2 hashes are base64url; a-witness hashes are `sha256:` plus hex. Converting is easy but must be exact, and every mapped value should say which form it is in.
9. **Personal data.** AP2 mandates carry payee and payment instrument details, in selectively disclosable form. a-witness keeps personal data out and references by hash. Storing a hash keeps the mandate's contents out of the trace. A hash is still a linkable identifier and may be personal data.
10. **Human-not-present confirmation.** In autonomous mode the user signed an *open* mandate earlier and never sees the final purchase. An a-witness `human_confirmation` event with `decision: approved` for that purchase would be false. The a-witness mandate would be `above_limits` or `never`, and the trace should point to the AP2 mandate chain as the authority instead. How to write that is not defined.
11. **Consent evidence.** AP2 has no field for the wording shown to the user. a-witness `consent.terms_hash` and `shown_summary_hash` have nowhere to land on the AP2 side. They stay a-witness-only evidence.
12. **Fit for insurance and savings.** AP2 is built around checkouts with line items, a payee and a payment instrument. A home insurance switch or a savings deposit may not look like that. The AP2 pages I read do not say whether a financial product fits a "Checkout". Neither AP2 nor a-witness settles it.
13. **`journey.transport: "ap2"`.** AP2 says it is not a transport: it runs inside a commerce protocol. A journey using AP2 would normally have transport `ucp`, `mcp` or `rest`, plus an AP2 reference on the binding action. Consider removing `ap2` from the enum or documenting what it means.
14. **Not read.** I did not read the AP2 flows, glossary, security and privacy, or implementation pages, nor the SDK code. Nothing here relies on them.
15. **The `reference` value is not unique to a mandate.** It is computed like `sd_hash`. For a chain of mandates AP2 says it is "a hash over the final SD-JWT in the chain" ([Agent Authorization, Action Authorization](https://ap2-protocol.org/ap2/agent_authorization/)). My inference, not stated by AP2: an SD-JWT presentation depends on which disclosures were presented, so different parties may hold different `reference` values for the same mandate. A reviewer should not assume two parties' values will match.
16. **Timing.** A receipt `reference` exists only once a Payment Receipt has come back, so `payment_mandate_ref` cannot be filled in before then. A purchase that was attempted and refused has a receipt with an error, not a successful `action_executed`.

## Sources

All checked on 2026-11-05.

| What | URL | Version read |
|---|---|---|
| AP2 documentation site (rendered) | https://ap2-protocol.org/ap2/specification/ and sibling pages `/ap2/payment_mandate/`, `/ap2/checkout_mandate/`, `/ap2/agent_authorization/` | AP2 v0.2, page title "Agent Payments Protocol - AP2"; the specification page's heading reads "Agentic Payment Protocol (v0.2)" |
| AP2 source repository | https://github.com/google-agentic-commerce/AP2 | Release `v0.2.0` (2026-04-28, commit `b4587ac`). Page text and JSON schemas were read from `main` at commit `e1ea56d` (2026-04-29), which is later than the tag. The GitHub compare of `v0.2.0...main` shows only `CHANGELOG.md`, `CONTRIBUTING.md`, `README.md` and `uv.lock` changed, so the docs and schemas I read match the tag. |
| AP2 JSON schemas | https://github.com/google-agentic-commerce/AP2/tree/main/code/sdk/schemas/ap2 | `main` at `e1ea56d` |
| AP2 changelog | https://github.com/google-agentic-commerce/AP2/blob/main/CHANGELOG.md | Lists 0.1.0 (2025-09-16) and 0.2.0 (2026-04-28) |
| UCP AP2 Mandates extension (for the algorithm note and issue 268) | https://ucp.dev/2026-08-25/specification/payment/extensions/ap2-mandates/ | UCP release `2026-08-25` |

Confidence: high for the v0.2 mandate, constraint and receipt structure, which I read in full. Medium for the `payment_mandate_ref` proposal, which is a design choice and not something AP2 states.
